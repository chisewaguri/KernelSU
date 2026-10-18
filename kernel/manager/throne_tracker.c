#include "ksu.h"
#include "linux/cred.h"
#include "linux/namei.h"
#include "util.h"
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>

#include "policy/allowlist.h"
#include "manager/apk_sign.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "manager/throne_tracker.h"

static DEFINE_MUTEX(throne_tracker_mutex);

static const struct ksu_manager_config default_manager = {
    .package = KSU_PACKAGE_NAME,
    .certificate_hash = EXPECTED_HASH,
    .certificate_size = EXPECTED_SIZE,
};

static struct ksu_manager_config manager_config = {
    .package = KSU_PACKAGE_NAME,
    .certificate_hash = EXPECTED_HASH,
    .certificate_size = EXPECTED_SIZE,
};

static char selected_package[KSU_MAX_PACKAGE_NAME] = KSU_PACKAGE_NAME;
static bool configured_manager_installed;

uid_t ksu_manager_appid = KSU_INVALID_APPID;

#define DATA_PATH_LEN 384 // 384 is enough for /data/app/<package>/base.apk

static char cached_manager_apk_path[DATA_PATH_LEN];

#define SYSTEM_PACKAGES_LIST_PATH "/data/system/packages.list"

struct uid_data {
    struct list_head list;
    u32 uid;
    char package[KSU_MAX_PACKAGE_NAME];
};

static void crown_manager(const char *package, struct list_head *uid_data)
{
    struct list_head *list = (struct list_head *)uid_data;
    struct uid_data *np;

    list_for_each_entry (np, list, list) {
        if (strncmp(np->package, package, KSU_MAX_PACKAGE_NAME) == 0) {
            pr_info("Crowning manager: uid=%d\n", np->uid);
            ksu_set_manager_appid(np->uid);
            break;
        }
    }
}

struct data_path {
    char dirpath[DATA_PATH_LEN];
    int depth;
    struct list_head list;
};

struct my_dir_context {
    struct dir_context ctx;
    struct list_head *data_path_list;
    char *parent_dir;
    void *private_data;
    int depth;
    const struct ksu_manager_config *config;
};
// https://docs.kernel.org/filesystems/porting.html
// filldir_t (readdir callbacks) calling conventions have changed. Instead of returning 0 or -E... it returns bool now. false means "no more" (as -E... used to) and true - "keep going" (as 0 in old calling conventions). Rationale: callers never looked at specific -E... values anyway. -> iterate_shared() instances require no changes at all, all filldir_t ones in the tree converted.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define FILLDIR_RETURN_TYPE bool
#define FILLDIR_ACTOR_CONTINUE true
#define FILLDIR_ACTOR_STOP false
#else
#define FILLDIR_RETURN_TYPE int
#define FILLDIR_ACTOR_CONTINUE 0
#define FILLDIR_ACTOR_STOP -EINVAL
#endif

static bool maybe_manager_apk_dir(const char *path, const char *package)
{
    _Static_assert(sizeof(KSU_PACKAGE_NAME) < KSU_MAX_PACKAGE_NAME, "KSU_PACKAGE_NAME too long!");
    char pkg[KSU_MAX_PACKAGE_NAME];
    if (get_pkg_from_apk_dir_path(pkg, path) < 0) {
        pr_err("Failed to get package name from apk dir path: %s\n", path);
        return false;
    }

    // pkg is `<real package>`
    return strcmp(pkg, package) == 0;
}

static FILLDIR_RETURN_TYPE my_actor(struct dir_context *ctx, const char *name, int namelen, loff_t off, u64 ino,
                                    unsigned int d_type)
{
    struct my_dir_context *my_ctx = container_of(ctx, struct my_dir_context, ctx);

    // we put the apk path we collected here
    char *candidate_path = (char *)my_ctx->private_data;

    char dirpath[DATA_PATH_LEN];

    if (!strncmp(name, "..", namelen) || !strncmp(name, ".", namelen))
        return FILLDIR_ACTOR_CONTINUE; // Skip "." and ".."

    if (d_type == DT_DIR && namelen >= 8 && !strncmp(name, "vmdl", 4) && !strncmp(name + namelen - 4, ".tmp", 4)) {
        pr_info("Skipping directory: %.*s\n", namelen, name);
        return FILLDIR_ACTOR_CONTINUE; // Skip staging package
    }

    if (snprintf(dirpath, DATA_PATH_LEN, "%s/%.*s", my_ctx->parent_dir, namelen, name) >= DATA_PATH_LEN) {
        pr_err("Path too long: %s/%.*s\n", my_ctx->parent_dir, namelen, name);
        return FILLDIR_ACTOR_CONTINUE;
    }

    if (d_type != DT_DIR)
        return FILLDIR_ACTOR_CONTINUE;

    // Opening the package dir would show up on an inotify watch held by the
    // package's own app. Runs before the depth add: on Android <= 12 the
    // package dir sits directly under /data/app.
    if (maybe_manager_apk_dir(dirpath, my_ctx->config->package)) {
        snprintf(candidate_path, DATA_PATH_LEN, "%s/base.apk", dirpath);
        return FILLDIR_ACTOR_STOP;
    }

    if (my_ctx->depth > 1) {
        struct data_path *data = kzalloc(sizeof(struct data_path), GFP_KERNEL);

        if (!data) {
            pr_err("Failed to allocate memory for %s\n", dirpath);
            return FILLDIR_ACTOR_CONTINUE;
        }

        strscpy(data->dirpath, dirpath, DATA_PATH_LEN);
        data->depth = my_ctx->depth - 1;
        list_add_tail(&data->list, my_ctx->data_path_list);
    }

    return FILLDIR_ACTOR_CONTINUE;
}

static void search_manager(const char *path, int depth, struct list_head *uid_data,
                           const struct ksu_manager_config *config)
{
    int i, stop = 0;
    struct list_head data_path_list;
    INIT_LIST_HEAD(&data_path_list);
    unsigned long data_app_magic = 0;

    // First depth
    struct data_path data;
    strscpy(data.dirpath, path, DATA_PATH_LEN);
    data.depth = depth;
    list_add_tail(&data.list, &data_path_list);

    // we put the apk path we collected here
    char candidate_path[DATA_PATH_LEN];
    candidate_path[0] = 0;

    for (i = depth; i >= 0; i--) {
        struct data_path *pos, *n;

        list_for_each_entry_safe (pos, n, &data_path_list, list) {
            if (stop)
                goto skip_iterate;
            struct my_dir_context ctx = { .ctx.actor = my_actor,
                                          .data_path_list = &data_path_list,
                                          .parent_dir = pos->dirpath,
                                          .private_data = candidate_path,
                                          .depth = pos->depth,
                                          .config = config };
            struct file *file = ksu_filp_open_nonotify(pos->dirpath, O_RDONLY | O_NOFOLLOW | O_NOATIME | O_DIRECTORY);
            if (IS_ERR(file)) {
                pr_err("Failed to open directory: %s, err: %ld\n", pos->dirpath, PTR_ERR(file));
                goto skip_iterate;
            }

            // grab magic on first folder, which is /data/app
            if (!data_app_magic) {
                if (file->f_inode->i_sb->s_magic) {
                    data_app_magic = file->f_inode->i_sb->s_magic;
                    pr_info("%s: dir: %s got magic! 0x%lx\n", __func__, pos->dirpath, data_app_magic);
                } else {
                    filp_close(file, NULL);
                    goto skip_iterate;
                }
            }

            if (file->f_inode->i_sb->s_magic != data_app_magic) {
                pr_info("%s: skip: %s magic: 0x%lx expected: 0x%lx\n", __func__, pos->dirpath,
                        file->f_inode->i_sb->s_magic, data_app_magic);
                filp_close(file, NULL);
                goto skip_iterate;
            }

            iterate_dir(file, &ctx.ctx);
            filp_close(file, NULL);

            if (!candidate_path[0])
                goto skip_iterate;

            // As soon as we get the manager apk path, we can stop
            stop = 1;

            bool is_manager = is_manager_apk(candidate_path, config->certificate_size, config->certificate_hash);
            pr_info("Found manager base.apk at path: %s, is_manager: %d\n", candidate_path, is_manager);

            // Only crown if signature verification pass
            if (unlikely(!is_manager))
                goto skip_iterate;

            strcpy(cached_manager_apk_path, candidate_path);
            crown_manager(config->package, uid_data);

        skip_iterate:
            list_del(&pos->list);
            if (pos != &data)
                kfree(pos);
        }
    }
}

static bool is_uid_exist(uid_t uid, char *package, void *data)
{
    struct list_head *list = (struct list_head *)data;
    struct uid_data *np;

    bool exist = false;
    list_for_each_entry (np, list, list) {
        if (np->uid == uid % PER_USER_RANGE && strncmp(np->package, package, KSU_MAX_PACKAGE_NAME) == 0) {
            exist = true;
            break;
        }
    }
    return exist;
}

static void track_throne_locked(bool prune_only)
{
    const struct cred *old_cred = override_creds(ksu_cred);
    struct file *fp = filp_open(SYSTEM_PACKAGES_LIST_PATH, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_err("%s: open " SYSTEM_PACKAGES_LIST_PATH " failed: %ld\n", __func__, PTR_ERR(fp));
        goto out_revert_cred;
    }

    struct list_head uid_list;
    INIT_LIST_HEAD(&uid_list);

    char chr = 0;
    loff_t pos = 0;
    loff_t line_start = 0;
    char buf[KSU_MAX_PACKAGE_NAME];
    for (;;) {
        ssize_t count = kernel_read(fp, &chr, sizeof(chr), &pos);
        if (count != sizeof(chr))
            break;
        if (chr != '\n')
            continue;

        count = kernel_read(fp, buf, sizeof(buf) - 1, &line_start);
        if (count <= 0) {
            break;
        }
        buf[count] = '\0';

        struct uid_data *data = kzalloc(sizeof(struct uid_data), GFP_KERNEL);
        if (!data) {
            filp_close(fp, 0);
            goto out;
        }

        char *tmp = buf;
        const char *delim = " ";
        char *package = strsep(&tmp, delim);
        char *uid = strsep(&tmp, delim);
        if (!uid || !package) {
            kfree(data);
            pr_err("update_uid: package or uid is NULL!\n");
            break;
        }

        u32 res;
        if (kstrtou32(uid, 10, &res)) {
            kfree(data);
            pr_err("update_uid: uid parse err\n");
            break;
        }
        data->uid = res;
        strscpy(data->package, package, sizeof(data->package));
        list_add_tail(&data->list, &uid_list);
        // reset line start
        line_start = pos;
    }
    filp_close(fp, 0);

    // now update uid list
    struct uid_data *np;
    struct uid_data *n;

    if (prune_only)
        goto prune;

    const struct ksu_manager_config *config = &manager_config;
    configured_manager_installed = false;
    list_for_each_entry (np, &uid_list, list) {
        if (!strcmp(np->package, manager_config.package)) {
            configured_manager_installed = true;
            break;
        }
    }
    if (!configured_manager_installed && !manager_config.strict)
        config = &default_manager;

    if (strcmp(selected_package, config->package)) {
        strscpy(selected_package, config->package, sizeof(selected_package));
        cached_manager_apk_path[0] = 0;
        ksu_invalidate_manager_uid();
    }

    // first, check if manager_uid exist!
    uid_t manager_package_uid = KSU_INVALID_APPID;
    bool need_rescan = false;
    list_for_each_entry (np, &uid_list, list) {
        if (strcmp(np->package, config->package) == 0) {
            manager_package_uid = np->uid;
            break;
        }
    }

    if (manager_package_uid == KSU_INVALID_APPID) {
        cached_manager_apk_path[0] = 0;
        if (ksu_is_manager_appid_valid()) {
            pr_info("manager is uninstalled, invalidate it!\n");
            ksu_invalidate_manager_uid();
            goto prune;
        }
    } else {
        if (!ksu_is_manager_appid_valid()) {
            need_rescan = true;
        } else if (unlikely(np->uid != ksu_get_manager_appid())) {
            // this should not happen in normal android system
            pr_info("manager uid changed, invalidate it!\n");
            cached_manager_apk_path[0] = 0;
            ksu_invalidate_manager_uid();
            need_rescan = true;
        } else {
            // uid unchanged, skip
            pr_info("manager uid unchanged, skip search!\n");
        }
    }

    if (need_rescan) {
        // If the apk path still exists, the verification result won't be changed
        if (cached_manager_apk_path[0]) {
            struct path p;
            int ret = kern_path(cached_manager_apk_path, 0, &p);
            if (ret == 0) {
                // skip search
                pr_info("manager apk path unchanged, skip search!\n");
                path_put(&p);
                goto prune;
            } else if (ret != -ENOENT) {
                pr_err("stat cached manager path failed: %d (path=%s)\n", ret, cached_manager_apk_path);
            }
        }
        pr_info("Searching manager %s...\n", config->package);
        search_manager("/data/app", 2, &uid_list, config);
        pr_info("Search manager finished\n");
    }

prune:
    // then prune the allowlist
    ksu_prune_allowlist(is_uid_exist, &uid_list);
out:
    // free uid_list
    list_for_each_entry_safe (np, n, &uid_list, list) {
        list_del(&np->list);
        kfree(np);
    }
out_revert_cred:
    revert_creds(old_cred);
}

void track_throne(bool prune_only)
{
    mutex_lock(&throne_tracker_mutex);
    track_throne_locked(prune_only);
    mutex_unlock(&throne_tracker_mutex);
}

static bool valid_manager_config(const struct ksu_manager_config *config)
{
    size_t i, length = strnlen(config->package, sizeof(config->package));
    bool first = true, has_dot = false;

    if (!length || length == sizeof(config->package) || config->strict > 1 || !config->certificate_size ||
        config->certificate_size > 1024 || strnlen(config->certificate_hash, sizeof(config->certificate_hash)) != 64)
        return false;

    for (i = 0; i < length; i++) {
        char c = config->package[i];
        bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');

        if (first && !letter)
            return false;
        if (c == '.') {
            first = true;
            has_dot = true;
        } else {
            if (!letter && !(c >= '0' && c <= '9') && c != '_')
                return false;
            first = false;
        }
    }
    if (first || !has_dot)
        return false;

    for (i = 0; i < 64; i++) {
        char c = config->certificate_hash[i];

        if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f'))
            return false;
    }
    return true;
}

void ksu_handle_manager_config(unsigned int operation, struct ksu_manager_config_cmd *cmd)
{
    cmd->result = -EINVAL;
    if (operation > KSU_MANAGER_CONFIG_RESET ||
        (operation == KSU_MANAGER_CONFIG_SET && !valid_manager_config(&cmd->config)))
        return;

    mutex_lock(&throne_tracker_mutex);
    if (operation != KSU_MANAGER_CONFIG_GET) {
        manager_config = operation == KSU_MANAGER_CONFIG_RESET ? default_manager : cmd->config;
        cached_manager_apk_path[0] = 0;
        ksu_invalidate_manager_uid();
    }
    configured_manager_installed = false;
    track_throne_locked(false);
    cmd->config = manager_config;
    cmd->default_config = default_manager;
    cmd->manager_appid = ksu_get_manager_appid();
    cmd->installed = configured_manager_installed;
    cmd->matches = configured_manager_installed && ksu_is_manager_appid_valid() &&
                   !strcmp(selected_package, manager_config.package);
    cmd->result = 0;
    mutex_unlock(&throne_tracker_mutex);
}

void __init ksu_throne_tracker_init()
{
    // nothing to do
}

void __exit ksu_throne_tracker_exit()
{
    // nothing to do
}

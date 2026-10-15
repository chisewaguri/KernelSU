/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/jump_label.h>
#include "compat/jailbreak.h"
#include "infra/symbol_resolver.h"
#include "klog.h"

DEFINE_STATIC_KEY_FALSE(ksu_rkp_key);

void rkp_jb_init(void)
{
    if (find_kernel_symbol_exact("rkp_started")) {
        static_branch_enable(&ksu_rkp_key);
        pr_info("Samsung RKP detected\n");
    }
}

#ifdef __aarch64__

#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/moduleloader.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>
#include <asm/cacheflush.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
#include <linux/execmem.h>
#define ksu_exec_alloc(sz) execmem_alloc(EXECMEM_MODULE_TEXT, (sz))
#define ksu_exec_free(p) execmem_free(p)
#else
#define ksu_exec_alloc(sz) module_alloc(sz)
#define ksu_exec_free(p) vfree(p)
#endif
#include "hook/patch_memory.h"

#define KSU_MAX_BRANCH_SITES 16
#define KSU_STUB_SIZE 16
#define KSU_INSN_BTI_C 0xD503245Fu

struct ksu_branch_site {
    void *fn_addr;
    void *patch_addr;
    void *stub;
    u32 displaced_insn;
    bool active;
    bool pinned;
};

static struct ksu_branch_site ksu_sites[KSU_MAX_BRANCH_SITES];
static int ksu_site_count;
static DEFINE_MUTEX(ksu_site_lock);
static void *ksu_stub_page;

static u32 ksu_encode_b(void *from, void *to)
{
    s64 offset = (s64)(unsigned long)to - (s64)(unsigned long)from;

    if ((offset & 3) || offset < -(1LL << 27) || offset >= (1LL << 27))
        return 0;
    return 0x14000000u | (u32)((offset >> 2) & 0x3FFFFFFu);
}

static bool ksu_insn_is_bti(u32 insn)
{
    return (insn & 0xFFFFFF3Fu) == 0xD503241Fu;
}

static bool ksu_insn_is_pc_relative(u32 insn)
{
    return ((insn & 0x1F000000u) == 0x10000000u) ||
           ((insn & 0x3B000000u) == 0x18000000u) ||
           ((insn & 0x7C000000u) == 0x14000000u) ||
           ((insn & 0xFE000000u) == 0x54000000u) ||
           ((insn & 0x7E000000u) == 0x34000000u) ||
           ((insn & 0x7E000000u) == 0x36000000u);
}

static struct ksu_branch_site *ksu_find_site(void *fn)
{
    int i;

    for (i = 0; i < ksu_site_count; i++)
        if (ksu_sites[i].fn_addr == fn)
            return &ksu_sites[i];
    return NULL;
}

static int ksu_rkp_write_insn(void *addr, u32 insn)
{
    int ret;

    cpus_read_lock();
    ret = aarch64_insn_patch_text(&addr, &insn, 1);
    cpus_read_unlock();
    return ret;
}

int ksu_rkp_branch_patch(void **slot, void *replacement, void **callthrough)
{
    void *fn = READ_ONCE(*slot);
    struct ksu_branch_site *site;
    u32 displaced, branch, back, words[4];
    void *patch, *stub;
    int i, ret = 0;

    if (!fn || !replacement)
        return -EINVAL;

    mutex_lock(&ksu_site_lock);
    site = ksu_find_site(fn);
    if (site && site->active) {
        ret = -EALREADY;
        goto out;
    }

    if (!site) {
        if (ksu_site_count == KSU_MAX_BRANCH_SITES) {
            ret = -ENOSPC;
            goto out;
        }
        patch = fn;
        displaced = READ_ONCE(*(u32 *)patch);
        if (ksu_insn_is_bti(displaced)) {
            patch = (u8 *)fn + 4;
            displaced = READ_ONCE(*(u32 *)patch);
        } else if (IS_ENABLED(CONFIG_ARM64_BTI_KERNEL) &&
                   (displaced == 0xD503233Fu || displaced == 0xD503237Fu)) {
            /* PAC is an implicit BTI landing pad. Replacing it needs two live writes. */
            ret = -EOPNOTSUPP;
            goto out;
        }
        if (ksu_insn_is_pc_relative(displaced) || ksu_insn_is_bti(displaced)) {
            ret = -EOPNOTSUPP;
            goto out;
        }
        branch = ksu_encode_b(patch, replacement);
        if (!branch) {
            ret = -ERANGE;
            goto out;
        }
        if (!ksu_stub_page) {
            ksu_stub_page = ksu_exec_alloc(PAGE_SIZE);
            if (!ksu_stub_page) {
                ret = -ENOMEM;
                goto out;
            }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
            ret = set_memory_rox((unsigned long)ksu_stub_page, 1);
#else
            ret = set_memory_ro((unsigned long)ksu_stub_page, 1);
            if (!ret)
                ret = set_memory_x((unsigned long)ksu_stub_page, 1);
#endif
            if (ret) {
                ksu_exec_free(ksu_stub_page);
                ksu_stub_page = NULL;
                goto out;
            }
        }
        stub = (u8 *)ksu_stub_page + ksu_site_count * KSU_STUB_SIZE;
        back = ksu_encode_b((u8 *)stub + 12, (u8 *)patch + 4);
        if (!back) {
            ret = -ERANGE;
            goto out;
        }
        /* The word before the callable entry holds its KCFI type hash. */
        words[0] = READ_ONCE(*(u32 *)((u8 *)fn - 4));
        words[1] = KSU_INSN_BTI_C;
        words[2] = displaced;
        words[3] = back;
        for (i = 0; i < ARRAY_SIZE(words); i++) {
            ret = aarch64_insn_write((u8 *)stub + i * 4, words[i]);
            if (ret)
                goto out;
        }
#if KSU_NEW_DCACHE_FLUSH
        caches_clean_inval_pou((unsigned long)stub, (unsigned long)stub + KSU_STUB_SIZE);
#else
        __flush_icache_range((unsigned long)stub, (unsigned long)stub + KSU_STUB_SIZE);
#endif
        site = &ksu_sites[ksu_site_count++];
        *site = (struct ksu_branch_site){
            .fn_addr = fn,
            .patch_addr = patch,
            .stub = (u8 *)stub + 4,
            .displaced_insn = displaced,
        };
    }
    branch = ksu_encode_b(site->patch_addr, replacement);
    if (!branch) {
        ret = -ERANGE;
        goto out;
    }
    if (!site->pinned) {
        if (!try_module_get(THIS_MODULE)) {
            ret = -EBUSY;
            goto out;
        }
        /* ponytail: stubs pin the module, add call-through quiescence before allowing unload. */
        site->pinned = true;
    }
    if (callthrough)
        smp_store_release(callthrough, site->stub);
    ret = ksu_rkp_write_insn(site->patch_addr, branch);
    if (!ret)
        site->active = true;
out:
    mutex_unlock(&ksu_site_lock);
    return ret;
}

int ksu_rkp_restore_slot(void *original)
{
    struct ksu_branch_site *site;
    int ret = 0;

    mutex_lock(&ksu_site_lock);
    site = ksu_find_site(original);
    if (site && site->active) {
        ret = ksu_rkp_write_insn(site->patch_addr, site->displaced_insn);
        if (!ret)
            site->active = false;
    }
    mutex_unlock(&ksu_site_lock);
    return ret;
}

void rkp_jb_exit(void)
{
    int i;

    for (i = 0; i < ksu_site_count; i++)
        if (ksu_rkp_restore_slot(ksu_sites[i].fn_addr))
            pr_err("RKP restore failed at %pS\n", ksu_sites[i].fn_addr);
}

#else

int ksu_rkp_branch_patch(void **slot, void *replacement, void **callthrough)
{
    return -EOPNOTSUPP;
}

int ksu_rkp_restore_slot(void *original)
{
    return -EOPNOTSUPP;
}

void rkp_jb_exit(void) {}

#endif

#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "feature/module_blacklist.h"
#include "infra/symbol_resolver.h"
#include "klog.h" // IWYU pragma: keep

void __init ksu_module_blacklist_init(const char *modules)
{
    char **module_blacklist;
    const char *existing;
    char *blacklist, *name;
    size_t existing_len, modules_len, offset;

    if (!modules[0])
        return;

    module_blacklist = (char **)find_kernel_symbol_exact("module_blacklist");
    if (!module_blacklist) {
        pr_warn("module_blacklist: kernel symbol not found, skipping blocked modules\n");
        return;
    }

    existing = *module_blacklist;
    existing_len = existing ? strlen(existing) : 0;
    modules_len = strlen(modules);

    blacklist = kzalloc(existing_len + modules_len + 2, GFP_KERNEL);
    if (!blacklist) {
        pr_err("module_blacklist: cannot allocate blacklist\n");
        return;
    }

    offset = 0;
    if (existing_len) {
        memcpy(blacklist, existing, existing_len);
        offset = existing_len;
        blacklist[offset++] = ',';
    }
    memcpy(blacklist + offset, modules, modules_len);

    // The kernel splits the parameter on whitespace, so a module name uses
    // '_' where it was loaded as '-'.
    for (name = blacklist + offset; *name; name++) {
        if (*name == '-')
            *name = '_';
    }

    *module_blacklist = blacklist;
    pr_info("module_blacklist: blocked modules: %s\n", blacklist);
}

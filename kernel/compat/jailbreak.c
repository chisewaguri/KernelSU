#include <linux/jump_label.h>

#include "compat/jailbreak.h"
#include "hook/patch_memory.h"

void kdp_jb_init(void);
void kdp_jb_exit(void);
void rkp_jb_init(void);
void rkp_jb_exit(void);
void defex_jb_init(void);
void defex_jb_exit(void);
#ifdef __aarch64__
void ksu_patch_memory_init(void);
#endif

int __init init_jailbreak(void)
{
#ifdef __aarch64__
    ksu_patch_memory_init();
#endif
    kdp_jb_init();
    rkp_jb_init();
    defex_jb_init();
    return 0;
}

void exit_jailbreak(void)
{
    defex_jb_exit();
    kdp_jb_exit();
    rkp_jb_exit();
}

int ksu_compat_patch_slot(void **slot, void *replacement, void **callthrough)
{
    if (static_branch_unlikely(&ksu_rkp_key))
        return ksu_rkp_branch_patch(slot, replacement, callthrough);

    if (callthrough)
        smp_store_release(callthrough, READ_ONCE(*slot));
    return ksu_patch_text(slot, &replacement, sizeof(replacement), KSU_PATCH_TEXT_FLUSH_DCACHE);
}

int ksu_compat_restore_slot(void **slot, void *original)
{
    if (static_branch_unlikely(&ksu_rkp_key))
        return ksu_rkp_restore_slot(original);
    return ksu_patch_text(slot, &original, sizeof(original), KSU_PATCH_TEXT_FLUSH_DCACHE);
}

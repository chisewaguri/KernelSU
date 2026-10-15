#ifndef __KSU_JAILBREAK_H
#define __KSU_JAILBREAK_H

#include <linux/cred.h>
#include <linux/jump_label.h>

DECLARE_STATIC_KEY_FALSE(ksu_kdp_key);
DECLARE_STATIC_KEY_FALSE(ksu_rkp_key);

int init_jailbreak(void);
void exit_jailbreak(void);

int ksu_compat_patch_slot(void **slot, void *replacement, void **callthrough);
int ksu_compat_restore_slot(void **slot, void *original);
int ksu_rkp_branch_patch(void **slot, void *replacement, void **callthrough);
int ksu_rkp_restore_slot(void *original);
void ksu_defex_sync_current(void);

void ksu_put_cred(const struct cred *cred);
int ksu_commit_creds(struct cred *cred);

#endif

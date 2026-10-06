#ifndef __KSU_SAMSUNG_KDP_H
#define __KSU_SAMSUNG_KDP_H

#include <linux/cred.h>
#include <linux/jump_label.h>

extern struct static_key_false ksu_samsung_kdp_key;

int ksu_samsung_kdp_init(void);
void ksu_samsung_kdp_exit(void);
int ksu_samsung_kdp_commit_creds(struct cred *cred);
void ksu_samsung_kdp_put_cred(const struct cred *cred);

static inline void ksu_put_cred(const struct cred *cred)
{
    if (static_branch_unlikely(&ksu_samsung_kdp_key))
        ksu_samsung_kdp_put_cred(cred);
    else
        put_cred(cred);
}

static inline int ksu_commit_creds(struct cred *cred)
{
    if (static_branch_unlikely(&ksu_samsung_kdp_key))
        return ksu_samsung_kdp_commit_creds(cred);
    else
        return commit_creds(cred);
}

#endif

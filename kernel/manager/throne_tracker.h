#ifndef __KSU_H_UID_OBSERVER
#define __KSU_H_UID_OBSERVER

#include <linux/types.h>
#include <linux/errno.h>
#include "uapi/supercall.h"
#ifdef CONFIG_KSU_DISABLE_MANAGER
static inline void ksu_throne_tracker_init()
{
}

static inline void ksu_throne_tracker_exit()
{
}

static inline void track_throne(bool prune_only)
{
    (void)prune_only;
}
static inline void ksu_handle_manager_config(unsigned int operation, struct ksu_manager_config_cmd *cmd)
{
    (void)operation;
    cmd->result = -EOPNOTSUPP;
}
#else
void ksu_throne_tracker_init();

void ksu_throne_tracker_exit();

void track_throne(bool prune_only);
void ksu_handle_manager_config(unsigned int operation, struct ksu_manager_config_cmd *cmd);
#endif

#endif

#ifndef __KSU_H_APK_V2_SIGN
#define __KSU_H_APK_V2_SIGN

#include <linux/types.h>

bool is_manager_apk(char *path, unsigned certificate_size, const char *certificate_hash);
int get_pkg_from_apk_dir_path(char *pkg, const char *path);

#endif

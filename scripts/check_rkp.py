"""Compile the real RKP engine with simulated kernel writers, then inject failures."""

import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "kernel/compat/rkp.c").read_text(encoding="utf-8")
source = re.sub(r"^#include .*\n", "", source, flags=re.M)
wrappers = (ROOT / "kernel/compat/jailbreak.c").read_text(encoding="utf-8")
wrappers = wrappers[wrappers.index("int ksu_compat_patch_slot("):]
shim = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
typedef uint32_t u32;
typedef uint8_t u8;
typedef int64_t s64;
#define PAGE_SIZE 4096
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define DEFINE_STATIC_KEY_FALSE(n) int n
#define DEFINE_MUTEX(n) int n
#define READ_ONCE(x) (x)
#define IS_ENABLED(x) (x)
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define smp_store_release(p,v) (*(p)=(v))
#define static_branch_enable(p) (*(p)=1)
#define static_branch_unlikely(p) (*(p))
#define KSU_PATCH_TEXT_FLUSH_DCACHE 1
#define mutex_lock(p) ((void)(p))
#define mutex_unlock(p) ((void)(p))
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
#define THIS_MODULE 0
#define EXECMEM_MODULE_TEXT 0
static u32 arena[PAGE_SIZE / 4], functions[32][8];
static int lock_depth, flushes, refs, write_count, fail_word, fail_patch, fail_permissions;
static void **expected_callthrough;
static void *find_kernel_symbol_exact(const char *s) { (void)s; return 0; }
static void *module_alloc(unsigned long n) { (void)n; return arena; }
#define execmem_alloc(t,n) module_alloc(n)
#define execmem_free(p) ((void)(p))
#define vfree(p) ((void)(p))
static int set_memory_rox(unsigned long p, int n) {
    (void)p; (void)n; return fail_permissions ? -EIO : 0;
}
#define set_memory_ro(p,n) set_memory_rox(p,n)
#define set_memory_x(p,n) set_memory_rox(p,n)
#define caches_clean_inval_pou(a,b) (++flushes)
#define __flush_icache_range(a,b) (++flushes)
static void cpus_read_lock(void) { assert(!lock_depth); lock_depth++; }
static void cpus_read_unlock(void) { assert(lock_depth == 1); lock_depth--; }
static bool try_module_get(int m) { (void)m; refs++; return true; }
static int aarch64_insn_write(void *p, u32 insn) {
    if (++write_count == fail_word) return -EIO;
    *(u32 *)p = insn; return 0;
}
static int aarch64_insn_patch_text(void **p, u32 *insn, int n) {
    assert(lock_depth == 1 && n == 1);
    if (expected_callthrough) assert(*expected_callthrough && flushes);
    if (fail_patch) return -EIO;
    *(u32 *)*p = *insn; return 0;
}
static int ksu_patch_text(void *dst, void *src, size_t len, int flags) {
    (void)flags;
    assert(len == sizeof(void *));
    if (expected_callthrough) assert(*expected_callthrough);
    if (fail_patch) return -EIO;
    *(void **)dst = *(void **)src; return 0;
}
"""
checks = r"""
int main(void) {
    void *slot, *through = NULL, *saved;
    u32 *fn = functions[0] + 1, *target = functions[31] + 1;
    assert(ksu_encode_b((void *)0x10000000, (void *)0x17fffffc));
    assert(!ksu_encode_b((void *)0x10000000, (void *)0x18000000));
    assert(ksu_encode_b((void *)0x10000000, (void *)0x08000000));
    assert(!ksu_encode_b((void *)0x10000000, (void *)0x07fffffc));
    assert(!ksu_encode_b(fn, (u8 *)fn + 1));
    functions[0][0] = 0x12345678;
    fn[0] = KSU_INSN_BTI_C;
    fn[1] = 0xD503233F;
    slot = fn;
    fail_permissions = 1;
    assert(ksu_rkp_branch_patch(&slot, target, &through) == -EIO);
    assert(!ksu_stub_page && !ksu_site_count && !through);
    fail_permissions = 0;
    for (int i = 1; i <= 4; i++) {
        write_count = 0; fail_word = i;
        assert(ksu_rkp_branch_patch(&slot, target, &through) == -EIO);
        assert(!ksu_site_count && !through && fn[1] == 0xD503233F);
    }
    fail_word = 0;
    expected_callthrough = &through;
    ksu_rkp_key = 1;
    assert(!ksu_compat_patch_slot(&slot, target, &through));
    assert(slot == fn && fn[0] == KSU_INSN_BTI_C && refs == 1);
    assert(fn[1] == ksu_encode_b(fn + 1, target));
    assert(arena[0] == 0x12345678 && arena[1] == KSU_INSN_BTI_C);
    assert(arena[2] == 0xD503233F && arena[3] == ksu_encode_b(arena + 3, fn + 2));
    saved = through;
    assert(ksu_rkp_branch_patch(&slot, target, &through) == -EALREADY);
    fail_patch = 1;
    assert(ksu_rkp_restore_slot(fn) == -EIO);
    assert(ksu_sites[0].active && through == saved && ksu_stub_page == arena);
    fail_patch = 0;
    assert(!ksu_rkp_restore_slot(fn) && fn[1] == 0xD503233F);
    assert(!ksu_rkp_branch_patch(&slot, target, &through));
    assert(ksu_site_count == 1 && refs == 1 && through == saved);
    rkp_jb_exit();
    assert(!ksu_sites[0].active && fn[1] == 0xD503233F && through == saved);
    fn = functions[1] + 1;
    fn[0] = 0xD503237F;
    slot = fn;
    through = NULL;
#if CONFIG_ARM64_BTI_KERNEL
    assert(ksu_rkp_branch_patch(&slot, target, &through) == -EOPNOTSUPP);
    assert(!through);
#else
    assert(!ksu_rkp_branch_patch(&slot, target, &through));
    assert(!ksu_rkp_restore_slot(fn) && fn[0] == 0xD503237F);
#endif
    fn = functions[2] + 1;
    slot = fn;
    through = NULL;
    fn[0] = 0x10000000;
    assert(ksu_rkp_branch_patch(&slot, target, &through) == -EOPNOTSUPP);
    fn[0] = 0xD503201F;
    fail_patch = 1;
    assert(ksu_rkp_branch_patch(&slot, target, &through) == -EIO);
    assert(through && fn[0] == 0xD503201F);
    fail_patch = 0;
    assert(!lock_depth);
    ksu_rkp_key = 0;
    slot = fn; through = NULL;
    assert(!ksu_compat_patch_slot(&slot, target, &through));
    assert(through == fn && slot == target);
    assert(!ksu_compat_restore_slot(&slot, fn) && slot == fn && through == fn);
    puts("RKP publication, BTI/PAC, write failures, restore and lifetime: PASS");
}
"""
with tempfile.TemporaryDirectory(prefix="rkp-check-", dir=ROOT) as directory:
    directory = Path(directory)
    unit = directory / "rkp.c"
    unit.write_text(shim + source + wrappers + checks, encoding="utf-8")
    binary = directory / ("rkp.exe" if os.name == "nt" else "rkp")
    for version, flush, bti in [(0x050A00, 0, 0), (0x060600, 1, 1), (0x060C00, 1, 1)]:
        subprocess.run([
            os.environ.get("CC", "gcc"), "-std=gnu11", "-Werror=implicit-function-declaration",
            "-Wno-pointer-to-int-cast", "-D__aarch64__",
            f"-DLINUX_VERSION_CODE={version}", f"-DKSU_NEW_DCACHE_FLUSH={flush}",
            f"-DCONFIG_ARM64_BTI_KERNEL={bti}", str(unit), "-o", str(binary)
        ], check=True)
        subprocess.run([str(binary)], check=True)

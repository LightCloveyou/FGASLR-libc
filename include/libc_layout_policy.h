/* Native ld policy notes. SPDX-License-Identifier: 0BSD
 * Compile and link normally against the matching custom libc/ld.
 * No executable rewriting, Python application step or runtime enable API.
 */
#ifndef LIBC_LAYOUT_POLICY_H
#define LIBC_LAYOUT_POLICY_H

#if !defined(__GNUC__) || !defined(__ELF__)
# error "libc-layout policy requires a GCC-compatible ELF compiler"
#endif

#ifdef __cplusplus
# define FG_POLICY_ASSERT(test, message) static_assert(test, message)
extern "C" void _dl_fg_policy_v1(void);
#else
# define FG_POLICY_ASSERT(test, message) _Static_assert(test, message)
extern void _dl_fg_policy_v1(void);
#endif

/* A retained relocation makes linking/loading with a policy-unaware ld fail,
 * rather than silently running without policy. No call is added to the program.
 */
__asm__(".pushsection .data.rel.ro.fg_policy,\"awR\",@progbits\n"
        ".balign 8\n.quad _dl_fg_policy_v1\n.popsection\n");

#define FG_POLICY_STRING_(x) #x
#define FG_POLICY_STRING(x) FG_POLICY_STRING_(x)
/* Each 156-byte ELF note survives --gc-sections and strip --strip-all. */
#define FG_POLICY_RECORD(action_, name_) \
  FG_POLICY_ASSERT(sizeof(name_) <= 128, "libc policy name exceeds 127 bytes"); \
  __asm__(".pushsection .note.fgpolicy,\"aR\",@note\n.balign 4\n" \
          ".long 4,140,0x46475031\n.asciz \"FGP\"\n" \
          ".long 0x46504731,1," FG_POLICY_STRING(action_) "\n" \
          "1: .asciz \"" name_ "\"\n.zero 128-(.-1b)\n.popsection\n")

/* All explicit mode declarations in the final executable must agree. */
#define FG_POLICY_WHITELIST() FG_POLICY_RECORD(4, "")
#define FG_POLICY_BLACKLIST() FG_POLICY_RECORD(5, "")

/* Names refer to libc symbols, not application functions. Aliases share policy.
 * ld reads these declarations before relocation/IFUNC and before main.
 * Imports, startup/data roots and transitive dependencies are retained too.
 * A deny/dependency conflict terminates startup with a diagnostic, status 127.
 */
#define FG_ALLOW_NAME(name_) FG_POLICY_RECORD(1, name_)
#define FG_DENY_NAME(name_)  FG_POLICY_RECORD(2, name_)
#define FG_ALLOW(function_) FG_ALLOW_NAME(#function_)
#define FG_DENY(function_)  FG_DENY_NAME(#function_)

/* Every retained unit is generated at load time; removed units never auto-load. */
#define FG_LOAD(function_) FG_ALLOW(function_)

#endif

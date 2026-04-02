// Include the right generated assembly file based on the architecture

#ifdef __arm64__

#ifdef __arm64e__
#if !__has_include("gen.arm64e.s")
#error "Generated arm64e assembly not found, please run gen_asm.sh with a recent enough clang to support __attribute__((musttail))"
#endif
#include "gen.arm64e.s"
#else
#if !__has_include("gen.arm64.s")
#error "Generated arm64 assembly not found, please run gen_asm.sh with a recent enough clang to support __attribute__((musttail))"
#endif
#include "gen.arm64.s"
#endif

#else

#if !__has_include("gen.armv7.s")
#error "Generated armv7 assembly not found, please run gen_asm.sh with a recent enough clang to support __attribute__((musttail))"
#endif
#include "gen.armv7.s"

#endif

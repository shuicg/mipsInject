#ifndef _INJECT_H_
#define _INJECT_H_

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
//#include <asm/user.h>
//#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
//#include <bits/dirent.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>

#include <linux/types.h>

#define DEBUG_PRINT(format,args...) printf(format, ##args)


const char *libc_path = "/lib/libuClibc-0.9.33.2.so";
const char *linker_path = "/lib/libdl-0.9.33.2.so";


/* 0 - 31 are integer registers, 32 - 63 are fp registers.  */
#define FPR_BASE        32
#define PC              64
#define CAUSE           65
#define BADVADDR        66
#define MMHI            67
#define MMLO            68
#define FPC_CSR         69
#define FPC_EIR         70
#define DSP_BASE        71              /* 3 more hi / lo register pairs */
#define DSP_CONTROL     77
#define ACX             78

/*
 * This struct defines the registers as used by PTRACE_{GET,SET}REGS. The
 * format is the same for both 32- and 64-bit processes. Registers for 32-bit
 * processes are sign extended.
 */
struct pt_regs {
        /* Saved main processor registers. */
        __u64 regs[32];

        /* Saved special registers. */
        __u64 lo;
        __u64 hi;
        __u64 cp0_epc;
        __u64 cp0_badvaddr;
        __u64 cp0_status;
        __u64 cp0_cause;
} __attribute__ ((aligned (8)));

#define MIPS_v0 general_regs.regs[2]
#define MIPS_v1 general_regs.regs[3]
#define MIPS_a0 general_regs.regs[4]
#define MIPS_a1 general_regs.regs[5]
#define MIPS_a2 general_regs.regs[6]
#define MIPS_a3 general_regs.regs[7]
#define MIPS_sp general_regs.regs[29]
#define MIPS_ra general_regs.regs[31]
#define MIPS_pc pc
#define MIPS_t9 general_regs.regs[25]

struct mips_regswithpc
{
    struct pt_regs general_regs;
    long pc;
};

union Uunion
{
    long val;
    char chars[sizeof(long)];
};

int ptrace_getregs(pid_t pid, struct mips_regswithpc *regs);

int inject_remote_process( pid_t target_pid, const char *library_path, const char *function_name, const char *param, size_t param_size);

//int find_pid_of(const char *process_name);

void *get_module_base(pid_t pid, const char *module_name);

#endif

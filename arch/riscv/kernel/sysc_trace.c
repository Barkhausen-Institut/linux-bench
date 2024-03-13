#include <linux/linkage.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <linux/slab.h>

#define MAX_SYSCALL_TIMES   65536

struct TracedSyscall {
    unsigned int no;
    unsigned long enter_time;
    unsigned long leave_time;
};

int sysc_pid = 0;
unsigned long sysc_counter = 0;
struct TracedSyscall *syscalls = 0;

#undef __SYSCALL
#define __SYSCALL(nr, call) [nr] = #call,

const char *sysc_names[__NR_syscalls] = {
    [0 ... __NR_syscalls - 1] = "sys_ni_syscall",
#include <asm/unistd.h>
};

static inline unsigned long _get_cycles(void) {
    unsigned long val;
    __asm__ volatile (
        "rdcycle %0;"
        : "=r" (val) : : "memory"
    );
    return val;
}

asmlinkage void sysc_trace_enter(unsigned int a0) {
    if(current->pid == sysc_pid) {
        syscalls[sysc_counter].no = a0;
        syscalls[sysc_counter].enter_time = _get_cycles();
    }
}

asmlinkage void sysc_trace_exit(void) {
    if(current->pid == sysc_pid) {
        syscalls[sysc_counter].leave_time = _get_cycles();
        sysc_counter = (sysc_counter + 1) % MAX_SYSCALL_TIMES;
    }
}

SYSCALL_DEFINE1(syscreset, int, pid) {
    if(syscalls == 0) {
        syscalls = kmalloc_array(MAX_SYSCALL_TIMES, sizeof(struct TracedSyscall), GFP_NOWAIT);
        if(syscalls == 0)
            panic("unable to allocate syscall tracing array");
    }

    sysc_pid = pid;
    sysc_counter = MAX_SYSCALL_TIMES - 1;
    return 0;
}

SYSCALL_DEFINE0(sysctrace) {
    unsigned long i;
    for(i = 0; i < sysc_counter; ++i) {
        pr_notice(" [%3lu] %s (%d) %011lu %011lu\n",
            i, sysc_names[syscalls[i].no], syscalls[i].no,
            syscalls[i].enter_time, syscalls[i].leave_time);
    }
    sysc_pid = 0;
    return 0;
}

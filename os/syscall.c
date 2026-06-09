#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "proc.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(TimeVal *val, int _tz)
{
	struct proc *p = curr_proc();
	TimeVal tv;
	uint64 cycle = get_cycle();
	tv.sec = cycle / CPU_FREQ;
	tv.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	if (copyout(p->pagetable, (uint64)val, (char *)&tv, sizeof(TimeVal)) < 0)
		return -1;
	return 0;
}

uint64 sys_trace(int trace_request, uint64 id, uint8 data)
{
	struct proc *p = curr_proc();
	uint8 byte_val;

	switch (trace_request) {
	case 0:
		if (copyin(p->pagetable, (char *)&byte_val, id, 1) < 0)
			return (uint64)-1;
		return byte_val;
	case 1:
		if (copyout(p->pagetable, id, (char *)&data, 1) < 0)
			return (uint64)-1;
		return 0;
	case 2:
		if (id >= NSYSCALL || p->syscall_counts == 0)
			return 0;
		return p->syscall_counts[id];
	default:
		return (uint64)-1;
	}
}

uint64 sys_mmap(void *start, uint64 len, int prot, int flags)
{
	struct proc *p = curr_proc();

	if (prot & ~0x7)
		return -1;
	if ((prot & 0x7) == 0)
		return -1;
	if (!PGALIGNED((uint64)start))
		return -1;

	uint64 aligned_len = PGROUNDUP(len);
	if (aligned_len == 0)
		return 0;

	int pte_flags = PTE_U;
	if (prot & 1) pte_flags |= PTE_R;
	if (prot & 2) pte_flags |= PTE_W;
	if (prot & 4) pte_flags |= PTE_X;

	for (uint64 va = (uint64)start; va < (uint64)start + aligned_len; va += PGSIZE) {
		pte_t *pte = walk(p->pagetable, va, 0);
		if (pte && (*pte & PTE_V))
			return -1;
	}

	for (uint64 va = (uint64)start; va < (uint64)start + aligned_len; va += PGSIZE) {
		void *pa = kalloc();
		if (pa == 0)
			return -1;
		memset(pa, 0, PGSIZE);
		if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, pte_flags) != 0) {
			kfree(pa);
			return -1;
		}
	}
	return 0;
}

uint64 sys_munmap(void *start, uint64 len)
{
	struct proc *p = curr_proc();

	if (!PGALIGNED((uint64)start))
		return -1;

	uint64 aligned_len = PGROUNDUP(len);
	if (aligned_len == 0)
		return 0;

	for (uint64 va = (uint64)start; va < (uint64)start + aligned_len; va += PGSIZE) {
		pte_t *pte = walk(p->pagetable, va, 0);
		if (!pte || !(*pte & PTE_V) || !(*pte & PTE_U))
			return -1;
	}

	uvmunmap(p->pagetable, (uint64)start, aligned_len / PGSIZE, 1);
	return 0;
}

uint64 sys_sbrk(int n)
{
	uint64 addr;
        struct proc *p = curr_proc();
        addr = p->program_brk;
        if(growproc(n) < 0)
                return -1;
        return addr;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);

	if (id >= 0 && id < NSYSCALL) {
		struct proc *p = curr_proc();
		if (p->syscall_counts == 0) {
			p->syscall_counts = (uint64 *)kalloc();
			if (p->syscall_counts)
				memset(p->syscall_counts, 0, PGSIZE);
		}
		if (p->syscall_counts)
			p->syscall_counts[id]++;
	}

	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	case SYS_sbrk:
		ret = sys_sbrk(args[0]);
		break;
	case SYS_trace:
		ret = sys_trace(args[0], args[1], args[2]);
		break;
	case SYS_mmap:
		ret = sys_mmap((void *)args[0], args[1], args[2], args[3]);
		break;
	case SYS_munmap:
		ret = sys_munmap((void *)args[0], args[1]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}

#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d str = %x, len = %d", fd, va, len);
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

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	debugf("sys_read fd = %d str = %x, len = %d", fd, va, len);
	if (fd != STDIN)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
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

uint64 sys_gettimeofday(uint64 val, int _tz)
{
	struct proc *p = curr_proc();
	uint64 cycle = get_cycle();
	TimeVal t;
	t.sec = cycle / CPU_FREQ;
	t.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	if (copyout(p->pagetable, val, (char *)&t, sizeof(TimeVal)) < 0)
		return -1;
	return 0;
}

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

uint64 sys_getppid()
{
	struct proc *p = curr_proc();
	return p->parent == NULL ? IDLE_PID : p->parent->pid;
}

uint64 sys_clone()
{
	debugf("fork!\n");
	return fork();
}

uint64 sys_exec(uint64 va)
{
	struct proc *p = curr_proc();
	char name[200];
	if (copyinstr(p->pagetable, name, va, 200) < 0)
		return -1;
	debugf("sys_exec %s\n", name);
	return exec(name);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}

// sys_spawn: create child process and load program (like fork + exec)
uint64 sys_spawn(uint64 va)
{
	struct proc *p = curr_proc();
	char name[200];
	if (copyinstr(p->pagetable, name, va, 200) < 0)
		return -1;

	int id = get_id_by_name(name);
	if (id < 0)
		return -1;

	struct proc *np = allocproc();
	if (np == 0)
		return -1;

	if (loader(id, np) < 0) {
		freeproc(np);
		return -1;
	}

	np->parent = p;
	np->trapframe->a0 = 0;
	add_task(np);
	return np->pid;
}

// sys_set_priority: set process priority for stride scheduling
uint64 sys_set_priority(long long prio)
{
	if (prio < 2)
		return -1;
	struct proc *p = curr_proc();
	p->priority = prio;
	p->pass = BIG_STRIDE / prio;
	return prio;
}

uint64 sys_sbrk(int n)
{
	uint64 addr;
	struct proc *p = curr_proc();
	addr = p->program_brk;
	if (growproc(n) < 0)
		return -1;
	return addr;
}

// ---- migrated from ch4 ----

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

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_clone:
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;
	case SYS_set_priority:
		ret = sys_set_priority(args[0]);
		break;
	case SYS_sbrk:
		ret = sys_sbrk(args[0]);
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

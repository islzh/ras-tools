/*
 * Copyright (C) 2015 Intel Corporation
 * Author: Tony Luck
 *
 * This software may be redistributed and/or modified under the terms of
 * the GNU General Public License ("GPL") version 2 only as published by the
 * Free Software Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <setjmp.h>
#include <signal.h>
#define _GNU_SOURCE 1
#define __USE_GNU 1
#include <sched.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/futex.h>

extern long long vtop(long long);
extern void proc_cpuinfo(int *nsockets, int *ncpus, char *model, int *modelnum, int **apicmap);
extern void proc_interrupts(long *nmce, long *ncmci);
extern void do_memcpy(void *dst, void *src, int cnt);
static void show_help(void);

static char *progname;
static int nsockets, ncpus, lcpus_persocket;
static int force_flag;
static int cmci_skip_flag;
static int all_flag;
static int Sflag;
static long pagesize;
static int *apicmap;
#define	CACHE_LINE_SIZE	64

#define EINJ_ETYPE "/sys/kernel/debug/apei/einj/error_type"
#define EINJ_ETYPE_AVAILABLE "/sys/kernel/debug/apei/einj/available_error_type"
#define EINJ_ADDR "/sys/kernel/debug/apei/einj/param1"
#define EINJ_MASK "/sys/kernel/debug/apei/einj/param2"
#define EINJ_APIC "/sys/kernel/debug/apei/einj/param3"
#define EINJ_FLAGS "/sys/kernel/debug/apei/einj/flags"
#define EINJ_NOTRIGGER "/sys/kernel/debug/apei/einj/notrigger"
#define EINJ_DOIT "/sys/kernel/debug/apei/einj/error_inject"

static int check_errortype_available(char *file, unsigned long long val)
{
	FILE *fp;
	int ret = -1;
	unsigned long long available_error_type;

	if (strcmp(file, EINJ_ETYPE) != 0) return 0;

	fp = fopen(EINJ_ETYPE_AVAILABLE, "r");
	if (!fp) {
		fprintf(stderr, "%s: cannot open '%s'\n", progname, file);
		exit(1);
	}

	while (fscanf(fp, "%llx%*[^\n]", &available_error_type) == 1) {
		if (val == available_error_type) {
			ret = 0;
			break;
		}
	}

	fclose(fp);
	return ret;
}

static void wfile(char *file, unsigned long long val)
{
	FILE *fp;

	if (check_errortype_available(file, val) != 0) {
		fprintf(stderr, "%s: no support for error type: 0x%llx\n", progname, val);
		exit(1);
	}

	fp = fopen(file, "w");
	if (fp == NULL) {
		fprintf(stderr, "%s: cannot open '%s'\n", progname, file);
		exit(1);
	}
	fprintf(fp, "0x%llx\n", val);
	if (fclose(fp) == EOF) {
		fprintf(stderr, "%s: write error on '%s'\n", progname, file);
		exit(1);
	}
}

static void inject_uc(unsigned long long addr, void *vaddr, int notrigger)
{
	if (Sflag) {
		vaddr = (void *)((long)vaddr & ~(pagesize - 1));
		madvise(vaddr, pagesize, MADV_HWPOISON);
		return;
	}

	wfile(EINJ_ETYPE, 0x10);
	wfile(EINJ_ADDR, addr);
	wfile(EINJ_MASK, ~0x0ul);
	wfile(EINJ_FLAGS, 2);
	wfile(EINJ_NOTRIGGER, notrigger);
	wfile(EINJ_DOIT, 1);
}

static void inject_llc(unsigned long long addr, void *vaddr, int notrigger)
{
	unsigned cpu;

	cpu = sched_getcpu();
	wfile(EINJ_ETYPE, 0x2);
	wfile(EINJ_ADDR, addr);
	wfile(EINJ_MASK, ~0x0ul);
	wfile(EINJ_APIC, apicmap[cpu]);
	wfile(EINJ_FLAGS, 3);
	wfile(EINJ_NOTRIGGER, notrigger);
	wfile(EINJ_DOIT, 1);
}

static int is_advanced_ras(char *model, int modelnum)
{
	switch (modelnum) {
	case 108: /* Ice Lake Xeon */
		return 1;
	}

	if (strstr(model, "E7-"))
		return 1;
	if (strstr(model, "Platinum"))
		return 1;
	if (strstr(model, "Gold"))
		return 1;
	return 0;
}

static void check_configuration(void)
{
	char	model[512];
	int	modelnum;

	if (getuid() != 0) {
		fprintf(stderr, "%s: must be root to run error injection tests\n", progname);
		exit(1);
	}
	if (access("/sys/firmware/acpi/tables/EINJ", R_OK) == -1) {
		fprintf(stderr, "%s: Error injection not supported, check your BIOS settings\n", progname);
		exit(1);
	}
	if (access(EINJ_NOTRIGGER, R_OK|W_OK) == -1) {
		fprintf(stderr, "%s: Is the einj.ko module loaded?\n", progname);
		exit(1);
	}
	model[0] = '\0';
	proc_cpuinfo(&nsockets, &ncpus, model, &modelnum, &apicmap);
	if (nsockets == 0 || ncpus == 0) {
		fprintf(stderr, "%s: could not find number of sockets/cpus\n", progname);
		exit(1);
	}
	if (ncpus % nsockets) {
		fprintf(stderr, "%s: strange topology. Are all cpus online?\n", progname);
		exit(1);
	}
	lcpus_persocket = ncpus / nsockets;
	if (!force_flag && !is_advanced_ras(model, modelnum)) {
		fprintf(stderr, "%s: warning: cpu may not support recovery\n", progname);
		exit(1);
	}
}

#define REP9(stmt) stmt;stmt;stmt;stmt;stmt;stmt;stmt;stmt;stmt

volatile int vol;

int dosums(void)
{
	vol = 0;
	REP9(REP9(REP9(vol++)));
	return vol;
}

#define MB(n)	((n) * 1024 * 1024)

static void *thp_data_alloc(void)
{
	char	*p = malloc(MB(128));
	int	i;

	if (p == NULL) {
		fprintf(stderr, "%s: cannot allocate memory\n", progname);
		exit(1);
	}
	srandom(getpid() * time(NULL));
	for (i = 0; i < MB(128); i++)
		p[i] = random();
	return p + MB(64);
}

static void *data_alloc(void)
{
	char	*p = mmap(NULL, pagesize, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, -1, 0);
	int	i;

	if (p == NULL) {
		fprintf(stderr, "%s: cannot allocate memory\n", progname);
		exit(1);
	}
	srandom(getpid() * time(NULL));
	for (i = 0; i < pagesize; i++)
		p[i] = random();
	return p + pagesize / 4;
}

static FILE *pcfile;

static void *page_cache_alloc(void)
{
	char c, *p;
	int i;

	pcfile = tmpfile();
	for (i = 0; i < pagesize; i++) {
		c = random();
		fputc(c, pcfile);
	}
	fflush(pcfile);

	p = mmap(NULL, pagesize, PROT_READ|PROT_WRITE, MAP_SHARED, fileno(pcfile), 0);
	if (p == NULL) {
		fprintf(stderr, "%s: cannot mmap tmpfile\n", progname);
		exit(1);
	}
	*p = random();

	return p + pagesize / 4;
}

static void *mlock_data_alloc(void)
{
	char	*p = mmap(NULL, pagesize, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, -1, 0);
	int	i;

	if (p == NULL) {
		fprintf(stderr, "%s: cannot allocate memory\n", progname);
		exit(1);
	}
	srandom(getpid() * time(NULL));
	for (i = 0; i < pagesize; i++)
		p[i] = random();
	if (mlock(p, pagesize) == -1) {
		fprintf(stderr, "%s: cannot mlock(2) memory\n", progname);
		exit(1);
	}
	return p + pagesize / 4;
}

static void *instr_alloc(void)
{
	char	*p = (char *)dosums;

	p += 2 * pagesize;

	/*pre-load the dosum memory page to prevent vtop conversion failure*/
	dosums();

	return (void *)((long)p & ~(pagesize - 1));
}

int trigger_single(char *addr)
{
	return addr[0];
}

int trigger_double(char *addr)
{
	return addr[0] + addr[1];
}

int trigger_split(char *addr)
{
	long *a = (long *)(addr - 1);

	return a[0];
}

int trigger_write(char *addr)
{
	addr[0] = 'a';
	return 0;
}

/*
 * parameters to the memcpy and copyin tests.
 */
int memcpy_runup = 0;	/* how much to copy before hitting poison */
int memcpy_size = 512;	/* Total amount to copy */
int memcpy_align = 0;	/* Relative alignment of src/dst */

/* argument is "runup:size:align" */
void parse_memcpy(char *arg)
{
	char *endp;

	memcpy_runup = strtol(arg, &endp, 0);
	if (*endp != ':')
		show_help();
	memcpy_size = strtol(endp + 1, &endp, 0);
	if (*endp != ':')
		show_help();
	memcpy_align = strtol(endp + 1, &endp, 0);
	if (*endp != '\0')
		show_help();
	if (memcpy_runup < 0 || memcpy_runup > pagesize / 4) {
		fprintf(stderr, "%s: runup out of range\n", progname);
		exit(1);
	}
	if (memcpy_size < 0 || memcpy_size > pagesize / 4) {
		fprintf(stderr, "%s: size out of range\n", progname);
		exit(1);
	}
	if (memcpy_runup > memcpy_size) {
		fprintf(stderr, "%s: runup must be less than size\n", progname);
		exit(1);
	}
	if (memcpy_align < 0 || memcpy_align >= CACHE_LINE_SIZE) {
		fprintf(stderr, "%s: bad alignment\n", progname);
		exit(1);
	}
}

int trigger_memcpy(char *addr)
{
	char *src = addr - memcpy_runup;
	char *dst = addr + pagesize / 2;

	dst -= memcpy_align;
	do_memcpy(dst, src, memcpy_size);
	return 0;
}

static int copyin_fd = -1;

int trigger_copyin(char *addr)
{
	int	ret;
	char	filename[] = "/tmp/einj-XXXXXX";

	if ((copyin_fd = mkstemp(filename)) == -1) {
		fprintf(stderr, "%s: couldn't make temp file\n", progname);
		return -1;
	}
	(void)unlink(filename);
	if ((ret = write(copyin_fd, addr - memcpy_runup, memcpy_size)) != memcpy_size) {
		if (ret == -1)
			fprintf(stderr, "%s: couldn't write temp file (errno=%d)\n", progname, errno);
		else
			fprintf(stderr, "%s: short (%d bytes) write to temp file\n", progname, ret);
	}

	return 0;
}

int trigger_copyout(char *addr)
{
	char *buf = malloc(pagesize);
	int ret;

	if (buf == NULL) {
		fprintf(stderr, "%s: couldn't allocate memory\n", progname);
		return -1;
	}
	rewind(pcfile);
	ret = fread(buf, 1, pagesize, pcfile);
	fprintf(stderr, "%s: read returned %d\n", progname);

	return 0;
}

int trigger_patrol(char *addr)
{
	sleep(1);
}

int trigger_llc(char *addr)
{
	asm volatile("clflush %0" : "+m" (*addr));
}

int trigger_instr(char *addr)
{
	int ret = dosums();

	if (ret != 729)
		printf("Corruption during instruction fault recovery (%d)\n", ret);

	return ret;
}

static int futex(int *uaddr, int futex_op, int val,
		 const struct timespec *timeout, int *uaddr2, int val3)
{
	return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr, val3);
}

int trigger_futex(char *addr)
{
	int ret;

	ret = futex((int *)addr, FUTEX_WAIT, 0, NULL, NULL, 0);
	if (ret == -1)
		printf("futex returned with errno=%d\n", errno);
	else
		printf("futex return %d\n", ret);

	return ret;
}

/* attributes of the test and which events will follow our trigger */
#define	F_MCE		1
#define	F_CMCI		2
#define F_SIGBUS	4
#define	F_FATAL		8
#define F_EITHER	16
#define F_LONGWAIT	32

struct test {
	char	*testname;
	char	*testhelp;
	void	*(*alloc)(void);
	void	(*inject)(unsigned long long, void *, int);
	int	notrigger;
	int	(*trigger)(char *);
	int	flags;
} tests[] = {
	{
		"single", "Single read in pipeline to target address, generates SRAR machine check",
		data_alloc, inject_uc, 1, trigger_single, F_MCE|F_CMCI|F_SIGBUS,
	},
	{
		"double", "Double read in pipeline to target address, generates SRAR machine check",
		data_alloc, inject_uc, 1, trigger_double, F_MCE|F_CMCI|F_SIGBUS,
	},
	{
		"split", "Unaligned read crosses cacheline from good to bad. Probably fatal",
		data_alloc, inject_uc, 1, trigger_split, F_MCE|F_CMCI|F_SIGBUS|F_FATAL,
	},
	{
		"THP", "Try to inject in transparent huge page, generates SRAR machine check",
		thp_data_alloc, inject_uc, 1, trigger_single, F_MCE|F_CMCI|F_SIGBUS,
	},
	{
		"store", "Write to target address. Should generate a UCNA/CMCI",
		data_alloc, inject_uc, 1, trigger_write, F_CMCI,
	},
	{
		"memcpy", "Streaming read from target address. Probably fatal",
		data_alloc, inject_uc, 1, trigger_memcpy, F_MCE|F_CMCI|F_SIGBUS|F_FATAL,
	},
	{
		"instr", "Instruction fetch. Generates SRAR that OS should transparently fix",
		instr_alloc, inject_uc, 1, trigger_instr, F_MCE|F_CMCI,
	},
	{
		"patrol", "Patrol scrubber, generates SRAO machine check",
		data_alloc, inject_uc, 0, trigger_patrol, F_EITHER|F_LONGWAIT,
	},
	{
		"llc", "Cache write-back, generates SRAO machine check",
		data_alloc, inject_llc, 1, trigger_llc, F_MCE,
	},
	{
		"copyin", "Kernel copies data from user. Probably fatal",
		data_alloc, inject_uc, 1, trigger_copyin, F_MCE|F_CMCI|F_FATAL,
	},
	{
		"copyout", "Kernel copies data to user. Probably fatal",
		page_cache_alloc, inject_uc, 1, trigger_copyout, F_MCE|F_CMCI|F_SIGBUS|F_FATAL,
	},
	{
		"futex", "Kernel access to futex(2). Probably fatal",
		data_alloc, inject_uc, 1, trigger_futex, F_MCE|F_CMCI|F_FATAL,
	},
	{
		"mlock", "mlock target page then inject/read to generates SRAR machine check",
		mlock_data_alloc, inject_uc, 1, trigger_single, F_MCE|F_CMCI|F_SIGBUS,
	},
	{ NULL }
};

static void show_help(void)
{
	struct test *t;

	printf("Usage: %s [-a][-c count][-d delay][-f][-i] [-m runup:size:align][testname]\n", progname);
	printf("  %-8s %-5s %s\n", "Testname", "Fatal", "Description");
	for (t = tests; t->testname; t++)
		printf("  %-8s %-5s %s\n", t->testname,
			(t->flags & F_FATAL) ? "YES" : "no",
			t->testhelp);
	exit(0);
}

static struct test *lookup_test(char *s)
{
	struct test *t;

	for (t = tests; t->testname; t++)
		if (strcmp(s, t->testname) == 0)
			return t;
	fprintf(stderr, "%s: unknown test '%s'\n", progname, s);
	exit(1);
}

static struct test *next_test(struct test *t)
{
	t++;
	if (t->testname == NULL)
		t = tests;
	return t;
}

static jmp_buf env;

static void recover(int sig, siginfo_t *si, void *v)
{
	printf("SIGBUS: addr = %p\n", si->si_addr);
	siglongjmp(env, 1);
}

struct sigaction recover_act = {
	.sa_sigaction = recover,
	.sa_flags = SA_SIGINFO,
};

int main(int argc, char **argv)
{
	int c, i;
	int	count = 1, cmci_wait_count = 0;
	double	delay = 1.0;
	struct test *t;
	void	*vaddr;
	long long paddr;
	long	b_mce, b_cmci, a_mce, a_cmci;
	struct timeval t1, t2;
	int either;

	progname = argv[0];
	pagesize = getpagesize();

	while ((c = getopt(argc, argv, "ac:d:fhim:S")) != -1) switch (c) {
	case 'a':
		all_flag = 1;
		break;
	case 'c':
		count = strtol(optarg, NULL, 0);
		break;
	case 'd':
		delay = strtod(optarg, NULL);
		break;
	case 'f':
		force_flag = 1;
		break;
	case 'i':
		cmci_skip_flag = 1;
		break;
	case 'm':
		parse_memcpy(optarg);
		break;
	case 'S':
		Sflag = 1;
		break;
	case 'h': case '?':
		show_help();
		break;
	}

	check_configuration();

	if (optind < argc)
		t = lookup_test(argv[optind]);
	else
		t = tests;

	if ((t->flags & F_FATAL) && !force_flag) {
		fprintf(stderr, "%s: selected test may be fatal. Use '-f' flag if you really want to do this\n", progname);
		exit(1);
	}

	sigaction(SIGBUS, &recover_act, NULL);

	for (i = 0; i < count; i++) {
		cmci_wait_count = 0;
		either = 0;
		vaddr = t->alloc();
		paddr = vtop((long long)vaddr);
		printf("%d: %-8s vaddr = %p paddr = %llx\n", i, t->testname, vaddr, paddr);

		proc_interrupts(&b_mce, &b_cmci);
		gettimeofday(&t1, NULL);
		if (sigsetjmp(env, 1)) {
			if ((t->flags & F_SIGBUS) == 0) {
				printf("Unexpected SIGBUS\n");
			}
		} else {
			t->inject(paddr, vaddr, t->notrigger);
			t->trigger(vaddr);
			if (t->flags & F_SIGBUS) {
				printf("Expected SIGBUS, didn't get one\n");
			}
		}

		if (copyin_fd != -1) {
			close(copyin_fd);
			copyin_fd = -1;
		}

		if (pcfile) {
			fclose(pcfile);
			pcfile = NULL;
		}

		/* if system didn't already take page offline, ask it to do so now */
		if (paddr == vtop((long long)vaddr)) {
			printf("Manually take page offline\n");
			wfile("/sys/devices/system/memory/hard_offline_page", paddr);
		}

		/* Give system a chance to process on possibly deep C-state idle cpus */
		usleep(100);

		proc_interrupts(&a_mce, &a_cmci);

		if (t->flags & F_FATAL) {
			printf("Big surprise ... still running. Thought that would be fatal\n");
		}

		if (Sflag == 0 && (t->flags & (F_MCE | F_EITHER))) {
			if (a_mce == b_mce) {
				if (t->flags & F_EITHER)
					goto skip1;
				printf("Expected MCE, but none seen\n");
			} else if (a_mce == b_mce + 1) {
				printf("Saw local machine check\n");
			} else if (a_mce == b_mce + ncpus) {
				printf("Saw broadcast machine check\n");
			} else {
				printf("Unusual number of MCEs seen: %ld\n", a_mce - b_mce);
			}
			either++;
		} else {
			if (a_mce != b_mce) {
				printf("Saw %ld unexpected MCEs (%ld systemwide)\n", b_mce - a_mce, (b_mce - a_mce) / ncpus);
			}
		}
skip1:
		if (Sflag == 0 && (t->flags & (F_CMCI | F_EITHER))) {
			int maxwait = (t->flags & F_LONGWAIT) ? 20000 : 500;

			while (a_cmci < b_cmci + lcpus_persocket) {
				if (cmci_wait_count > maxwait) {
					break;
				}
				usleep(1000);
				proc_interrupts(&a_mce, &a_cmci);
				cmci_wait_count++;
			}
			if (a_cmci != b_cmci && cmci_wait_count != 0) {
				gettimeofday(&t2, NULL);
				printf("CMCIs took ~%.6f secs to be reported.\n",
					(t2.tv_sec - t1.tv_sec) +
						(t2.tv_usec - t1.tv_usec) /1.0e6);
			}
			if (a_cmci == b_cmci) {
				if (t->flags & F_EITHER)
					goto skip2;
				if (!cmci_skip_flag) {
					printf("Expected CMCI, but none seen\n");
					printf("Test failed\n");
					return 1;
				}
			} else if (!cmci_skip_flag && a_cmci < b_cmci + lcpus_persocket) {
				printf("Unusual number of CMCIs seen: %ld\n", a_cmci - b_cmci);
				printf("Test failed\n");
				return 1;
			}
			either++;
		} else {
			if (!cmci_skip_flag && a_cmci != b_cmci) {
				printf("Saw %ld unexpected CMCIs (%ld per socket)\n", a_cmci - b_cmci, (a_cmci - b_cmci) / lcpus_persocket);
				printf("Test failed\n");
				return 1;
			}
		}
skip2:
		if (t->flags & F_EITHER) switch (either) {
		case 0:
			printf("Expected CMCI or MCE, but saw neither\n");
			printf("Test failed\n");
			return 1;
		case 2:
			printf("Expected one of CMCI or MCE, but saw both\n");
			printf("Test failed\n");
			return 1;
		}

		usleep((useconds_t)(delay * 1.0e6));
		if (all_flag) {
			t = next_test(t);
			while (t->flags & F_FATAL)
				t = next_test(t);
		}
	}

	printf("Test passed\n");
	return 0;
}

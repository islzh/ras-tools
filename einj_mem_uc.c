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

extern long long vtop(long long);

static char *progname;
static int nsockets, ncpus, lcpus_persocket;
static int force_flag;
static int all_flag;
static long pagesize;
#define	CACHE_LINE_SIZE	64

#define EINJ_ETYPE "/sys/kernel/debug/apei/einj/error_type"
#define EINJ_ADDR "/sys/kernel/debug/apei/einj/param1"
#define EINJ_MASK "/sys/kernel/debug/apei/einj/param2"
#define EINJ_NOTRIGGER "/sys/kernel/debug/apei/einj/notrigger"
#define EINJ_DOIT "/sys/kernel/debug/apei/einj/error_inject"

static void wfile(char *file, unsigned long long val)
{
	FILE *fp = fopen(file, "w");

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

static void inject_uc(unsigned long long addr, int notrigger)
{
	wfile(EINJ_ETYPE, 0x10);
	wfile(EINJ_ADDR, addr);
	wfile(EINJ_MASK, ~0x0ul);
	wfile(EINJ_NOTRIGGER, notrigger);
	wfile(EINJ_DOIT, 1);
}

static void check_configuration(void)
{
	char	model[512];

	pagesize = getpagesize();

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
	proc_cpuinfo(&nsockets, &ncpus, model);
	if (nsockets == 0 || ncpus == 0) {
		fprintf(stderr, "%s: could not find number of sockets/cpus\n", progname);
		exit(1);
	}
	if (ncpus % nsockets) {
		fprintf(stderr, "%s: strange topology. Are all cpus online?\n", progname);
		exit(1);
	}
	lcpus_persocket = ncpus / nsockets;
	if (!force_flag && strstr(model, "E7-") == NULL) {
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
	return p + CACHE_LINE_SIZE;
}

static void *instr_alloc(void)
{
	char	*p = (char *)dosums;

	p += 2 * pagesize;

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

int trigger_memcpy(char *addr)
{
	/* phantom arg3 so values in %rdi,%rsi,%ecx are right for "rep mov" */
	do_memcpy(addr + 1024, addr, 0, 512);
	return 0;
}

int trigger_copyin(char *addr)
{
	int	fd, ret;
	char	filename[] = "/tmp/einj-XXXXXX";

	if ((fd = mkstemp(filename)) == -1) {
		fprintf(stderr, "%s: couldn't make temp file\n", progname);
		return -1;
	}
	(void)unlink(filename);
	if ((ret = write(fd, addr, 16) != 16)) {
		if (ret == -1)
			fprintf(stderr, "%s: couldn't write temp file\n", progname);
		else
			fprintf(stderr, "%s: short write to temp file\n", progname);
	}
	close(fd);
	return 0;
}

int trigger_patrol(char *addr)
{
	sleep(1);
}

int trigger_instr(char *addr)
{
	int ret = dosums();

	if (ret != 729)
		printf("Corruption during instruction fault recovery (%d)\n", ret);

	return ret;
}

/* attributes of the test and which events will follow our trigger */
#define	F_MCE		1
#define	F_CMCI		2
#define F_SIGBUS	4
#define	F_FATAL		8

struct test {
	char	*testname;
	char	*testhelp;
	void	*(*alloc)(void);
	int	notrigger;
	int	(*trigger)(char *);
	int	flags;
} tests[] = {
	{
		"single", "Single read in pipeline to target address, generates SRAR machine check",
		data_alloc, 1, trigger_single, F_MCE|F_CMCI|F_SIGBUS,
	},
	{
		"double", "Double read in pipeline to target address, generates SRAR machine check",
		data_alloc, 1, trigger_double, F_MCE|F_CMCI|F_SIGBUS,
	},
	{
		"split", "Unaligned read crosses cacheline from good to bad. Probably fatal",
		data_alloc, 1, trigger_split, F_MCE|F_CMCI|F_SIGBUS|F_FATAL,
	},
	{
		"THP", "Try to inject in transparent huge page, generates SRAR machine check",
		thp_data_alloc, 1, trigger_single, F_MCE|F_CMCI|F_SIGBUS,
	},
	{
		"store", "Write to target address. Should generate a UCNA/CMCI",
		data_alloc, 1, trigger_write, F_CMCI,
	},
	{
		"memcpy", "Streaming read from target address. Probably fatal",
		data_alloc, 1, trigger_memcpy, F_MCE|F_CMCI|F_SIGBUS|F_FATAL,
	},
	{
		"instr", "Instruction fetch. Generates SRAR that OS should transparently fix",
		instr_alloc, 1, trigger_instr, F_MCE|F_CMCI,
	},
	{
		"patrol", "Patrol scrubber, generates SRAO machine check",
		data_alloc, 0, trigger_patrol, F_MCE,
	},
	{
		"copyin", "Kernel copies data from user. Probably fatal",
		data_alloc, 1, trigger_copyin, F_MCE|F_CMCI|F_SIGBUS|F_FATAL,
	},
	{ NULL }
};

static void show_help(void)
{
	struct test *t;

	printf("Usage: %s [-a][-c count][-d delay][-f] [testname]\n", progname);
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

	progname = argv[0];

	while ((c = getopt(argc, argv, "ac:d:fh")) != -1) switch (c) {
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
			inject_uc(paddr, t->notrigger);
			t->trigger(vaddr);
			if (t->flags & F_SIGBUS) {
				printf("Expected SIGBUS, didn't get one\n");
			}
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

		if (t->flags & F_MCE) {
			if (a_mce == b_mce) {
				printf("Expected MCE, but none seen\n");
			} else if (a_mce == b_mce + 1) {
				printf("Saw local machine check\n");
			} else if (a_mce == b_mce + ncpus) {
				printf("Saw broadcast machine check\n");
			} else {
				printf("Unusual number of MCEs seen: %ld\n", a_mce - b_mce);
			}
		} else {
			if (a_mce != b_mce) {
				printf("Saw %ld unexpected MCEs (%ld systemwide)\n", b_mce - a_mce, (b_mce - a_mce) / ncpus);
			}
		}

		if (t->flags & F_CMCI) {
			while (a_cmci < b_cmci + lcpus_persocket) {
				if (cmci_wait_count > 1000) {
					break;
				}
				usleep(100);
				proc_interrupts(&a_mce, &a_cmci);
				cmci_wait_count++;
			}
			if (cmci_wait_count != 0) {
				gettimeofday(&t2, NULL);
				printf("CMCIs took ~%ld usecs to be reported.\n",
					1000000 * (t2.tv_sec - t1.tv_sec) +
						(t2.tv_usec - t1.tv_usec));
			}
			if (a_cmci == b_cmci) {
				printf("Expected CMCI, but none seen\n");
			} else if (a_cmci < b_cmci + lcpus_persocket) {
				printf("Unusual number of CMCIs seen: %ld\n", a_cmci - b_cmci);
			}
		} else {
			if (a_cmci != b_cmci) {
				printf("Saw %ld unexpected CMCIs (%ld per socket)\n", a_cmci - b_cmci, (a_cmci - b_cmci) / lcpus_persocket);
			}
		}

		usleep((useconds_t)(delay * 1.0e6));
		if (all_flag) {
			t = next_test(t);
			while (t->flags & F_FATAL)
				t = next_test(t);
		}
	}

	return 0;
}

/*
 * Copyright (C) 2014 Intel Corporation
 * Authors: Tony Luck
 *
 * This software may be redistributed and/or modified under the terms of
 * the GNU General Public License ("GPL") version 2 only as published by the
 * Free Software Foundation.
 */

/*
 * hornet: Start a process (or point to an existing one) and inject
 * an uncorrectable memory error to a targeted or randomly chosen
 * memory address
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>

static char *progname;

long	addr;
double	delay;
int	pid;
int	tflag, dflag, bflag, sflag, mflag, pflag, vflag;
int 	trace;

static void usage(void)
{
	fprintf(stderr, "Usage: %s [-v] -P PID\n", progname);
	fprintf(stderr, "Usage: %s [hornetopts] -p PID\n", progname);
	fprintf(stderr, "Usage: %s [hornetopts] command args ...\n", progname);
	fprintf(stderr, "  hornetopts = [-D delay][-v][ -a ADDRESS][-t|-d|-b|-s|-m]\n");
	exit(1);
}

#define EINJ_ETYPE "/sys/kernel/debug/apei/einj/error_type"
#define EINJ_ADDR "/sys/kernel/debug/apei/einj/param1"
#define EINJ_MASK "/sys/kernel/debug/apei/einj/param2"
#define EINJ_NOTRIGGER "/sys/kernel/debug/apei/einj/notrigger"
#define EINJ_DOIT "/sys/kernel/debug/apei/einj/error_inject"

#define check_ptrace(req, pid, addr, data) 				\
	do { 								\
		if (ptrace(req, pid, addr, data) == -1) { 		\
			fprintf(stderr, "Failed to run "#req": %s\n",	\
				strerror(errno)); 			\
			return 1; 					\
		} 							\
	} while (0)

static void wfile(char *file, unsigned long val)
{
	FILE *fp;

	fp = fopen(file, "w");
	if (fp == NULL) {
		perror(file);
		exit(1);
	}
	fprintf(fp, "0x%lx\n", val);
	if (fclose(fp) == EOF) {
		perror(file);
		exit(1);
	}
}

static int startproc(char **args)
{
	int	pid;

	switch ((pid = fork())) {
	case -1:
		perror("fork");
		exit(1);
	case 0:
		execvp(args[0], args);
		fprintf(stderr, "%s: cannot run '%s'\n", progname, args[0]);
		exit(1);
	}
	return pid;
}

static void parsemaps(int pid, long *lo, long *hi)
{
	char mapfile[32], perm[10], file[4096], line[4096];
	long vstart, vend;
	int pgoff, maj, min, ino;
	char *p;
	long sz, maxsz = -1, vmstart, vmend;
	FILE *fp;

	sprintf(mapfile, "/proc/%d/maps", pid);

	if ((fp = fopen(mapfile, "r")) == NULL) {
		fprintf(stderr, "%s: can't open %s\n", progname, mapfile);
		exit(1);
	}

	while ((p = fgets(line, sizeof line, fp)) != NULL) {
		file[0] = '\0';
		if (sscanf(line, "%lx-%lx %s %x %d:%d %d %s\n",
		&vstart, &vend, perm, &pgoff, &maj, &min, &ino, file) >= 7) {
			sz = vend - vstart;
			if (strcmp(perm, "rw-p") == 0 && file[0] == '\0' && sz > maxsz) {
				vmstart = vstart;
				vmend = vend;
				maxsz = sz;
			}
			if (tflag && strcmp(perm, "r-xp") == 0 && file[0] == '/')
				break;
			if (dflag && strcmp(perm, "rw-p") == 0 && file[0] == '/')
				break;
			if (bflag && strcmp(perm, "rw-p") == 0 && file[0] == '\0' && vstart < 0x400000000000)
				break;
			if (sflag && strcmp(perm, "rw-p") == 0 && strcmp(file, "[stack]") == 0)
				break;
			if (mflag && strcmp(perm, "rw-p") == 0 && file[0] == '\0' && vstart > 0x400000000000)
				break;
			if (addr && addr >= vstart && addr < vend)
				break;
		}
	}
	fclose(fp);

	if (p) {
		*lo = vstart; *hi = vend;
		return;
	}
	if (!tflag && !dflag && !bflag && !sflag && !mflag && addr == 0) {
		*lo = vmstart; *hi = vmend;
		return;
	}
	fprintf(stderr, "%s: can't find suitable address range\n", progname);
	exit(1);
}

static long randaddr(long lo, long hi)
{
	long sz = hi - lo;
	long a;

	srandom(getpid() ^ time(0));
	a = lo + sz/10 + (long)(sz * 0.8 * random() / RAND_MAX);

	return a & ~0x3ful;
}

static long pickaddr(int pid, long lo, long hi, long *phys)
{
	int pagesize = getpagesize();
	unsigned long pinfo;
	long offset;
	int fd, skip = 0;
	char pagemap[32];
	long a;

	sprintf(pagemap, "/proc/%d/pagemap", pid);
	fd = open(pagemap, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "%s: cannot open pagemap for pid=%d\n", progname, pid);
		return -1;
	}
	if (addr)
		a = addr;
	else
		a = randaddr(lo, hi);
again:
	if (vflag)
		printf("checking virtual address 0x%lx in [0x%lx,0x%lx]\n", a, lo, hi);
	offset = a / pagesize * (sizeof pinfo);
	if (pread(fd, &pinfo, sizeof pinfo, offset) != sizeof pinfo) {
		fprintf(stderr, "%s: cannot read pagemap for pid=%d addr=%lx\n", progname, pid, a);
		goto fail;
	}
	if ((pinfo & (1ul << 63)) == 0) {
		if (addr) {
			fprintf(stderr, "%s: chosen address %lx not allocated\n", progname, addr);
			goto fail;
		}
		skip = (skip <= 0) ? -skip + 1 : -(skip + 1);
		a += pagesize * skip;
		if (vflag) printf("skip=%d new addr=0x%lx\n", skip, a);
		if (a < lo || a >= hi) {
			fprintf(stderr, "%s: could not find allocated address\n", progname);
			goto fail;
		}
		goto again;
	}
	*phys = ((pinfo & 0x007ffffffffffffful) * pagesize) + (a & (pagesize - 1));
	return a;
fail:
	close(fd);
	return -1;
}

int main(int argc, char **argv)
{
	int	c;
	int	status;
	long	lo, hi, phys, virt;
	struct user_regs_struct regs;
	int ret = 0;

	progname = argv[0];

	while ((c = getopt(argc, argv, "D:P:a:tdbsmp:v")) != -1) switch (c) {
	case 'D': delay = atof(optarg); break;
	case 'a': addr = strtol(optarg, NULL, 0); break;
	case 't': tflag = 1; break;
	case 'd': dflag = 1; break;
	case 'b': bflag = 1; break;
	case 's': sflag = 1; break;
	case 'm': mflag = 1; break;
	case 'p': pflag = 1; pid = atoi(optarg); break;
	case 'P': trace = 1; pid = atoi(optarg); break;
	case 'v': vflag++; break;
	default: usage(); break;
	}

	wfile(EINJ_ETYPE, 0x10);
	wfile(EINJ_MASK, ~0x0ul);
	wfile(EINJ_NOTRIGGER, 1);

	if (!pflag && !trace)
		pid = startproc(&argv[optind]);
	if (delay != 0.0)
		usleep((useconds_t)(delay * 1.0e6));
	if (trace) {
		check_ptrace(PTRACE_ATTACH, pid, NULL, NULL);
		waitpid(pid, NULL, 0);
		check_ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		virt = regs.rip;
		check_ptrace(PTRACE_PEEKTEXT, pid, virt, NULL);
		lo = hi = addr = virt;
	} else {
		if (kill(pid, SIGSTOP) == -1) {
			fprintf(stderr, "%s: cannot stop process\n", progname);
			return 1;
		}

		parsemaps(pid, &lo, &hi);

	}

	if ((virt = pickaddr(pid, lo, hi, &phys)) == -1) {
		kill(pid, SIGKILL);
		return 1;
	}

	wfile(EINJ_ADDR, phys);
	wfile(EINJ_DOIT, 1);

	if (vflag) printf("%s: injected UC error at virt=%lx phys=%lx to pid=%d%s\n",
		progname, virt, phys, pid, trace == 1 ? "(ptrace)" : "");

	if (trace) {
		sleep(1);
		check_ptrace(PTRACE_DETACH, pid, NULL, NULL);
		goto end;
	}
	if (kill(pid, SIGCONT) == -1) {
		fprintf(stderr, "%s: cannot resume process\n", progname);
		ret = 1;
		goto end;
	}
	if (pflag) {
		while (kill(pid, 0) != -1)
			usleep(1000000);
	} else {
		while (wait(&status) != pid)
			;
		if (WIFSIGNALED(status) && WTERMSIG(status) == SIGBUS)
			printf("%s: process terminated by SIGBUS\n", progname);
	}

end:
	wfile("/sys/devices/system/memory/hard_offline_page", phys);
	return ret;
}

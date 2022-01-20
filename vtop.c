/*
 * Copyright (C) 2014 Intel Corporation
 * Authors: Tony Luck
 *
 * This software may be redistributed and/or modified under the terms of
 * the GNU General Public License ("GPL") version 2 only as published by the
 * Free Software Foundation.
 */

/*
 * Given a process if and virtual address, dig around in
 * /proc/id/pagemap to find the physical address (if present)
 * behind the virtual one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/mman.h>

static int pagesize=0x1000;

/*
 * get information about address from /proc/{pid}/pagemap
 */

unsigned long long vtop(unsigned long long addr, int proc_id)
{
	unsigned long  pinfo;
	
	int fd;
	char	pagemapname[64];
	long offset;
	
	offset = addr / pagesize * (sizeof pinfo);
	
	/* sprintf(pagemapname, "/proc/%d/pagemap", getpid()); */
	sprintf(pagemapname, "/proc/%d/pagemap",proc_id);

	fd = open(pagemapname, O_RDONLY);
	if (fd == -1) {
		perror(pagemapname);
		exit(1);
	}
	if (pread(fd, &pinfo, sizeof pinfo, offset) != sizeof pinfo) {
		perror(pagemapname);
		exit(1);
	}
	close(fd);
	if ((pinfo & (1ull << 63)) == 0) {
		printf("page not present\n");
		exit(1);
	}
	return ((pinfo & 0x007fffffffffffffull) * pagesize) + (addr & (pagesize - 1));
}

int main(int argc, char **argv)
{
	int process_id;
	unsigned long long buf, phys;

	if (argc != 3) {
		printf("require virtual address and pid: 'vtop vaddress pid'\n");
		return 1;
	}		
		
	pagesize = getpagesize();	
	buf = strtoul(argv[1], NULL, 16);
	
	process_id = atol(argv[2]);
 
	phys =  vtop(buf, process_id);

	printf("vtop(%llx,%d) = %llx\n", buf, process_id, phys);
 
	return 0;
}

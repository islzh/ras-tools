/*
 * Copyright (C) 2022 Intel Corporation
 * Author: Tony Luck
 *
 * This software may be redistributed and/or modified under the terms of
 * the GNU General Public License ("GPL") version 2 only as published by the
 * Free Software Foundation.
 */

/*
 * Allocate memory - loop using EINJ to inject a soft error,
 * consuming after each until the page is taken offline.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/mman.h>

#define EINJ_ETYPE "/sys/kernel/debug/apei/einj/error_type"
#define EINJ_ADDR "/sys/kernel/debug/apei/einj/param1"
#define EINJ_MASK "/sys/kernel/debug/apei/einj/param2"
#define EINJ_NOTRIGGER "/sys/kernel/debug/apei/einj/notrigger"
#define EINJ_DOIT "/sys/kernel/debug/apei/einj/error_inject"

volatile int trigger;

extern unsigned long long vtop(unsigned long long addr);

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

#define MAX_TRIES 30

int main(int argc, char **argv)
{
	char *addr = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	unsigned long long paddr;
	int tries = MAX_TRIES;
	int i;

	if (argc == 2)
		tries = atoi(argv[1]);

	if (addr == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	wfile(EINJ_ETYPE, 0x8);
	wfile(EINJ_MASK, ~0x0ul);
	wfile(EINJ_NOTRIGGER, 1);

	*addr = '*';
	paddr = vtop((unsigned long long)addr);

	for (i = 0; i < tries; i++) {
		printf("%d: Inject to vaddr=%p paddr=0x%llx\n", i, addr, paddr);
		wfile(EINJ_ADDR, paddr);
		wfile(EINJ_DOIT, 1);
		usleep(250);
		trigger += *addr;
		sleep(2);
		if (paddr != vtop((unsigned long long)addr))
			break;
	}

	if (i == tries) {
		fprintf(stderr, "FAIL: Page was not offline after %d errors\n", i);
		return 1;
	}

	printf("PASS: page taken offline after %d corrected errors\n", i + 1);
	return 0;
}

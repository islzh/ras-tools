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
#include <ctype.h>
#include <string.h>

static long sumint(char *s)
{
	long total = 0;
	char	*se;

	for (;;) {
		total += strtol(s, &se, 10);
		if (s == se)
			break;
		s = se;
	}

	return total;
}

/*
 * Parse /proc/interrupts to sum the number of observed
 * machine checks and corrected machine check interrupts
 * across all cpus
 */
void proc_interrupts(long *nmce, long *ncmci)
{
	FILE *fp = fopen("/proc/interrupts", "r");
	char	*p, line[4096];

	*ncmci = *nmce = -1;
	if (fp == NULL)
		return;

	while (fgets(line, sizeof(line), fp) != NULL) {
		for (p = line; isspace(*p); p++)
			;
		if (strncmp(p, "MCE:", 4) == 0)
			*nmce = sumint(p+4);
		else if (strncmp(p, "THR:", 4) == 0)
			*ncmci = sumint(p+4);
	}

	fclose(fp);
}

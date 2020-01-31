/*
 * Copyright (C) 2011 Jiaju Zhang <jjzhang@suse.de>
 * Copyright (C) 2013-2014 Philipp Marek <philipp.marek@linbit.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "utils.h"

#include <stdio.h>  /* EXIT_FAILURE */
#include <stdlib.h>  /* fprintf */
#include <string.h>  /* strlen, strncpy */

void safe_copy(char *dest, const char *value, size_t buflen,
               const char *description)
{
	int content_len = buflen - 1;

	if (strlen(value) >= content_len) {
		fprintf(stderr, "'%s' exceeds maximum %s length of %d\n",
			value, description, content_len);
		exit(EXIT_FAILURE);
	}
	strncpy(dest, value, content_len);
	dest[content_len] = 0;
}

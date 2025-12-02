/*
 * ipconf: configure network interfaces using ioth_config conf strings
 * Copyright (C) 2025  Renzo Davoli, University of Bologna
 *
 * ipconf is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#include <iothconf.h>

static void usage(char *progname) {
	fprintf(stderr, 
			"Usage: %s OPTIONS [config_str]\n"
			"configure ip interfaces\n"
			"OPTIONS:\n"
			" -v --verbose:     verbose mode\n"
			" -h, --help:       usage message\n", progname);
	exit(1);
}

int main(int argc, char *argv[]) {
	char *progname = basename(argv[0]);
	int exit_value = 0;
	static char *short_options = "vh";
	static struct option long_options[] = {
		{"verbose", no_argument, 0,  'v'},
		{"help",    no_argument, 0,  'h'},
		{0,         0,           0,   0}
	};

	int verbose = 0;
	int c;
	while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) >= 0) {
		switch (c) {
			case 'v': verbose = 1; break;
			case '?':
			case 'h':
			default: usage(progname); break;
		}
	}
	for (; argv[optind]; optind++) {
		int rv = ioth_config(NULL, argv[optind]);
		if (rv == -1) {
			perror(argv[optind]);
			exit_value = 1;
		}
		else if (verbose) {
			printf("ioth_config confirmed:");
			if (rv & IOTHCONF_STATIC) printf(" static");
			if (rv & IOTHCONF_ETH) printf(" eth");
			if (rv & IOTHCONF_DHCP) printf(" dhcp");
			if (rv & IOTHCONF_DHCPV6) printf(" dhcpv6");
			if (rv & IOTHCONF_RD) printf(" rd");
			printf("\n");
		}
	}
	return(exit_value);
}

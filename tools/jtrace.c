/*
 *
 */
#include "../kmod/jtrace.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <stdarg.h>
#include <time.h>
#include <sys/types.h>
#include <stddef.h>
#include <linux/stddef.h>
#include <linux/version.h>
#include <inttypes.h>
#include <unistd.h>
#include <assert.h>
#include <sys/param.h> /* MIN() / MAX() */

#define DUMP_HEX_BYTES_PER_LINE 16

void usage(int rc)
{

	fprintf(rc ? stderr : stdout,
		"usage: jtrace -n <trc_buf_name> <options>\n"
		"\n    Display trace information:\n"
		"    -n <trc_buf_name>   trace buffer name\n"
		"    -D     use default trace buffer name\n"
		"    [-v]        verbose\n"
		"\n    Trace flag control (requires -n|-D first):\n"
		"    [-h trace_flags]  trace flags absolute, hex value\n"
		"    [-f trace_flag_strs] trace flags absolute, string values\n"
		"    [-s trace_flag_strs] set a trace flag(s) (logical or)\n"
		"    [-u trace_flag_strs] unset a trace flag(s) (logical nand)\n"
		"    [-g ] Show currently set trace flags\n"
		"\n    Output Trace to console (requires -n|-D first):\n"
		"    [-p <0|1> ] Set printk value (1=print to console enabled)\n"
		"\n    Clear Trace buffer (requires -n|-D first):\n"
		"    [-c]        clear the trace buffer\n"
		"\n    ACPI/Config helpers :\n"
		"    [-A]        Dump ACPI info to jtrc_default.\n"
		"    [-L]        Dump physical location info to jtrc_default.\n");

	printf("\nValid trace flags:\n\n");
	show_trc_flags(0xffffffff);

	exit(rc);
}


/****************************************************************************/

#define TRC_BUF_NAME_REQUIRED "ERROR: Specify -n <trc_buf_name> first.\n"

/**
 * main()
 */
int main(int argc, char **argv)
{
	int ch;
	uint32_t trc_flags = 0;
	uint32_t trc_flag = 0;
	int n_flag = 0;
	int printk_value = 0;
	int rc = 0;
	unsigned int dump_mask = 0xffffffff;
	char *trc_buf_name = NULL;
	void *all_trc_info = NULL;
	int jtrace_kfd;
	struct jtrc_cb *jtrc_cb = NULL;

	jtrace_kfd = jtrace_kopen();
	if (jtrace_kfd < 0) {
		printf("jtrace_kopen failed\n");
		exit(-1);
	}

	while ((ch = getopt(argc, argv, "?vgh:cd:f:s:u:p:n:Dm:")) != EOF) {
		switch (ch) {

		case 'v':
			++jtrc_verbose;
			break;

		case 'p':
			if (!n_flag) {
				printf(TRC_BUF_NAME_REQUIRED);
				usage(rc);
				rc = -1;
				goto jtrc_util_exit;
			}

			printk_value = strtol(optarg, NULL, 16);
			rc = set_printk_value(trc_buf_name, printk_value);
			if (rc) {
				printf("Could not set trace flags to 0x%x\n",
				       trc_flags);
				rc = -1;
				goto jtrc_util_exit;
			}
			printf("\nPrintk set to (%d):\n\n", printk_value);
			rc = 0;
			goto jtrc_util_exit;

		case 'n':
			n_flag++;
			if (!trc_buf_name) {
				trc_buf_name = optarg;
			} else {
				usage(1);
				rc = -1;
				goto jtrc_util_exit;
			}
			printf("\ntrc_buf_name=%s\n", trc_buf_name);
			/* get trace_info from running kernel */
			jtrc_cb = get_all_trc_info(trc_buf_name, &all_trc_info);
			if (rc) {
				printf("get_trc_info failed errno=%d\n", rc);
				goto jtrc_util_exit;
			}
			break;

		case 'D':
			n_flag++;
			if (!trc_buf_name) {
				trc_buf_name = JTRC_DEFAULT_NAME;
			} else {
				usage(1);
				rc = -1;
				goto jtrc_util_exit;
			}
			printf("\ntrc_buf_name=%s\n", trc_buf_name);
			/* get trace_info from running kernel */
			jtrc_cb = get_all_trc_info(trc_buf_name, &all_trc_info);
			if (rc) {
				printf("get_trc_info failed errno=%d\n", rc);
				goto jtrc_util_exit;
			}
			break;

		case 'm':
			dump_mask = strtol(optarg, NULL, 16);
			printf("\ndump_mask %x\n\n",
			       dump_mask);
			break;

		case 'h':
			if (!n_flag) {
				printf(TRC_BUF_NAME_REQUIRED);
				usage(rc);
				rc = -1;
				goto jtrc_util_exit;
			}

			trc_flags = strtol(optarg, NULL, 16);
			rc = set_trc_flags(trc_buf_name, trc_flags);
			if (rc) {
				printf("Could not set trace flags to 0x%x\n",
				       trc_flags);
				rc = -1;
				goto jtrc_util_exit;
			}
			printf("\nTrace flags set to (0x%08x):\n\n",
			       trc_flags);
			show_trc_flags(trc_flags);
			rc = 0;
			goto jtrc_util_exit;

		case 'g':
			if (!n_flag) {
				printf(TRC_BUF_NAME_REQUIRED);
				usage(rc);
				rc = -1;
				goto jtrc_util_exit;
			}

			printf("\nCurrent set trace flags(0x%08x) for %s:\n\n",
			       jtrc_cb->jtrc_flags,
			       jtrc_cb->jtrc_name);
			show_trc_flags(jtrc_cb->jtrc_flags);
			rc = 0;
			goto jtrc_util_exit;

		case 'f':
			if (!n_flag) {
				printf(TRC_BUF_NAME_REQUIRED);
				usage(rc);
				rc = -1;
				goto jtrc_util_exit;
			}

			trc_flags = 0;
			/* Get first flag string */
			rc = flag_str_to_flag(optarg, &trc_flag);
			if (rc) {
				printf("Invalid flag %s\n", optarg);
				usage(rc);
				rc = -1;
				goto jtrc_util_exit;
			}
			/* trc_flag was valid */
			trc_flags |= trc_flag;
			/* See if there are other valid flag strings */
			while (optind < argc) {
				rc = flag_str_to_flag(argv[optind], &trc_flag);
				if (rc) {
					printf("Invalid flag %s\n",
					       argv[optind]);
					usage(rc);
					rc = -1;
					goto jtrc_util_exit;
				}
				/* trc_flag was valid */
				trc_flags |= trc_flag;
				optind++;
			}
			/* Set the flags to the new value */
			rc = set_trc_flags(trc_buf_name, trc_flags);
			if (rc) {
				printf("Could not set trace flags.\n");
				rc = -1;
				goto jtrc_util_exit;
			}
			printf("\nTrace flags set to (0x%08x):\n\n",
			       trc_flags);
			show_trc_flags(trc_flags);
			rc = 0;
			goto jtrc_util_exit;

		case 's':
			if (!n_flag) {
				printf(TRC_BUF_NAME_REQUIRED);
				usage(rc);
				rc = -1;
				goto jtrc_util_exit;
			}

			trc_flags = jtrc_cb->jtrc_flags;

			/* Get first flag string */
			rc = flag_str_to_flag(optarg, &trc_flag);
			if (rc) {
				printf("Invalid flag %s\n", optarg);
				usage(rc);
				rc = -1;
				goto jtrc_util_exit;
			}
			/* trc_flag was valid */
			trc_flags |= trc_flag;
			/* See if there are other valid flag strings */
			while (optind < argc) {
				rc = flag_str_to_flag(argv[optind], &trc_flag);
				if (rc) {
					printf("Invalid flag %s\n",
					       argv[optind]);
					usage(rc);
					rc = -1;
					goto jtrc_util_exit;
				}
				/* trc_flag was valid */
				trc_flags |= trc_flag;
				optind++;
			}
			/* Set the flags to the new value */
			rc = set_trc_flags(trc_buf_name, trc_flags);
			if (rc) {
				printf("Could not set trace flags.\n");
				rc = -1;
				goto jtrc_util_exit;
			}
			printf("\nCurrent set trace flags (0x%08x):\n\n",
			       trc_flags);
			show_trc_flags(trc_flags);
			rc = 0;
			goto jtrc_util_exit;

		case 'u':
			if (!n_flag) {
				printf(TRC_BUF_NAME_REQUIRED);
				usage(rc);
				rc = -1;
				goto jtrc_util_exit;
			}

			trc_flags = jtrc_cb->jtrc_flags;

			/* Get first flag string */
			rc = flag_str_to_flag(optarg, &trc_flag);
			if (rc) {
				printf("Invalid flag %s\n", optarg);
				usage(rc);
				rc = -1;
				goto jtrc_util_exit;
			}
			/* trc_flag was valid */
			trc_flags &= ~(trc_flag);
			/* See if there are other valid flag strings */
			while (optind < argc) {
				rc = flag_str_to_flag(argv[optind], &trc_flag);
				if (rc) {
					printf("Invalid flag %s\n",
					       argv[optind]);
					usage(rc);
					rc = -1;
					goto jtrc_util_exit;
				}
				/* trc_flag was valid */
				trc_flags &= ~(trc_flag);
				optind++;
			}
			/* Set the flags to the new value */
			rc = set_trc_flags(trc_buf_name, trc_flags);
			if (rc) {
				printf("Could not set trace flags.\n");
				rc = -1;
				goto jtrc_util_exit;
			}
			printf("\nCurrent set trace flags (0x%08x):\n\n",
			       trc_flags);

			show_trc_flags(trc_flags);
			rc = -1;
			goto jtrc_util_exit;

		case 'c':
			if (!n_flag) {
				printf(TRC_BUF_NAME_REQUIRED);
				usage(rc);
				rc = -1;
				goto jtrc_util_exit;
			}
			clear_trace_buf(trc_buf_name);
			printf("Trace buffer cleared\n");
			rc = 0;
			goto jtrc_util_exit;

		case '?':
			/* Try to get all info for flag information */
			jtrc_cb = get_all_trc_info(trc_buf_name, &all_trc_info);
			usage(0);
			rc = 0;
			goto jtrc_util_exit;

		default:
			usage(1);
		}
	}

	if (!jtrc_cb) {
		printf("Error: Could not find trc_buf_name=%s\n",
		       trc_buf_name);
		/* Try to get all info for module and flag information */
		jtrc_cb = get_all_trc_info(trc_buf_name, &all_trc_info);
		usage(1);
		rc = -1;
		goto jtrc_util_exit;
	}

	print_trace(jtrc_cb, dump_mask);

jtrc_util_exit:
	if (all_trc_info)
		free(all_trc_info);

	if (jtrace_kfd > 0)
		close(jtrace_kfd);

	exit(0);
}

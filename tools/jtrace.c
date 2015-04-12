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

/*
 * Global vars
 */
char *namel = "/stand/vmunix";

int verbose = 0;                /* flag: verbose or not    */

char jtrc_dev[] = JTRACE_DEV_SPECIAL_FILE;
int kutil_dev_fd = -1;

void *all_trc_info = NULL;
int jtrc_num_common_flags = 0;
jtrc_flag_descriptor_t *jtrc_common_flag_array = 0;
int jtrc_num_instances = 0;
jtrc_cb_t *jtrc_first_cb = NULL;
jtrc_cb_t *jtrc_cb = NULL;

/*******************************************************************/

int show_trc_flags(uint32_t trc_flags);
int print_trace(jtrc_cb_t * cb, uint32_t dump_mask);
int set_printk_value(char *buf_name, int value);

#define DUMP_HEX_BYTES_PER_LINE 16

void usage(rc)
{

    fprintf(rc ? stderr : stdout,
            "usage: jtrace -n <trc_buf_name> <options>\n"
            "\n    Display trace information:\n"
            "    -n <trc_buf_name>   trace buffer name\n"
	    "    -D     use default trace buffer name\n"
            "    [-v]        verbose\n"
            /* XXX maybe once on 2.6 kernel.. "    [-d dumpfile] pull out of dumpfile, not memory\n" */
            "\n    Trace flag control (requires -n|-D first):\n"
            "    [-h trace_flags]  trace flags absolute, hex value\n"
            "    [-f trace_flag_strs] trace flags absolute, string values\n"
            "    [-s trace_flag_strs] set a trace flag(s) (logical or)\n"
            "    [-u trace_flag_strs] unset a trace flag(s) (logical nand)\n"
            "    [-g ] Show currently set trace flags\n"
            "\n    Output Trace to console (requires -n|-D first):\n"
            "    [-p <0|1> ] Set printk value (1=print to console enabled) \n"
            "\n    Clear Trace buffer (requires -n|-D first):\n"
            "    [-c]        clear the trace buffer\n"
            "\n    ACPI/Config helpers :\n"
            "    [-A]        Dump ACPI info to jtrc_default.\n"
            "    [-L]        Dump physical location info to jtrc_default.\n");

    printf("\nValid trace flags:\n\n");
    show_trc_flags(0xffffffff);

    printf("num_common_flags=%d\n", jtrc_num_common_flags);

    exit(rc);
}

/*
 * Snarfing is getting strings or other values that are pointed to by
 * entries in the jtrace. The trick is we must have access to the address
 * space that was in effect when the trace entries were made.  Possibilities
 * are:
 *
 * 1. the current process (snarf is just a memory access)
 * 2. the kernel address space (snarf gets help from the jtrace kmod)
 * 3. a core file - TBD
 * 4. a kernel crash dump - TBD
 */

/**
 * snarf_from_kernel()
 *
 * Once upon a time snarfing was easy because we could open /dev/kmem
 * (with sufficient priveleges) and read whatever we needed.  Now we need
 * help from the jtrace kernel module.
 */
int snarf_from_kernel(void *from, void *buf, size_t len)
{
	jtrc_cmd_req_t cmd_req;

	cmd_req.snarf_addr = from;
	cmd_req.data = buf;
	cmd_req.data_size = len;

	cmd_req.cmd = JTRCTL_SNARF;
	if (ioctl(kutil_dev_fd, JTRC_CMD_IOCTL, &cmd_req)) {
		fprintf(stderr, "JTRCTL_SNARF Failed errno=%d\n", errno);
		return 1;
	}

	return (0);
}

void snarf(void *from, void *buf, size_t len)
{
	size_t cc = 0;

	cc = snarf_from_kernel(from, buf, len);
	if (cc) {
		fprintf(stderr,
			"snarf: read failed at %p, len %lx rc=%ld\n", from,
			(long) len, (long) cc);
	}
}

struct CacheStats {
    int hits;
    int misses;
    int fastHits;
} cStats;

/**
 * snarf_str()
 *
 * Snarf a null-terminated string, which requires a bit of initiative.
 */
char *snarf_str(void *from)
{
	static struct StrCache {
		void *addr;
		char str[128];
		uint lru;
	} cache[512], *last, *hiwat = &cache[0];
	static uint lru;
	struct StrCache *ent, *old;

	if (last && last->addr == from) {
		++cStats.fastHits;
		return last->str;
	}

	for (old = ent = cache; ent < hiwat; ++ent) {
		if (ent->addr == from) {
			++cStats.hits;
			ent->lru = ++lru;
			last = ent;
			return ent->str;
		}
		if (old->lru > ent->lru)
			old = ent;
	}

	/*
	 * cache miss - either use a new entry, or the oldest
	 */
	if (ent == hiwat && hiwat < &cache[512])
		ent = hiwat++;
	else
		ent = old;

	ent->addr = from;
	ent->lru = ++lru;

	snarf(from, ent->str, (size_t) sizeof(ent->str));
	ent->str[sizeof(ent->str) - 1] = 0;
	++cStats.misses;

	return (last = ent)->str;
}

/**********************************************************************/

int clear_trace_buf(char *buf_name)
{
	jtrc_cmd_req_t cmd_req;

	bzero(&cmd_req, sizeof(jtrc_cmd_req_t));

	strncpy(cmd_req.trc_name, buf_name, sizeof(cmd_req.trc_name));

	cmd_req.cmd = JTRCTL_CLEAR;
	if (ioctl(kutil_dev_fd, JTRC_CMD_IOCTL, &cmd_req)) {
		fprintf(stderr, "JTRCTL_CLEAR Failed errno=%d\n", errno);
		return 1;
	}

	return (0);
}

int set_trc_flags(char *buf_name, int trc_flags)
{
	int rc = 0;
	jtrc_cmd_req_t cmd_req;

	bzero(&cmd_req, sizeof(jtrc_cmd_req_t));
	strncpy(cmd_req.trc_name, buf_name, sizeof(cmd_req.trc_name));

	cmd_req.cmd = JTRCTL_SET_TRC_FLAGS;
	cmd_req.data = &trc_flags;
	rc = ioctl(kutil_dev_fd, JTRC_CMD_IOCTL, &cmd_req);
	if (rc) {
		printf("ioctl JTRCTL_SET_TRC_FLAGS failed, rc=%d errno=%d\n",
		       rc, errno);
		return (rc);
	}

	return (0);
}

int set_printk_value(char *buf_name, int value)
{
	int rc = 0;
	jtrc_cmd_req_t cmd_req;

	bzero(&cmd_req, sizeof(jtrc_cmd_req_t));

	strncpy(cmd_req.trc_name, buf_name, sizeof(cmd_req.trc_name));

	cmd_req.cmd = JTRCTL_SET_PRINTK;
	cmd_req.data = &value;
	rc = ioctl(kutil_dev_fd, JTRC_CMD_IOCTL, &cmd_req);
	if (rc) {
		printf("ioctl JTRCTL_SET_PRINTK failed, rc=%d errno=%d\n",
		       rc, errno);
		return (rc);
	}

	return (0);
}


/**
 * get_all_trc_info()
 *
 * Get all trace info from the jtrace kernel module. This function "knows"
 * what gets packed into the output buffer by the jtrace kernel module.
 *
 * XXX: should de-obfuscate this...
 */
int get_all_trc_info(char *trc_buf_name)
{
	jtrc_cb_t *cb = NULL;
	jtrc_cmd_req_t cmd_req;
	int i = 0;
	char *out_bufp = 0;
	int rc = 0;

	bzero(&cmd_req, sizeof(jtrc_cmd_req_t));

	cmd_req.cmd = JTRCTL_GET_ALL_TRC_INFO;
	cmd_req.data = 0;
	cmd_req.data_size = 0;

	/* Call once with no output buffer, to get required size */
	rc = ioctl(kutil_dev_fd, JTRC_CMD_IOCTL, &cmd_req);
	if (rc && (rc != ENOMEM)) {
		fprintf(stderr, "JTR_GET_ALL_TRC_INFO(0) Failed rc=%d\n", rc);
		return (rc);
	}
	/* Upon clean return, the jtrace kernel driver has set
	 *  cmd_req.data_size to the required size */
	if (verbose) {
		printf("required_size=%d\n", cmd_req.data_size);
	}

	/* all_trc_info is global */
	all_trc_info = malloc(cmd_req.data_size);
	assert(all_trc_info);

	cmd_req.data = all_trc_info;
	rc = ioctl(kutil_dev_fd, JTRC_CMD_IOCTL, &cmd_req);
	if (rc) {
		fprintf(stderr,
			"JTR_GET_ALL_TRC_INFO(%d) Failed describe rc=%d\n",
			cmd_req.data_size);
		return (rc);
	}
	/* Number of common Flags */
	out_bufp = all_trc_info;
	memcpy(&jtrc_num_common_flags, out_bufp,
	       sizeof(jtrc_num_common_flags));
	out_bufp += sizeof(jtrc_num_common_flags);

	/* Array of common flag descriptors */
	jtrc_common_flag_array = (jtrc_flag_descriptor_t *) out_bufp;
	out_bufp += (jtrc_num_common_flags * sizeof(jtrc_flag_descriptor_t));

	/* Number of registered modules */
	memcpy(&jtrc_num_instances, out_bufp,
	       sizeof(jtrc_num_instances));
	out_bufp += sizeof(jtrc_num_instances);

	if (verbose) {
		printf("jtrc_num_common_flags=%d "
		       "jtrc_num_instances=%d\n",
		       jtrc_num_common_flags, jtrc_num_instances);
	}

	/* Array of registered modules, each followed
	 * by optional custom flags */
	if (jtrc_num_instances) {
		jtrc_first_cb = (jtrc_cb_t *) out_bufp;
		cb = jtrc_first_cb;
	}

	/* If trc_buf_name supplied, find that trace module information */
	if (trc_buf_name) {
		for (i = 0; i < jtrc_num_instances; i++) {
			if (strcmp(cb->jtrc_name,
				   trc_buf_name) == 0) {
				/* Found a match */
				jtrc_cb = cb;
				break;
			}
			/* Get next trace information */
			out_bufp = (char *) cb;
			/* Skip past this trace information */
			out_bufp += sizeof(jtrc_cb_t);
			/* Also, skip past any custom flag descriptions */
			out_bufp +=
				(cb->jtrc_num_custom_flags *
				 sizeof(jtrc_flag_descriptor_t));
			cb = (jtrc_cb_t *) out_bufp;
		}
	}

	return (rc);
}


int show_trc_flags(uint32_t trc_flags)
{
	int i = 0;
	int j = 0;
	char *ptr = NULL;
	jtrc_flag_descriptor_t *flag_descp = NULL;
	jtrc_cb_t *cb = NULL;

	printf("\nCommon trace flags:\n");
	for (i = 0; i < jtrc_num_common_flags; i++) {
		flag_descp = &jtrc_common_flag_array[i];
		if ((JTR_COMMON_FLAG(i)) & trc_flags) {
			printf("%12s (0x%08x) - %s\n",
			       flag_descp->jtrc_flag_cmd_line_name,
			       JTR_COMMON_FLAG(i),
			       flag_descp->jtrc_flag_description);
		}
	}

	/* Specific trace module requested */
	if (jtrc_cb) {
		if (jtrc_cb->jtrc_num_custom_flags) {
			printf("\nCustom trace flags for module %s:\n",
			       jtrc_cb->jtrc_name);
			/* Custom flags start after the module trc info */
			ptr = (char *) jtrc_cb;
			ptr += sizeof(jtrc_cb_t);
			flag_descp = (jtrc_flag_descriptor_t *) ptr;
			for (i = 0;
			     i < (jtrc_cb->jtrc_num_custom_flags);
			     i++) {
				if ((JTR_CUSTOM_FLAG(i)) & trc_flags) {
					printf("%12s (0x%08x) - %s\n",
					       flag_descp->jtrc_flag_cmd_line_name,
					       JTR_CUSTOM_FLAG(i),
					       flag_descp->jtrc_flag_description);
				}
				flag_descp++;
			}
		} else {
			printf("\nNo custom trace flags for module %s:\n",
			       jtrc_cb->jtrc_name);
		}
		printf("\n\n");
		return (0);
	}

	cb = jtrc_first_cb;
	if (!cb) {
		/* No registered trace modules */
		printf("\n\n");
		return (0);
	}

	/*
	 * No specific trace module requested.
	 * Check all registered modules
	 */
	for (i = 0; i < jtrc_num_instances; i++) {

		if (cb->jtrc_num_custom_flags) {
			printf("\nCustom trace flags for module %s:\n",
			       cb->jtrc_name);

			/* Custom flags start after the module trc info */
			ptr = (char *) cb;
			ptr += sizeof(jtrc_cb_t);
			flag_descp = (jtrc_flag_descriptor_t *) ptr;
			for (j = 0;
			     j < (cb->jtrc_num_custom_flags); j++) {
				if ((JTR_CUSTOM_FLAG(j)) & trc_flags) {
					printf("%12s (0x%08x) - %s\n",
					       flag_descp->jtrc_flag_cmd_line_name,
					       JTR_CUSTOM_FLAG(j),
					       flag_descp->jtrc_flag_description);
				}
				flag_descp++;
			}
		} else {
			printf("\nNo custom trace flags for module %s:\n",
			       cb->jtrc_name);
		}

		/* Get next trace information */
		ptr = (char *) cb;
		/* Skip past this trace information */
		ptr += sizeof(jtrc_cb_t);
		/* Also, skip past any custom flag descriptions */
		ptr +=
			(cb->jtrc_num_custom_flags *
			 sizeof(jtrc_flag_descriptor_t));
		cb = (jtrc_cb_t *) ptr;
	}

	printf("\n\n");
	return (0);
}

int flag_str_to_flag(char *trc_flag_str, int *trc_flag)
{
	int i = 0;
	char *ptr = NULL;
	jtrc_flag_descriptor_t *flag_descp = NULL;

	for (i = 0; i < jtrc_num_common_flags; i++) {
		flag_descp = &jtrc_common_flag_array[i];
		if (strcmp(flag_descp->jtrc_flag_cmd_line_name,
			   trc_flag_str) ==
		    0) {
			/* Found a match */
			*trc_flag = JTR_COMMON_FLAG(i);
			return (0);
		}
	}

	if (jtrc_cb && jtrc_cb->jtrc_num_custom_flags) {
		if (verbose) {
			printf("Checking custom flags for %s\n",
			       jtrc_cb->jtrc_name);
		}
		/* Custom flags start after the module trc info */
		ptr = (char *) jtrc_cb;
		ptr += sizeof(jtrc_cb_t);
		flag_descp = (jtrc_flag_descriptor_t *) ptr;
		for (i = 0;
		     i < (jtrc_cb->jtrc_num_custom_flags); i++) {
			if (strcmp(flag_descp->jtrc_flag_cmd_line_name,
				   trc_flag_str) == 0) {
				/* Found a match */
				*trc_flag = JTR_CUSTOM_FLAG(i);
				return (0);
			}
			flag_descp++;
		}
	}

	/* Found no match, invalid flag */
	return (-1);
}

#define TRC_BUF_NAME_REQUIRED "ERROR: Specify -n <trc_buf_name> first.\n"

int main(int argc, char **argv)
{
	int ch, trace;
	uint32_t trc_flags = 0;
	uint32_t trc_flag = 0;
	int n_flag = 0;
	int printk_value = 0;
	int rc = 0;
	unsigned int dump_mask = 0xffffffff;
	char *trc_buf_name = NULL;

	trace = 0;

	kutil_dev_fd = open(jtrc_dev, O_RDWR);
	if (kutil_dev_fd < 0) {
		printf("%s: Device open failed %d\n", jtrc_dev, errno);
		exit(-1);
	}

	while ((ch = getopt(argc, argv, "?vgh:cd:f:s:u:p:n:Dm:")) != EOF) {
		switch (ch) {

		case 'v':
			++verbose;
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
			break;

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
			rc = get_all_trc_info(trc_buf_name);
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
			rc = get_all_trc_info(trc_buf_name);
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
			break;

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
			break;

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
			get_all_trc_info(trc_buf_name);
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
		get_all_trc_info(trc_buf_name);
		usage(1);
		rc = -1;
		goto jtrc_util_exit;
	}

	if (optind < argc) {
		namel = argv[optind++];
	}

	print_trace(jtrc_cb, dump_mask);

	if (verbose) {
		printf("cache stats: fastHits %d hits %d misses %d\n",
		       cStats.fastHits, cStats.hits, cStats.misses);
	}

jtrc_util_exit:
	if (all_trc_info) {
		free(all_trc_info);
	}

	if (kutil_dev_fd > 0) {
		close(kutil_dev_fd);
	}

	exit(0);
}


char *save_str(char *fmt, ...)
{
	char buf[512];
	int len;
	char *p;
	va_list ap;

	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);

	len = strlen(buf);
	if (!(p = (char *) malloc(len + 1))) {
		printf("no mem, err=%d\n", errno);
	}

	bcopy(buf, p, len + 1);

	return p;
}

/****************************************************************************
 * Functions concerned with expanding and printing trace elements and buffers
 */

int
printd(char *fmt, jtrc_arg_t a0, jtrc_arg_t a1, jtrc_arg_t a2,
       jtrc_arg_t a3, jtrc_arg_t a4)
{
    jtrc_arg_t abuf[5];
    register char *p;
    jtrc_arg_t *ap = &abuf[0];
    register int i;

    abuf[0] = a0;
    abuf[1] = a1;
    abuf[2] = a2;
    abuf[3] = a3;
    abuf[4] = a4;

    for (p = fmt, i = 0; *p && i < 5;) {
        switch (*p++) {
        case '%':
            for (; *p;) {
                switch (*p++) {
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                case '.':
                case '-':
                    continue;

                case 's':
                        *ap = (jtrc_arg_t) snarf_str((void *) *ap);
                    break;

                default:
                    break;
                }
                break;
            }
            ++ap;
            ++i;
            break;

        default:
            break;
        }
    }

    printf(fmt, abuf[0], abuf[1], abuf[2], abuf[3], abuf[4],
	   "", "", "", "", "", "");
    return (0);
}

/**
 * display_reg_trc_elem()
 */
int display_reg_trc_elem(jtrc_regular_element_t * tp, char *beg_buf,
                         char *end_buf)
{
    register char *p;

    time_t time_stamp_secs;
    struct tm time_stamp_formated;
    char header[256];

    tp->fmt = snarf_str(tp->fmt);
    tp->func_name = snarf_str((void *) tp->func_name);

    time_stamp_secs = tp->tv_sec;

    localtime_r(&time_stamp_secs, &time_stamp_formated);

    snprintf(header, 256,
             "%02d-%02d:%02d:%02d:%02d:%8.08d:%02d:%p:0x%0*lx:%25.25s:%4.4d",
             /* tm_mon is 0-11, add 1 for humans */
             time_stamp_formated.tm_mon + 1,
             time_stamp_formated.tm_mday,
             time_stamp_formated.tm_hour,
             time_stamp_formated.tm_min,
             time_stamp_formated.tm_sec,
             tp->tv_nsec,
             tp->cpu,
             tp->tid,
             ((int) (2 * sizeof(tp->id))),
             (long) tp->id, tp->func_name, tp->line_num);

    printf("%s", header);

    printf(":");
    {
	    int len = strlen(tp->fmt);
	    if (tp->fmt[len-1] == '\n') tp->fmt[len-1] = 0;
    }
    printd(tp->fmt, tp->a0, tp->a1, tp->a2, tp->a3, tp->a4);

    /*
     * Strip any extra "\n"'s in the format strings.
     */
    for (p = tp->fmt; *p; ++p);

    printf("\n");

    return (0);
}

static uint32_t curr_slot;
static uint32_t num_slots;
static jtrc_element_t *ldTbuf;

int display_preformatted_str_begin_trc_elem(jtrc_element_t * tp)
{
    time_t time_stamp_secs;
    struct tm time_stamp_formated;
    char header[256];
    char *string_data = NULL;
    size_t string_length = 0;
    char *end_buf = NULL;

    tp->pfs_begin.func_name = snarf_str((void *) tp->pfs_begin.func_name);

    time_stamp_secs = tp->pfs_begin.tv_sec;

    localtime_r(&time_stamp_secs, &time_stamp_formated);

    snprintf(header, 256,
             "%02d-%02d:%02d:%02d:%02d:%8.08d:%02d:%p:0x%0*lx:%25.25s:%4.4d",
             /* tm_mon is 0-11, add 1 for humans */
             time_stamp_formated.tm_mon + 1,
             time_stamp_formated.tm_mday,
             time_stamp_formated.tm_hour,
             time_stamp_formated.tm_min,
             time_stamp_formated.tm_sec,
             tp->pfs_begin.tv_nsec,
             tp->pfs_begin.cpu,
             tp->pfs_begin.tid,
             ((int) (2 * sizeof(tp->pfs_begin.id))),
             (long) tp->pfs_begin.id, tp->pfs_begin.func_name,
             tp->pfs_begin.line_num);

    string_length = (size_t) tp->pfs_begin.total_length;
    if (verbose) {
        printf("\ntotal_length=%ld\n", string_length);
    }

    /* The string data starts at the data_start location */
    string_data = (char *) &tp->pfs_begin.data_start;

    end_buf = string_data + JTRC_MAX_PREFMT_STR_FOR_BEG_ELEM;
    printf("%s:", header);
    while (string_length > 0) {
        int length2 = 0;
        length2 = printf("%s", string_data);
        if (verbose) {
            printf("\nstring_length=%ld length2=%d curr_slot=%d\n",
                   string_length, length2, curr_slot);
        }

        string_data += length2;
        string_length -= length2;

        /* check for end of element */
        if (string_length && (string_data >= end_buf)) {
            /* Move to next element */
            curr_slot++;
            if (curr_slot >= num_slots) {
                curr_slot = 0;
            }

            tp = &ldTbuf[curr_slot];

            string_data = (char *) &tp->pfs_continue.data_start;
            end_buf = string_data + JTRC_MAX_PREFMT_STR_PER_ELEM;
        }
    }
    printf("\n");

    return (0);
}

void dump_hex_line(char *buf_ptr, int buf_len)
{
    int idx;
    char ch;
    int ebcdic_ch;

    /* Print the hexadecimal values */
    for (idx = 0; idx < DUMP_HEX_BYTES_PER_LINE; idx++) {
        if (idx < buf_len) {
            printf("%02x ", ((int) buf_ptr[idx]) & 0xff);
        } else {
            printf("   ");
        }
    }
    printf("  ");
    /* Translate and print hex to ASCII values */
    for (idx = 0; idx < DUMP_HEX_BYTES_PER_LINE; idx++) {
        if (idx < buf_len) {
            ch = buf_ptr[idx];
            if ((ch < 0x20) || (ch > 0x7e)) {
                printf(".");
            } else {
                printf("%c", buf_ptr[idx]);
            }
        }
    }
}

int display_hex_begin_trc_elem(jtrc_element_t * tp)
{
    time_t time_stamp_secs;
    struct tm time_stamp_formated;
    char *binary_data = NULL;
    size_t binary_length = 0;
    char header[256];
    char *end_buf;

    tp->hex_begin.func_name = snarf_str((void *) tp->hex_begin.func_name);
    tp->hex_begin.msg = snarf_str((void *) tp->hex_begin.msg);

    time_stamp_secs = tp->hex_begin.tv_sec;

    localtime_r(&time_stamp_secs, &time_stamp_formated);

    snprintf(header, 256,
             "%02d-%02d:%02d:%02d:%02d:%8.08d:%02d:%p:0x%0*lx:%25.25s:%4.4d:hex: %s len %x",
             /* tm_mon is 0-11, add 1 for humans */
             time_stamp_formated.tm_mon + 1,
             time_stamp_formated.tm_mday,
             time_stamp_formated.tm_hour,
             time_stamp_formated.tm_min,
             time_stamp_formated.tm_sec,
             tp->hex_begin.tv_nsec,
             tp->hex_begin.cpu,
             tp->hex_begin.tid,
             ((int) (2 * sizeof(tp->hex_begin.id))),
             (long) tp->hex_begin.id, tp->hex_begin.func_name,
             tp->hex_begin.line_num, tp->hex_begin.msg,
             tp->hex_begin.total_length);

    printf("%s", header);
    printf("\n");

    int idx = 0;
    binary_length = (size_t) tp->hex_begin.total_length;

    /* The binary data starts at the data_start location */
    binary_data = (char *) &tp->hex_begin.data_start;

    printf("%s:        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f   "
	   "-----ASCII------"
	   "\n",
	   header);

    end_buf = binary_data + JTRC_MAX_HEX_DATA_FOR_BEG_ELEM;
    char line_buf[DUMP_HEX_BYTES_PER_LINE];
    /* Dump in increments of hex line size */
    while (binary_length > 0) {
        int i = 0;
        int length2 = MIN(binary_length, DUMP_HEX_BYTES_PER_LINE);
        printf("%s:%04x:  ", header, idx);

        binary_length -= length2;

        /*
         * The binary hex information is not contiguous, so
         * copy into a temporary buffer of DUMP_HEX_BYTES_PER_LINE size
         */
        for (i = 0; i < length2; i++) {
            line_buf[i] = *binary_data;
            binary_data++;
            /* check for end of element */
            if (binary_length && (binary_data >= end_buf)) {
                /* Move to next element */

                curr_slot++;
                if (curr_slot >= num_slots) {
                    curr_slot = 0;
                }

                tp = &ldTbuf[curr_slot];

                binary_data = (char *) &tp->hex.data_start;
                end_buf = binary_data + JTRC_MAX_HEX_DATA_PER_ELEM;
            }
        }
        dump_hex_line(line_buf, length2);
        printf("\n");
        idx += length2;
    }

    return (0);
}

/**
 * print_trace()
 *
 * Expand and print entries from the trace buffer
 *
 * @cb - The control block for the jtrace instance of interest
 * @dump_mask - Mask to select which entries should be printed
 */
int print_trace(jtrc_cb_t * cb, uint32_t dump_mask)
{
	size_t ldTbufSz;
	uint32_t slot_idx, mark_slot;
	jtrc_element_t *tp;
	char *beg_buf = NULL;
	char *end_buf = NULL;
	void *p = NULL;
	uint32_t zero_slots = 0;

	if (!cb) {
		printf("ERROR:%s: trace_info is NULL\n", __FUNCTION__);
		return (-1);
	}

	/* TODO: handle core files and kernel crash dumps */

	if (verbose) {
		printf("jtrc_info.jtrc_buf_size=0x%x,"
		       " jtrc_info.jtrc_buf_index=0x%x\n",
		       cb->jtrc_buf_size,
		       cb->jtrc_buf_index);

		printf("cb->ldTbuf=%p, cb->ldTbufSz=0x%x, "
		       "cb->slotidx=0x%x "
		       "cb->num_slots=0x%x\n",
		       cb->jtrc_buf,
		       cb->jtrc_buf_size,
		       cb->jtrc_buf_index,
		       cb->jtrc_num_entries);
	}

	ldTbufSz = cb->jtrc_buf_size;
	slot_idx = cb->jtrc_buf_index;

	p = malloc(ldTbufSz);
	ldTbuf = (jtrc_element_t *) p;

	if (ldTbuf == NULL) {
		printf("malloc failed");
		return 1;
	}

	snarf(cb->jtrc_buf, (void *) ldTbuf, ldTbufSz);

	if (verbose) {
		printf("ldTbuf = %p, ldTbufSz=%lx slot_idx=0x%x\n",
		       ldTbuf, (long) ldTbufSz, slot_idx);
		printf("sizeof(jtrc_arg_t)=%ld\n",
		       (long) sizeof(jtrc_arg_t));
		printf("sizeof(jtrc_element_t)=%ld\n",
		       (long) sizeof(jtrc_element_t));
	}

	num_slots = cb->jtrc_num_entries;
	beg_buf = (char *) ldTbuf;
	end_buf = beg_buf + ldTbufSz;

	curr_slot = slot_idx % num_slots;

	/*
	 * Loop through the trace buffer and print each entry
	 */
	for (mark_slot = curr_slot; ++curr_slot != mark_slot;) {
		if (curr_slot >= num_slots) {
			curr_slot = -1;
			continue;
		}

		tp = &ldTbuf[curr_slot];

		if (verbose) {
			printf("num_slots=0x%x mark_slot=0x%x, curr_slot=0x%x, "
			       "elem_fmt=%d zero_slots=0x%x\n",
			       num_slots, mark_slot, curr_slot,
			       tp->elem_fmt, zero_slots);
		}

		if (tp->flag & dump_mask)
		switch (tp->elem_fmt) {
		case JTRC_FORMAT_REGULAR:
			if (tp->reg.fmt == 0) {
				continue;
			}
			printf("%03x ", tp->flag);
			display_reg_trc_elem(&tp->reg, beg_buf, end_buf);
			zero_slots = 0;
			break;

			/* This dumps hex data slots until JTRC_HEX_DATA_END */
		case JTRC_HEX_DATA_BEGIN:
			display_hex_begin_trc_elem(tp);
			zero_slots = 0;
			break;

			/*
			 * If we hit these here, we've lost the BEGIN
			 * slot context, so just skip
			 */
		case JTRC_HEX_DATA_CONTINUE:
		case JTRC_HEX_DATA_END:
			zero_slots = 0;
			break;

		case JTRC_PREFORMATTED_STR_BEGIN:
			display_preformatted_str_begin_trc_elem(tp);
			zero_slots = 0;
			break;

			/*
			 * If we hit these here, we've lost the BEGIN slot
			 * context, so just skip
			 */
		case JTRC_PREFORMATTED_STR_CONTINUE:
		case JTRC_PREFORMATTED_STR_END:
			zero_slots = 0;
			break;

		default:
			zero_slots++;
			break;
		}
		/*
		 * The slot may have been incremented by
		 * display_hex_begin_trc_elem() or
		 * display_preformatted_str_begin_trc_elem().
		 * If so and now equal to marked slot, we are done.
		 */
		if (curr_slot == mark_slot) {
			break;
		}
	}

	printf("\n");
	return (0);
}


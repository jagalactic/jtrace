/*
 * 
 */
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

#include "k_trc.h"
//#include "../jtrace/j_trc_mod.h"

char *namel = "/stand/vmunix";
/*
 * Access to /dev/kmem is broken in 2.6
 * Just have jtrace copyout the info we need.
 * Yep, its slower.
 */
char *coref = "/dev/kmem";
int verbose = 0;                /* flag: verbose or not    */
int kfd = -1;                   /* kernel memory fd    */
int isDumpFile = 0;
char *trc_buf_name = NULL;

char *snarf_str(void *addr);
int debugLvl = 0;
char k_trc_dev[] = JTRACE_DEV_SPECIAL_FILE;
int kutil_dev_fd = -1;

void *all_trc_info = NULL;
int k_trc_num_common_flags = 0;
k_trc_flag_descriptor_t *k_trc_common_flag_array = 0;
int k_trc_num_registered_mods = 0;
k_trc_module_trc_info_t *k_trc_first_trace_infop = NULL;
k_trc_module_trc_info_t *k_trc_trace_infop = NULL;

int display_reg_trc_elem(k_trc_regular_element_t * tp, char *beg_buf,
                         char *end_buf);
int printd(char *fmt, k_trc_arg_t a0, k_trc_arg_t a1, k_trc_arg_t a2,
           k_trc_arg_t a3, k_trc_arg_t a4);

int display_hex_begin_trc_elem(k_trc_element_t * tp);
int display_preformatted_str_begin_trc_elem(k_trc_element_t * tp);

int show_trc_flags(uint32_t trc_flags);
int dump_trace(k_trc_module_trc_info_t * trace_infop);
int set_printk_value(char *buf_name, int value);

int snarf_no_kmem(void *addr, void *buf, size_t len);

#define MIN(a,b) (((a)<(b))?(a):(b))
#define DUMP_HEX_BYTES_PER_LINE 16
void dump_hex_line(char *buf_ptr, int buf_len);

void usage(rc)
{

    fprintf(rc ? stderr : stdout,
            "usage: jtrace -n <trc_buf_name> <options>\n"
            "\n    Display trace information:\n"
            "    -n <trc_buf_name>   trace buffer name\n"
            "    [-v]        verbose\n"
            /* XXX maybe once on 2.6 kernel.. "    [-d dumpfile] pull out of dumpfile, not memory\n" */
            "\n    Trace flag control (requires -n first):\n"
            "    [-h trace_flags]  trace flags absolute, hex value\n"
            "    [-f trace_flag_strs] trace flags absolute, string values\n"
            "    [-s trace_flag_strs] set a trace flag(s) (logical or)\n"
            "    [-u trace_flag_strs] unset a trace flag(s) (logical nand)\n"
            "    [-g ] Show currently set trace flags\n"
            "\n    Output Trace to console (requires -n first):\n"
            "    [-p <0|1> ] Set printk value (1=print to console enabled) \n"
            "\n    Clear Trace buffer (requires -n first):\n"
            "    [-c]        clear the trace buffer\n"
            "\n    ACPI/Config helpers :\n"
            "    [-A]        Dump ACPI info to k_trc_default.\n"
            "    [-L]        Dump physical location info to k_trc_default.\n");

    printf("\nValid trace flags:\n\n");
    show_trc_flags(0xffffffff);

    printf("num_common_flags=%d\n", k_trc_num_common_flags);

    exit(rc);
}

void snarf(void *addr, void *buf, size_t len)
{
    size_t cc = 0;

#if APP_KREL >= 26
    /* 
     * Access to /dev/kmem is broken in 2.6 
     * Just have jtrace copyout the info we need.
     * Yep, its slower.
     */
    cc = snarf_no_kmem(addr, buf, len);
    if (cc) {
        printf("snarf: read failed at %p, len %lx rc=%ld\n", addr,
               (long) len, (long) cc);
    }
#else
    if (isDumpFile) {
#ifdef LATER
        cc = osDumpRead(addr, buf, len);
#endif
        if (cc != len) {
            printf("snarf: short read at %p, len %lx cc %lx\n", addr,
                   (long) len, (long) cc);
        }
    } else {
        off_t offset;
        /* reading from memory */
        offset = lseek(kfd, (off_t) addr, SEEK_SET);
        if (offset == -1) {
            /* 
             * TODO: On the IA64 RHE1, this keeps returning -1 even though the
             * data looks sane. Just comment out for now. 
             */
            /* printf("snarf: lseek(%p) offset=%p errno=%d sizeof(offset)=%d\n", 
               addr, offset, errno, sizeof(offset)); */
        }
        cc = read(kfd, buf, len);
        if (cc != len) {
            printf("snarf: short read at %p, len %lx cc %lx\n", addr,
                   (long) len, (long) cc);
        }
    }
#endif
}

struct CacheStats {
    int hits;
    int misses;
    int fastHits;
} cStats;

char *snarf_str(void *addr)
{
    static struct StrCache {
        void *addr;
        char str[128];
        uint lru;
    } cache[512], *last, *hiwat = &cache[0];
    static uint lru;
    struct StrCache *ent, *old;

    if (last && last->addr == addr) {
        ++cStats.fastHits;

        return last->str;
    }

    for (old = ent = cache; ent < hiwat; ++ent) {
        if (ent->addr == addr) {
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

    ent->addr = addr;
    ent->lru = ++lru;

    snarf(addr, ent->str, (size_t) sizeof(ent->str));

    ent->str[sizeof(ent->str) - 1] = 0;

    ++cStats.misses;

    return (last = ent)->str;
}


void setup(char *namelist, char *corefile, int flag)
{
#if APP_KREL < 26
    /* /dev/kmem currently broken in 2.6, just skip */
    kfd = open(corefile, flag);

    if (kfd < 0) {
        printf("Corefile open error, %s, errno=%d\n", corefile, errno);
    }
#endif
    return;
}


int clear_trace_buf(char *buf_name)
{
    k_trc_cmd_req_t cmd_req;

    bzero(&cmd_req, sizeof(k_trc_cmd_req_t));

    strncpy(cmd_req.trc_name, buf_name, sizeof(cmd_req.trc_name));

    cmd_req.cmd = KTRCTL_CLEAR;
    if (ioctl(kutil_dev_fd, K_TRC_CMD_IOCTL, &cmd_req)) {
        printf("Failed describe errno=%d\n", errno);
        return 1;
    }

    return (0);
}

int snarf_no_kmem(void *addr, void *buf, size_t len)
{
    k_trc_cmd_req_t cmd_req;

    cmd_req.snarf_addr = addr;
    cmd_req.data = buf;
    cmd_req.data_size = len;

    cmd_req.cmd = KTRCTL_SNARF;
    if (ioctl(kutil_dev_fd, K_TRC_CMD_IOCTL, &cmd_req)) {
        printf("Failed describe errno=%d\n", errno);
        return 1;
    }

    return (0);
}

int set_trc_flags(char *buf_name, int trc_flags)
{
    int rc = 0;
    k_trc_cmd_req_t cmd_req;

    bzero(&cmd_req, sizeof(k_trc_cmd_req_t));
    strncpy(cmd_req.trc_name, buf_name, sizeof(cmd_req.trc_name));

    cmd_req.cmd = KTRCTL_SET_TRC_FLAGS;
    cmd_req.data = &trc_flags;
    rc = ioctl(kutil_dev_fd, K_TRC_CMD_IOCTL, &cmd_req);
    if (rc) {
        printf("ioctl KTRCTL_SET_TRC_FLAGS failed, rc=%d errno=%d\n",
               rc, errno);
        return (rc);
    }

    return (0);
}

int set_printk_value(char *buf_name, int value)
{
	int rc = 0;
	k_trc_cmd_req_t cmd_req;

	bzero(&cmd_req, sizeof(k_trc_cmd_req_t));

	strncpy(cmd_req.trc_name, buf_name, sizeof(cmd_req.trc_name));

	cmd_req.cmd = KTRCTL_SET_PRINTK;
	cmd_req.data = &value;
	rc = ioctl(kutil_dev_fd, K_TRC_CMD_IOCTL, &cmd_req);
	if (rc) {
		printf("ioctl KTRCTL_SET_PRINTK failed, rc=%d errno=%d\n",
		       rc, errno);
		return (rc);
	}
	
	return (0);
}

int display_all_ACPI_info(void)
{
	int rc = 0;

	rc = ioctl(kutil_dev_fd, K_UTIL_ACPI_DUMP, 0);
	if (rc) {
		printf("ioctl K_UTIL_ACPI_DUMP failed, rc=%d errno=%d\n",
		       rc, errno);
		return (errno);
	}

	return (0);
}

int display_all_physloc_info(void)
{
	int rc = 0;

	rc = ioctl(kutil_dev_fd, K_UTIL_PHYSLOC_DUMP, 0);
	if (rc) {
		printf("ioctl K_UTIL_PHYSLOC_DUMP failed, rc=%d errno=%d\n",
		       rc, errno);
		return (errno);
	}

	return (0);
}

/*
 * Get all trace info. If trc_buf_name supplied,
 * set pointer to trace buffer with trc_buf_name
 */
int get_all_trc_info(char *trc_buf_name)
{
	k_trc_module_trc_info_t *trace_infop = NULL;
	k_trc_cmd_req_t cmd_req;
	int i = 0;
	char *out_bufp = 0;
	int rc = 0;

	bzero(&cmd_req, sizeof(k_trc_cmd_req_t));

	cmd_req.cmd = KTRCTL_GET_ALL_TRC_INFO;
	cmd_req.data = 0;
	cmd_req.data_size = 0;

	/* Call once with zero to get required size */
	rc = ioctl(kutil_dev_fd, K_TRC_CMD_IOCTL, &cmd_req);
	if (rc && (errno != ENOMEM)) {
		printf("Failed describe errno=%d\n", errno);
		return (rc);
	}
	if (verbose) {
		printf("required_size=%d\n", cmd_req.data_size);
	}
	all_trc_info = malloc(cmd_req.data_size);
	if (!all_trc_info) {
		printf("malloc() failed\n");
		return (-1);
		
	}

	cmd_req.data = all_trc_info;
	rc = ioctl(kutil_dev_fd, K_TRC_CMD_IOCTL, &cmd_req);
	if (rc) {
		printf("Failed describe errno=%d\n", errno);
		return (rc);
	}
	/* Number of common Flags */
	out_bufp = all_trc_info;
	memcpy(&k_trc_num_common_flags, out_bufp,
	       sizeof(k_trc_num_common_flags));
	out_bufp += sizeof(k_trc_num_common_flags);

	/* Array of common flag descriptors */
	k_trc_common_flag_array = (k_trc_flag_descriptor_t *) out_bufp;
	out_bufp += (k_trc_num_common_flags * sizeof(k_trc_flag_descriptor_t));

	/* Number of registered modules */
	memcpy(&k_trc_num_registered_mods, out_bufp,
	       sizeof(k_trc_num_registered_mods));
	out_bufp += sizeof(k_trc_num_registered_mods);

	if (verbose) {
		printf("k_trc_num_common_flags=%d "
		       "k_trc_num_registered_mods=%d\n",
		       k_trc_num_common_flags, k_trc_num_registered_mods);
	}
	
	/* Array of registered modules, each followed
	 * by optional custom flags */
	if (k_trc_num_registered_mods) {
		k_trc_first_trace_infop = (k_trc_module_trc_info_t *) out_bufp;
		trace_infop = k_trc_first_trace_infop;
	}
	
	/* If trc_buf_name supplied, find that trace module information */
	if (trc_buf_name) {
		for (i = 0; i < k_trc_num_registered_mods; i++) {
			if (strcmp(trace_infop->k_trc_name,
				   trc_buf_name) == 0) {
				/* Found a match */
				k_trc_trace_infop = trace_infop;
				break;
			}
			/* Get next trace information */
			out_bufp = (char *) trace_infop;
			/* Skip past this trace information */
			out_bufp += sizeof(k_trc_module_trc_info_t);
			/* Also, skip past any custom flag descriptions */
			out_bufp +=
				(trace_infop->k_trc_num_custom_flags *
				 sizeof(k_trc_flag_descriptor_t));
			trace_infop = (k_trc_module_trc_info_t *) out_bufp;
		}
	}
	
	return (rc);
}


int show_trc_flags(uint32_t trc_flags)
{
    int i = 0;
    int j = 0;
    char *ptr = NULL;
    k_trc_flag_descriptor_t *flag_descp = NULL;
    k_trc_module_trc_info_t *trace_infop = NULL;

    printf("\nCommon trace flags:\n");
    for (i = 0; i < k_trc_num_common_flags; i++) {
        flag_descp = &k_trc_common_flag_array[i];
        if ((KTR_COMMON_FLAG(i)) & trc_flags) {
            printf("%12s (0x%08x) - %s\n",
                   flag_descp->k_trc_flag_cmd_line_name,
                   KTR_COMMON_FLAG(i), flag_descp->k_trc_flag_description);
        }
    }

    /* Specific trace module requested */
    if (k_trc_trace_infop) {
        if (k_trc_trace_infop->k_trc_num_custom_flags) {
            printf("\nCustom trace flags for module %s:\n",
                   k_trc_trace_infop->k_trc_name);
            /* Custom flags start after the module trc info */
            ptr = (char *) k_trc_trace_infop;
            ptr += sizeof(k_trc_module_trc_info_t);
            flag_descp = (k_trc_flag_descriptor_t *) ptr;
            for (i = 0; i < (k_trc_trace_infop->k_trc_num_custom_flags);
                 i++) {
                if ((KTR_CUSTOM_FLAG(i)) & trc_flags) {
                    printf("%12s (0x%08x) - %s\n",
                           flag_descp->k_trc_flag_cmd_line_name,
                           KTR_CUSTOM_FLAG(i),
                           flag_descp->k_trc_flag_description);
                }
                flag_descp++;
            }
        } else {
            printf("\nNo custom trace flags for module %s:\n",
                   k_trc_trace_infop->k_trc_name);
        }
        printf("\n\n");
        return (0);
    }

    trace_infop = k_trc_first_trace_infop;
    if (!trace_infop) {
        /* No registered trace modules */
        printf("\n\n");
        return (0);
    }

    /*
     * No specific trace module requested. 
     * Check all registered modules 
     */
    for (i = 0; i < k_trc_num_registered_mods; i++) {

        if (trace_infop->k_trc_num_custom_flags) {
            printf("\nCustom trace flags for module %s:\n",
                   trace_infop->k_trc_name);

            /* Custom flags start after the module trc info */
            ptr = (char *) trace_infop;
            ptr += sizeof(k_trc_module_trc_info_t);
            flag_descp = (k_trc_flag_descriptor_t *) ptr;
            for (j = 0; j < (trace_infop->k_trc_num_custom_flags); j++) {
                if ((KTR_CUSTOM_FLAG(j)) & trc_flags) {
                    printf("%12s (0x%08x) - %s\n",
                           flag_descp->k_trc_flag_cmd_line_name,
                           KTR_CUSTOM_FLAG(j),
                           flag_descp->k_trc_flag_description);
                }
                flag_descp++;
            }
        } else {
            printf("\nNo custom trace flags for module %s:\n",
                   trace_infop->k_trc_name);
        }

        /* Get next trace information */
        ptr = (char *) trace_infop;
        /* Skip past this trace information */
        ptr += sizeof(k_trc_module_trc_info_t);
        /* Also, skip past any custom flag descriptions */
        ptr +=
            (trace_infop->k_trc_num_custom_flags *
             sizeof(k_trc_flag_descriptor_t));
        trace_infop = (k_trc_module_trc_info_t *) ptr;
    }

    printf("\n\n");
    return (0);
}

int flag_str_to_flag(char *trc_flag_str, int *trc_flag)
{
    int i = 0;
    char *ptr = NULL;
    k_trc_flag_descriptor_t *flag_descp = NULL;

    for (i = 0; i < k_trc_num_common_flags; i++) {
        flag_descp = &k_trc_common_flag_array[i];
        if (strcmp(flag_descp->k_trc_flag_cmd_line_name, trc_flag_str) ==
            0) {
            /* Found a match */
            *trc_flag = KTR_COMMON_FLAG(i);
            return (0);
        }
    }

    if (k_trc_trace_infop && k_trc_trace_infop->k_trc_num_custom_flags) {
        if (verbose) {
            printf("Checking custom flags for %s\n",
                   k_trc_trace_infop->k_trc_name);

        }
        /* Custom flags start after the module trc info */
        ptr = (char *) k_trc_trace_infop;
        ptr += sizeof(k_trc_module_trc_info_t);
        flag_descp = (k_trc_flag_descriptor_t *) ptr;
        for (i = 0; i < (k_trc_trace_infop->k_trc_num_custom_flags); i++) {

            if (strcmp(flag_descp->k_trc_flag_cmd_line_name, trc_flag_str)
                == 0) {
                /* Found a match */
                *trc_flag = KTR_CUSTOM_FLAG(i);
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

	trace = 0;

	kutil_dev_fd = open(k_trc_dev, O_RDWR);
	if (kutil_dev_fd < 0) {
		printf("Device open failed %d\n", errno);
		exit(-1);
	}

	while ((ch = getopt(argc, argv, "?ZvALgh:cd:f:s:u:p:n:")) != EOF) {
		switch (ch) {
		case 'A':
			rc = display_all_ACPI_info();
			if (rc) {
				printf("ERROR, display_all_ACPI_info() "
				       "rc=%d\n", rc);
			} else {
				printf("Dumped all ACPI info to default "
				       "trace buffer\n");
			}
			goto k_trc_util_exit;
			
		case 'L':
			rc = display_all_physloc_info();
			if (rc) {
				printf("ERROR, display_all_physloc_info() "
				       "rc=%d\n", rc);
			} else {
				printf("Dumped all physloc info to "
				       "default trace buffer\n");
			}
			goto k_trc_util_exit;


		case 'Z':              /* undocumented -Zdebug option    */
			++debugLvl;
			break;
			
		case 'v':
			++verbose;
			
			break;
			
		case 'p':
			if (!n_flag) {
				printf(TRC_BUF_NAME_REQUIRED);
				usage(rc);
				rc = -1;
				goto k_trc_util_exit;
			}
			
			printk_value = strtol(optarg, NULL, 16);
			rc = set_printk_value(trc_buf_name, printk_value);
			if (rc) {
				printf("Could not set trace flags to 0x%x\n",
				       trc_flags);
				rc = -1;
				goto k_trc_util_exit;
			}
			printf("\nPrintk set to (%d):\n\n", printk_value);
			rc = 0;
			goto k_trc_util_exit;
			break;
			
		case 'n':
			n_flag++;
			if (!trc_buf_name) {
				trc_buf_name = optarg;
			} else {
				usage(1);
				rc = -1;
				goto k_trc_util_exit;
				
			}
			printf("\ntrc_buf_name=%s\n", trc_buf_name);
			/* get trace_info from running kernel */
			rc = get_all_trc_info(trc_buf_name);
			if (rc) {
				printf("get_trc_info failed errno=%d\n", rc);
				goto k_trc_util_exit;
			}
			break;


		case 'h':
			if (!n_flag) {
				printf(TRC_BUF_NAME_REQUIRED);
				usage(rc);
				rc = -1;
				goto k_trc_util_exit;
			}

			trc_flags = strtol(optarg, NULL, 16);
			rc = set_trc_flags(trc_buf_name, trc_flags);
			if (rc) {
				printf("Could not set trace flags to 0x%x\n",
				       trc_flags);
				rc = -1;
				goto k_trc_util_exit;
			}
			printf("\nTrace flags set to (0x%08x):\n\n",
			       trc_flags);
			show_trc_flags(trc_flags);
			rc = 0;
			goto k_trc_util_exit;
			
			break;
			
		case 'g':
			if (!n_flag) {
				printf(TRC_BUF_NAME_REQUIRED);
				usage(rc);
				rc = -1;
				goto k_trc_util_exit;
			}
			
			printf("\nCurrent set trace flags(0x%08x) for %s:\n\n",
			       k_trc_trace_infop->k_trc_flags,
			       k_trc_trace_infop->k_trc_name);
			show_trc_flags(k_trc_trace_infop->k_trc_flags);
			rc = 0;
			goto k_trc_util_exit;
			
		case 'f':
			if (!n_flag) {
				printf(TRC_BUF_NAME_REQUIRED);
				usage(rc);
				rc = -1;
				goto k_trc_util_exit;
			}
			
			trc_flags = 0;
			/* Get first flag string */
			rc = flag_str_to_flag(optarg, &trc_flag);
			if (rc) {
				printf("Invalid flag %s\n", optarg);
				usage(rc);
				rc = -1;
				goto k_trc_util_exit;
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
					goto k_trc_util_exit;
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
				goto k_trc_util_exit;
			}
			printf("\nTrace flags set to (0x%08x):\n\n",
			       trc_flags);
			show_trc_flags(trc_flags);
			rc = 0;
			goto k_trc_util_exit;
			
		case 's':
			if (!n_flag) {
				printf(TRC_BUF_NAME_REQUIRED);
				usage(rc);
				rc = -1;
				goto k_trc_util_exit;
			}
			
			trc_flags = k_trc_trace_infop->k_trc_flags;
			
			/* Get first flag string */
			rc = flag_str_to_flag(optarg, &trc_flag);
			if (rc) {
				printf("Invalid flag %s\n", optarg);
				usage(rc);
				rc = -1;
				goto k_trc_util_exit;
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
					goto k_trc_util_exit;
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
				goto k_trc_util_exit;
			}
			printf("\nCurrent set trace flags (0x%08x):\n\n",
			       trc_flags);
			show_trc_flags(trc_flags);
			rc = 0;
			goto k_trc_util_exit;
			
		case 'u':
			
			if (!n_flag) {
				printf(TRC_BUF_NAME_REQUIRED);
				usage(rc);
				rc = -1;
				goto k_trc_util_exit;
			}
			
			trc_flags = k_trc_trace_infop->k_trc_flags;
			
			/* Get first flag string */
			rc = flag_str_to_flag(optarg, &trc_flag);
			if (rc) {
				printf("Invalid flag %s\n", optarg);
				usage(rc);
				rc = -1;
				goto k_trc_util_exit;
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
					goto k_trc_util_exit;
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
				goto k_trc_util_exit;
			}
			printf("\nCurrent set trace flags (0x%08x):\n\n",
			       trc_flags);

			show_trc_flags(trc_flags);
			rc = -1;
			goto k_trc_util_exit;
			break;
			
#if 0
			/* XXX maybe in 2.6 kernel linux will support
			 * kernel dumps. */
		case 'd':
			coref = optarg;
			++isDumpFile;
			setup(namel, coref, O_RDONLY);
			dump_trace(k_trc_trace_infop);
			/* XXX not yet supported */
			rc = -1;
			goto k_trc_util_exit;
#endif
			
		case 'c':
			if (!n_flag) {
				printf(TRC_BUF_NAME_REQUIRED);
				usage(rc);
				rc = -1;
				goto k_trc_util_exit;
			}
			clear_trace_buf(trc_buf_name);
			printf("Trace buffer cleared\n");
			rc = 0;
			goto k_trc_util_exit;
			
		case '?':
			/* Try to get all info for flag information */
			get_all_trc_info(trc_buf_name);
			usage(0);
			rc = 0;
			goto k_trc_util_exit;
			
		default:
			usage(1);
		}
	}

	if (!k_trc_trace_infop) {
		printf("Error: Could not find trc_buf_name=%s\n",
		       trc_buf_name);
		/* Try to get all info for module and flag information */
		get_all_trc_info(trc_buf_name);
		usage(1);
		rc = -1;
		goto k_trc_util_exit;
	}
	
	if (optind < argc) {
		namel = argv[optind++];
	}
	if (optind < argc) {
		coref = argv[optind++];
	}
	
	setup(namel, coref, O_RDONLY);
	
	dump_trace(k_trc_trace_infop);
	
	if (verbose) {
		printf("cache stats: fastHits %d hits %d misses %d\n",
		       cStats.fastHits, cStats.hits, cStats.misses);
	}

k_trc_util_exit:
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

static uint32_t slot;
static uint32_t num_slots;
static k_trc_element_t *ldTbuf;

static int was_nl;

int dump_trace(k_trc_module_trc_info_t * trace_infop)
{
	size_t ldTbufSz;
	uint32_t slot_idx, mark_slot;
	k_trc_element_t *tp;
	char *beg_buf = NULL;
	char *end_buf = NULL;
	void *p = NULL;
	uint32_t zero_slots = 0;

	if (!trace_infop) {
		printf("ERROR:%s: trace_info is NULL\n", __FUNCTION__);
		return (-1);
	}
#if 0
	if (isDumpFile) {
#ifdef J_LATER
		osDumpInit(coref, &trace_info_addr);
		/* get trace_info from dump file */
		snarf(trace_info_addr, &trace_info, sizeof(k_trc_info));
#endif
	} else {
		strncpy(trace_info.k_trc_name, buf_name,
			sizeof(trace_info.k_trc_name));

#if 0
		/* get trace_info from running kernel */
		rc = get_trc_info(&trace_info);
		if (rc) {
			printf("get_trc_info failed errno=%d\n", rc);
			return 1;
		}
#endif
	}
#endif

	if (verbose) {
		printf("k_trc_info.k_trc_buf_size=0x%x,"
		       " k_trc_info.k_trc_buf_index=0x%x\n",
		       trace_infop->k_trc_buf_size,
		       trace_infop->k_trc_buf_index);
	}
	
	ldTbufSz = trace_infop->k_trc_buf_size;
	slot_idx = trace_infop->k_trc_buf_index;

	if (verbose) {
		printf("trace_infop->ldTbuf=%p, trace_infop->ldTbufSz=0x%x, "
		       "trace_infop->slotidx=0x%x "
		       "trace_infop->num_slots=0x%x\n",
		       trace_infop->k_trc_buf_ptr,
		       trace_infop->k_trc_buf_size,
		       trace_infop->k_trc_buf_index,
		       trace_infop->k_trc_num_entries);
	}

	p = malloc(ldTbufSz);
	ldTbuf = (k_trc_element_t *) p;

	if (ldTbuf == NULL) {
		printf("malloc failed");
		return 1;
	}

	snarf(trace_infop->k_trc_buf_ptr, (void *) ldTbuf, ldTbufSz);

	if (verbose) {
		printf("ldTbuf = %p, ldTbufSz=%lx slot_idx=0x%x\n",
		       ldTbuf, (long) ldTbufSz, slot_idx);
		printf("sizeof(k_trc_arg_t)=%ld\n",
		       (long) sizeof(k_trc_arg_t));
		printf("sizeof(k_trc_element_t)=%ld\n",
		       (long) sizeof(k_trc_element_t));
	}

	num_slots = trace_infop->k_trc_num_entries;
	beg_buf = (char *) ldTbuf;
	end_buf = beg_buf + ldTbufSz;

	was_nl = 0;
	slot = slot_idx % num_slots;

	for (mark_slot = slot; ++slot != mark_slot;) {
		if (slot >= num_slots) {
			slot = -1;
			continue;
		}

		tp = &ldTbuf[slot];

		if (verbose) {
			printf("num_slots=0x%x mark_slot=0x%x, slot=0x%x, "
			       "elem_fmt=%d zero_slots=0x%x\n",
			       num_slots, mark_slot, slot,
			       tp->elem_fmt, zero_slots);
			
		}

		switch (tp->elem_fmt) {
		case KTRC_FORMAT_REGULAR:
			
			if (tp->reg.fmt == 0) {
				continue;
			}
			display_reg_trc_elem(&tp->reg, beg_buf, end_buf);
			zero_slots = 0;
			break;
			
			/* This dumps hex data slots until KTRC_HEX_DATA_END */
		case KTRC_HEX_DATA_BEGIN:
			display_hex_begin_trc_elem(tp);
			zero_slots = 0;
			break;
			
			/*  
			 * If we hit these here, we've lost the BEGIN
			 * slot context, so just skip 
			 */
		case KTRC_HEX_DATA_CONTINUE:
		case KTRC_HEX_DATA_END:
			zero_slots = 0;
			break;
			
		case KTRC_PREFORMATTED_STR_BEGIN:
			display_preformatted_str_begin_trc_elem(tp);
			zero_slots = 0;
			break;
			
			/*
			 * If we hit these here, we've lost the BEGIN slot
			 * context, so just skip
			 */
		case KTRC_PREFORMATTED_STR_CONTINUE:
		case KTRC_PREFORMATTED_STR_END:
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
		if (slot == mark_slot) {
			break;
		}
	}
	
	printf("\n");
	return (0);
}

int display_reg_trc_elem(k_trc_regular_element_t * tp, char *beg_buf,
                         char *end_buf)
{
    register char *p;

    time_t time_stamp_secs;
    struct tm time_stamp_formated;
    char header[256];


    if (debugLvl) {
        printf("fmt addr=%p\n", tp->fmt);
    }

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
    printd(tp->fmt, tp->a0, tp->a1, tp->a2, tp->a3, tp->a4);

    /*
     * Strip any extra "\n"'s in the format strings.
     */
    for (p = tp->fmt; *p; ++p);

    was_nl = (p[-1] == '\n');

    printf("\n");

    return (0);
}

int display_preformatted_str_begin_trc_elem(k_trc_element_t * tp)
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

    end_buf = string_data + K_TRC_MAX_PREFMT_STR_FOR_BEG_ELEM;
    printf("%s:", header);
    while (string_length > 0) {
        int length2 = 0;
        length2 = printf("%s", string_data);
        if (verbose) {
            printf("\nstring_length=%ld length2=%d slot=%d\n",
                   string_length, length2, slot);
        }

        string_data += length2;
        string_length -= length2;

        /* check for end of element */
        if (string_length && (string_data >= end_buf)) {
            /* Move to next element */
            slot++;
            if (slot >= num_slots) {
                slot = 0;
            }

            tp = &ldTbuf[slot];

            string_data = (char *) &tp->pfs_continue.data_start;
            end_buf = string_data + K_TRC_MAX_PREFMT_STR_PER_ELEM;
        }
    }
    printf("\n");

    return (0);
}


int display_hex_begin_trc_elem(k_trc_element_t * tp)
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

    printf
        ("%s:        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f   -----ASCII------   -----EBCDIC-----\n",
         header);

    end_buf = binary_data + K_TRC_MAX_HEX_DATA_FOR_BEG_ELEM;
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

                slot++;
                if (slot >= num_slots) {
                    slot = 0;
                }

                tp = &ldTbuf[slot];

                binary_data = (char *) &tp->hex.data_start;
                end_buf = binary_data + K_TRC_MAX_HEX_DATA_PER_ELEM;
            }
        }
        dump_hex_line(line_buf, length2);
        printf("\n");
        idx += length2;
    }

    return (0);
}

int
printd(char *fmt, k_trc_arg_t a0, k_trc_arg_t a1, k_trc_arg_t a2,
       k_trc_arg_t a3, k_trc_arg_t a4)
{
    k_trc_arg_t abuf[5];
    register char *p;
    k_trc_arg_t *ap = &abuf[0];
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
                    if (!debugLvl) {
                        *ap = (k_trc_arg_t) snarf_str((void *) *ap);
                    }
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

    if (debugLvl) {
        printf("'%s' %p %p %p %p %p", fmt, abuf[0], abuf[1], abuf[2],
               abuf[3], abuf[4]);
    } else {
        printf(fmt, abuf[0], abuf[1], abuf[2], abuf[3], abuf[4],
               "", "", "", "", "", "");
    }
    return (0);
}

/* EBCDIC-to-ASCII translation table    */
static const unsigned char e2a[] =
    /*   0123456789ABCDEF         */
    "................"          /* 00 */
    "................"          /* 10 */
    "................"          /* 20 */
    "................"          /* 30 */
    " ...........<(+|"          /* 40 */
    "&.........!$*);^"          /* 50 */
    "-/.........,%_>?"          /* 60 */
    "..........:#@'=\""         /* 70 */
    ".abcdefghi.{...."          /* 80 */
    ".jklmnopqr.}...."          /* 90 */
    "..stuvwxyz...[.."          /* A0 */
    ".............].."          /* B0 */
    "{ABCDEFGHI......"          /* C0 */
    "}JKLMNOPQR......"          /* D0 */
    "\\.STUVWXYZ......"         /* E0 */
    "0123456789......"          /* F0 */
    ;



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

    printf("  ");
    /* Translate and print hex to EBCDIC values */
    for (idx = 0; idx < DUMP_HEX_BYTES_PER_LINE; idx++) {
        if (idx < buf_len) {
            ebcdic_ch = (((int) buf_ptr[idx]) & 0xff);
            printf("%c", e2a[ebcdic_ch]);
        }
    }

}

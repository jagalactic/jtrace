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
#include <execinfo.h> /* backtrace() */
#include <pthread.h>

#include <jtrace_common.h>

/*
 * Global vars
 */

int jtrc_verbose = 0;                /* flag: verbose or not    */

char *jtrc_dev = JTRACE_DEV_SPECIAL_FILE;
int jtrace_kfd = -1;  /* File descriptor for jtrace kernel module */

/*
 * These globals are initialized when we get_all_trc_info from the kernel:
 */
int jtrc_num_common_flags = 0;
struct jtrc_flag_descriptor *jtrc_common_flag_array = 0;
int jtrc_num_instances = 0;
/* first cb returned by the kernel module */
struct jtrc_cb *jtrc_first_kernel_cb = NULL;

/* cb returned by jtrace kernel module that matches name search;
 * NULL if no match */
struct jtrc_cb *jtrc_cb = NULL;

/*******************************************************************/

#define DUMP_HEX_BYTES_PER_LINE 16

int
jtrace_kopen(void)
{
	jtrace_kfd = open(jtrc_dev, O_RDWR);
	if (jtrace_kfd < 0) {
		printf("%s: Device open failed %d\n", jtrc_dev, errno);
		return -1;
	}
	return jtrace_kfd;
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
int snarf_from_kernel(void *to, void *from, size_t len)
{
	struct jtrc_cmd_req cmd_req;

	memset(&cmd_req, 0, sizeof(cmd_req));
	cmd_req.snarf_addr = from;
	cmd_req.data = to;
	cmd_req.data_size = len;

	cmd_req.cmd = JTRCTL_SNARF;
	if (ioctl(jtrace_kfd, JTRC_CMD_IOCTL, &cmd_req)) {
		void *buf[255];
		const int calls = backtrace(buf, 255);

		fprintf(stderr, "JTRCTL_SNARF Failed errno=%d\n", errno);
		backtrace_symbols_fd(buf, calls, 1);
		exit(-1);
		return 1;
	}

	return 0;
}

void snarf(void *to, void *from, size_t len)
{
	size_t cc = 0;

	cc = snarf_from_kernel(to, from, len);
	if (cc) {
		fprintf(stderr,
			"snarf: read failed at %p, len %lx rc=%ld\n", from,
			(long) len, (long) cc);
	}
}

struct _cache_stats {
	int hits;
	int misses;
	int fastHits;
} cstats;

/**
 * snarf_str()
 *
 * Snarf a null-terminated string, which requires a bit of initiative.
 * Ok, this is some squirrely shit.  String gets stored in a local static.
 * Clearly not re-entrant!
 *
 * I have no recollection of writing this, so somebody else is probably the
 * culprit ;-).  Strings must be <128b.
 */
char *snarf_str(void *from)
{
	static uint lru;
	struct StrCache *ent, *old;
	static struct StrCache {
		void *addr;
		char str[128];
		uint lru;
	} cache[512], *last = NULL, *hiwat = &cache[0];

	if (last && last->addr == from) {
		++cstats.fastHits;
		return last->str;
	}

	/* If the requested string address has recently been snarfed
	 * (i.e. we still have it), return the copy we already have
	 */
	for (old = ent = cache; ent < hiwat; ++ent) {
		if (ent->addr == from) {
			++cstats.hits;
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

	snarf(ent->str, from, (size_t) sizeof(ent->str));
	ent->str[sizeof(ent->str) - 1] = 0; /* put NULL @ end just in case */
	++cstats.misses;

	return (last = ent)->str;
}

/**********************************************************************/

/**
 * jtrc_clear()
 *
 * Clear a user space trace buffer.
 *
 */
int jtrc_clear(struct jtrace_instance *jti)
{
	int rc = 0;

	spin_lock_irqsave(&jti->jtrc_buf_mutex, flags);
	if (jti->jtrc_cb.jtrc_flags) {
		fprintf(stderr,
			"%s: tracing must be off (flags=0) to clear trace\n",
			__func__);
		rc = -EBUSY;
		goto out;
	}
	memset(jti->jtrc_cb.jtrc_buf, 0, jti->jtrc_cb.jtrc_buf_size);

out:
	spin_unlock_irqrestore(&jti->jtrc_buf_mutex, flags);
	return rc;
}

int jtrc_clear_by_name(char *buf_name) /* kernel XXX */
{
	struct jtrc_cmd_req cmd_req;
	struct jtrace_instance *jtri;
	int found = 0;
	int rc = 0;

	/* If there is a userspace instance, clear it */
	jtri = jtrc_find_get_instance(buf_name);
	if (jtri) {
		found++;
		rc = jtrc_clear(jtri);
		jtrace_put_instance(jtri);
		/* If we found one and jtrc_clear failed, fail */
		if (rc)
			return rc;
	}

	/* If there is a kernel instance clear it */
	bzero(&cmd_req, sizeof(struct jtrc_cmd_req));
	strncpy(cmd_req.trc_name, buf_name, sizeof(cmd_req.trc_name));
	cmd_req.cmd = JTRCTL_CLEAR;
	rc = ioctl(jtrace_kfd, JTRC_CMD_IOCTL, &cmd_req);

	/* If user space succeeded, it's success even if kernel space failed */
	if (found)
		return 0;

	return rc;
}

/**
 * jtrc_set_flags()
 *
 * Set the flag mask for a user space jtrace instance
 */
void jtrc_set_flags(struct jtrace_instance *jti, int flags)
{
	if (jti->jtrc_cb.jtrc_context != USER)
		return;

	jti->jtrc_cb.jtrc_flags = flags;
	return;
}

/**
 * jtrc_set_flags_by_name()
 */
int jtrc_set_flags_by_name(char *buf_name, int trc_flags) /* kernel XXX */
{
	int rc = 0;
	struct jtrc_cmd_req cmd_req;
	struct jtrace_instance *jtri;
	int found = 0;

	/* If there is a userspace instance, set flags for it */
	jtri = jtrc_find_get_instance(buf_name);
	if (jtri) {
		jtrc_set_flags(jtri, trc_flags);
		jtrace_put_instance(jtri);
		found ++;
	}

	bzero(&cmd_req, sizeof(struct jtrc_cmd_req));
	strncpy(cmd_req.trc_name, buf_name, sizeof(cmd_req.trc_name));

	cmd_req.cmd = JTRCTL_SET_TRC_FLAGS;
	cmd_req.data = &trc_flags;
	rc = ioctl(jtrace_kfd, JTRC_CMD_IOCTL, &cmd_req);
	if (rc) {
		printf("ioctl JTRCTL_SET_TRC_FLAGS failed, rc=%d errno=%d\n",
		       rc, errno);
	}

	if (found)
		return 0;

	return rc;
}

/**
 * jtrc_set_printk_by_name()
 *
 * This is a kernel-only function
 */
int jtrc_set_printk_by_name(char *buf_name, int value) /* kernel XXX */
{
	int rc = 0;
	struct jtrc_cmd_req cmd_req;

	bzero(&cmd_req, sizeof(struct jtrc_cmd_req));

	strncpy(cmd_req.trc_name, buf_name, sizeof(cmd_req.trc_name));

	cmd_req.cmd = JTRCTL_SET_PRINTK;
	cmd_req.data = &value;
	rc = ioctl(jtrace_kfd, JTRC_CMD_IOCTL, &cmd_req);
	if (rc) {
		printf("ioctl JTRCTL_SET_PRINTK failed, rc=%d errno=%d\n",
		       rc, errno);
		return rc;
	}

	return 0;
}


/**
 * get_all_trc_info()
 *
 * Get all trace info from the jtrace kernel module. This function "knows"
 * what gets packed into the output buffer by the jtrace kernel module.
 *
 * XXX: should de-obfuscate this...
 *
 * This function gets trace info from the KERNEL ONLY
 */
struct jtrc_cb *
get_all_trc_info(char *trc_buf_name, void **buf)
{
	struct jtrc_cb *cb = NULL;
	struct jtrc_cmd_req cmd_req;
	int i = 0;
	char *out_bufp = 0;
	int rc = 0;
	int offset = 0;

	bzero(&cmd_req, sizeof(struct jtrc_cmd_req));

	cmd_req.cmd = JTRCTL_GET_ALL_TRC_INFO;
	cmd_req.data = 0;
	cmd_req.data_size = 0;

	/* Call once with no output buffer, to get required size */
	rc = ioctl(jtrace_kfd, JTRC_CMD_IOCTL, &cmd_req);
	if (rc && (rc != ENOMEM)) {
		fprintf(stderr, "JTR_GET_ALL_TRC_INFO(0) Failed rc=%d\n", rc);
		return NULL;
	}
	/* Upon clean return, the jtrace kernel driver has set
	 *  cmd_req.data_size to the required size */
	if (jtrc_verbose)
		printf("required_size=%d\n", cmd_req.data_size);

	/* We currently "leak" this, since a bunch of stuff gets packed
	 * into it, and that stuff is referenced through globals.
	 * TODO: get our payload out of the kernel in a less brain-dead way
	 */
	out_bufp = malloc(cmd_req.data_size);
	memset(out_bufp, 0, cmd_req.data_size); /* for valgrind :-/ */

	/* Now know how much data is coming, and we have a buffer big enough */
	cmd_req.data = out_bufp;
	rc = ioctl(jtrace_kfd, JTRC_CMD_IOCTL, &cmd_req);
	if (rc) {
		fprintf(stderr,
			"JTR_GET_ALL_TRC_INFO(%d) Failed describe rc=%d\n",
			cmd_req.data_size, rc);
		return NULL;
	}

	/*
	 * use out_bufp[offset] to walk through the glob that we got from
	 * the kernel
	 */
	/* Number of common Flags */
	offset = 0; /* # common flags is first; will increment offset after...*/
	memcpy(&jtrc_num_common_flags, &out_bufp[offset],
	       sizeof(jtrc_num_common_flags));
	offset += sizeof(jtrc_num_common_flags);

	/* Array of common flag descriptors */
	jtrc_common_flag_array = (struct jtrc_flag_descriptor *)
		&out_bufp[offset];
	offset += (jtrc_num_common_flags * sizeof(struct jtrc_flag_descriptor));

	/* Number of registered instances */
	memcpy(&jtrc_num_instances, &out_bufp[offset],
	       sizeof(jtrc_num_instances));
	offset += sizeof(jtrc_num_instances);

	if (jtrc_verbose) {
		printf("jtrc_num_common_flags=%d jtrc_num_instances=%d\n",
		       jtrc_num_common_flags, jtrc_num_instances);
	}

	/* Array of registered instances, each followed
	 * by optional custom flags */
	if (jtrc_num_instances) {
		jtrc_first_kernel_cb = (struct jtrc_cb *)&out_bufp[offset];
	}

	/*
	 * If there is more than one registered instance (jtrc_cb), we will
	 * get them all here.  Gotta look for the one that matches trc_buf_name
	 */
	if (trc_buf_name) {
		for (i = 0; i < jtrc_num_instances; i++) {
			cb = (struct jtrc_cb *)&out_bufp[offset];
			if (strcmp(cb->jtrc_name,
				   trc_buf_name) == 0) {
				/* Found a match */
				jtrc_cb = cb;
				break;
			}
			/* Increment past the current cb */
			offset += sizeof(struct jtrc_cb);
			/* Following the current cb is (maybe) some custom
			 * flag descriptors.  Skip past those too */
			offset += (cb->jtrc_num_custom_flags *
				   sizeof(struct jtrc_flag_descriptor));
		}
	}

	return jtrc_cb;
}

static void
__show_jtrc_custom_flags(struct jtrc_cb *cb, uint32_t trc_flags)
{
	char *ptr = NULL;
	int i;
	struct jtrc_flag_descriptor *flag_descp = NULL;

	if (cb->jtrc_num_custom_flags) {
		printf("\nCustom trace flags for module %s:\n",
		       cb->jtrc_name);
		/* Custom flags start after the module trc info */
		ptr = (char *) cb;
		ptr += sizeof(struct jtrc_cb);
		flag_descp = (struct jtrc_flag_descriptor *) ptr;
		for (i = 0; i < (cb->jtrc_num_custom_flags); i++) {
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
		       cb->jtrc_name);
	}
	printf("\n\n");
}

int show_trc_flags(uint32_t trc_flags)
{
	int i = 0;
	char *ptr = NULL;
	struct jtrc_flag_descriptor *flag_descp = NULL;
	struct jtrc_cb *cb = NULL;

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
		__show_jtrc_custom_flags(jtrc_cb, trc_flags);
		return 0;
	}

	cb = jtrc_first_kernel_cb;
	if (!cb) {
		/* No registered trace modules */
		printf("\n\n");
		return 0;
	}

	/*
	 * No specific trace module requested.
	 * Check all registered modules
	 */
	for (i = 0; i < jtrc_num_instances; i++) {
		__show_jtrc_custom_flags(cb, trc_flags);

		/* Get next trace information */
		ptr = (char *) cb;
		/* Skip past this trace information */
		ptr += sizeof(struct jtrc_cb);
		/* Also, skip past any custom flag descriptions */
		ptr +=
			(cb->jtrc_num_custom_flags *
			 sizeof(struct jtrc_flag_descriptor));
		cb = (struct jtrc_cb *) ptr;
	}

	printf("\n\n");
	return 0;
}

int flag_str_to_flag(char *trc_flag_str, uint *trc_flag)
{
	int i = 0;
	char *ptr = NULL;
	struct jtrc_flag_descriptor *flag_descp = NULL;

	for (i = 0; i < jtrc_num_common_flags; i++) {
		flag_descp = &jtrc_common_flag_array[i];
		if (strcmp(flag_descp->jtrc_flag_cmd_line_name,
			   trc_flag_str) ==
		    0) {
			/* Found a match */
			*trc_flag = JTR_COMMON_FLAG(i);
			return 0;
		}
	}

	if (jtrc_cb && jtrc_cb->jtrc_num_custom_flags) {
		if (jtrc_verbose) {
			printf("Checking custom flags for %s\n",
			       jtrc_cb->jtrc_name);
		}
		/* Custom flags start after the module trc info */
		ptr = (char *) jtrc_cb;
		ptr += sizeof(struct jtrc_cb);
		flag_descp = (struct jtrc_flag_descriptor *) ptr;
		for (i = 0;
		     i < (jtrc_cb->jtrc_num_custom_flags); i++) {
			if (strcmp(flag_descp->jtrc_flag_cmd_line_name,
				   trc_flag_str) == 0) {
				/* Found a match */
				*trc_flag = JTR_CUSTOM_FLAG(i);
				return 0;
			}
			flag_descp++;
		}
	}

	/* Found no match, invalid flag */
	return -1;
}


/****************************************************************************
 * Functions concerned with expanding and printing trace elements and buffers
 */

/**
 * printd()
 *
 * Formatted print which assumes that the argument pointers are in kernel
 * context (and this runs in user context).
 *
 * The format string has already been snarfed, but the args need to be snarfed
 */
int printd(char *fmt, void *a0, void *a1, void *a2, void *a3, void *a4)
{
	void *abuf[5];
	char *p;
	int i;
	void **ap = &abuf[0];

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
					*ap = (void *)snarf_str((void *)
								    *ap);
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
	return 0;
}

/**
 * display_reg_trc_elem()
 */
static int
display_reg_trc_elem(struct jtrc_entry *te, enum jtrace_context context)
{
	register char *p;
	struct jtrc_reg_entry *tp = &te->reg;
	int len;
	char header[256];

	if (context == KERNEL) {
		tp->fmt = snarf_str(tp->fmt);
		tp->func_name = snarf_str((void *) tp->func_name);
	}

	snprintf(header, 256,
		 "%lx : %03x:%02d:%p:0x%0*lx:%25.25s:%4.4d",
		 tp->tscp,
		 te->flag,
		 tp->cpu,
		 tp->tid,
		 ((int) (2 * sizeof(tp->id))),
		 (long) tp->id, tp->func_name, tp->line_num);

	printf("%s", header);

	printf(":");

	len = strlen(tp->fmt);
	if (tp->fmt[len-1] == '\n')
		tp->fmt[len-1] = 0;

	if (context == KERNEL)
		printd(tp->fmt, tp->a0, tp->a1, tp->a2, tp->a3, tp->a4);
	else if (context == USER)
		printf(tp->fmt, tp->a0, tp->a1, tp->a2, tp->a3, tp->a4,
		       "", "", "", "", "", "");
	else
		printf("Oops: bogus context");

	/*
	 * Strip any extra "\n"'s in the format strings.
	 */
	for (p = tp->fmt; *p; ++p)
		;

	printf("\n");

	return 0;
}

static void
dump_hex_line(char *buf_ptr, int buf_len)
{
	int idx;
	char ch;

	/* Print the hexadecimal values */
	for (idx = 0; idx < DUMP_HEX_BYTES_PER_LINE; idx++) {
		if (idx < buf_len)
			printf("%02x ", ((int) buf_ptr[idx]) & 0xff);
		else
			printf("   ");
	}
	printf("  ");
	/* Translate and print hex to ASCII values */
	for (idx = 0; idx < DUMP_HEX_BYTES_PER_LINE; idx++) {
		if (idx < buf_len) {
			ch = buf_ptr[idx];
			if ((ch < 0x20) || (ch > 0x7e))
				printf(".");
			else
				printf("%c", buf_ptr[idx]);
		}
	}
}

static int
display_hex_begin_trc_elem(struct jtrc_entry *trc_buf, uint32_t *curr_slot,
			   uint32_t num_slots, enum jtrace_context context)
{
	char *binary_data = NULL;
	size_t binary_length = 0;
	char header[256];
	char *end_buf;
	int idx = 0;
	struct jtrc_entry *tp = &trc_buf[*curr_slot];

	if (context == KERNEL) {
		tp->hex_begin.func_name = snarf_str((void *)
						    tp->hex_begin.func_name);
		tp->hex_begin.msg = snarf_str((void *)tp->hex_begin.msg);
	}

	snprintf(header, 256,
		 "%lx : %02d:%p:0x%0*lx:%25.25s:%4.4d:hex: %s len %x",
		 tp->hex_begin.tscp,
		 tp->hex_begin.cpu,
		 tp->hex_begin.tid,
		 ((int) (2 * sizeof(tp->hex_begin.id))),
		 (long) tp->hex_begin.id, tp->hex_begin.func_name,
		 tp->hex_begin.line_num, tp->hex_begin.msg,
		 tp->hex_begin.total_length);

	printf("%s", header);
	printf("\n");

	binary_length = (size_t) tp->hex_begin.total_length;

	/* The binary data starts at the data_start location */
	binary_data = (char *) &tp->hex_begin.data_start;

	printf("%s:        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f   ",
	       header);
	printf("-----ASCII------\n");

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

				(*curr_slot)++;
				if (*curr_slot >= num_slots)
					*curr_slot = 0;

				tp = &trc_buf[*curr_slot];

				binary_data = (char *)
					&tp->hex_continue.data_start;
				end_buf = binary_data
					+ JTRC_MAX_HEX_DATA_PER_ELEM;
			}
		}
		dump_hex_line(line_buf, length2);
		printf("\n");
		idx += length2;
	}

	return 0;
}

static int
display_pfs_begin_trc_elem(struct jtrc_entry *trc_buf,
			   uint32_t *curr_slot,
			   uint32_t num_slots,
			   enum jtrace_context context)
{
	char header[256];
	char *string_data = NULL;
	size_t string_length = 0;
	char *end_buf = NULL;
	struct jtrc_entry *tp = &trc_buf[*curr_slot];

	if (context == KERNEL) {
		tp->pfs_begin.func_name =
			snarf_str((void *) tp->pfs_begin.func_name);
	}

	snprintf(header, 256,
		 "%lx : %02d:%p:0x%0*lx:%25.25s:%4.4d",
		 tp->pfs_begin.tscp,
		 tp->pfs_begin.cpu,
		 tp->pfs_begin.tid,
		 ((int) (2 * sizeof(tp->pfs_begin.id))),
		 (long) tp->pfs_begin.id, tp->pfs_begin.func_name,
		 tp->pfs_begin.line_num);

	string_length = (size_t) tp->pfs_begin.total_length;
	if (jtrc_verbose)
		printf("\ntotal_length=%ld\n", string_length);

	/* The string data starts at the data_start location */
	string_data = (char *) &tp->pfs_begin.data_start;

	end_buf = string_data + JTRC_MAX_PREFMT_STR_FOR_BEG_ELEM;
	printf("%s:", header);
	while (string_length > 0) {
		int length2 = 0;

		length2 = printf("%s", string_data);
		if (jtrc_verbose)
			printf("\nstring_length=%ld length2=%d curr_slot=%d\n",
			       string_length, length2, *curr_slot);

		string_data += length2;
		string_length -= length2;

		/* check for end of element */
		if (string_length && (string_data >= end_buf)) {
			/* Move to next element */
			(*curr_slot)++;
			if (*curr_slot >= num_slots)
				*curr_slot = 0;

			tp = &trc_buf[*curr_slot];

			string_data = (char *) &tp->pfs_continue.data_start;
			end_buf = string_data + JTRC_MAX_PREFMT_STR_PER_ELEM;
		}
	}
	printf("\n");

	return 0;
}

/**
 * print_trace()
 *
 * Expand and print entries from the trace buffer
 *
 * @cb - The control block for the jtrace instance of interest
 * @dump_mask - Mask to select which entries should be printed
 */
int print_trace(struct jtrc_cb *cb, uint32_t dump_mask)
{
	size_t trc_buf_size;
	uint32_t slot_idx, mark_slot;
	struct jtrc_entry *tp;
	uint32_t zero_slots = 0;
	uint32_t curr_slot;
	uint32_t num_slots;
	struct jtrc_entry *trc_buf;
	int trc_buf_allocated = 0;

	if (!cb) {
		fprintf(stderr, "ERROR:%s: trace_info is NULL\n", __func__);
		return -1;
	}

	trc_buf_size = cb->jtrc_buf_size;
	slot_idx = cb->jtrc_buf_index;

	/* TODO: handle core files and kernel crash dumps */

	if (jtrc_verbose) {
		printf("jtrc_info.jtrc_buf_size=0x%x,",
		       cb->jtrc_buf_size);
		printf(" jtrc_info.jtrc_buf_index=0x%x\n",
		       cb->jtrc_buf_index);

		printf("cb->trc_buf=%p, cb->trc_buf_size=0x%x, ",
		       cb->jtrc_buf, cb->jtrc_buf_size);
		printf("cb->slotidx=0x%x cb->num_slots=0x%x\n",
		       cb->jtrc_buf_index, cb->jtrc_num_entries);
	}

	if (cb->jtrc_context == USER) {
		printf("%s: USER context\n", __func__);
		trc_buf = cb->jtrc_buf;
	} else if (cb->jtrc_context == KERNEL) {
		printf("%s: KERNEL context\n", __func__);
		trc_buf = (struct jtrc_entry *)calloc(1, trc_buf_size);
		if (trc_buf == NULL) {
			fprintf(stderr, "%s: malloc failed", __func__);
			return -1;
		}
		trc_buf_allocated = 1;
		/* Get the whole trc_buf in one bodacious snarf */
		snarf((void *) trc_buf, cb->jtrc_buf, trc_buf_size);
	} else {
		fprintf(stderr, "%s: invalid jtrc_context\n", __func__);
		return -1;
	}

	if (jtrc_verbose) {
		printf("trc_buf = %p, trc_buf_size=%lx slot_idx=0x%x\n",
		       trc_buf, (long) trc_buf_size, slot_idx);
		printf("sizeof(struct jtrc_entry)=%ld\n",
		       (long) sizeof(struct jtrc_entry));
	}

	num_slots = cb->jtrc_num_entries;
	curr_slot = slot_idx % num_slots;

	/*
	 * Loop through the trace buffer and print each entry
	 */
	for (mark_slot = curr_slot; ++curr_slot != mark_slot;) {
		if (curr_slot >= num_slots) {
			curr_slot = -1;
			continue;
		}

		tp = &trc_buf[curr_slot];

		if (jtrc_verbose) {
			printf("num_slots=0x%x mark_slot=0x%x, ",
			       num_slots, mark_slot);
			printf("elem_fmt=%d zero_slots=0x%x\ncurr_slot=0x%x, ",
			       curr_slot, tp->elem_fmt, zero_slots);
		}

		if (tp->flag & dump_mask) {
			switch (tp->elem_fmt) {
			case JTRC_FORMAT_REGULAR:
				if (tp->reg.fmt == 0)
					continue;

				display_reg_trc_elem(tp, cb->jtrc_context);
				zero_slots = 0;
				break;

				/* This dumps hex data slots until
				 * JTRC_HEX_DATA_END */
			case JTRC_HEX_DATA_BEGIN:
				display_hex_begin_trc_elem(trc_buf, &curr_slot,
							   num_slots,
							   cb->jtrc_context);
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
				display_pfs_begin_trc_elem(trc_buf, &curr_slot,
							   num_slots,
							   cb->jtrc_context);
				zero_slots = 0;
				break;

				/*
				 * If we hit these here, we've lost the BEGIN
				 * slot context, so just skip
				 */
			case JTRC_PREFORMATTED_STR_CONTINUE:
			case JTRC_PREFORMATTED_STR_END:
				zero_slots = 0;
				break;

			default:
				zero_slots++;
				break;
			}
		}
		/*
		 * The slot may have been incremented by
		 * display_hex_begin_trc_elem() or
		 * display_pfs_begin_trc_elem().
		 * If so and now equal to marked slot, we are done.
		 */
		if (curr_slot == mark_slot)
			break;
	}

	printf("\n");
	if (trc_buf_allocated)
		free(trc_buf);
	return 0;
}


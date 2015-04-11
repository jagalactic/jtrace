/*
 * jtrc.c 
 */

#define JTRC_TEST

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/notifier.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/notifier.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <asm/current.h>
#include <asm/smp.h>
#include "jtrace.h"

/* 
 * A reasonable amount of common flags.
 */
jtrc_flag_descriptor_t jtrc_common_flag_array[] = {
    {"ERROR", "Trace error conditions"}
    ,
    {"WARN", "Trace warning conditions"}
    ,
    {"CONFIG", "Trace configuration routines"}
    ,
    {"ENTX", "Trace all routine entry and exit points."}
    ,
    {"IOCTL", "Trace ioctl() calls"}
    ,
    {"DEBUG", "General debug"}
    ,
};

#define JTRC_NUM_COMMON_FLAGS (sizeof(jtrc_common_flag_array)/sizeof(jtrc_flag_descriptor_t))
static int jtrc_num_common_flags = JTRC_NUM_COMMON_FLAGS;

/**
 *
 * This is the kernel-mode list of extant jtrace instances
 */
DEFINE_SPINLOCK(jtrc_config_lock);
static struct list_head jtrc_instance_list
            = LIST_HEAD_INIT(jtrc_instance_list);

static int jtrc_num_instances;

/*
 * local fuctions
 */
static void jtrc_v(jtrace_instance_t * jt, void *id,
		    uint32_t flags, struct timespec *tm,
                    const char *func, int line, char *fmt, va_list vap);

#define MIN(a,b) (((a)<(b))?(a):(b))
#define DUMP_HEX_BYTES_PER_LINE 16
static void dump_hex_line(char *buf_ptr, int buf_len);

void jtrace_print_element(jtrc_element_t * tp);
void jtrace_print_tail(jtrace_instance_t * jt,
                            int num_elems);

#if 0
static int jtrc_panic_event(struct notifier_block *, unsigned long event,
                             void *ptr);
static struct notifier_block jtrc_panic_block = {
	jtrc_panic_event,
	NULL,                       /* Next notifier block */
	INT_MAX                     /* try to do it first */
};
#endif

#ifdef JTRC_TEST
static void jtrc_test(void);
#endif

#include "../common/jtrace_common.c"

/**
 * copyout_append()
 *
 * Copy to user space; can be called repeatedly and will append the data
 * in user space, keeping track of remainder.
 *
 * The total_bytes_copied is updated whether or not we copy to user space.
 * This is how we count up how much data we need room for.  User space uses
 * this by calling us with 0 (or undersized buffer) first to find out how
 * much space is needed.
 *
 * @out_buffer         - user space address to copy to; pointer updated
 *                       to point to the append point
 * @objp               - object to copy out
 * @obj_size           - size of object
 * @total_bytes        - this gets updated each time we get called
 * @out_buf_remainder  - this gets updated until it goes to 0
 *
 * Return value
 * 0 - if copy_to_user() was not called
 * Otherwise, the return value of copy_to_user()
 */
static inline int
copyout_append(char **out_buffer,  /* Where to copy */
	       void *objp,         /* What to copy */
	       int obj_size,       /* How big is it */
	       int *total_bytes,
	       int *out_buf_remainder)
{
	int rc = 0;
	if (*out_buffer &&
	    (objp) &&
	    (obj_size) &&
	    (obj_size <= *out_buf_remainder) ) {
		int size = MIN(obj_size, *out_buf_remainder);
		rc = copy_to_user(*out_buffer, objp, size);
		*out_buf_remainder -= size;
		*out_buffer += size;
	}
	*total_bytes += obj_size;
	return rc;
}

/**
 * jtrc_get_all_trc_info()
 *
 * Get all of the trace elements in the specified trace buffer
 *
 * @cmd_req - the cmd_req struct from user space
 *
 * The userspace caller receives the following:
 *
 * 1. The number of common flags
 * 2. The common flags descriptors
 * 3. The number of registered modules
 * 4. the (module_trc_info_t, (jtrc_flag_descriptor_t, ...)) set for each module
 */
static int jtrc_get_all_trc_info(jtrc_cmd_req_t * cmd_req)
{
	char *out_buffer = 0;
	int out_buf_remainder = 0;
	int total_bytes = 0;
	jtrace_instance_t *jtri = NULL;
	int i = 0;
	int rc = 0;
	int req_size;

	if (!cmd_req) {
		return (EINVAL);
	}

	out_buffer = cmd_req->data;
	out_buf_remainder = req_size = cmd_req->data_size;

	/* Output the number of common flags */
	copyout_append(&out_buffer,
		       (void *)&jtrc_num_common_flags,
		       sizeof(jtrc_num_common_flags),
		       &total_bytes,
		       &out_buf_remainder);

	/* Output common flag descriptors */
	for (i = 0; i < jtrc_num_common_flags; i++) {
		copyout_append(&out_buffer,
			       (void *) &jtrc_common_flag_array[i],
			       sizeof(jtrc_flag_descriptor_t),
			       &total_bytes,
			       &out_buf_remainder);
	}

	/* Output number of registered modules */
	copyout_append(&out_buffer,
		       (char *) &jtrc_num_instances,
		       sizeof(jtrc_num_instances),
		       &total_bytes,
		       &out_buf_remainder);

	/* Output each registered module's info */
	list_for_each_entry(jtri,
			    &jtrc_instance_list, jtrc_list) {
		copyout_append(&out_buffer,
			       (char *) &jtri->mod_trc_info,
			       sizeof(jtrc_cb_t),
			       &total_bytes,
			       &out_buf_remainder);

		/* Output each registered module's custom flags */
		for (i = 0;
		     i < jtri->mod_trc_info.jtrc_num_custom_flags;
		     i++) {
			copyout_append(&out_buffer,
				       &jtri->custom_flags[i],
				       sizeof(jtrc_flag_descriptor_t),
				       &total_bytes,
				       &out_buf_remainder);
		}
	}

	/* Always set required size */
	if (total_bytes != cmd_req->data_size) {
		cmd_req->data_size = total_bytes;
	}

	return (rc);
}


static int jtrc_snarf(jtrc_cmd_req_t * cmd_req)
{
	int rc = 0;

	if (!cmd_req) {
		return (EINVAL);
	}

	rc = copy_to_user(cmd_req->data, cmd_req->snarf_addr,
			  cmd_req->data_size);

	return (rc);
}


/**
 * jtrace_cmd()
 *
 * IOCTL handler for jtrc
 *
 * @cmd_req - jtrc_cmd_req_t struct, describing what the caller wants
 */
int jtrace_cmd(jtrc_cmd_req_t * cmd_req, void *uaddr)
{
	int rc = 0;
	jtrace_instance_t *jt = NULL;

	/* JTRCTL_GET_ALL_TRC_INFO does not require valid jtrace context */
	if (cmd_req->cmd == JTRCTL_GET_ALL_TRC_INFO) {
		rc = jtrc_get_all_trc_info(cmd_req);
		cmd_req->status = rc;
		if (rc == 0) {
			rc = copy_to_user(uaddr, cmd_req, sizeof(*cmd_req));
		}
		return (rc);
	}

	/* JTRCTL_SNARF does not require valid jt */
	if (cmd_req->cmd == JTRCTL_SNARF) {
		rc = jtrc_snarf(cmd_req);
		cmd_req->status = rc;
		return (rc);
	}

	/* All others require valid trc_name info */
	jt = jtrc_find_instance_by_name(&jtrc_instance_list,
					cmd_req->trc_name);
	if (!jt) {
		cmd_req->status = ENODEV;
		return (ENODEV);
	}

	switch (cmd_req->cmd) {
	case JTRCTL_SET_PRINTK:
        {
		/* Turn printk on & off */
		int value;
		rc = copy_from_user((caddr_t) & value,
				    (caddr_t) cmd_req->data, sizeof(value));
		if (!((value == 0) || (value == 1))) {
			cmd_req->status = EINVAL;
			rc = EINVAL;
			break;
		}
		jt->mod_trc_info.jtrc_kprint_enabled = value;
		printk("JTRCTL_SET_PRINTK %d\n", value);
		cmd_req->status = 0;
		rc = 0;
        }
        break;

	case JTRCTL_SET_TRC_FLAGS:
		/* Set the flag mask which controls what is traced */
		rc = copy_from_user((caddr_t) 
			    &jt->mod_trc_info.jtrc_flags,
			    (caddr_t) cmd_req->data,
			    sizeof(jt->mod_trc_info.jtrc_flags));
		cmd_req->status = 0;
		rc = 0;
		break;

	case JTRCTL_CLEAR:
		/* Clear the trace buffer(s) */
		jt->mod_trc_info.jtrc_buf_index = 0;
		memset((caddr_t) jt->mod_trc_info.jtrc_buf, 0,
		       jt->mod_trc_info.jtrc_buf_size);
		rc = 0;
		break;

	default:
		cmd_req->status = EINVAL;
		return EINVAL;
	}

	return (rc);
}

void dump_hex_line(char *buf_ptr, int buf_len)
{
	int idx;
	char ch;
#ifdef OUTPUT_EBCIDIC_TOO
	int ebcdic_ch;
#endif

	/* Print the hexadecimal values */
	for (idx = 0; idx < DUMP_HEX_BYTES_PER_LINE; idx++) {
		if (idx < buf_len) {
			printk("%02x ", ((int) buf_ptr[idx]) & 0xff);
		} else {
			printk("   ");
		}
	}
	printk("  ");
	/* Translate and print hex to ASCII values */
	for (idx = 0; idx < DUMP_HEX_BYTES_PER_LINE; idx++) {
		if (idx < buf_len) {
			ch = buf_ptr[idx];
			if ((ch < 0x20) || (ch > 0x7e)) {
				printk(".");
			} else {
				printk("%c", buf_ptr[idx]);
			}
		}
	}
#ifdef OUTPUT_EBCIDIC_TOO
	printk("  ");
	/* Translate and print hex to EBCDIC values */
	for (idx = 0; idx < DUMP_HEX_BYTES_PER_LINE; idx++) {
		if (idx < buf_len) {
			ebcdic_ch = (((int) buf_ptr[idx]) & 0xff);
			printk("%c", e2a[ebcdic_ch]);
		}
	}
#endif
}

#define JTRC_KPRINT_BUF_SIZE 256
static char buf[JTRC_KPRINT_BUF_SIZE];
static int idx = 0;

/**
 * jtrc_print_element()
 *
 * @tp - the trace element to print
 *
 * This prints a trace element to the system log (printk) in an
 * element-type-dependent format
 */
void jtrc_print_element(jtrc_element_t * tp)
{
	int prefix_len = 0;

	switch (tp->elem_fmt) {
	case JTRC_FORMAT_REGULAR:

	prefix_len = snprintf(buf, JTRC_KPRINT_BUF_SIZE,
                              "%6.6d.%2.2d:%2.2d:%p:%p:%25.25s:%4d:",
                              tp->reg.tv_sec, tp->reg.tv_nsec / 10000,
                              tp->reg.cpu, tp->reg.tid,
                              tp->reg.id, tp->reg.func_name,
                              tp->reg.line_num);

        snprintf(&buf[prefix_len], JTRC_KPRINT_BUF_SIZE - prefix_len,
                 tp->reg.fmt, tp->reg.a0, tp->reg.a1, tp->reg.a2,
                 tp->reg.a3, tp->reg.a4);
        printk("%s\n", buf);
        buf[0] = 0;
        idx = 0;

        break;

    case JTRC_HEX_DATA_BEGIN:
        {
            size_t binary_length = 0;
            char *binary_data = NULL;

            idx = 0;

            prefix_len = snprintf(buf, JTRC_KPRINT_BUF_SIZE,
                                  "%6.6d.%2.2d:%2.2d:%p:%p:%25.25s:%4d:",
                                  tp->hex_begin.tv_sec,
                                  tp->hex_begin.tv_nsec / 10000000,
                                  tp->reg.cpu, tp->reg.tid,
                                  tp->hex_begin.id,
                                  tp->hex_begin.func_name,
                                  tp->hex_begin.line_num);

            snprintf(&buf[prefix_len], JTRC_KPRINT_BUF_SIZE - prefix_len,
                     "hex: %s len=0x%x", tp->hex_begin.msg,
                     tp->hex_begin.total_length);

            binary_length =
                (size_t) MIN(tp->hex_begin.total_length,
                             JTRC_MAX_HEX_DATA_FOR_BEG_ELEM);

            /* The binary data starts at the data_start location */
            binary_data = (char *) &tp->hex_begin.data_start;

            /* Dump in increments of hex line size */
            while (binary_length > 0) {
                int length2 = MIN(binary_length, DUMP_HEX_BYTES_PER_LINE);
                printk("%s:%04x:  ", buf, idx);
                dump_hex_line(binary_data, length2);
                printk("\n");
                idx += length2;
                binary_data += length2;
                binary_length -= length2;
            }
        }
        break;

    case JTRC_HEX_DATA_CONTINUE:
    case JTRC_HEX_DATA_END:
        {
            size_t binary_length = 0;
            char *binary_data = NULL;

            binary_length =
                (size_t) MIN(tp->hex.length, JTRC_MAX_HEX_DATA_PER_ELEM);

            /* The binary data starts at the data_start location */
            binary_data = (char *) &tp->hex.data_start;

            /* Dump in increments of hex line size */
            while (binary_length > 0) {
                int length2 = MIN(binary_length, DUMP_HEX_BYTES_PER_LINE);
                printk("%s:%04x:  ", buf, idx);
                dump_hex_line(binary_data, length2);
                printk("\n");
                idx += length2;
                binary_data += length2;
                binary_length -= length2;
            }
        }

        if (tp->elem_fmt == JTRC_HEX_DATA_END) {
            buf[0] = 0;
            idx = 0;
        }

        break;

    case JTRC_PREFORMATTED_STR_BEGIN:
        {
            idx = 0;

            prefix_len = snprintf(buf, JTRC_KPRINT_BUF_SIZE,
                                  "%6.6d.%2.2d:%2.2d:%p:%p:%25.25s:%4d:",
                                  tp->pfs_begin.tv_sec,
                                  tp->pfs_begin.tv_nsec / 10000000,
                                  tp->pfs_begin.cpu, tp->pfs_begin.tid,
                                  tp->pfs_begin.id,
                                  tp->pfs_begin.func_name,
                                  tp->pfs_begin.line_num);

            snprintf(&buf[prefix_len], JTRC_KPRINT_BUF_SIZE - prefix_len,
                     "%s", (char *) &tp->pfs_begin.data_start);
            printk("%s\n", buf);
            buf[0] = 0;
            idx = 0;
        }
        break;

    case JTRC_PREFORMATTED_STR_CONTINUE:
    case JTRC_PREFORMATTED_STR_END:
        {
            printk("%s\n", (char *) &tp->pfs_continue.data_start);

            if (tp->elem_fmt == JTRC_PREFORMATTED_STR_END) {
                buf[0] = 0;
                idx = 0;
            }
        }

        break;

    default:
        return;
    }


    return;
}


/**
 * jtrace_print_tail()
 *
 * @jt      - the jtrace instance
 * @num_elems - the number of elements to print, at the tail of the trace
 */
void jtrace_print_tail(jtrace_instance_t * jt,
                            int num_elems)
{
	/* Back up the index num_elems slots */
	int32_t temp_index =
		jt->mod_trc_info.jtrc_buf_index - num_elems;
	register jtrc_element_t *tp = NULL;
	int i = 0;

	if (temp_index < 0) {
		temp_index += jt->mod_trc_info.jtrc_num_entries;
	}

	tp = &jt->mod_trc_info.jtrc_buf[temp_index];

	/*
	 * If we are in the middle of a hex dump or string,
	 * go back to BEGIN so we can get the context.
	 */
	while ((tp->elem_fmt == JTRC_HEX_DATA_END) ||
	       (tp->elem_fmt == JTRC_HEX_DATA_CONTINUE) ||
	       (tp->elem_fmt == JTRC_PREFORMATTED_STR_CONTINUE) ||
	       (tp->elem_fmt == JTRC_PREFORMATTED_STR_END)) {
		num_elems++;

		temp_index = jt->mod_trc_info.jtrc_buf_index - num_elems;
		if (temp_index < 0) {
			temp_index += jt->mod_trc_info.jtrc_num_entries;
		}

		tp = &jt->mod_trc_info.jtrc_buf[temp_index];
	}

	temp_index = jt->mod_trc_info.jtrc_buf_index - num_elems;

	if (temp_index < 0) {
		temp_index += jt->mod_trc_info.jtrc_num_entries;
	}

	for (i = 0; i < num_elems; i++) {
		tp = &jt->mod_trc_info.jtrc_buf[temp_index];
		jtrc_print_element(tp);

		temp_index++;
		if (temp_index > jt->mod_trc_info.jtrc_num_entries - 1) {
			temp_index = 0;
		}
	}
	return;
}

/* Put stuff in trace buffers *********************************************/

/**
 * jtrc_v() - add trace entries to buffer
 */
static void
jtrc_v(jtrace_instance_t * jt, void *id,
	uint32_t tflags, struct timespec *tm,
        const char *func_name, int line_num, char *fmt, va_list vap)
{
	register jtrc_element_t *tp;
	struct timespec time;
	unsigned long flags;

	spin_lock_irqsave(&jt->jtrc_buf_mutex, flags);

	if (!tm) {
		tm = &time;
		/* XXX: this is slow; need to just read the clock */
		getnstimeofday(&time);
	}

	/* Increment index and handle wrap */
	jt->mod_trc_info.jtrc_buf_index++;
	if (jt->mod_trc_info.jtrc_buf_index >
	    (jt->mod_trc_info.jtrc_num_entries - 1)) {
		jt->mod_trc_info.jtrc_buf_index = 0;
	}

	tp = &jt->mod_trc_info.jtrc_buf[jt->mod_trc_info.
						    jtrc_buf_index];

	tp->elem_fmt = JTRC_FORMAT_REGULAR;
	tp->flag = tflags;
	tp->reg.tv_sec = tm->tv_sec;
	tp->reg.tv_nsec = tm->tv_nsec;
	tp->reg.cpu = smp_processor_id();
	tp->reg.tid = (void *) current;
	tp->reg.func_name = func_name;
	tp->reg.line_num = line_num;
	tp->reg.id = id;
	tp->reg.fmt = fmt;
	tp->reg.a0 = va_arg(vap, jtrc_arg_t);
	tp->reg.a1 = va_arg(vap, jtrc_arg_t);
	tp->reg.a2 = va_arg(vap, jtrc_arg_t);
	tp->reg.a3 = va_arg(vap, jtrc_arg_t);
	tp->reg.a4 = va_arg(vap, jtrc_arg_t);

	/*
	 * If things are really crashing, enable jtrc_kprint_enabled = 1
	 * for output to the console.
	 */
	if (jt->mod_trc_info.jtrc_kprint_enabled) {
		jtrc_print_element(tp);
	}
	spin_unlock_irqrestore(&jt->jtrc_buf_mutex, flags);
}


/**
 * _jtrace() -    add trace entries to buffer
 */
void _jtrace(jtrace_instance_t * jt, void *id,
	     uint32_t flags, struct timespec *tm,
	     const char *func, int line, char *fmt, ...)
{
    va_list vap;

    va_start(vap, fmt);

    jtrc_v(jt, id, flags, tm, func, line, fmt, vap);

    va_end(vap);
}

/**
 * jtrace_preformatted_str_v() - add trace entries to buffer
 */
static void
__jtrace_preformatted_str(jtrace_instance_t * jt, void *id,
			  uint32_t flags,
			  const char *func_name, int line_num, char *buf,
			  int str_len)
{
	register jtrc_element_t *tp;
	struct timespec time;
	jtrc_element_fmt_t elem_fmt;

	char *in_buf = (char *) buf;
	char *in_buf_end = NULL;
	char *out_buf = NULL;
	unsigned char length2;

	if (!buf) {
		return;
	}

	if (!str_len) {
		return;
	}

	in_buf_end = in_buf + str_len;

	getnstimeofday(&time);

	jt->mod_trc_info.jtrc_buf_index++;
	if (jt->mod_trc_info.jtrc_buf_index >
	    (jt->mod_trc_info.jtrc_num_entries - 1)) {
		jt->mod_trc_info.jtrc_buf_index = 0;
	}

	tp = &jt->mod_trc_info.jtrc_buf[jt->mod_trc_info.jtrc_buf_index];

	tp->elem_fmt = JTRC_PREFORMATTED_STR_BEGIN;
	tp->flag = flags;
	tp->pfs_begin.tv_sec = time.tv_sec;
	tp->pfs_begin.tv_nsec = time.tv_nsec;
	tp->pfs_begin.cpu = smp_processor_id();
	tp->pfs_begin.tid = (void *) current;
	tp->pfs_begin.func_name = func_name;
	tp->pfs_begin.line_num = line_num;
	tp->pfs_begin.id = id;
	tp->pfs_begin.total_length = str_len;

	/* Fill the rest of first element with string data */
	length2 =
		MIN((in_buf_end - in_buf), JTRC_MAX_PREFMT_STR_FOR_BEG_ELEM);
	out_buf = (char *) &tp->pfs_begin.data_start;
	memcpy(out_buf, in_buf, length2);
	out_buf += length2;
	/* Terminate string */
	*out_buf = 0;

	if (jt->mod_trc_info.jtrc_kprint_enabled) {
		jtrc_print_element(tp);
	}

	in_buf += length2;

	/* Fill in remaining elements */
	if (in_buf < in_buf_end) {
		elem_fmt = JTRC_PREFORMATTED_STR_CONTINUE;
		while (in_buf < in_buf_end) {
			length2 =
				MIN((in_buf_end - in_buf),
				    JTRC_MAX_PREFMT_STR_PER_ELEM);

			jt->mod_trc_info.jtrc_buf_index++;
			if (jt->mod_trc_info.jtrc_buf_index >
			    (jt->mod_trc_info.jtrc_num_entries - 1)) {
				jt->mod_trc_info.jtrc_buf_index = 0;
			}
			tp = &jt->mod_trc_info.jtrc_buf[jt->
							    mod_trc_info.
							    jtrc_buf_index];

			tp->elem_fmt = elem_fmt;
			tp->pfs_continue.length = length2;

			out_buf = (char *) &tp->pfs_continue.data_start;

			memcpy(out_buf, in_buf, length2);
			out_buf += length2;
			/* Terminate string */
			*out_buf = 0;

			if (jt->mod_trc_info.jtrc_kprint_enabled) {
				jtrc_print_element(tp);
			}

			in_buf += length2;
			elem_fmt = JTRC_PREFORMATTED_STR_CONTINUE;
		}
		tp->elem_fmt = JTRC_PREFORMATTED_STR_END;
	}
}

#define MAX_PREFORMATTED_STR_LEN 256
static char pre_fmt_buf[MAX_PREFORMATTED_STR_LEN];
void jtrace_preformatted_str(jtrace_instance_t * jt,
			     void *id, uint32_t tflags,
			     const char *func, int line,
			     char *fmt, ...)
{
	int str_len = 0;
	va_list vap;
	unsigned long flags;

	spin_lock_irqsave(&jt->jtrc_buf_mutex, flags);
	va_start(vap, fmt);
	str_len = vsnprintf(pre_fmt_buf, MAX_PREFORMATTED_STR_LEN, fmt, vap);
	va_end(vap);

	__jtrace_preformatted_str(jt, id, tflags, func, line, pre_fmt_buf,
			       str_len);
	spin_unlock_irqrestore(&jt->jtrc_buf_mutex, flags);
}

#define MAX_HEX_BUF 1024
/**
 * jtrace_hex_dump() - add a HEX dump to the trace
 */
void
jtrace_hex_dump(jtrace_instance_t * jt, const char *func,
                uint line, void *id, uint32_t tflags,
		char *msg, void *p, uint len)
{
	register jtrc_element_t *tp = NULL;
	int max_len = 0;
	char *in_buf = (char *) p;
	char *in_buf_end = NULL;
	char *out_buf = NULL;
	struct timespec time;
	unsigned long flags;
	jtrc_element_fmt_t elem_fmt;
	unsigned char length2;

	if (!p) {
		return;
	}

	max_len = MIN(len, MAX_HEX_BUF);
	in_buf_end = in_buf + max_len;

	spin_lock_irqsave(&jt->jtrc_buf_mutex, flags);

	getnstimeofday(&time);

	jt->mod_trc_info.jtrc_buf_index++;
	if (jt->mod_trc_info.jtrc_buf_index >
	    (jt->mod_trc_info.jtrc_num_entries - 1)) {
		jt->mod_trc_info.jtrc_buf_index = 0;
	}

	tp = &jt->mod_trc_info.jtrc_buf[jt->mod_trc_info.
						    jtrc_buf_index];

	tp->elem_fmt = JTRC_HEX_DATA_BEGIN;
	tp->flag = tflags;
	tp->hex_begin.tv_sec = time.tv_sec;
	tp->hex_begin.tv_nsec = time.tv_nsec;
	tp->hex_begin.cpu = smp_processor_id();
	tp->hex_begin.tid = (void *) current;
	tp->hex_begin.func_name = func;
	tp->hex_begin.line_num = line;
	tp->hex_begin.id = id;
	tp->hex_begin.msg = msg;
	tp->hex_begin.total_length = max_len;

	/* Fill the rest of first element with hex data */
	length2 = MIN((in_buf_end - in_buf), JTRC_MAX_HEX_DATA_FOR_BEG_ELEM);
	out_buf = (char *) &tp->hex_begin.data_start;
	memcpy(out_buf, in_buf, length2);

	if (jt->mod_trc_info.jtrc_kprint_enabled) {
		jtrc_print_element(tp);
	}

	in_buf += length2;

	/* Fill in remaining elements */
	if (in_buf < in_buf_end) {
		elem_fmt = JTRC_HEX_DATA_CONTINUE;
		while (in_buf < in_buf_end) {
			length2 = MIN((in_buf_end - in_buf),
				      JTRC_MAX_HEX_DATA_PER_ELEM);

			jt->mod_trc_info.jtrc_buf_index++;
			if (jt->mod_trc_info.jtrc_buf_index >
			    (jt->mod_trc_info.jtrc_num_entries - 1)) {
				jt->mod_trc_info.jtrc_buf_index = 0;
			}

			tp = &jt->mod_trc_info.jtrc_buf[jt->
							    mod_trc_info.
							    jtrc_buf_index];
			tp->elem_fmt = elem_fmt;
			tp->hex.length = length2;

			out_buf = (char *) &tp->hex.data_start;

			memcpy(out_buf, in_buf, length2);

			if (jt->mod_trc_info.jtrc_kprint_enabled) {
				jtrc_print_element(tp);
			}

			in_buf += length2;
			elem_fmt = JTRC_HEX_DATA_CONTINUE;
		}
		tp->elem_fmt = JTRC_HEX_DATA_END;
	}

	spin_unlock_irqrestore(&jt->jtrc_buf_mutex, flags);

}

#if 0
static int jtrc_has_paniced = 0;

static int jtrc_panic_event(struct notifier_block *this,
                             unsigned long event, void *ptr)
{
	jtrace_instance_t *jt;

	if (jtrc_has_paniced) {
		return NOTIFY_DONE;
	}
	jtrc_has_paniced = 1;

	list_for_each_entry(jt, &jtrc_instance_list, jtrc_list) {
		jtrace_print_tail(jt, 500);
	}

	return NOTIFY_DONE;
}
#endif

/***************************************************************************/

/**
 * jtrace_register_instance()
 *
 * Create a jtrace instance, and get its handle.  Fail if there is already
 * an instance with the same name.
 *
 * @jt - pointer to initialized jtrace_instance_t struct.
 *
 */
int jtrace_register_instance(jtrace_instance_t * jt)
{
	unsigned long flags;

	if (strnlen(jt->mod_trc_info.jtrc_name,
		    sizeof(jt->mod_trc_info.jtrc_name)) == 0) {
		printk("ERROR: jtrace_register_instance: "
		       "jtrc_name must be non-NULL\n");
		return (EINVAL);
	}

	if (jt->mod_trc_info.
	    jtrc_custom_flags_mask & JTR_COMMON_FLAGS_MASK) {
		printk("ERROR: jtrace_register_instance: Custom flag values "
		       "contain reserved JTR_COMMON_FLAGS_MASK\n");
		return (EINVAL);
	}

	spin_lock_irqsave(&jtrc_config_lock, flags);

	/* Does this instance already exist? */
	if (jtrc_find_instance_by_addr(&jtrc_instance_list, jt) ||
	    jtrc_find_instance_by_name(&jtrc_instance_list,
				       jt->mod_trc_info.jtrc_name)) {
		printk("jtrace_register_instance: EALREADY\n");
		spin_unlock_irqrestore(&jtrc_config_lock, flags);
		return (EALREADY);
	}

	if (!jt->mod_trc_info.jtrc_buf) {
		jt->mod_trc_info.jtrc_buf =
			vmalloc_user(jt->mod_trc_info.jtrc_buf_size);
		if (!jt->mod_trc_info.jtrc_buf)
			return ENOMEM;
	}
	spin_lock_init(&jt->jtrc_buf_mutex);
	jt->mod_trc_info.jtrc_buf_index = 0;
	memset((caddr_t) jt->mod_trc_info.jtrc_buf, 0,
	       jt->mod_trc_info.jtrc_buf_size);
	list_add_tail(&jt->jtrc_list, &jtrc_instance_list);
	jtrc_num_instances++;
	jt->refcount++;

	spin_unlock_irqrestore(&jtrc_config_lock, flags);

	return (0);
}

/* 
 * Use existing trace buffer information 
 */
jtrace_instance_t *jtrace_get_instance(char *name)
{
	jtrace_instance_t *tmp_jtri;
	unsigned long flags;

	spin_lock_irqsave(&jtrc_config_lock, flags);
	tmp_jtri = jtrc_find_instance_by_name(&jtrc_instance_list, name);

	if (!tmp_jtri) {
		spin_unlock_irqrestore(&jtrc_config_lock, flags);
		return (0);
	}

	tmp_jtri->refcount++;
	spin_unlock_irqrestore(&jtrc_config_lock, flags);
	return (tmp_jtri);
}

/* Unregister module trace information */
void jtrace_put_instance(jtrace_instance_t * jt)
{
	unsigned long flags;

	spin_lock_irqsave(&jtrc_config_lock, flags);
	if (!jtrc_find_instance_by_addr(&jtrc_instance_list, jt)) {
		spin_unlock_irqrestore(&jtrc_config_lock, flags);
		return;
	}

	jt->refcount--;
	if (jt->refcount == 0) {
		list_del(&jt->jtrc_list);
		jtrc_num_instances--;
	}

	spin_unlock_irqrestore(&jtrc_config_lock, flags);
	return;
}

/* Module Parameters */
int num_trc_elements = 0x100000;
module_param(num_trc_elements, int, 0444); /* Can't be changed, must re-load */



//#define  num_trc_elements  (0x100000) /* # trace entries  */
static jtrace_instance_t jtrc_default_info;

/* Static jtrace reg info for default instance; should probably not be static */
jtrace_instance_t *jtri = NULL;

#define DEFAULT_BUF_NAME "jtrc_default"

/**
 * jtrace_init()
 *
 * Initialize the default jtrace instance.
 */
int jtrace_init(void)
{
	int result;

	//notifier_chain_register(&panic_notifier_list, &jtrc_panic_block);

	/* We automatically init a trace buffer with DEFAULT_BUF_NAME
	 * at module init time. */
	strncpy(jtrc_default_info.mod_trc_info.jtrc_name,
		DEFAULT_BUF_NAME,
		sizeof(jtrc_default_info.mod_trc_info.jtrc_name));
	jtrc_default_info.mod_trc_info.jtrc_buf = NULL;
	jtrc_default_info.mod_trc_info.jtrc_num_entries =
		num_trc_elements;
	jtrc_default_info.mod_trc_info.jtrc_buf_size =
	  num_trc_elements * sizeof(jtrc_element_t);

	jtrc_default_info.mod_trc_info.jtrc_buf_index = 0;
	jtrc_default_info.mod_trc_info.jtrc_kprint_enabled = 0;
	jtrc_default_info.mod_trc_info.jtrc_flags = JTR_COMMON_FLAGS_MASK;

	result = jtrace_register_instance(&jtrc_default_info);
	if (result) {
		return (result);
	}

	jtri = &jtrc_default_info;
#ifdef JTRC_TEST
	jtrc_test();
#endif

	return 0;

}

void jtrace_exit(void)
{
	if (jtri) {
		jtrace_put_instance(jtri);
	}

	//notifier_chain_unregister(&panic_notifier_list, &jtrc_panic_block);

	return;
}

#ifdef JTRC_TEST

static void jtrc_test(void)
{
	char *id = 0;
	int value1 = 1;
	//int value2 = 2;
	char hex_dump_data[512];
	int i = 0;

	for (i = 0; i < 512; i++) {
		hex_dump_data[i] = (char) (i & 0xff);
	}

	jtrc_setprint(jtri, 1);

	jtrc(jtri, JTR_CONF, id, "First Entry");

	jtrc(jtri, JTR_CONF, id, "sizeof(jtrc_element_t)=%d",
	     sizeof(jtrc_element_t));
	jtrc(jtri, JTR_CONF, id, "sizeof(jtrc_regular_element_t)=%d",
	     sizeof(jtrc_regular_element_t));
	jtrc(jtri, JTR_CONF, id, "sizeof(jtrc_hex_begin_element_t)=%d",
	     sizeof(jtrc_hex_begin_element_t));
	jtrc(jtri, JTR_CONF, id, "sizeof(jtrc_hex_element_t)=%d",
	     sizeof(jtrc_hex_element_t));
	jtrc(jtri, JTR_CONF, id, "sizeof(jtrc_element_fmt_t)=%d",
	     sizeof(jtrc_element_fmt_t));
	jtrc(jtri, JTR_CONF, id, "offsetof(jtrc_element_t, elem_fmt)=%d",
	     offsetof(jtrc_element_t, elem_fmt));
	jtrc(jtri, JTR_CONF, id, "offsetof(jtrc_element_t, hex.length)=%d",
	     offsetof(jtrc_element_t, hex.length));
	jtrc(jtri, JTR_CONF, id, "offsetof(jtrc_element_t, hex.data_start)=%d",
	     offsetof(jtrc_element_t, hex.data_start));
	jtrc(jtri, JTR_CONF, id,
	     "offsetof(jtrc_element_t, hex_begin.total_length)=%d",
	     offsetof(jtrc_element_t, hex_begin.total_length));
	jtrc(jtri, JTR_CONF, id,
	     "offsetof(jtrc_element_t, hex_begin.data_start)=%d",
	     offsetof(jtrc_element_t, hex_begin.data_start));
	jtrc(jtri, JTR_CONF, id, "JTRC_MAX_HEX_DATA_FOR_BEG_ELEM=%d",
	     JTRC_MAX_HEX_DATA_FOR_BEG_ELEM);
	jtrc(jtri, JTR_CONF, id, "JTRC_MAX_HEX_DATA_PER_ELEM=%d",
	     JTRC_MAX_HEX_DATA_PER_ELEM);

	jtrc_pfs(jtri, JTR_CONF, id, "preformatted_data, value1=%d", value1);

	jtrc_pfs(jtri, JTR_CONF, id,
		"preformatted_data, lots of args %d %d %d %d %d %d %d", value1,
		value1, value1, value1, value1, value1, value1);

	jtrc(jtri, JTR_CONF, id, "value1=%d", value1);

	jtrc_hexdump(jtri, JTR_CONF, id, "hex_dump_data", hex_dump_data, 27);

	jtrc_hexdump(jtri, JTR_CONF, id, "hex_dump_data",
		    hex_dump_data, JTRC_MAX_HEX_DATA_FOR_BEG_ELEM);

	jtrc(jtri, JTR_CONF, id, "value1=%d", value1);

	jtrc_hexdump(jtri, JTR_CONF, id, "hex_dump_data", hex_dump_data, 256);

	jtrc(jtri, JTR_CONF, id, "Last Entry");

	jtrace_print_tail(jtri, 3);

	jtrc_setprint(jtri, 0);
}
#endif

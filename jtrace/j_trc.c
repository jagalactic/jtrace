/*
 * j_trc.c 
 */

//#define J_TRC_TEST

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
#include "j_trc.h"

/* 
 * A reasonable amount of common flags.
 */
j_trc_flag_descriptor_t j_trc_common_flag_array[] = {
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
    {"XMIT", "Transmit activities"}
    ,
    {"DEBUG", "General debug"}
    ,
};

#define J_TRC_NUM_COMMON_FLAGS (sizeof(j_trc_common_flag_array)/sizeof(j_trc_flag_descriptor_t))
static int j_trc_num_common_flags = J_TRC_NUM_COMMON_FLAGS;

static spinlock_t j_trc_mutex = SPIN_LOCK_UNLOCKED;
static struct list_head j_trc_registered_mods =
LIST_HEAD_INIT(j_trc_registered_mods);
static int j_trc_num_registered_mods;

/*
 * local fuctions
 */
static void j_trc_v(j_trc_register_trc_info_t * ktr_infop, void *id,
		    struct timespec *tm,
                    const char *func, int line, char *fmt, va_list vap);

#define MIN(a,b) (((a)<(b))?(a):(b))
#define DUMP_HEX_BYTES_PER_LINE 16
static void dump_hex_line(char *buf_ptr, int buf_len);

void j_trc_print_element(j_trc_element_t * tp);
void j_trc_print_last_elems(j_trc_register_trc_info_t * ktr_infop,
                            int num_elems);

#if 0
static int j_trc_panic_event(struct notifier_block *, unsigned long event,
                             void *ptr);
static struct notifier_block j_trc_panic_block = {
    j_trc_panic_event,
    NULL,                       /* Next notifier block */
    INT_MAX                     /* try to do it first */
};
#endif

#ifdef J_TRC_TEST
static void j_trc_test(void);
#endif


/*
 * Find ktr_infop in j_trc_registered_mods list by address 
 */
static j_trc_register_trc_info_t
    * j_trc_find_trc_info_by_addr(j_trc_register_trc_info_t * ktr_infop)
{
    j_trc_register_trc_info_t *tmp_reg_infop = NULL;
    int found = 0;

    list_for_each_entry(tmp_reg_infop, &j_trc_registered_mods, j_trc_list) {
        if (tmp_reg_infop == ktr_infop) {
            found = 1;
            break;
        }
    }

    if (!found) {
        return (NULL);
    }
    return (tmp_reg_infop);
}

/*
 * Find trace info by name.
 */
static j_trc_register_trc_info_t *j_trc_find_trc_info_by_name(char
                                                              *trc_name)
{
    int found = 0;
    j_trc_register_trc_info_t *ktr_infop = NULL;

    list_for_each_entry(ktr_infop, &j_trc_registered_mods, j_trc_list) {
        if (strncmp(ktr_infop->mod_trc_info.j_trc_name, trc_name,
                    sizeof(ktr_infop->mod_trc_info.j_trc_name)) == 0) {
            found = 1;
            break;
        }
    }

    if (!found) {
        return (NULL);
    }
    return (ktr_infop);
}


#define CONDITIONAL_COPYOUT(objp, obj_size) do {\
    required_size += obj_size;\
    if(out_buffer && (objp) && (obj_size) && (rc == 0) && (required_size <= out_buffer_size) ){\
        rc = copy_to_user(out_buffer, (objp), (obj_size));\
        out_buffer += (obj_size);\
    }\
} while(0);

static int j_trc_get_all_trc_info(j_trc_cmd_req_t * cmd_req)
{
    char *out_buffer = 0;
    int out_buffer_size = 0;
    int required_size = 0;
    j_trc_register_trc_info_t *ktr_reg_infop = NULL;
    int i = 0;
    int rc = 0;

    if (!cmd_req) {
        return (EINVAL);
    }

    out_buffer = cmd_req->data;
    out_buffer_size = cmd_req->data_size;


    /* Output the number of common flags */
    CONDITIONAL_COPYOUT((char *) &j_trc_num_common_flags,
                        sizeof(j_trc_num_common_flags));

    /* Output common flag descriptors */
    for (i = 0; i < j_trc_num_common_flags; i++) {
        CONDITIONAL_COPYOUT((char *) &j_trc_common_flag_array[i],
                            sizeof(j_trc_flag_descriptor_t));
    }

    /* Output number of registered modules */
    CONDITIONAL_COPYOUT((char *) &j_trc_num_registered_mods,
                        sizeof(j_trc_num_registered_mods));


    /* Output each registered module's info */
    list_for_each_entry(ktr_reg_infop, &j_trc_registered_mods, j_trc_list) {
        CONDITIONAL_COPYOUT((char *) &ktr_reg_infop->mod_trc_info,
                            sizeof(j_trc_module_trc_info_t));
        /* Output each registered module's custom flags */
        for (i = 0; i < ktr_reg_infop->mod_trc_info.j_trc_num_custom_flags;
             i++) {
            CONDITIONAL_COPYOUT((char *) &ktr_reg_infop->custom_flags[i],
                                sizeof(j_trc_flag_descriptor_t));
        }
    }

    /* Always set required size */
    if (required_size > out_buffer_size) {
        rc = ENOMEM;
        cmd_req->data_size = required_size;
    }

    return (rc);
}


static int j_trc_snarf(j_trc_cmd_req_t * cmd_req)
{
    int rc = 0;

    if (!cmd_req) {
        return (EINVAL);
    }

    rc = copy_to_user(cmd_req->data, cmd_req->snarf_addr,
                      cmd_req->data_size);

    return (rc);
}


/*
 * IOCTL handler for j_trc
 */
int j_trc_cmd(j_trc_cmd_req_t * cmd_req)
{
	int rc = 0;
	j_trc_register_trc_info_t *ktr_infop = NULL;

	/* KTRCTL_GET_ALL_TRC_INFO does not require valid ktr_infop */
	if (cmd_req->cmd == KTRCTL_GET_ALL_TRC_INFO) {
		rc = j_trc_get_all_trc_info(cmd_req);
		cmd_req->status = rc;
		return (rc);
	}

	/* KTRCTL_SNARF does not require valid ktr_infop */
	if (cmd_req->cmd == KTRCTL_SNARF) {
		rc = j_trc_snarf(cmd_req);
		cmd_req->status = rc;
		return (rc);
	}

	/* All others require valid trc_name info */
	printk("ktr: find_info_by_name (%s)\n",
	       (cmd_req->trc_name) ? cmd_req->trc_name : "NULL");
	ktr_infop = j_trc_find_trc_info_by_name(cmd_req->trc_name);
	if (!ktr_infop) {
		cmd_req->status = ENODEV;
		return (ENODEV);
	}

	switch (cmd_req->cmd) {
	case KTRCTL_SET_PRINTK:
        {
		int value;
		printk("KTRCTL_SET_PRINTK\n");
		rc = copy_from_user((caddr_t) & value,
				    (caddr_t) cmd_req->data, sizeof(value));
		if (!((value == 0) || (value == 1))) {
			cmd_req->status = EINVAL;
			rc = EINVAL;
			break;
		}
		ktr_infop->mod_trc_info.j_trc_kprint_enabled = value;
		cmd_req->status = 0;
		rc = 0;
        }
        break;

	case KTRCTL_SET_TRC_FLAGS:
		rc = copy_from_user((caddr_t) 
			    &ktr_infop->mod_trc_info.j_trc_flags,
			    (caddr_t) cmd_req->data,
			    sizeof(ktr_infop->mod_trc_info.j_trc_flags));
		cmd_req->status = 0;
		rc = 0;
		break;
	case KTRCTL_CLEAR:
		ktr_infop->mod_trc_info.j_trc_buf_index = 0;
		memset((caddr_t) ktr_infop->mod_trc_info.j_trc_buf_ptr, 0,
		       ktr_infop->mod_trc_info.j_trc_buf_size);
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

#define J_TRC_KPRINT_BUF_SIZE 256
static char buf[J_TRC_KPRINT_BUF_SIZE];
static int idx = 0;


void j_trc_print_element(j_trc_element_t * tp)
{
	int prefix_len = 0;

	switch (tp->elem_fmt) {
	case KTRC_FORMAT_REGULAR:

        prefix_len = snprintf(buf, J_TRC_KPRINT_BUF_SIZE,
                              "%6.6d.%2.2d:%2.2d:%p:%p:%25.25s:%4d:",
                              tp->reg.tv_sec, tp->reg.tv_nsec / 10000,
                              tp->reg.cpu, tp->reg.tid,
                              tp->reg.id, tp->reg.func_name,
                              tp->reg.line_num);

        snprintf(&buf[prefix_len], J_TRC_KPRINT_BUF_SIZE - prefix_len,
                 tp->reg.fmt, tp->reg.a0, tp->reg.a1, tp->reg.a2,
                 tp->reg.a3, tp->reg.a4);
        printk("%s\n", buf);
        buf[0] = 0;
        idx = 0;

        break;

    case KTRC_HEX_DATA_BEGIN:
        {
            size_t binary_length = 0;
            char *binary_data = NULL;

            idx = 0;

            prefix_len = snprintf(buf, J_TRC_KPRINT_BUF_SIZE,
                                  "%6.6d.%2.2d:%2.2d:%p:%p:%25.25s:%4d:",
                                  tp->hex_begin.tv_sec,
                                  tp->hex_begin.tv_nsec / 10000000,
                                  tp->reg.cpu, tp->reg.tid,
                                  tp->hex_begin.id,
                                  tp->hex_begin.func_name,
                                  tp->hex_begin.line_num);

            snprintf(&buf[prefix_len], J_TRC_KPRINT_BUF_SIZE - prefix_len,
                     "hex: %s len=0x%x", tp->hex_begin.msg,
                     tp->hex_begin.total_length);

            binary_length =
                (size_t) MIN(tp->hex_begin.total_length,
                             J_TRC_MAX_HEX_DATA_FOR_BEG_ELEM);

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

    case KTRC_HEX_DATA_CONTINUE:
    case KTRC_HEX_DATA_END:
        {
            size_t binary_length = 0;
            char *binary_data = NULL;

            binary_length =
                (size_t) MIN(tp->hex.length, J_TRC_MAX_HEX_DATA_PER_ELEM);

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

        if (tp->elem_fmt == KTRC_HEX_DATA_END) {
            buf[0] = 0;
            idx = 0;
        }

        break;

    case KTRC_PREFORMATTED_STR_BEGIN:
        {
            idx = 0;

            prefix_len = snprintf(buf, J_TRC_KPRINT_BUF_SIZE,
                                  "%6.6d.%2.2d:%2.2d:%p:%p:%25.25s:%4d:",
                                  tp->pfs_begin.tv_sec,
                                  tp->pfs_begin.tv_nsec / 10000000,
                                  tp->pfs_begin.cpu, tp->pfs_begin.tid,
                                  tp->pfs_begin.id,
                                  tp->pfs_begin.func_name,
                                  tp->pfs_begin.line_num);

            snprintf(&buf[prefix_len], J_TRC_KPRINT_BUF_SIZE - prefix_len,
                     "%s", (char *) &tp->pfs_begin.data_start);
            printk("%s\n", buf);
            buf[0] = 0;
            idx = 0;
        }
        break;

    case KTRC_PREFORMATTED_STR_CONTINUE:
    case KTRC_PREFORMATTED_STR_END:
        {
            printk("%s\n", (char *) &tp->pfs_continue.data_start);

            if (tp->elem_fmt == KTRC_PREFORMATTED_STR_END) {
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


void j_trc_print_last_elems(j_trc_register_trc_info_t * ktr_infop,
                            int num_elems)
{
    /* Back up the index num_elems slots */
    int32_t temp_index =
        ktr_infop->mod_trc_info.j_trc_buf_index - num_elems;
    register j_trc_element_t *tp = NULL;
    int i = 0;

    if (temp_index < 0) {
        temp_index += ktr_infop->mod_trc_info.j_trc_num_entries;
    }

    tp = &ktr_infop->mod_trc_info.j_trc_buf_ptr[temp_index];

    /* 
     * If we are in the middle of a hex dump or string,
     * go back to BEGIN so we can get the context.
     */
    while ((tp->elem_fmt == KTRC_HEX_DATA_END) ||
           (tp->elem_fmt == KTRC_HEX_DATA_CONTINUE) ||
           (tp->elem_fmt == KTRC_PREFORMATTED_STR_CONTINUE) ||
           (tp->elem_fmt == KTRC_PREFORMATTED_STR_END)) {
        num_elems++;

        temp_index = ktr_infop->mod_trc_info.j_trc_buf_index - num_elems;
        if (temp_index < 0) {
            temp_index += ktr_infop->mod_trc_info.j_trc_num_entries;
        }

        tp = &ktr_infop->mod_trc_info.j_trc_buf_ptr[temp_index];
    }

    temp_index = ktr_infop->mod_trc_info.j_trc_buf_index - num_elems;

    if (temp_index < 0) {
        temp_index += ktr_infop->mod_trc_info.j_trc_num_entries;
    }

    for (i = 0; i < num_elems; i++) {
        tp = &ktr_infop->mod_trc_info.j_trc_buf_ptr[temp_index];
        j_trc_print_element(tp);

        temp_index++;
        if (temp_index > ktr_infop->mod_trc_info.j_trc_num_entries - 1) {
            temp_index = 0;
        }
    }
    return;
}

/*
 * j_trc_v - add trace entries to buffer
 */
static void
j_trc_v(j_trc_register_trc_info_t * ktr_infop, void *id,
	struct timespec *tm,
        const char *func_name, int line_num, char *fmt, va_list vap)
{
	register j_trc_element_t *tp;
	struct timespec time;
	unsigned long flags;

	spin_lock_irqsave(&ktr_infop->j_trc_buf_mutex, flags);

	if (!tm) {
		tm = &time;
		/* XXX: this is slow; need to just read the clock */
		getnstimeofday(&time);
	}

	/* Increment index and handle wrap */
	ktr_infop->mod_trc_info.j_trc_buf_index++;
	if (ktr_infop->mod_trc_info.j_trc_buf_index >
	    (ktr_infop->mod_trc_info.j_trc_num_entries - 1)) {
		ktr_infop->mod_trc_info.j_trc_buf_index = 0;
	}
	
	tp = &ktr_infop->mod_trc_info.j_trc_buf_ptr[ktr_infop->mod_trc_info.
						    j_trc_buf_index];

	tp->elem_fmt = KTRC_FORMAT_REGULAR;
	tp->reg.tv_sec = tm->tv_sec;
	tp->reg.tv_nsec = tm->tv_nsec;
	tp->reg.cpu = smp_processor_id();
	tp->reg.tid = (void *) current;
	tp->reg.func_name = func_name;
	tp->reg.line_num = line_num;
	tp->reg.id = id;
	tp->reg.fmt = fmt;
	tp->reg.a0 = va_arg(vap, j_trc_arg_t);
	tp->reg.a1 = va_arg(vap, j_trc_arg_t);
	tp->reg.a2 = va_arg(vap, j_trc_arg_t);
	tp->reg.a3 = va_arg(vap, j_trc_arg_t);
	tp->reg.a4 = va_arg(vap, j_trc_arg_t);

	/* 
	 * If things are really crashing, enable j_trc_kprint_enabled = 1 
	 * for output to the console.
	 */
	//printk("j_trc_v: addr %p\n", tp);
	if (ktr_infop->mod_trc_info.j_trc_kprint_enabled) {
		j_trc_print_element(tp);
	}
	spin_unlock_irqrestore(&ktr_infop->j_trc_buf_mutex, flags);

}


/*
 * _j_trace -    add trace entries to buffer
 */
void _j_trace(j_trc_register_trc_info_t * ktr_infop, void *id,
	      struct timespec *tm,
              const char *func, int line, char *fmt, ...)
{
    va_list vap;

    va_start(vap, fmt);

    j_trc_v(ktr_infop, id, tm, func, line, fmt, vap);

    va_end(vap);
}

/*
 * j_trc_preformatted_str_v - add trace entries to buffer
 */
static void
j_trc_preformatted_str(j_trc_register_trc_info_t * ktr_infop, void *id,
                       const char *func_name, int line_num, char *buf,
                       int str_len)
{
    register j_trc_element_t *tp;
    struct timespec time;
    j_trc_element_fmt_t elem_fmt;

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


    ktr_infop->mod_trc_info.j_trc_buf_index++;
    if (ktr_infop->mod_trc_info.j_trc_buf_index >
        (ktr_infop->mod_trc_info.j_trc_num_entries - 1)) {
        ktr_infop->mod_trc_info.j_trc_buf_index = 0;
    }

    tp = &ktr_infop->mod_trc_info.j_trc_buf_ptr[ktr_infop->mod_trc_info.
                                                j_trc_buf_index];

    tp->elem_fmt = KTRC_PREFORMATTED_STR_BEGIN;
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
        MIN((in_buf_end - in_buf), J_TRC_MAX_PREFMT_STR_FOR_BEG_ELEM);
    out_buf = (char *) &tp->pfs_begin.data_start;
    memcpy(out_buf, in_buf, length2);
    out_buf += length2;
    /* Terminate string */
    *out_buf = 0;

    if (ktr_infop->mod_trc_info.j_trc_kprint_enabled) {
        j_trc_print_element(tp);
    }

    in_buf += length2;

    /* Fill in remaining elements */
    if (in_buf < in_buf_end) {
        elem_fmt = KTRC_PREFORMATTED_STR_CONTINUE;
        while (in_buf < in_buf_end) {
            length2 =
                MIN((in_buf_end - in_buf), J_TRC_MAX_PREFMT_STR_PER_ELEM);

            ktr_infop->mod_trc_info.j_trc_buf_index++;
            if (ktr_infop->mod_trc_info.j_trc_buf_index >
                (ktr_infop->mod_trc_info.j_trc_num_entries - 1)) {
                ktr_infop->mod_trc_info.j_trc_buf_index = 0;
            }
            tp = &ktr_infop->mod_trc_info.j_trc_buf_ptr[ktr_infop->
                                                        mod_trc_info.
                                                        j_trc_buf_index];

            tp->elem_fmt = elem_fmt;
            tp->pfs_continue.length = length2;

            out_buf = (char *) &tp->pfs_continue.data_start;

            memcpy(out_buf, in_buf, length2);
            out_buf += length2;
            /* Terminate string */
            *out_buf = 0;


            if (ktr_infop->mod_trc_info.j_trc_kprint_enabled) {
                j_trc_print_element(tp);
            }

            in_buf += length2;
            elem_fmt = KTRC_PREFORMATTED_STR_CONTINUE;
        }
        tp->elem_fmt = KTRC_PREFORMATTED_STR_END;
    }
}

#define MAX_PREFORMATTED_STR_LEN 256
static char pre_fmt_buf[MAX_PREFORMATTED_STR_LEN];
void _j_trace_preformated_str(j_trc_register_trc_info_t * ktr_infop,
                              void *id, const char *func, int line,
                              char *fmt, ...)
{
    int str_len = 0;
    va_list vap;
    unsigned long flags;

    spin_lock_irqsave(&ktr_infop->j_trc_buf_mutex, flags);
    va_start(vap, fmt);
    str_len = vsnprintf(pre_fmt_buf, MAX_PREFORMATTED_STR_LEN, fmt, vap);
    va_end(vap);

    j_trc_preformatted_str(ktr_infop, id, func, line, pre_fmt_buf,
                           str_len);
    spin_unlock_irqrestore(&ktr_infop->j_trc_buf_mutex, flags);
}

#define MAX_HEX_BUF 1024
/*
 * _j_trc_hex_dump - add a HEX dump to the trace
 */
void
_j_trc_hex_dump(j_trc_register_trc_info_t * ktr_infop, const char *func,
                uint line, void *id, char *msg, void *p, uint len)
{
    register j_trc_element_t *tp = NULL;
    int max_len = 0;
    char *in_buf = (char *) p;
    char *in_buf_end = NULL;
    char *out_buf = NULL;
    struct timespec time;
    unsigned long flags;
    j_trc_element_fmt_t elem_fmt;
    unsigned char length2;

    if (!p) {
        return;
    }

    max_len = MIN(len, MAX_HEX_BUF);
    in_buf_end = in_buf + max_len;

    spin_lock_irqsave(&ktr_infop->j_trc_buf_mutex, flags);

    getnstimeofday(&time);

    ktr_infop->mod_trc_info.j_trc_buf_index++;
    if (ktr_infop->mod_trc_info.j_trc_buf_index >
        (ktr_infop->mod_trc_info.j_trc_num_entries - 1)) {
        ktr_infop->mod_trc_info.j_trc_buf_index = 0;
    }

    tp = &ktr_infop->mod_trc_info.j_trc_buf_ptr[ktr_infop->mod_trc_info.
                                                j_trc_buf_index];

    tp->elem_fmt = KTRC_HEX_DATA_BEGIN;
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
    length2 = MIN((in_buf_end - in_buf), J_TRC_MAX_HEX_DATA_FOR_BEG_ELEM);
    out_buf = (char *) &tp->hex_begin.data_start;
    memcpy(out_buf, in_buf, length2);

    if (ktr_infop->mod_trc_info.j_trc_kprint_enabled) {
        j_trc_print_element(tp);
    }

    in_buf += length2;

    /* Fill in remaining elements */
    if (in_buf < in_buf_end) {
        elem_fmt = KTRC_HEX_DATA_CONTINUE;
        while (in_buf < in_buf_end) {
            length2 =
                MIN((in_buf_end - in_buf), J_TRC_MAX_HEX_DATA_PER_ELEM);

            ktr_infop->mod_trc_info.j_trc_buf_index++;
            if (ktr_infop->mod_trc_info.j_trc_buf_index >
                (ktr_infop->mod_trc_info.j_trc_num_entries - 1)) {
                ktr_infop->mod_trc_info.j_trc_buf_index = 0;
            }

            tp = &ktr_infop->mod_trc_info.j_trc_buf_ptr[ktr_infop->
                                                        mod_trc_info.
                                                        j_trc_buf_index];
            tp->elem_fmt = elem_fmt;
            tp->hex.length = length2;

            out_buf = (char *) &tp->hex.data_start;

            memcpy(out_buf, in_buf, length2);

            if (ktr_infop->mod_trc_info.j_trc_kprint_enabled) {
                j_trc_print_element(tp);
            }

            in_buf += length2;
            elem_fmt = KTRC_HEX_DATA_CONTINUE;
        }
        tp->elem_fmt = KTRC_HEX_DATA_END;
    }

    spin_unlock_irqrestore(&ktr_infop->j_trc_buf_mutex, flags);

}

#ifdef JUST_TOC_PRINT_HOWTO_DONT_DEFINE
/* 
 * This section explains changes to the linux kernel 
 * to support the TOC trace buffer print. Don't define 
 * JUST_TOC_PRINT_HOWTO_DONT_DEFINE.
 *
 * A TOC is a "transfer of control" on HP systems.
 * It can be used to for a re-initialization on hung
 * systems. Methods of issueing a TOC vary depending
 * on the system. On the rx2600, there is a small blue
 * button that can be depressed to force a TOC.
 * Also, from the service processor "CM" menu a TOC
 * can be started by issuing "TC". The service
 * processor console can be accessed by "CTRL-b" on 
 * a system serial console, at least on the rx2600
 *
 * Using the TOC print requires a couple of simple
 * change to the linux kernel.
 *

 * Change the file:
 * 
 * arch/ia64/kernel/mca.c:
 *
 * so that the function init_handler_platform() will call 
 * panic() upon TOC.
 * CHANGED FUNCTION:
 */
void init_handler_platform(struct pt_regs *regs)
{
    /* if a kernel debugger is available call it here else just dump the registers */

    show_regs(regs);            /* dump the state info */
    /*
     * LINE ADDED: Just panic since there is no kernel debugger. 
     * panic() will call j_trc_panic_event() to print trace buffer 
     * entries.
     */
    panic("init_handler_platform: no kernel debugger, just panicing.\n");
    while (1);                  /* hang city if no debugger */
}

/* 
 * Now the new kernel must be rebuild and loaded.
 */
#endif


#if 0
static int j_trc_has_paniced = 0;

static int j_trc_panic_event(struct notifier_block *this,
                             unsigned long event, void *ptr)
{
    j_trc_register_trc_info_t *ktr_infop;

    if (j_trc_has_paniced) {
        return NOTIFY_DONE;
    }
    j_trc_has_paniced = 1;

    list_for_each_entry(ktr_infop, &j_trc_registered_mods, j_trc_list) {
        j_trc_print_last_elems(ktr_infop, 500);
    }

    return NOTIFY_DONE;
}
#endif

/* 
 * Register new trace buffer information 
 */
int j_trc_register_trc_info(j_trc_register_trc_info_t * ktr_infop)
{
	unsigned long flags;

	if (strnlen(ktr_infop->mod_trc_info.j_trc_name,
		    sizeof(ktr_infop->mod_trc_info.j_trc_name)) == 0) {
		printk("ERROR: j_trc_register_trc_info: "
		       "j_trc_name must be non-NULL\n");
		return (EINVAL);
	}

	if (ktr_infop->mod_trc_info.
	    j_trc_custom_flags_mask & KTR_COMMON_FLAGS_MASK) {
		printk("ERROR: j_trc_register_trc_info: Custom flag values "
		       "contain reserved KTR_COMMON_FLAGS_MASK\n");
		return (EINVAL);
	}

	spin_lock_irqsave(&j_trc_mutex, flags);

	if (j_trc_find_trc_info_by_addr(ktr_infop) ||
	    j_trc_find_trc_info_by_name(ktr_infop->mod_trc_info.j_trc_name)) {
		printk("j_trc_register_trc_info: EALREADY\n");
		spin_unlock_irqrestore(&j_trc_mutex, flags);
		return (EALREADY);
	}

	spin_lock_init(&ktr_infop->j_trc_buf_mutex);
	ktr_infop->mod_trc_info.j_trc_buf_index = 0;
	memset((caddr_t) ktr_infop->mod_trc_info.j_trc_buf_ptr, 0,
	       ktr_infop->mod_trc_info.j_trc_buf_size);
	list_add_tail(&ktr_infop->j_trc_list, &j_trc_registered_mods);
	j_trc_num_registered_mods++;
	ktr_infop->use_count++;

	spin_unlock_irqrestore(&j_trc_mutex, flags);

	return (0);
}

/* 
 * Use existing trace buffer information 
 */
j_trc_register_trc_info_t *j_trc_use_registered_trc_info(char *name)
{
	j_trc_register_trc_info_t *tmp_reg_infop;
	unsigned long flags;

	spin_lock_irqsave(&j_trc_mutex, flags);
	tmp_reg_infop = j_trc_find_trc_info_by_name(name);

	if (!tmp_reg_infop) {
		spin_unlock_irqrestore(&j_trc_mutex, flags);
		return (0);
	}

	tmp_reg_infop->use_count++;
	spin_unlock_irqrestore(&j_trc_mutex, flags);
	return (tmp_reg_infop);
}

/* Unregister module trace information */
void j_trc_unregister_trc_info(j_trc_register_trc_info_t * ktr_infop)
{
	unsigned long flags;

	spin_lock_irqsave(&j_trc_mutex, flags);
	if (!j_trc_find_trc_info_by_addr(ktr_infop)) {
		spin_unlock_irqrestore(&j_trc_mutex, flags);
		return;
	}

	ktr_infop->use_count--;
	if (ktr_infop->use_count == 0) {
		list_del(&ktr_infop->j_trc_list);
		j_trc_num_registered_mods--;
	}

	spin_unlock_irqrestore(&j_trc_mutex, flags);
	return;
}

#define  J_TRC_DEFAULT_NUM_ELEMENTS  (0x100000) /* # trace entries  */
static j_trc_element_t j_trc_default_buf[J_TRC_DEFAULT_NUM_ELEMENTS];
static j_trc_register_trc_info_t j_trc_default_info;
j_trc_register_trc_info_t *j_trc_reg_infop = NULL;


#define DEFAULT_BUF_NAME "j_trc_default"

int j_trc_init(void)
{

	int result;

	//notifier_chain_register(&panic_notifier_list, &j_trc_panic_block);

	strncpy(j_trc_default_info.mod_trc_info.j_trc_name,
		DEFAULT_BUF_NAME,
		sizeof(j_trc_default_info.mod_trc_info.j_trc_name));
	j_trc_default_info.mod_trc_info.j_trc_buf_ptr = &j_trc_default_buf[0];
	j_trc_default_info.mod_trc_info.j_trc_num_entries =
		J_TRC_DEFAULT_NUM_ELEMENTS;
	j_trc_default_info.mod_trc_info.j_trc_buf_size =
		sizeof(j_trc_default_buf);
	j_trc_default_info.mod_trc_info.j_trc_buf_index = 0;
	j_trc_default_info.mod_trc_info.j_trc_kprint_enabled = 0;
	j_trc_default_info.mod_trc_info.j_trc_flags = KTR_COMMON_FLAGS_MASK;

	result = j_trc_register_trc_info(&j_trc_default_info);
	if (result) {
		return (result);
	}

	j_trc_reg_infop = &j_trc_default_info;
#ifdef J_TRC_TEST
	j_trc_test();
#endif

	return 0;

}

void j_trc_exit(void)
{
	if (j_trc_reg_infop) {
		j_trc_unregister_trc_info(j_trc_reg_infop);
	}

	//notifier_chain_unregister(&panic_notifier_list, &j_trc_panic_block);

	return;
}

#ifdef J_TRC_TEST

static void j_trc_test(void)
{
    char *id = 0;
    int value1 = 1;
    //int value2 = 2;
    char hex_dump_data[512];
    int i = 0;

    for (i = 0; i < 512; i++) {
        hex_dump_data[i] = (char) (i & 0xff);
    }

    kTrcPrintkSet(1);

    kTrc(KTR_CONF, id, "First Entry");

    kTrc(KTR_CONF, id, "sizeof(j_trc_element_t)=%d",
         sizeof(j_trc_element_t));
    kTrc(KTR_CONF, id, "sizeof(j_trc_regular_element_t)=%d",
         sizeof(j_trc_regular_element_t));
    kTrc(KTR_CONF, id, "sizeof(j_trc_hex_begin_element_t)=%d",
         sizeof(j_trc_hex_begin_element_t));
    kTrc(KTR_CONF, id, "sizeof(j_trc_hex_element_t)=%d",
         sizeof(j_trc_hex_element_t));
    kTrc(KTR_CONF, id, "sizeof(j_trc_element_fmt_t)=%d",
         sizeof(j_trc_element_fmt_t));
    kTrc(KTR_CONF, id, "offsetof(j_trc_element_t, elem_fmt)=%d",
         offsetof(j_trc_element_t, elem_fmt));
    kTrc(KTR_CONF, id, "offsetof(j_trc_element_t, hex.length)=%d",
         offsetof(j_trc_element_t, hex.length));
    kTrc(KTR_CONF, id, "offsetof(j_trc_element_t, hex.data_start)=%d",
         offsetof(j_trc_element_t, hex.data_start));
    kTrc(KTR_CONF, id,
         "offsetof(j_trc_element_t, hex_begin.total_length)=%d",
         offsetof(j_trc_element_t, hex_begin.total_length));
    kTrc(KTR_CONF, id,
         "offsetof(j_trc_element_t, hex_begin.data_start)=%d",
         offsetof(j_trc_element_t, hex_begin.data_start));
    kTrc(KTR_CONF, id, "J_TRC_MAX_HEX_DATA_FOR_BEG_ELEM=%d",
         J_TRC_MAX_HEX_DATA_FOR_BEG_ELEM);
    kTrc(KTR_CONF, id, "J_TRC_MAX_HEX_DATA_PER_ELEM=%d",
         J_TRC_MAX_HEX_DATA_PER_ELEM);

    kTrcPFS(KTR_CONF, id, "preformatted_data, value1=%d", value1);

    kTrcPFS(KTR_CONF, id,
            "preformatted_data, lots of args %d %d %d %d %d %d %d", value1,
            value1, value1, value1, value1, value1, value1);

    kTrc(KTR_CONF, id, "value1=%d", value1);

    kTrcHexDump(KTR_CONF, id, "hex_dump_data", hex_dump_data, 27);

    kTrcHexDump(KTR_CONF, id, "hex_dump_data",
                hex_dump_data, J_TRC_MAX_HEX_DATA_FOR_BEG_ELEM);

    kTrc(KTR_CONF, id, "value1=%d", value1);

    kTrcHexDump(KTR_CONF, id, "hex_dump_data", hex_dump_data, 256);


    kTrc(KTR_CONF, id, "Last Entry");

    j_trc_print_last_elems(j_trc_reg_infop, 3);

    kTrcPrintkSet(0);
}
#endif

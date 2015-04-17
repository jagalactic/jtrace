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
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/smp.h>
#include <linux/slab.h>

#include "jtrace.h"
#include "jtrace_common.h"

/*
 * A reasonable amount of common flags.
 */
struct jtrc_flag_descriptor jtrc_common_flag_array[] = {
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

#define JTRC_NUM_COMMON_FLAGS (sizeof(jtrc_common_flag_array)		\
			       / sizeof(struct jtrc_flag_descriptor))
static int jtrc_num_common_flags = JTRC_NUM_COMMON_FLAGS;

/**
 *
 * This is the kernel-mode list of extant jtrace instances
 */
DEFINE_SPINLOCK(jtrc_config_lock);

int jtrc_num_instances;

static void dump_hex_line(char *buf_ptr, int buf_len);

#ifdef JTRC_TEST
static void jtrc_test(void);
#endif

/**
 * __free_jtrace_instance()
 *
 * Called from jtrace_common.c to free allocated resources.  Kernel and user
 * must provide separate versions of this function.
 */
void __free_jtrace_instance(struct jtrace_instance *jt)
{
	vfree(jt->jtrc_cb.jtrc_buf);
	kfree(jt);
}

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
	    (obj_size <= *out_buf_remainder)) {
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
 * 4. the (module_trc_info_t, (struct jtrc_flag_descriptor, ...))
 *    set for each module
 */
static int jtrc_get_all_trc_info(struct jtrc_cmd_req *cmd_req)
{
	char *out_buffer = 0;
	int out_buf_remainder = 0;
	int total_bytes = 0;
	struct jtrace_instance *jtri = NULL;
	int i = 0;
	int rc = 0;
	int req_size;

	if (!cmd_req)
		return -EINVAL;

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
			       sizeof(struct jtrc_flag_descriptor),
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
	list_for_each_entry(jtri, &jtrc_instance_list, jtrc_list) {
		copyout_append(&out_buffer,
			       (char *) &jtri->jtrc_cb,
			       sizeof(struct jtrc_cb),
			       &total_bytes,
			       &out_buf_remainder);

		/* Output each registered module's custom flags */
		for (i = 0;
		     i < jtri->jtrc_cb.jtrc_num_custom_flags;
		     i++) {
			copyout_append(&out_buffer,
				       &jtri->custom_flags[i],
				       sizeof(struct jtrc_flag_descriptor),
				       &total_bytes,
				       &out_buf_remainder);
		}
	}

	/* Always set required size */
	if (total_bytes != cmd_req->data_size)
		cmd_req->data_size = total_bytes;

	return rc;
}


static int jtrc_snarf(struct jtrc_cmd_req *cmd_req)
{
	int rc = 0;

	if (!cmd_req)
		return -EINVAL;

	rc = copy_to_user(cmd_req->data, cmd_req->snarf_addr,
			  cmd_req->data_size);

	return rc;
}


/**
 * jtrace_cmd()
 *
 * IOCTL handler for jtrc
 *
 * @cmd_req - struct jtrc_cmd_req struct, describing what the caller wants
 */
int jtrace_cmd(struct jtrc_cmd_req *cmd_req, void *uaddr)
{
	int rc = 0;
	struct jtrace_instance *jt = NULL;

	/* JTRCTL_GET_ALL_TRC_INFO does not require valid jtrace context */
	if (cmd_req->cmd == JTRCTL_GET_ALL_TRC_INFO) {
		rc = jtrc_get_all_trc_info(cmd_req);
		cmd_req->status = rc;
		if (rc == 0)
			rc = copy_to_user(uaddr, cmd_req, sizeof(*cmd_req));
		return rc;
	}

	/* JTRCTL_SNARF does not require valid jt */
	if (cmd_req->cmd == JTRCTL_SNARF) {
		rc = jtrc_snarf(cmd_req);
		cmd_req->status = rc;
		return rc;
	}

	/* All others require valid trc_name info */
	jt = jtrc_find_get_instance(cmd_req->trc_name);
	if (!jt) {
		cmd_req->status = ENODEV;
		return -ENODEV;
	}

	switch (cmd_req->cmd) {
	case JTRCTL_SET_PRINTK:
	{
		/* Turn printk on & off */
		int value;

		rc = copy_from_user((caddr_t) &value,
				    (caddr_t) cmd_req->data, sizeof(value));
		if (!((value == 0) || (value == 1))) {
			cmd_req->status = EINVAL;
			rc = EINVAL;
			break;
		}
		jt->jtrc_cb.jtrc_kprint_enabled = value;
		pr_info("JTRCTL_SET_PRINTK %d\n", value);
		cmd_req->status = 0;
		rc = 0;
	}
	break;

	case JTRCTL_SET_TRC_FLAGS:
		/* Set the flag mask which controls what is traced */
		rc = copy_from_user((caddr_t)
			    &jt->jtrc_cb.jtrc_flags,
			    (caddr_t) cmd_req->data,
			    sizeof(jt->jtrc_cb.jtrc_flags));
		cmd_req->status = 0;
		rc = 0;
		break;

	case JTRCTL_CLEAR:
		/* Clear the trace buffer(s) */
		jt->jtrc_cb.jtrc_buf_index = 0;
		memset((caddr_t) jt->jtrc_cb.jtrc_buf, 0,
		       jt->jtrc_cb.jtrc_buf_size);
		rc = 0;
		break;

	default:
		cmd_req->status = EINVAL;
		return -EINVAL;
	}

	return rc;
}

#define DUMP_HEX_BYTES_PER_LINE 16

void dump_hex_line(char *buf_ptr, int buf_len)
{
	int idx;
	char ch;
#ifdef OUTPUT_EBCIDIC_TOO
	int ebcdic_ch;
#endif

	/* Print the hexadecimal values */
	for (idx = 0; idx < DUMP_HEX_BYTES_PER_LINE; idx++) {
		if (idx < buf_len)
			printk("%02x ", ((int) buf_ptr[idx]) & 0xff);
		else
			printk("   ");
	}
	printk("  ");
	/* Translate and print hex to ASCII values */
	for (idx = 0; idx < DUMP_HEX_BYTES_PER_LINE; idx++) {
		if (idx < buf_len) {
			ch = buf_ptr[idx];
			if ((ch < 0x20) || (ch > 0x7e))
				printk(".");
			else
				printk("%c", buf_ptr[idx]);
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
static int idx;

/**
 * jtrc_print_element()
 *
 * @tp - the trace element to print
 *
 * This prints a trace element to the system log (printk) in an
 * element-type-dependent format
 */
void jtrc_print_element(struct jtrc_entry *tp)
{
	int prefix_len = 0;

	switch (tp->elem_fmt) {
	case JTRC_FORMAT_REGULAR:

	prefix_len = snprintf(buf, JTRC_KPRINT_BUF_SIZE,
			      "%ld : %2.2d:%p:%p:%25.25s:%4d:",
			      tp->reg.tscp,
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
				  "%ld : %2.2d:%p:%p:%25.25s:%4d:",
				  tp->hex_begin.tscp,
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
		(size_t)MIN(tp->hex_continue.length,
			    JTRC_MAX_HEX_DATA_PER_ELEM);

	    /* The binary data starts at the data_start location */
	    binary_data = (char *)&tp->hex_continue.data_start;

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
		idx = 0;

		prefix_len = snprintf(buf, JTRC_KPRINT_BUF_SIZE,
				      "%ld : %2.2d:%p:%p:%25.25s:%4d:",
				      tp->pfs_begin.tscp,
				      tp->pfs_begin.cpu, tp->pfs_begin.tid,
				      tp->pfs_begin.id,
				      tp->pfs_begin.func_name,
				      tp->pfs_begin.line_num);

		snprintf(&buf[prefix_len], JTRC_KPRINT_BUF_SIZE - prefix_len,
			 "%s", (char *) &tp->pfs_begin.data_start);
		printk("%s\n", buf);
		buf[0] = 0;
		idx = 0;
		break;

	case JTRC_PREFORMATTED_STR_CONTINUE:
	case JTRC_PREFORMATTED_STR_END:
		printk("%s\n", (char *) &tp->pfs_continue.data_start);

		if (tp->elem_fmt == JTRC_PREFORMATTED_STR_END) {
			buf[0] = 0;
			idx = 0;
		}
		break;

	case JTRC_FORMAT_INVALID:
		/* Ignore invalid entries */
		break;

	}
}


/**
 * jtrace_print_tail()
 *
 * @jt      - the jtrace instance
 * @num_elems - the number of elements to print, at the tail of the trace
 */
void jtrace_print_tail(struct jtrace_instance *jt,
			    int num_elems)
{
	/* Back up the index num_elems slots */
	int32_t temp_index =
		jt->jtrc_cb.jtrc_buf_index - num_elems;
	register struct jtrc_entry *tp = NULL;
	int i = 0;

	if (temp_index < 0)
		temp_index += jt->jtrc_cb.jtrc_num_entries;

	tp = &jt->jtrc_cb.jtrc_buf[temp_index];

	/*
	 * If we are in the middle of a hex dump or string,
	 * go back to BEGIN so we can get the context.
	 */
	while ((tp->elem_fmt == JTRC_HEX_DATA_END) ||
	       (tp->elem_fmt == JTRC_HEX_DATA_CONTINUE) ||
	       (tp->elem_fmt == JTRC_PREFORMATTED_STR_CONTINUE) ||
	       (tp->elem_fmt == JTRC_PREFORMATTED_STR_END)) {
		num_elems++;

		temp_index = jt->jtrc_cb.jtrc_buf_index - num_elems;
		if (temp_index < 0)
			temp_index += jt->jtrc_cb.jtrc_num_entries;

		tp = &jt->jtrc_cb.jtrc_buf[temp_index];
	}

	temp_index = jt->jtrc_cb.jtrc_buf_index - num_elems;

	if (temp_index < 0)
		temp_index += jt->jtrc_cb.jtrc_num_entries;

	for (i = 0; i < num_elems; i++) {
		tp = &jt->jtrc_cb.jtrc_buf[temp_index];
		jtrc_print_element(tp);

		temp_index++;
		if (temp_index > jt->jtrc_cb.jtrc_num_entries - 1)
			temp_index = 0;
	}
}
EXPORT_SYMBOL(jtrace_print_tail);

/* Put stuff in trace buffers *********************************************/


/***************************************************************************/


/* Module Parameters */
int num_trc_elements = 0x100000;
module_param(num_trc_elements, int, 0444); /* Can't be changed, must re-load */

/**
 * jtrace_init()
 *
 * Initialize the default jtrace instance.
 */
static int
__jtrace_init(int32_t num_slots)
{
	int result;
	struct jtrace_instance *jtri = NULL;

	/*
	 * Create the default jtrace instance
	 */
	jtri = kmalloc(sizeof(struct jtrace_instance), GFP_KERNEL);
	if (!jtri)
		return -ENOMEM;

	memset(jtri, 0, sizeof(*jtri));

	/* We automatically init a trace buffer with JTRC_DEFAULT_NAME
	 * at module init time. */
	jtri->jtrc_cb.jtrc_context = KERNEL;
	strncpy(jtri->jtrc_cb.jtrc_name,
		JTRC_DEFAULT_NAME, sizeof(jtri->jtrc_cb.jtrc_name));
	jtri->jtrc_cb.jtrc_buf = NULL;
	jtri->jtrc_cb.jtrc_num_entries = num_slots;
	jtri->jtrc_cb.jtrc_buf_size = num_slots * sizeof(struct jtrc_entry);

	jtri->jtrc_cb.jtrc_buf_index = 0;
	jtri->jtrc_cb.jtrc_kprint_enabled = 0;
	jtri->jtrc_cb.jtrc_flags = JTR_COMMON_FLAGS_MASK;
	spin_lock_init(&jtri->jtrc_buf_mutex);

	if (!jtri->jtrc_cb.jtrc_buf) {
		jtri->jtrc_cb.jtrc_buf =
			vmalloc_user(jtri->jtrc_cb.jtrc_buf_size);
		if (!jtri->jtrc_cb.jtrc_buf) {
			pr_info("%s: vmalloc failed\n", __func__);
			return -ENOMEM;
		}
	}

	result = jtrace_register_instance(jtri);
	if (result) {
		vfree(jtri->jtrc_cb.jtrc_buf);
		kfree(jtri);
		return result;
	}

#ifdef JTRC_TEST
	jtrc_test();
#endif

	return 0;

}

int jtrace_init(void)
{
	return __jtrace_init(num_trc_elements);
}

void jtrace_exit(void)
{
	struct jtrace_instance *jtri;
	struct list_head *this, *next;

	list_for_each_safe(this, next, &jtrc_instance_list) {
		jtri = list_entry(this, struct jtrace_instance, jtrc_list);
		pr_info("jtrace: unloading instance %s\n",
		       jtri->jtrc_cb.jtrc_name);
		jtrace_put_instance(jtri);
	}
}

#ifdef JTRC_TEST

static void jtrc_test(void)
{
	char *id = 0;
	int value1 = 1;
	char hex_dump_data[512];
	int i = 0;
	struct jtrace_instance *jtri;

	jtri = jtrc_default_instance();
	if (jtrace_get_instance(jtri)) {
		pr_info("jtrc_test: failed refount on default instance\n");
		return;
	}

	for (i = 0; i < 512; i++)
		hex_dump_data[i] = (char) (i & 0xff);

	jtrc_setprint(jtri, 1);

	jtrc(jtri, JTR_CONF, id, "First Entry");

	jtrc(jtri, JTR_CONF, id, "sizeof(struct jtrc_entry)=%d",
	     sizeof(struct jtrc_entry));
	jtrc(jtri, JTR_CONF, id, "sizeof(struct jtrc_reg_entry)=%d",
	     sizeof(struct jtrc_reg_entry));
	jtrc(jtri, JTR_CONF, id, "sizeof(struct jtrc_hex_entry)=%d",
	     sizeof(struct jtrc_hex_entry));
	jtrc(jtri, JTR_CONF, id, "sizeof(struct jtrc_hex_continue)=%d",
	     sizeof(struct jtrc_hex_continue));
	jtrc(jtri, JTR_CONF, id, "sizeof(enum jtrc_entry_fmt)=%d",
	     sizeof(enum jtrc_entry_fmt));
	jtrc(jtri, JTR_CONF, id, "offsetof(struct jtrc_entry, elem_fmt)=%d",
	     offsetof(struct jtrc_entry, elem_fmt));
	jtrc(jtri, JTR_CONF, id, "offsetof(struct jtrc_entry, hex.length)=%d",
	     offsetof(struct jtrc_entry, hex_continue.length));
	jtrc(jtri, JTR_CONF, id,
	     "offsetof(struct jtrc_entry, hex.data_start)=%d",
	     offsetof(struct jtrc_entry, hex_continue.data_start));
	jtrc(jtri, JTR_CONF, id,
	     "offsetof(struct jtrc_entry, hex_begin.total_length)=%d",
	     offsetof(struct jtrc_entry, hex_begin.total_length));
	jtrc(jtri, JTR_CONF, id,
	     "offsetof(struct jtrc_entry, hex_begin.data_start)=%d",
	     offsetof(struct jtrc_entry, hex_begin.data_start));
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




#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/notifier.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/notifier.h>
#include <linux/types.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include <asm/current.h>
#include <asm/smp.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#else
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/param.h>
#endif

#include "jtrace.h"
#include "jtrace_common.h"

/**
 * jtrc_find_instance_by_addr()
 *
 * Find instance in jtrc_instance_list list by address.
 */
jtrace_instance_t *
jtrc_find_instance_by_addr(struct list_head *jtri_list,
			   jtrace_instance_t * jt)
{
	jtrace_instance_t *tmp_jtri = NULL;
	int found = 0;

	list_for_each_entry(tmp_jtri, jtri_list, jtrc_list) {
		if (tmp_jtri == jt) {
			found = 1;
			break;
		}
	}

	if (!found) {
		return (NULL);
	}
	return (tmp_jtri);
}

/**
 * jtrc_find_instance_by_name()
 *
 * Find trace info by name.
 */
jtrace_instance_t *
jtrc_find_instance_by_name(struct list_head *jtri_list, char *trc_name)
{
	int found = 0;
	jtrace_instance_t *jt = NULL;

	list_for_each_entry(jt, jtri_list, jtrc_list) {
		if (strncmp(jt->jtrc_cb.jtrc_name, trc_name,
			    sizeof(jt->jtrc_cb.jtrc_name)) == 0) {
			found = 1;
			break;
		}
	}

	if (!found) {
		return (NULL);
	}
	return (jt);
}

jtrace_instance_t *
jtrc_default_instance(struct list_head *jtri_list)
{
	return jtrc_find_instance_by_name(jtri_list, JTRC_DEFAULT_NAME);
}

/**
 * jtrace_get_instance()
 *
 * Get a refcount on an existing jtrace instance
 */
int jtrace_get_instance(jtrace_instance_t *jt)
{
#ifdef __KERNEL__
	unsigned long flags;
#endif

	spin_lock_irqsave(&jtrc_config_lock, flags);
	jt->refcount++;
	spin_unlock_irqrestore(&jtrc_config_lock, flags);
	return 0;
}

/**
 * jtrace_put_instance()
 *
 * Put a refcount on a jtrace instance
 */
void jtrace_put_instance(jtrace_instance_t * jt)
{
#ifdef __KERNEL__
	unsigned long flags;
#endif

	spin_lock_irqsave(&jtrc_config_lock, flags);
	/* Can only put if it's on the instance list */
	if (!jtrc_find_instance_by_addr(&jtrc_instance_list, jt)) {
		spin_unlock_irqrestore(&jtrc_config_lock, flags);
		return;
	}

	jt->refcount--;
	if (jt->refcount == 0) {
		list_del(&jt->jtrc_list);
		jtrc_num_instances--;
		__free_jtrace_instance(jt);
	}

	spin_unlock_irqrestore(&jtrc_config_lock, flags);
	return;
}

/******************************************* NEW ***************************/

/**
 * jtrc_v() - add trace entries to buffer
 */
static void
jtrc_v(jtrace_instance_t * jt, void *id, uint32_t tflags,
       const char *func_name, int line_num, char *fmt, va_list vap)
{
	register jtrc_element_t *tp;
#ifdef __KERNEL__
	unsigned long flags = 0;
#endif

	spin_lock_irqsave(&jt->jtrc_buf_mutex, flags);

	/* Increment index and handle wrap */
	jt->jtrc_cb.jtrc_buf_index++;
	if (jt->jtrc_cb.jtrc_buf_index >
	    (jt->jtrc_cb.jtrc_num_entries - 1)) {
		jt->jtrc_cb.jtrc_buf_index = 0;
	}
	jt->jtrc_cb.jtrc_num_insert++;

	tp = &jt->jtrc_cb.jtrc_buf[jt->jtrc_cb.jtrc_buf_index];

	tp->elem_fmt = JTRC_FORMAT_REGULAR;
	tp->flag = tflags;
	tp->reg.tscp = jtrace_rdtscp();
#ifdef __KERNEL__
	tp->reg.cpu = smp_processor_id();
	tp->reg.tid = (void *) current;
#else
	tp->reg.cpu = -1;
	tp->reg.tid = (void *) pthread_self();
#endif
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
#ifdef __KERNEL__
	if (jt->jtrc_cb.jtrc_kprint_enabled) {
		jtrc_print_element(tp);
	}
#endif
	spin_unlock_irqrestore(&jt->jtrc_buf_mutex, flags);
}


/**
 * _jtrace() -    add trace entries to buffer
 */
void _jtrace(jtrace_instance_t * jt, void *id,
	     uint32_t flags, const char *func, int line, char *fmt, ...)
{
    va_list vap;

    va_start(vap, fmt);

    jtrc_v(jt, id, flags, func, line, fmt, vap);

    va_end(vap);
}

/**
 * jtrace_preformatted_str_v() - add trace entries to buffer
 */
static void
__jtrace_preformatted_str(jtrace_instance_t * jt, void *id, uint32_t flags,
			  const char *func_name, int line_num, char *buf,
			  int str_len)
{
	register jtrc_element_t *tp;
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

	jt->jtrc_cb.jtrc_buf_index++;
	if (jt->jtrc_cb.jtrc_buf_index > (jt->jtrc_cb.jtrc_num_entries - 1)) {
		jt->jtrc_cb.jtrc_buf_index = 0;
	}
	jt->jtrc_cb.jtrc_num_insert++;

	tp = &jt->jtrc_cb.jtrc_buf[jt->jtrc_cb.jtrc_buf_index];

	tp->elem_fmt = JTRC_PREFORMATTED_STR_BEGIN;
	tp->flag = flags;
	tp->pfs_begin.tscp = jtrace_rdtscp();
#ifdef __KERNEL__
	tp->reg.cpu = smp_processor_id();
	tp->reg.tid = (void *) current;
#else
	tp->reg.cpu = -1;
	tp->reg.tid = (void *) pthread_self();
#endif
	tp->pfs_begin.func_name = func_name;
	tp->pfs_begin.line_num = line_num;
	tp->pfs_begin.id = id;
	tp->pfs_begin.total_length = str_len;

	/* Fill the rest of first element with string data */
	length2 = MIN((in_buf_end - in_buf), JTRC_MAX_PREFMT_STR_FOR_BEG_ELEM);
	out_buf = (char *) &tp->pfs_begin.data_start;
	memcpy(out_buf, in_buf, length2);
	out_buf += length2;
	/* Terminate string */
	*out_buf = 0;

#ifdef __KERNEL__
	if (jt->jtrc_cb.jtrc_kprint_enabled) {
		jtrc_print_element(tp);
	}
#endif

	in_buf += length2;

	/* Fill in remaining elements */
	if (in_buf < in_buf_end) {
		elem_fmt = JTRC_PREFORMATTED_STR_CONTINUE;
		while (in_buf < in_buf_end) {
			length2 =
				MIN((in_buf_end - in_buf),
				    JTRC_MAX_PREFMT_STR_PER_ELEM);

			jt->jtrc_cb.jtrc_buf_index++;
			if (jt->jtrc_cb.jtrc_buf_index >
			    (jt->jtrc_cb.jtrc_num_entries - 1)) {
				jt->jtrc_cb.jtrc_buf_index = 0;
			}
			jt->jtrc_cb.jtrc_num_insert++;
			tp = &jt->jtrc_cb.jtrc_buf[jt->jtrc_cb.jtrc_buf_index];

			tp->elem_fmt = elem_fmt;
			tp->pfs_continue.length = length2;

			out_buf = (char *) &tp->pfs_continue.data_start;

			memcpy(out_buf, in_buf, length2);
			out_buf += length2;
			/* Terminate string */
			*out_buf = 0;

#ifdef __KERNEL__
			if (jt->jtrc_cb.jtrc_kprint_enabled) {
				jtrc_print_element(tp);
			}
#endif
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
#ifdef __KERNEL__
	unsigned long flags;
#endif

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
	jtrc_element_fmt_t elem_fmt;
	unsigned char length2;
#ifdef __KERNEL__
	unsigned long flags;
#endif

	if (!p) {
		return;
	}

	max_len = MIN(len, MAX_HEX_BUF);
	in_buf_end = in_buf + max_len;

	spin_lock_irqsave(&jt->jtrc_buf_mutex, flags);

	jt->jtrc_cb.jtrc_buf_index++;
	if (jt->jtrc_cb.jtrc_buf_index > (jt->jtrc_cb.jtrc_num_entries - 1)) {
		jt->jtrc_cb.jtrc_buf_index = 0;
	}
	jt->jtrc_cb.jtrc_num_insert++;

	tp = &jt->jtrc_cb.jtrc_buf[jt->jtrc_cb.jtrc_buf_index];

	tp->elem_fmt = JTRC_HEX_DATA_BEGIN;
	tp->flag = tflags;
	tp->hex_begin.tscp = jtrace_rdtscp();
#ifdef __KERNEL__
	tp->reg.cpu = smp_processor_id();
	tp->reg.tid = (void *) current;
#else
	tp->reg.cpu = -1;
	tp->reg.tid = (void *) pthread_self();
#endif
	tp->hex_begin.func_name = func;
	tp->hex_begin.line_num = line;
	tp->hex_begin.id = id;
	tp->hex_begin.msg = msg;
	tp->hex_begin.total_length = max_len;

	/* Fill the rest of first element with hex data */
	length2 = MIN((in_buf_end - in_buf), JTRC_MAX_HEX_DATA_FOR_BEG_ELEM);
	out_buf = (char *) &tp->hex_begin.data_start;
	memcpy(out_buf, in_buf, length2);

#ifdef __KERNEL__
	if (jt->jtrc_cb.jtrc_kprint_enabled) {
		jtrc_print_element(tp);
	}
#endif

	in_buf += length2;

	/* Fill in remaining elements */
	if (in_buf < in_buf_end) {
		elem_fmt = JTRC_HEX_DATA_CONTINUE;
		while (in_buf < in_buf_end) {
			length2 = MIN((in_buf_end - in_buf),
				      JTRC_MAX_HEX_DATA_PER_ELEM);

			jt->jtrc_cb.jtrc_buf_index++;
			if (jt->jtrc_cb.jtrc_buf_index >
			    (jt->jtrc_cb.jtrc_num_entries - 1)) {
				jt->jtrc_cb.jtrc_buf_index = 0;
			}
			jt->jtrc_cb.jtrc_num_insert++;

			tp = &jt->jtrc_cb.jtrc_buf[jt->jtrc_cb.jtrc_buf_index];
			tp->elem_fmt = elem_fmt;
			tp->hex.length = length2;

			out_buf = (char *) &tp->hex.data_start;

			memcpy(out_buf, in_buf, length2);

#ifdef __KERNEL__
			if (jt->jtrc_cb.jtrc_kprint_enabled) {
				jtrc_print_element(tp);
			}
#endif

			in_buf += length2;
			elem_fmt = JTRC_HEX_DATA_CONTINUE;
		}
		tp->elem_fmt = JTRC_HEX_DATA_END;
	}

	spin_unlock_irqrestore(&jt->jtrc_buf_mutex, flags);
}

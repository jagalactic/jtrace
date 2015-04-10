

/**
 * @file jtrc.h 
 */
#ifndef __JTRC_H
#define __JTRC_H

#include "jtrace_mod.h"

typedef void *jtrc_arg_t;

typedef enum {
	JTRC_FORMAT_INVALID = 0,
	JTRC_FORMAT_REGULAR,
	JTRC_HEX_DATA_BEGIN,
	JTRC_HEX_DATA_CONTINUE,
	JTRC_HEX_DATA_END,
	JTRC_PREFORMATTED_STR_BEGIN,
	JTRC_PREFORMATTED_STR_CONTINUE,
	JTRC_PREFORMATTED_STR_END
} jtrc_element_fmt_t;


/* Members of the jtrace element union: *****************************/

/**
 * @jtrc_regular_element_t
 *
 * Regular format trace buffer element
 */
typedef struct _jtrc_regular_element {
	int cpu;                    /* cpu */
	uint tv_sec;                /* copy of `tod' tv_sec  */
	uint tv_nsec;               /* copy of `tod' tv_nsec */
	void *tid;                  /* tasket or tid */
	const char *func_name;      /* pointer to function name */
	int line_num;               /* line number */
	void *id;                   /* correlator */
	char *fmt;                  /* printf() format string */
	jtrc_arg_t a0;             /* arg 0 */
	jtrc_arg_t a1;             /* arg 1 */
	jtrc_arg_t a2;             /* arg 2 */
	jtrc_arg_t a3;             /* arg 3 */
	jtrc_arg_t a4;             /* arg 4 */
} jtrc_regular_element_t;

/**
 * @jtrc_hex_begin_element_t
 *
 * Hex dump begin format trace buffer element
 */
typedef struct _jtrc_hex_begin_element {
	int cpu;                    /* cpu */
	uint tv_sec;                /* copy of `tod' tv_sec  */
	uint tv_nsec;               /* copy of `tod' tv_nsec */
	void *tid;                  /* tasket or tid */
	const char *func_name;      /* pointer to function name */
	int line_num;               /* line number */
	void *id;                   /* correlator */
	char *msg;                  /* message to print */
	int total_length;           /* Total length of data to dump */
	char data_start;            /* First byte of binary hex data */
} jtrc_hex_begin_element_t;


/**
 * @jtrc_hex_element_t
 *
 * Hex dump format trace buffer element
 */
typedef struct _jtrc_hex_element {
	unsigned char length;            /* Length of data for this element */
	char data_start;   /* First byte of binary hex data in this element */
} jtrc_hex_element_t;


/**
 * @jtrc_prefmtstr_begin_element_t
 *
 * Preformatted str trace buffer element begin
 */
typedef struct _jtrc_prefmtstr_begin_element {
	int cpu;                    /* cpu */
	uint tv_sec;                /* copy of `tod' tv_sec  */
	uint tv_nsec;               /* copy of `tod' tv_nsec */
	void *tid;                  /* tasket or tid */
	const char *func_name;      /* pointer to function name */
	int line_num;               /* line number */
	void *id;                   /* correlator */
	int total_length;           /* Total length of formatted str to dump */
	char data_start;            /* First byte of formatted str */
} jtrc_prefmtstr_begin_element_t;


/**
 * @jtrc_prefmtstr_element_t
 *
 * Preformatted str trace buffer element continue
 */
typedef struct _jtrc_prefmtstr_element {
    unsigned char length;                /* Length of data for this element */
    char data_start;            /* First byte of str data in this element */
} jtrc_prefmtstr_element_t;

/* The jtrace element union: *******************************************/
/**
 * @jtrc_element_t
 *
 * Trace buffer element
 */
typedef struct _jtrc_element {
	jtrc_element_fmt_t elem_fmt; /* Element format type */
	uint32_t flag;
	union {
		jtrc_regular_element_t reg;
		jtrc_hex_begin_element_t hex_begin;
		jtrc_hex_element_t hex;
		jtrc_prefmtstr_begin_element_t pfs_begin;
		jtrc_prefmtstr_element_t pfs_continue;
	};
} jtrc_element_t;

#define JTRC_MAX_HEX_DATA_FOR_BEG_ELEM \
    (sizeof(jtrc_element_t)-offsetof(jtrc_element_t, hex_begin.data_start))

#define JTRC_MAX_HEX_DATA_PER_ELEM \
    (sizeof(jtrc_element_t)-offsetof(jtrc_element_t, hex.data_start))

#define JTRC_MAX_PREFMT_STR_FOR_BEG_ELEM \
    (sizeof(jtrc_element_t)-offsetof(jtrc_element_t, pfs_begin.data_start)-1)

#define JTRC_MAX_PREFMT_STR_PER_ELEM \
    (sizeof(jtrc_element_t)-offsetof(jtrc_element_t, pfs_continue.data_start)-1)

/**
 * @jtrc_module_trc_info_t
 *
 * Trace module information common between user and kernel 
 * space.
 *
 * Contains information describing the location, size
 * and number of entries in the trace buffer, flag values, etc.
 */
typedef struct _jtrc_module_trc_info {
#define JTRC_MOD_NAME_SIZE 32
	/** Module trace info name */
	char jtrc_name[JTRC_MOD_NAME_SIZE];

	/** Number of trace entries in the buffer. */
	uint32_t jtrc_num_entries;

	/** Size of the trace buffer */
	uint32_t jtrc_buf_size;

	/** Index to current trace entry */
	uint32_t jtrc_buf_index;

	/** Pointer to the trace buffer */
	jtrc_element_t *jtrc_buf_ptr;

	/** 
	 * If enabled, then all trace statements are sent to console.
	 * Use this if things get hairy and the buffer cannot be
	 * extracted. (Note, this is very slow.)
	 */
	int jtrc_kprint_enabled;

	/**
	 * Trace flag mask.
	 */
	uint32_t jtrc_flags;

	/* NOTE: We have the conceptual ability to dynamically add custom
	 * flags, but we don't have the code in place to support it. */
	/**
	 * Custom defined flags for this module.
	 */
	int jtrc_num_custom_flags;

	/**
	 * Mask of valid custom flags.
	 */
	uint32_t jtrc_custom_flags_mask;
} jtrc_module_trc_info_t;

#define JTRC_FLAG_CMD_LINE_SIZE 32
#define JTRC_FLAG_DESCRIPTION_SIZE 128
typedef struct _jtrc_flag_descriptor {
	char jtrc_flag_cmd_line_name[JTRC_FLAG_CMD_LINE_SIZE];
	char jtrc_flag_description[JTRC_FLAG_DESCRIPTION_SIZE];
} jtrc_flag_descriptor_t;

#define JTR_COMMON_FLAG( jtr_flag_num ) ( 1 << (jtr_flag_num) )

#define JTR_ERR     JTR_COMMON_FLAG(0)  /* Trace error conditions */
#define JTR_WARN    JTR_COMMON_FLAG(1)  /* Trace warning conditions */
#define JTR_CONF    JTR_COMMON_FLAG(2)  /* Trace configuration routines */
#define JTR_ENTX    JTR_COMMON_FLAG(3)  /* Trace function entry/exit points */
#define JTR_IOCTL   JTR_COMMON_FLAG(4)  /* Trace ioctl() calls */
#define JTR_MEM     JTR_COMMON_FLAG(5)  /* Trace memory alloc/free */
#define JTR_DEBUG   JTR_COMMON_FLAG(6)  /* General debug */

/* Must match the number of flags above */
#define JTR_NUM_FLAGS 7

#define JTR_COMMON_FLAGS_MASK (JTR_ERR|JTR_WARN|JTR_CONF|JTR_ENTX|JTR_IOCTL|JTR_MEM|JTR_DEBUG)

/* The first "custom flag" starts at JTR_NUM_FLAGS
 * NOTE: if you add standard flags, you gotta update JTR_NUM_FLAGS */
#define JTR_CUSTOM_FLAG( jtr_flag_num ) ( 1 << ((jtr_flag_num) + JTR_NUM_FLAGS))

/* Sub-commands for JTRC_CMD_IOCTL */
typedef enum {
    JTRCTL_SET_TRC_FLAGS,
    JTRCTL_SET_PRINTK,
    JTRCTL_CLEAR,
    JTRCTL_GET_ALL_TRC_INFO,
    JTRCTL_SNARF
} jtrc_cmd_t;

#ifdef __KERNEL__
#include <linux/list.h>

/**
 * @jtrace_instance_t
 *
 * Contains the per-module trace information, plus
 * extra fields for kernel use. 
 * Each kernel module which uses trace facility should
 * register this structure.
 */
typedef struct _jtrace_instance {
	jtrc_module_trc_info_t mod_trc_info;
	struct _jtrc_flag_descriptor *custom_flags;
	spinlock_t jtrc_buf_mutex;
	struct list_head jtrc_list;
	int use_count;
} jtrace_instance_t;

#if 0
/**
 * @my_jtrace_inst
 *
 * We have the concept of tracing to more than one instance of jtrace.
 * Oversimplified, you can think of that as "which trace buffer am I logging
 * to?", although when we get to per-thread and per-cpu trace buffers, it's
 * more like "which trace buffer *set* am I logging to?"
 *
 * Each caller must define a macro "my_jtrace_inst" which evaluates to the
 * valid name of a "jtrace_instance_t *" prior to including this file.
 *
 * This pointer will not be used by jtrace until you call jtrace_init() or
 * jtrace_register_instance().
 */
#ifndef my_jtrace_inst
#error "You must define my_jtrace_inst to evaluate to a valid jtrace_instance_t *"
#endif
#endif

extern int jtrace_init(void);
extern void jtrace_exit(void);
extern int jtrace_cmd(struct _jtrc_cmd_req *cmd_req, void *uaddr);
extern void _jtrace(jtrace_instance_t * jtri, void *id,
		    uint32_t tflags, struct timespec *tm,
		    const char *func, int line, char *fmt, ...);
extern void jtrace_hex_dump(jtrace_instance_t * jtri,
			    const char *func, uint line,
			    void *id, uint32_t tflags,
			    char *msg, void *p, uint len);
extern void jtrace_preformatted_str(jtrace_instance_t * jtri,
				    void *id, uint32_t tflags,
				    const char *func, int line,
				    char *fmt, ...);
extern void jtrace_print_tail(jtrace_instance_t * jtri,
			      int num_elems);

/* Register new jtrace instance */
extern int jtrace_register_instance(jtrace_instance_t * jtri);
/* get pointer to existing instance, and get refcount on it */
extern jtrace_instance_t *jtrace_get_instance(char *name);
/* Put refcount on jtrace instance.  Unregister if ref goes to zero */
extern void jtrace_put_instance(jtrace_instance_t *jtri);

#ifdef JTRC_ENABLE
#define jtrc_setmask(jtri, mask) do{				\
		jtri->mod_trc_info.jtrc_flags = mask;	\
	} while (0)
#define jtrc_off() jtrc_setmask(0)

/**
 * Macro to send a trace statement to the buffer.
 *
 * @mask - Trace flags for this statement.
 * @id   - This can be used as a tag or correlator.
 * @fmt  - The trace format strings.
 * @...  - Up to 5 arguments for the trace format string.
 */
#define jtrc(jtri, mask, id, fmt, ...)  do {		   \
    if (jtri->mod_trc_info.jtrc_flags & (mask)){ \
	    _jtrace( jtri, (void *)(id), mask,		\
		      (struct timespec *)NULL,				\
		      __FUNCTION__, __LINE__ , (fmt), ## __VA_ARGS__);	\
    }\
} while (0)

/* Same thing, but caller provides timespec... */
#define jtrc_tm(jtri, mask, id, tm, fmt, ...)  do {	   \
    if (jtri->mod_trc_info.jtrc_flags & (mask)){ \
	    _jtrace(jtri, (void *)(id), mask, tm,		\
		      __FUNCTION__, __LINE__ , (fmt), ## __VA_ARGS__);	\
    }\
} while (0)


/**
 * jtrc_pfs()
 *
 * Macro to send a formatted trace string to the trace buffer.
 *
 * The string is first formatted, and then then entire formatted string is
 * copied to the buffer. This is useful for volatile strings, or if the number
 * of arguments exceeds 5.
 *
 * WARNING: Slow; don't use in performance path.
 */
#define jtrc_pfs(jtri, mask, id, fmt, ...)  do {		   \
    if (jtri->mod_trc_info.jtrc_flags & (mask)){ \
	    jtrace_preformatted_str(jtri, (void *)(id), mask,\
		  __FUNCTION__, __LINE__ , (fmt), ## __VA_ARGS__); \
    }\
} while (0)

/**
 * jtrc_funcline()
 *
 * Macro to send a trace statement to the buffer, also specifying
 * function name and line number.  This is useful for trace statements 
 * in utility functions where the context of the calling function is
 * more useful than the utility function.
 *
 * @param mask - Trace flags for this statement.
 * @param id - This can be used as a tag or correlator.
 * @func - Function name.
 * @line - Line number.
 * @param fmt - The trace format strings.
 * @param ... - Up to 5 arguments for the trace format string.
 */
#define jtrc_funcline(jtri, mask, id, func, line, fmt, ...)  do {	\
    if (jtri->mod_trc_info.jtrc_flags & (mask)){ \
	    _jtrace(jtri, (void *)(id), mask,	\
		     (func), (line), (fmt) , ## __VA_ARGS__);	\
    }\
} while (0)

/**
 * jtrc_hexdump()
 *
 * Dump hex data to the trace buffer.
 * WARNING: Slow, don't use in performance path.
 *
 * @param mask - Trace flags for this statement. 
 * @param id   - This can be used as a tag or correlator.
 * @param msg  - Description of what hex data is being traced.
 * @param p    - Pointer to data to dump.
 * @param len  - Length of data to dump.
 */
#define jtrc_hexdump(jtri, mask, id, msg, p, len) do {	   \
    if (jtri->mod_trc_info.jtrc_flags & (mask)){ \
	jtrace_hex_dump(jtri, __FUNCTION__, __LINE__, (void *)(id),\
			mask, (msg), (p), (len));			\
    }\
} while (0)

#define jtrc_setprint(jtri, enabled) do {				\
    jtri->mod_trc_info.jtrc_kprint_enabled = (enabled);\
} while (0)

#define jtrc_print_tail(jtri, num_elems) do {		\
    jtrc_print_last_elems(jtri, (num_elems)); \
} while(0);

#define jtrc_entry(flags, id, fmt, ...) do { \
    jtrc(jtri, ((flags)|JTR_ENTX), (id), ("Entry [ " fmt), ## __VA_ARGS__); \
} while (0)

#define jtrc_exit(flags, id, fmt, ...) do { \
    jtrc(jtri, ((flags)|JTR_ENTX), (id), ("Exit ] " fmt), ## __VA_ARGS__); \
} while (0)

#define jtrc_err(flags, id, fmt, ...) do { \
    jtrc(jtri, ((flags)|JTR_ERR), (id), ("ERROR: " fmt), ## __VA_ARGS__); \
} while (0)

#define jtrc_errexit(flags, id, fmt, ...) do { \
    jtrc(jtri, ((flags)|JTR_ERR), (id), ("ERROR: " fmt), ## __VA_ARGS__); \
    jtrc(jtri, ((flags)|JTR_ENTX), (id), "Exit ]");			\
} while (0)

#else

#define jtrc(jtri, mask, id, fmt, ...)
#define jtrc_pfs(jtri, mask, id, fmt, ...)
#define jtrc_funcline(jtri, mask, id, func, line, fmt, ...)
#define jtrc_hexdump(jtri, mask, id, msg, p, len)
#define jtrc_setprint(jtri, enabled)
#define jtrc_print_tail(jtri, num_elems)
#define jtrc_entry(jtri, flags, id, fmt, ...)
#define jtrc_exit(jtri,flags, id, fmt, ...)
#define jtrc_err(jtri,flags, id, fmt, ...)
#define jtrc_errexit(jtri, flags, id, fmt, ...)

#endif                          /* JTRC_ENABLE */

#endif                          /* __KERNEL__ */

#endif                          /* __JTRC_H */
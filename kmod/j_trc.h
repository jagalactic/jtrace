

/**
 * @file j_trc.h 
 */
#ifndef __J_TRC_H
#define __J_TRC_H

#include "j_trc_mod.h"

typedef void *j_trc_arg_t;

typedef enum {
	JTRC_FORMAT_INVALID = 0,
	JTRC_FORMAT_REGULAR,
	JTRC_HEX_DATA_BEGIN,
	JTRC_HEX_DATA_CONTINUE,
	JTRC_HEX_DATA_END,
	JTRC_PREFORMATTED_STR_BEGIN,
	JTRC_PREFORMATTED_STR_CONTINUE,
	JTRC_PREFORMATTED_STR_END
} j_trc_element_fmt_t;


/* Members of the jtrace element union: *****************************/

/**
 * @j_trc_regular_element_t
 *
 * Regular format trace buffer element
 */
typedef struct _j_trc_regular_element {
	int cpu;                    /* cpu */
	uint tv_sec;                /* copy of `tod' tv_sec  */
	uint tv_nsec;               /* copy of `tod' tv_nsec */
	void *tid;                  /* tasket or tid */
	const char *func_name;      /* pointer to function name */
	int line_num;               /* line number */
	void *id;                   /* correlator */
	char *fmt;                  /* printf() format string */
	j_trc_arg_t a0;             /* arg 0 */
	j_trc_arg_t a1;             /* arg 1 */
	j_trc_arg_t a2;             /* arg 2 */
	j_trc_arg_t a3;             /* arg 3 */
	j_trc_arg_t a4;             /* arg 4 */
} j_trc_regular_element_t;

/**
 * @j_trc_hex_begin_element_t
 *
 * Hex dump begin format trace buffer element
 */
typedef struct _j_trc_hex_begin_element {
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
} j_trc_hex_begin_element_t;


/**
 * @j_trc_hex_element_t
 *
 * Hex dump format trace buffer element
 */
typedef struct _j_trc_hex_element {
	unsigned char length;            /* Length of data for this element */
	char data_start;   /* First byte of binary hex data in this element */
} j_trc_hex_element_t;


/**
 * @j_trc_prefmtstr_begin_element_t
 *
 * Preformatted str trace buffer element begin
 */
typedef struct _j_trc_prefmtstr_begin_element {
	int cpu;                    /* cpu */
	uint tv_sec;                /* copy of `tod' tv_sec  */
	uint tv_nsec;               /* copy of `tod' tv_nsec */
	void *tid;                  /* tasket or tid */
	const char *func_name;      /* pointer to function name */
	int line_num;               /* line number */
	void *id;                   /* correlator */
	int total_length;           /* Total length of formatted str to dump */
	char data_start;            /* First byte of formatted str */
} j_trc_prefmtstr_begin_element_t;


/**
 * @j_trc_prefmtstr_element_t
 *
 * Preformatted str trace buffer element continue
 */
typedef struct _j_trc_prefmtstr_element {
    unsigned char length;                /* Length of data for this element */
    char data_start;            /* First byte of str data in this element */
} j_trc_prefmtstr_element_t;

/* The jtrace element union: *******************************************/
/**
 * @j_trc_element_t
 *
 * Trace buffer element
 */
typedef struct _j_trc_element {
	j_trc_element_fmt_t elem_fmt; /* Element format type */
	uint32_t flag;
	union {
		j_trc_regular_element_t reg;
		j_trc_hex_begin_element_t hex_begin;
		j_trc_hex_element_t hex;
		j_trc_prefmtstr_begin_element_t pfs_begin;
		j_trc_prefmtstr_element_t pfs_continue;
	};
} j_trc_element_t;

#define J_TRC_MAX_HEX_DATA_FOR_BEG_ELEM \
    (sizeof(j_trc_element_t)-offsetof(j_trc_element_t, hex_begin.data_start))

#define J_TRC_MAX_HEX_DATA_PER_ELEM \
    (sizeof(j_trc_element_t)-offsetof(j_trc_element_t, hex.data_start))

#define J_TRC_MAX_PREFMT_STR_FOR_BEG_ELEM \
    (sizeof(j_trc_element_t)-offsetof(j_trc_element_t, pfs_begin.data_start)-1)

#define J_TRC_MAX_PREFMT_STR_PER_ELEM \
    (sizeof(j_trc_element_t)-offsetof(j_trc_element_t, pfs_continue.data_start)-1)

/**
 * @j_trc_module_trc_info_t
 *
 * Trace module information common between user and kernel 
 * space.
 *
 * Contains information describing the location, size
 * and number of entries in the trace buffer, flag values, etc.
 */
typedef struct _j_trc_module_trc_info {
#define JTRC_MOD_NAME_SIZE 32
	/** Module trace info name */
	char j_trc_name[JTRC_MOD_NAME_SIZE];

	/** Number of trace entries in the buffer. */
	uint32_t j_trc_num_entries;

	/** Size of the trace buffer */
	uint32_t j_trc_buf_size;

	/** Index to current trace entry */
	uint32_t j_trc_buf_index;

	/** Pointer to the trace buffer */
	j_trc_element_t *j_trc_buf_ptr;

	/** 
	 * If enabled, then all trace statements are sent to console.
	 * Use this if things get hairy and the buffer cannot be
	 * extracted. (Note, this is very slow.)
	 */
	int j_trc_kprint_enabled;

	/**
	 * Trace flag mask.
	 */
	uint32_t j_trc_flags;

	/**
	 * Custom defined flags for this module.
	 */
	int j_trc_num_custom_flags;

	/**
	 * Mask of valid custom flags.
	 */
	uint32_t j_trc_custom_flags_mask;
} j_trc_module_trc_info_t;

#define J_TRC_FLAG_CMD_LINE_SIZE 32
#define J_TRC_FLAG_DESCRIPTION_SIZE 128
typedef struct _j_trc_flag_descriptor {
	char j_trc_flag_cmd_line_name[J_TRC_FLAG_CMD_LINE_SIZE];
	char j_trc_flag_description[J_TRC_FLAG_DESCRIPTION_SIZE];
} j_trc_flag_descriptor_t;

#define JTR_COMMON_FLAG( jtr_flag_num ) ( 1 << (jtr_flag_num) )

#define JTR_ERR     JTR_COMMON_FLAG(0)  /* Trace error conditions */
#define JTR_WARN    JTR_COMMON_FLAG(1)  /* Trace warning conditions */
#define JTR_CONF    JTR_COMMON_FLAG(2)  /* Trace configuration routines */
#define JTR_ENTX    JTR_COMMON_FLAG(3)  /* Trace all routine entry and exit points." */
#define JTR_IOCTL   JTR_COMMON_FLAG(4)  /* Trace ioctl() calls */
#define JTR_MEM     JTR_COMMON_FLAG(5)  /* Trace memory alloc/free */
#define JTR_DEBUG   JTR_COMMON_FLAG(6)  /* General debug */

/* This must be the number of flags above */
#define JTR_NUM_FLAGS 7

#define JTR_COMMON_FLAGS_MASK (JTR_ERR|JTR_WARN|JTR_CONF|JTR_ENTX|JTR_IOCTL|JTR_MEM|JTR_DEBUG)

/* The first "custom flag" starts at JTR_NUM_FLAGS
 * NOTE: if you add standard flags, you gotta update JTR_NUM_FLAGS */
#define JTR_CUSTOM_FLAG( jtr_flag_num ) ( 1 << ((jtr_flag_num) + JTR_NUM_FLAGS))

/* Sub-commands for J_TRC_CMD_IOCTL */
typedef enum {
    JTRCTL_SET_TRC_FLAGS,
    JTRCTL_SET_PRINTK,
    JTRCTL_CLEAR,
    JTRCTL_GET_ALL_TRC_INFO,
    JTRCTL_SNARF
} j_trc_cmd_t;

#ifdef __KERNEL__
#include <linux/list.h>

/**
 * @j_trc_register_trc_info_t
 *
 * Contains the per-module trace information, plus
 * extra fields for kernel use. 
 * Each kernel module which uses trace facility should
 * register this structure.
 */
typedef struct _j_trc_register_trc_info {
	j_trc_module_trc_info_t mod_trc_info;
	struct _j_trc_flag_descriptor *custom_flags;
	spinlock_t j_trc_buf_mutex;
	struct list_head j_trc_list;
	int use_count;
} j_trc_register_trc_info_t;

extern int j_trc_init(void);
extern void j_trc_exit(void);
extern int j_trc_cmd(struct _j_trc_cmd_req *cmd_req, void *uaddr);
extern j_trc_register_trc_info_t *j_trc_reg_infop;
extern void _j_trace(j_trc_register_trc_info_t * jtr_infop, void *id,
		     uint32_t tflags, struct timespec *tm,
                     const char *func, int line, char *fmt, ...);
extern void _j_trc_hex_dump(j_trc_register_trc_info_t * jtr_infop,
                            const char *func, uint line,
			    void *id, uint32_t tflags,
                            char *msg, void *p, uint len);
extern void _j_trace_preformated_str(j_trc_register_trc_info_t * jtr_infop,
                                     void *id, uint32_t tflags,
				     const char *func, int line,
                                     char *fmt, ...);
extern void j_trc_print_last_elems(j_trc_register_trc_info_t * jtr_infop,
                                   int num_elems);

/* Register new module trace information */
extern int j_trc_register_trc_info(j_trc_register_trc_info_t * jtr_infop);
/* Use existing module trace information */
extern j_trc_register_trc_info_t *j_trc_use_registered_trc_info(char
                                                                *name);
/* Unregister module trace information */
extern void j_trc_unregister_trc_info(j_trc_register_trc_info_t *
                                      jtr_infop);

#ifdef JTRC_ENABLE
#define jtrc_setmask(mask) do{			\
		j_trc_reg_infop->mod_trc_info.j_trc_flags = mask;	\
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
#define jtrc(mask, id, fmt, ...)  do {		     \
    if (j_trc_reg_infop->mod_trc_info.j_trc_flags & (mask)){ \
	    _j_trace( j_trc_reg_infop, (void *)(id), mask,		\
		      (struct timespec *)NULL,				\
		      __FUNCTION__, __LINE__ , (fmt), ## __VA_ARGS__);	\
    }\
} while (0)

/* Same thing, but caller provides timespec... */
#define jtrc_tm(mask, id, tm, fmt, ...)  do {		     \
    if (j_trc_reg_infop->mod_trc_info.j_trc_flags & (mask)){ \
	    _j_trace( j_trc_reg_infop, (void *)(id), mask, tm,		\
		      __FUNCTION__, __LINE__ , (fmt), ## __VA_ARGS__);	\
    }\
} while (0)


/**
 * jtrc_pfs()
 *
 * Macro to send a formatted trace string to the trace buffer.
 *
 * The string is first formatted, and then then entire
 * formatted string is copied to the buffer. This is 
 * useful for volatile strings, or if the number of arguments
 * exceeds 5.
 *
 * WARNING: Slow, don't use in performance path.
 */
#define jtrc_pfs(mask, id, fmt, ...)  do { \
    if (j_trc_reg_infop->mod_trc_info.j_trc_flags & (mask)){ \
	    _j_trace_preformated_str( j_trc_reg_infop, (void *)(id), mask,\
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
#define jtrc_funcline(mask, id, func, line, fmt, ...)  do { \
    if (j_trc_reg_infop->mod_trc_info.j_trc_flags & (mask)){ \
	    _j_trace(j_trc_reg_infop, (void *)(id), mask,	\
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
#define jtrc_hexdump(mask, id, msg, p, len) do { \
    if (j_trc_reg_infop->mod_trc_info.j_trc_flags & (mask)){ \
	_j_trc_hex_dump(j_trc_reg_infop, __FUNCTION__, __LINE__, (void *)(id),\
			mask, (msg), (p), (len));			\
    }\
} while (0)

#define jtrc_setprint(enabled) do { \
    j_trc_reg_infop->mod_trc_info.j_trc_kprint_enabled = (enabled);\
} while (0)

#define jtrc_print_tail(num_elems) do { \
    j_trc_print_last_elems(j_trc_reg_infop, (num_elems)); \
} while(0);

#define jtrc_entry(flags, id, fmt, ...) do { \
    jtrc(((flags)|JTR_ENTX), (id), ("Entry [ " fmt), ## __VA_ARGS__); \
} while (0)

#define jtrc_exit(flags, id, fmt, ...) do { \
    jtrc(((flags)|JTR_ENTX), (id), ("Exit ] " fmt), ## __VA_ARGS__); \
} while (0)

#define jtrc_err(flags, id, fmt, ...) do { \
    jtrc(((flags)|JTR_ERR), (id), ("ERROR: " fmt), ## __VA_ARGS__); \
} while (0)

#define jtrc_errexit(flags, id, fmt, ...) do { \
    jtrc(((flags)|JTR_ERR), (id), ("ERROR: " fmt), ## __VA_ARGS__); \
    jtrc(((flags)|JTR_ENTX), (id), "Exit ]"); \
} while (0)

#else

#define jtrc(mask, id, fmt, ...)
#define jtrc_pfs(mask, id, fmt, ...)
#define jtrc_funcline(mask, id, func, line, fmt, ...)
#define jtrc_hexdump(mask, id, msg, p, len)
#define jtrc_setprint(enabled)
#define jtrc_print_tail(num_elems)
#define jtrc_entry(flags, id, fmt, ...)
#define jtrc_exit(flags, id, fmt, ...)
#define jtrc_err(flags, id, fmt, ...)
#define jtrc_errexit(flags, id, fmt, ...)

#endif                          /* JTRC_ENABLE */

#endif                          /* __KERNEL__ */

#endif                          /* __J_TRC_H */

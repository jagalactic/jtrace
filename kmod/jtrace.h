
/**
 * @file jtrc.h
 */
#ifndef __JTRC_H
#define __JTRC_H

#ifndef __KERNEL__
#include <time.h>
#include <sys/types.h>
#include <inttypes.h>
#endif

/* Default trace buffer name */
#define JTRC_DEFAULT_NAME "jtrc_default"

enum jtrc_entry_fmt {
	JTRC_FORMAT_INVALID = 0,
	JTRC_FORMAT_REGULAR,
	JTRC_HEX_DATA_BEGIN,
	JTRC_HEX_DATA_CONTINUE,
	JTRC_HEX_DATA_END,
	JTRC_PREFORMATTED_STR_BEGIN,
	JTRC_PREFORMATTED_STR_CONTINUE,
	JTRC_PREFORMATTED_STR_END
};


/* Members of the jtrace element union: *****************************/

/**
 * @jtrc_regular_element_t
 *
 * Regular format trace buffer element
 */
struct jtrc_reg_entry {
	int cpu;                /* cpu */
	unsigned long tscp;     /* time from rdtscp */
	void *tid;              /* tasket or tid */
	const char *func_name;  /* pointer to function name */
	int line_num;           /* line number */
	void *id;               /* correlator */
	char *fmt;              /* printf() format string */
	void *a0;		/* arg 0 */
	void *a1;		/* arg 1 */
	void *a2;		/* arg 2 */
	void *a3;		/* arg 3 */
	void *a4;		/* arg 4 */
};

/**
 * struct @jtrc_hex_entry
 *
 * Hex dump begin format trace buffer element
 */
struct jtrc_hex_entry {
	int cpu;                    /* cpu */
	unsigned long tscp;         /* time from rdtscp */
	void *tid;                  /* tasket or tid */
	const char *func_name;      /* pointer to function name */
	int line_num;               /* line number */
	void *id;                   /* correlator */
	char *msg;                  /* message to print */
	int total_length;           /* Total length of data to dump */
	char data_start;            /* First byte of binary hex data */
};


/**
 * @jtrc_hex_element_t
 *
 * Hex dump format trace buffer element
 */
struct jtrc_hex_continue {
	unsigned char length;            /* Length of data for this element */
	char data_start;   /* First byte of binary hex data in this element */
};


/**
 * @jtrc_prefmtstr_begin_element_t
 *
 * Preformatted str trace buffer element begin
 */
struct jtrc_pfs_entry {
	int cpu;                    /* cpu */
	unsigned long tscp;         /* time from rdtscp */
	void *tid;                  /* tasket or tid */
	const char *func_name;      /* pointer to function name */
	int line_num;               /* line number */
	void *id;                   /* correlator */
	int total_length;           /* Total length of formatted str to dump */
	char data_start;            /* First byte of formatted str */
};


/**
 * struct @jtrc_prefmtstr_element_t
 *
 * Preformatted str trace buffer element continue
 */
struct jtrc_pfs_continue {
	unsigned char length;       /* Length of data for this element */
	char data_start;            /* First byte of str data in this element */
};

/* The jtrace element union: *******************************************/
/**
 * struct @struct jtrc_entry
 *
 * Trace buffer element
 */
struct jtrc_entry {
	enum jtrc_entry_fmt elem_fmt; /* Element format type */
	uint32_t flag;
	union {
		struct jtrc_reg_entry reg;
		struct jtrc_hex_entry hex_begin;
		struct jtrc_hex_continue hex_continue;
		struct jtrc_pfs_entry pfs_begin;
		struct jtrc_pfs_continue pfs_continue;
	};
};

#define JTRC_MAX_HEX_DATA_FOR_BEG_ELEM 					\
	(sizeof(struct jtrc_entry)					\
	 -offsetof(struct jtrc_entry, hex_begin.data_start))

#define JTRC_MAX_HEX_DATA_PER_ELEM 					\
	(sizeof(struct jtrc_entry)					\
	 -offsetof(struct jtrc_entry, hex_continue.data_start))

#define JTRC_MAX_PREFMT_STR_FOR_BEG_ELEM \
	(sizeof(struct jtrc_entry) -		\
	 offsetof(struct jtrc_entry, pfs_begin.data_start) - 1)

#define JTRC_MAX_PREFMT_STR_PER_ELEM \
	(sizeof(struct jtrc_entry) -		\
	 offsetof(struct jtrc_entry, pfs_continue.data_start) - 1)

enum jtrace_context {
	KERNEL = 0,
	USER,
};

/**
 * struct @jtrc_cb
 *
 * Trace module control block
 *
 * Location, size, number of entries in the trace buffer, flag values, etc.
 */
struct jtrc_cb {
	enum jtrace_context jtrc_context;

	/** Module trace info name */
#define JTRC_MOD_NAME_SIZE 32
	char jtrc_name[JTRC_MOD_NAME_SIZE];

	/** Number of trace entries in the buffer. */
	uint32_t jtrc_num_entries;

	/** Size of the trace buffer */
	uint32_t jtrc_buf_size;

	/** Index to current trace entry */
	uint32_t jtrc_buf_index;

	uint32_t jtrc_num_insert; /* tmp flag for debug */

	/** Pointer to the trace buffer */
	struct jtrc_entry *jtrc_buf;

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
};

#define JTRC_FLAG_CMD_LINE_SIZE 32
#define JTRC_FLAG_DESCRIPTION_SIZE 128
struct jtrc_flag_descriptor {
	char jtrc_flag_cmd_line_name[JTRC_FLAG_CMD_LINE_SIZE];
	char jtrc_flag_description[JTRC_FLAG_DESCRIPTION_SIZE];
};

#define JTR_COMMON_FLAG(jtr_flag_num) (1 << (jtr_flag_num))

#define JTR_ERR     JTR_COMMON_FLAG(0)  /* Trace error conditions */
#define JTR_WARN    JTR_COMMON_FLAG(1)  /* Trace warning conditions */
#define JTR_CONF    JTR_COMMON_FLAG(2)  /* Trace configuration routines */
#define JTR_ENTX    JTR_COMMON_FLAG(3)  /* Trace function entry/exit points */
#define JTR_IOCTL   JTR_COMMON_FLAG(4)  /* Trace ioctl() calls */
#define JTR_MEM     JTR_COMMON_FLAG(5)  /* Trace memory alloc/free */
#define JTR_DEBUG   JTR_COMMON_FLAG(6)  /* General debug */

/* Must match the number of flags above */
#define JTR_NUM_FLAGS 7

#define JTR_COMMON_FLAGS_MASK (JTR_ERR		\
			       | JTR_WARN	\
			       | JTR_CONF	\
			       | JTR_ENTX	\
			       | JTR_IOCTL	\
			       | JTR_MEM	\
			       | JTR_DEBUG)

/* The first "custom flag" starts at JTR_NUM_FLAGS
 * NOTE: if you add standard flags, you gotta update JTR_NUM_FLAGS */
#define JTR_CUSTOM_FLAG(jtr_flag_num) (1 << ((jtr_flag_num) + JTR_NUM_FLAGS))

/* Sub-commands for JTRC_CMD_IOCTL */
enum jtrc_cmd {
	JTRCTL_SET_TRC_FLAGS,   /* Set trace flag mask (what will be logged) */
	JTRCTL_SET_PRINTK,
	JTRCTL_CLEAR,
	JTRCTL_GET_ALL_TRC_INFO,
	JTRCTL_SNARF
};

#ifndef __KERNEL__
#include "userlist.h"
#include <pthread.h>

/* The common code uses kernel APIs;
 * macros to fix that up to run in user space: */
#define spinlock_t pthread_spinlock_t
#define spin_lock_irqsave(lock, flags) pthread_spin_lock(lock)
#define spin_unlock_irqrestore(lock, flags) pthread_spin_unlock(lock)
#define pr_info printf
#define EXPORT_SYMBOL(sym)

/* Read the tscp timer register */
static inline uint64_t
jtrace_rdtscp(void)
{
	uint32_t eax = 0, edx = 0;

	__asm__ __volatile__("rdtscp"
				: "+a" (eax), "=d" (edx)
				:
				: "%ecx", "memory");

	return (((uint64_t)edx << 32) | eax);
}

#else
/* Kernel mode */
#define jtrace_rdtscp get_cycles
/* Simple kernel func to print a jtrace element */
void jtrc_print_element(struct jtrc_entry *tp);
#define MIN(x, y)  ((x) < (y) ? (x) : (y))
#endif

extern spinlock_t jtrc_config_lock;

/**
 * @struct jtrace_instance
 *
 * Contains the per-module trace information, plus
 * extra fields for kernel use.
 * Each kernel module which uses trace facility should
 * register this structure.
 */
struct jtrace_instance {
	struct jtrc_cb jtrc_cb;
	struct jtrc_flag_descriptor *custom_flags;
	spinlock_t jtrc_buf_mutex;
	struct list_head jtrc_list;  /* List of jtrace instances */
	int refcount;
};


/* jtrace driver ioctl interface */

#define JTRACE_DEV_SPECIAL_FILE_NAME "jtrace"
#define JTRACE_DEV_SPECIAL_FILE "/dev/jtrace"

#ifndef JTRC_ENABLE
#define JTRC_ENABLE
#endif

#define JTRACE_IOCTL_BASE 0xCC

/*
 * Kernel trace buffer controls and information.
 */
struct jtrc_cmd_req {
	char trc_name[32];
	enum jtrc_cmd cmd;
	void *snarf_addr;   /* jtrace buffer addr */
	void *data;         /* Client address */
	int data_size;      /* Amount of data requested */
	int status;
};

#define JTRC_CMD_IOCTL _IOWR(JTRACE_IOCTL_BASE, 0x1, struct jtrc_cmd_req)

#ifdef __KERNEL__

#include <linux/list.h>

/* Kernel-only prototypes */
extern int jtrace_init(void);
extern void jtrace_exit(void);
extern int jtrace_cmd(struct jtrc_cmd_req *cmd_req, void *uaddr);
extern void jtrace_print_tail(struct jtrace_instance *jtri,
			      int num_elems);

#else

/* Userspace libjtrace globals */
extern int jtrc_verbose;

/* Userspace libjtrace prototypes */
int jtrace_kopen(void);
int jtrc_set_printk_by_name(char *buf_name, int value);
int jtrc_clear_by_name(char *buf_name);
int jtrc_set_flags_by_name(char *buf_name, int trc_flags);
struct jtrc_cb *get_all_trc_info(char *trc_buf_name, void **buf);
int flag_str_to_flag(char *trc_flag_str, uint *trc_flag);
int print_trace(struct jtrc_cb *cb, uint32_t dump_mask);
int show_trc_flags(uint32_t trc_flags);
struct jtrace_instance *jtrace_init(const char *name, int num_entries);

#endif                          /* __KERNEL__ / USER */

/* Dual mode (user/kernel) prototypes:
 * These are implemented in jtrace_common, and linked both in the kmod
 * and in libjtrace */

/* Register new jtrace instance: */
extern int jtrace_register_instance(struct jtrace_instance *jtri);
/* Get a refcount on an existing jtrace instance: */
extern int jtrace_get_instance(struct jtrace_instance *jtri);
/* Put refcount on jtrace instance.  Unregister if ref goes to zero: */
extern void jtrace_put_instance(struct jtrace_instance *jtri);

extern void _jtrace(struct jtrace_instance *jtri, void *id,
		    uint32_t tflags,
		    const char *func, int line, char *fmt, ...);
extern void jtrace_preformatted_str(struct jtrace_instance *jtri,
				    void *id, uint32_t tflags,
				    const char *func, int line,
				    char *fmt, ...);
extern void jtrace_hex_dump(struct jtrace_instance *jtri,
			    const char *func, uint line,
			    void *id, uint32_t tflags,
			    char *msg, void *p, uint len);
extern void __free_jtrace_instance(struct jtrace_instance *jtri);
void jtrace_config(void);

/************************************************************************
 * jtrace macros (all are user/kernel dual-mode)
 */
#ifdef JTRC_ENABLE
#define jtrc_setmask(jtri, mask) jtri->jtrc_cb.jtrc_flags = mask
#define jtrc_off(jtri) jtrc_setmask(jtri, 0)

/**
 * Macro to send a trace statement to the buffer.
 *
 * @mask - Trace flags for this statement.
 * @id   - This can be used as a tag or correlator.
 * @fmt  - The trace format strings.
 * @...  - Up to 5 arguments for the trace format string.
 */
#define jtrc(jtri, mask, id, fmt, ...)  do {				\
	if (jtri->jtrc_cb.jtrc_flags & (mask)) {			\
		_jtrace(jtri, (void *)(id), mask,			\
			__func__, __LINE__, (fmt), ## __VA_ARGS__);	\
	}								\
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
#define jtrc_pfs(jtri, mask, id, fmt, ...)  do {			\
	if (jtri->jtrc_cb.jtrc_flags & (mask)) {			\
		jtrace_preformatted_str(jtri, (void *)(id), mask,	\
					__func__, __LINE__, (fmt),	\
					## __VA_ARGS__);		\
	}								\
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
	if (jtri->jtrc_cb.jtrc_flags & (mask)) {			\
		_jtrace(jtri, (void *)(id), mask,			\
			(func), (line), (fmt), ## __VA_ARGS__);		\
	} \
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
#define jtrc_hexdump(jtri, mask, id, msg, p, len) do {			\
	if (jtri->jtrc_cb.jtrc_flags & (mask)) {			\
		jtrace_hex_dump(jtri, __func__, __LINE__, (void *)(id),	\
				mask, (msg), (p), (len));		\
	}								\
} while (0)

#define jtrc_setprint(jtri, enabled)					\
		jtri->jtrc_cb.jtrc_kprint_enabled = (enabled)

#define jtrc_print_tail(jtri, num_elems)				\
		jtrc_print_last_elems(jtri, (num_elems))

#define jtrc_entry(flags, id, fmt, ...)					\
		jtrc(jtri, ((flags)|JTR_ENTX), (id),			\
		     ("Entry [ " fmt), ## __VA_ARGS__)

#define jtrc_exit(flags, id, fmt, ...)					\
		jtrc(jtri, ((flags)|JTR_ENTX), (id),			\
		     ("Exit ] " fmt), ## __VA_ARGS__)

#define jtrc_err(flags, id, fmt, ...)					\
		jtrc(jtri, ((flags)|JTR_ERR), (id),			\
		     ("ERROR: " fmt), ## __VA_ARGS__)

#define jtrc_errexit(flags, id, fmt, ...) do {				\
	jtrc(jtri, ((flags)|JTR_ERR), (id), ("ERROR: " fmt), ## __VA_ARGS__); \
	jtrc(jtri, ((flags)|JTR_ENTX), (id), "Exit ]")			\
} while (0)

#else

#define jtrc(jtri, mask, id, fmt, ...)
#define jtrc_pfs(jtri, mask, id, fmt, ...)
#define jtrc_funcline(jtri, mask, id, func, line, fmt, ...)
#define jtrc_hexdump(jtri, mask, id, msg, p, len)
#define jtrc_setprint(jtri, enabled)
#define jtrc_print_tail(jtri, num_elems)
#define jtrc_entry(jtri, flags, id, fmt, ...)
#define jtrc_exit(jtri, flags, id, fmt, ...)
#define jtrc_err(jtri, flags, id, fmt, ...)
#define jtrc_errexit(jtri, flags, id, fmt, ...)

#endif                          /* JTRC_ENABLE */


#endif                          /* __JTRC_H */

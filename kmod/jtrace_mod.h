
/**
 * @file j_trc_mod.h
 */
#ifndef __JTRACE_H
#define __JTRACE_H

#define JTRACE_DEV_SPECIAL_FILE_NAME "jtrace"
#define JTRACE_DEV_SPECIAL_FILE "/dev/jtrace"

#ifndef JTRC_ENABLE
#define JTRC_ENABLE
#endif

#define JTRACE_IOCTL_BASE 0xCC

/*
 * Kernel trace buffer controls and information.
 */
typedef struct _jtrc_cmd_req {
	char trc_name[32];
	int cmd;
	void *snarf_addr;   /* jtrace buffer addr */
	void *data;         /* Client address */
	int data_size;      /* Amount of data requested */
	int status;
} jtrc_cmd_req_t;

#define JTRC_CMD_IOCTL _IOWR(JTRACE_IOCTL_BASE, 0x1, jtrc_cmd_req_t)

#endif   /* __JTRACE_H */

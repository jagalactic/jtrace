

#ifndef _H_JTRACE_COMMON
#define _H_JTRACE_COMMON

extern struct list_head jtrc_instance_list;
extern int jtrc_num_instances;
extern void free_jtrc_instance(struct jtrace_instance *jtri);

struct jtrace_instance *jtrc_find_get_instance(char *trc_name);
struct jtrace_instance *jtrc_default_instance(void);

#endif /* _H_JTRACE_COMMON */

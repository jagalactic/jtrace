

#ifndef _H_JTRACE_COMMON
#define _H_JTRACE_COMMON

extern struct list_head jtrc_instance_list;
extern int jtrc_num_instances;
extern void free_jtrc_instance(struct jtrace_instance *jtri);

struct jtrace_instance *jtrc_find_instance_by_addr(struct list_head *jtri_list,
						   struct jtrace_instance *jt);
struct jtrace_instance *jtrc_find_instance_by_name(struct list_head *jtri_list,
						   char *trc_name);
struct jtrace_instance *jtrc_default_instance(struct list_head *jtri_list);

#endif /* _H_JTRACE_COMMON */

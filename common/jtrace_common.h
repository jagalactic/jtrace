

#ifndef _H_JTRACE_COMMON
#define _H_JTRACE_COMMON

extern struct list_head jtrc_instance_list;
extern int jtrc_num_instances;
extern void free_jtrc_instance(jtrace_instance_t *jtri);

jtrace_instance_t *jtrc_find_instance_by_addr(struct list_head *jtri_list,
					      jtrace_instance_t *jt);
jtrace_instance_t *jtrc_find_instance_by_name(struct list_head *jtri_list,
					      char *trc_name);
jtrace_instance_t *jtrc_default_instance(struct list_head *jtri_list);

#endif /* _H_JTRACE_COMMON */

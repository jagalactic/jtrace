


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
#include <string.h>
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

	list_for_each_entry(tmp_jtri,
			    jtri_list, jtrc_list) {
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

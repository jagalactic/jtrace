/*
 * jtrc_mod.c
 *
 * Module wrapper for the jtrc code
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <asm/current.h>
#include <asm/smp.h>

#include "jtrace.h"

/* A chrdev is used for ioctl interface */
long jtrace_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static struct file_operations jtrc_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = jtrace_ioctl,
};

#define JTRC_NAME "jtrace"

static struct miscdevice jtr_mdev = {
	.minor = 0,
	.name = JTRC_NAME,
	.fops = &jtrc_fops,
};


long
jtrace_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int rc = EINVAL;

	switch (cmd) {
	case JTRC_CMD_IOCTL: {
		jtrc_cmd_req_t cmd_req;
		if (!arg) {
			printk("arg must be non-zero\n");
			return (EINVAL);
		}
		rc = copy_from_user(&cmd_req, (void *)arg, sizeof(cmd_req));
		if (rc) break;
		rc = jtrace_cmd(&cmd_req, (void *)arg);
		break;
	}

	default:
		rc = EINVAL;
	}

	return (rc);
}

extern void jtrc_print_element(jtrc_element_t * tp);
static jtrace_instance_t jtr;

static int __init jtrace_cdev_init(void)
{

	int rc;
	//int i;

	rc = misc_register(&jtr_mdev);

	if (rc < 0) {
		goto errexit;
	}

	rc = jtrace_init();
	if (rc) {
		goto errexit;
	}

	/* 
	 * Register and put something in the "master" trace buffer
	 * (as an example plus proof of functionality)
	 */
	{
#define NUM_ELEM 1048576
//#define NUM_ELEM 32
		int elem_size = sizeof(jtrc_element_t);
		int bufsize = (elem_size * NUM_ELEM);
		char *buf;

		memset(&jtr, 0, sizeof(jtr));
		jtr.jtrc_cb.jtrc_num_entries = NUM_ELEM;
		jtr.jtrc_cb.jtrc_buf_size = bufsize;
		jtr.jtrc_cb.jtrc_flags = JTR_COMMON_FLAGS_MASK;

		strcpy(jtr.jtrc_cb.jtrc_name, "master");

		buf = vmalloc_user(bufsize);
		
		jtr.jtrc_cb.jtrc_buf = (jtrc_element_t *)buf;
		if (!buf) {
			printk("jtrace: unable to vmalloc master buffer\n");
			goto errexit;
		}

		strcpy(jtr.jtrc_cb.jtrc_name, "master");

		printk("jtrace loaded: devno major %d minor %d elem size %d\n",
		       MISC_MAJOR, jtr_mdev.minor, elem_size);

#if 0
		jtrace_register_instance(&jtr);

		jtrc_setprint(1);
		jtrc(&jtr, 0, "jtrace module loaded");
		jtrc(&jtr, 0, "jtrace module loaded");
		jtrc(JTR_ERR, 0, "jtrace module loaded");
		jtrc(JTR_ENTX, 0, "jtrace module loaded");
		jtrc(JTR_MEM, 0, "jtrace module loaded");
		jtrc_setprint(0);

		for (i=jtr.jtrc_cb.jtrc_buf_index;
		     (i+1) != jtr.jtrc_cb.jtrc_num_entries;
		     i++) {
			jtrc_element_t *tp;
			if (i > jtr.jtrc_cb.jtrc_num_entries)
				i = 0;

			tp = (jtrc_element_t *)
				&jtr.jtrc_cb.jtrc_buf[i];
			printk("slot %d addr %p fmt %d (%s)\n",
			       i, tp, tp->elem_fmt,
			       (tp->elem_fmt) ? "used" : "empty");

			jtrc_print_element(tp);
		}
#endif

	}
	return 0;

  errexit:

	if (jtr_mdev.minor) {
		misc_deregister(&jtr_mdev);
	}

	return (-rc);
}

static void __exit jtrace_cdev_exit(void)
{
	printk("jtrace: unloading\n");

	jtrace_exit();

	misc_deregister(&jtr_mdev);

	return;
}

module_init(jtrace_cdev_init);
module_exit(jtrace_cdev_exit);

MODULE_DESCRIPTION("John's kernel trace facility");
MODULE_AUTHOR("Groves Technology Corporation");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(jtrace_register_instance);
EXPORT_SYMBOL(jtrace_put_instance);
EXPORT_SYMBOL(jtrace_get_instance);
EXPORT_SYMBOL(_jtrace);
EXPORT_SYMBOL(jtrace_hex_dump);
EXPORT_SYMBOL(jtrace_print_tail);



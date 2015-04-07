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

#include "j_trc.h"

/* A chrdev is used for ioctl interface */
long jtrc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static struct file_operations jtrc_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = jtrc_ioctl,
};

#define JTRC_NAME "jtrc"

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
static jtrace_register_trc_info_t jtr;

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

#define JTR_SPFILE "jtrace"

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
		jtr.mod_trc_info.jtrc_num_entries = NUM_ELEM;
		jtr.mod_trc_info.jtrc_buf_size = bufsize;
		jtr.mod_trc_info.jtrc_flags = JTR_COMMON_FLAGS_MASK;

		strcpy(jtr.mod_trc_info.jtrc_name, "master");

		buf = vmalloc_user(bufsize);
		
		jtr.mod_trc_info.jtrc_buf_ptr = (jtrc_element_t *)buf;
		if (!buf) {
			printk("jtrace: unable to vmalloc master buffer\n");
			goto errexit;
		}

		strcpy(jtr.mod_trc_info.jtrc_name, "master");


		printk("jtrace loaded: devno major %d minor %d elem size %d\n",
		       MISC_MAJOR, jtr_mdev.minor, elem_size);

#if 0
		jtrace_register_trc_info(&jtr);

		jtrc_setprint(1);
		jtrc(&jtr, 0, "jtrace module loaded");
		jtrc(&jtr, 0, "jtrace module loaded");
		jtrc(JTR_ERR, 0, "jtrace module loaded");
		jtrc(JTR_ENTX, 0, "jtrace module loaded");
		jtrc(JTR_MEM, 0, "jtrace module loaded");
		jtrc_setprint(0);

		for (i=jtr.mod_trc_info.jtrc_buf_index;
		     (i+1) != jtr.mod_trc_info.jtrc_num_entries;
		     i++) {
			jtrc_element_t *tp;
			if (i > jtr.mod_trc_info.jtrc_num_entries)
				i = 0;

			tp = (jtrc_element_t *)
				&jtr.mod_trc_info.jtrc_buf_ptr[i];
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
	printk("jtrace unloading\n");

	//jtrace_unregister_trc_info(&jtr);

	jtrace_exit();

	misc_deregister(&jtr_mdev);

	return;
}

module_init(jtrace_cdev_init);
module_exit(jtrace_cdev_exit);

MODULE_DESCRIPTION("John's kernel trace facility");
MODULE_AUTHOR("Groves Technology Corporation");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(jtrace_reg_infop);
EXPORT_SYMBOL(jtrace_register_trc_info);
EXPORT_SYMBOL(jtrace_use_registered_trc_info);
EXPORT_SYMBOL(jtrace_unregister_trc_info);
EXPORT_SYMBOL(_jtrace);
EXPORT_SYMBOL(jtrace_hex_dump);
EXPORT_SYMBOL(jtrace_print_last_elems);



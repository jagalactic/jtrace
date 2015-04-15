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
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/smp.h>

#include "jtrace.h"
#include "jtrace_common.h"

long
jtrace_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int rc = EINVAL;

	switch (cmd) {
	case JTRC_CMD_IOCTL: {
		jtrc_cmd_req_t cmd_req;

		if (!arg) {
			pr_info("arg must be non-zero\n");
			return -EINVAL;
		}
		rc = copy_from_user(&cmd_req, (void *)arg, sizeof(cmd_req));
		if (rc)
			break;

		rc = jtrace_cmd(&cmd_req, (void *)arg);
		break;
	}

	default:
		rc = -EINVAL;
	}

	return rc;
}

/* A chrdev is used for ioctl interface */
static const struct file_operations jtrc_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = jtrace_ioctl,
};

#define JTRC_NAME "jtrace"

static struct miscdevice jtr_mdev = {
	.minor = 0,
	.name = JTRC_NAME,
	.fops = &jtrc_fops,
};

static jtrace_instance_t tmp_jtr;

static int __init jtrace_cdev_init(void)
{
	int rc;

	rc = misc_register(&jtr_mdev);

	if (rc < 0)
		goto errexit;

	rc = jtrace_init();
	if (rc)
		goto errexit;

	/*
	 * Register and put something in the "master" trace buffer
	 * (as an example plus proof of functionality)
	 */
#define NUM_ELEM 1048576
	{
		int elem_size = sizeof(jtrc_element_t);
		int bufsize = (elem_size * NUM_ELEM);
		char *buf;

		memset(&tmp_jtr, 0, sizeof(tmp_jtr));
		tmp_jtr.jtrc_cb.jtrc_num_entries = NUM_ELEM;
		tmp_jtr.jtrc_cb.jtrc_buf_size = bufsize;
		tmp_jtr.jtrc_cb.jtrc_flags = JTR_COMMON_FLAGS_MASK;

		strcpy(tmp_jtr.jtrc_cb.jtrc_name, "master");

		buf = vmalloc_user(bufsize);

		tmp_jtr.jtrc_cb.jtrc_buf = (jtrc_element_t *)buf;
		if (!buf) {
			pr_info("jtrace: unable to vmalloc master buffer\n");
			goto errexit;
		}

		strcpy(tmp_jtr.jtrc_cb.jtrc_name, "master");

		pr_info("jtrace loaded: devno major %d minor %d elem size %d\n",
			MISC_MAJOR, jtr_mdev.minor, elem_size);
	}
	return 0;

errexit:

	if (jtr_mdev.minor || (jtr_mdev.list.next != jtr_mdev.list.prev)) {
		pr_info("jtrace: failed config, deregister misc device\n");
		misc_deregister(&jtr_mdev);
	}

	return (-rc);
}

static void __exit jtrace_cdev_exit(void)
{
	pr_info("jtrace: unloading\n");

	jtrace_exit();

	misc_deregister(&jtr_mdev);
}

module_init(jtrace_cdev_init);
module_exit(jtrace_cdev_exit);

MODULE_DESCRIPTION("John's kernel trace facility");
MODULE_AUTHOR("Groves Technology Corporation");
MODULE_LICENSE("GPL");

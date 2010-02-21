/*
 * j_trc_mod.c
 *
 * Module wrapper for the j_trc code
 */


/* This is to export entry points */
#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kmod.h>
// #include <linux/notifier.h>
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
#include "j_trc_mod.h"
#include "j_trc.h"
#include "j_trc_devfile.h"
//#include "../include/k_trc.h"

/* A chrdev is used for ioctl interface */
int j_trc_ioctl(struct inode *inode, struct file *file,
                       unsigned int cmd, unsigned long arg);

static struct file_operations j_trc_fops = {
    .owner = THIS_MODULE,
    .ioctl = j_trc_ioctl,
};

#define J_TRC_NAME "j_trc"

static struct miscdevice jtr_mdev = {
	.minor = 0,
	.name = J_TRC_NAME,
	.fops = &j_trc_fops,
};


int
j_trc_ioctl(struct inode *inode,
                   struct file *file, unsigned int cmd, unsigned long arg)
{
    int rc = EINVAL;

    switch (cmd) {
    case J_TRC_CMD_IOCTL:
        if (!arg) {
            printk("arg must be non-zero\n");
            return (-EINVAL);
        }
        rc = j_trc_cmd((j_trc_cmd_req_t *) arg);
        break;

#if 0
    case K_UTIL_ACPI_DUMP:
        display_all_ACPI_devices();
        rc = 0;
        break;
    case K_UTIL_PHYSLOC_DUMP:
        rc = psi_display_all_physloc();
        break;
#endif

    default:
        rc = EINVAL;
    }

    return (-rc);
}

static int __init j_trc_cdev_init(void)
{

	int rc;

	rc = misc_register(&jtr_mdev);

	if (rc < 0) {
		goto errexit;
	}

	rc = j_trc_init();
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
		int elem_size = sizeof(j_trc_element_t);
		int bufsize = (elem_size * NUM_ELEM);
		char *buf;
		j_trc_register_trc_info_t jtr = {
			.mod_trc_info =  {
				.j_trc_num_entries = NUM_ELEM,
				.j_trc_buf_size = bufsize,
				.j_trc_flags = KTR_COMMON_FLAGS_MASK,
			},

		};

		strcpy(jtr.mod_trc_info.j_trc_name, "master");
		buf = vmalloc(bufsize);
		
		jtr.mod_trc_info.j_trc_buf_ptr = (j_trc_element_t *)buf;
		if (!buf) {
			printk("jtrace: unable to vmalloc master buffer\n");
			goto errexit;
		}

		strcpy(jtr.mod_trc_info.j_trc_name, "master");

		j_trc_register_trc_info(&jtr);

		printk("jtrace loaded: devno major %d minor %d elem size %d\n",
		       MISC_MAJOR, jtr_mdev.minor, elem_size);
		kTrc(KTR_CONF, 0, "jtrace module loaded");

	}
	return 0;

  errexit:

	if (jtr_mdev.minor) {
		misc_deregister(&jtr_mdev);
	}

	return (-rc);
}

static void __exit j_trc_cdev_exit(void)
{
	printk("jtrace unloading\n");

	j_trc_exit();

	misc_deregister(&jtr_mdev);

	return;
}

module_init(j_trc_cdev_init);
module_exit(j_trc_cdev_exit);

MODULE_DESCRIPTION("John's kernel trace facility");
MODULE_AUTHOR("Groves Technology Corporation");
MODULE_LICENSE("Proprietary");

EXPORT_SYMBOL(j_trc_register_trc_info);
EXPORT_SYMBOL(j_trc_use_registered_trc_info);
EXPORT_SYMBOL(j_trc_unregister_trc_info);
EXPORT_SYMBOL(_j_trace);
EXPORT_SYMBOL(_j_trc_hex_dump);
EXPORT_SYMBOL(j_trc_print_last_elems);




#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/moduleparam.h>
#else
#include <linux/kmod.h>
#endif

#include "k_trc.h"
#include "psi_chan_phys_loc.h"
#include "j_trc_devfile.h"


/*
 * FIXME Do we really want a default, or just error
 * message and fail to load if not specified?
 */
char *psi_devfile_helper_dir = "/usr/psi/src/exe";
/* Default name of device special file helper script */
char *psi_devfile_helper_name = "psi_devfile_helper";


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
module_param(psi_devfile_helper_dir, charp, 0);
module_param(psi_devfile_helper_name, charp, 0);
#else
MODULE_PARM(psi_devfile_helper_dir, "s");
MODULE_PARM(psi_devfile_helper_name, "s");
#endif

static int psi_call_devfile_helper(char *envp[]);

atomic_t event_id;

/* 
 * Build a special file for a specific channel instance.
 *
 * /dev/[dev_base_dir]/[slot_prefix_dir_str/]slot_XX[_portXX]
 *
 * slot_prefix_dir_str, and portXX are only created depending
 * on platform and HBA type.
 * 
 * Returns 0 on success, -1 on failure.
 * 
 * ( Note, since the actual special file is created by the 
 * devfile helper script asynchronously in user space, a return 
 * of 0 does not guarantee successful special file creation.)
 */
int psi_chan_create_special_file(psi_chan_create_special_file_t * csfp)
{
    int rc = 0;
    char special_file_name[128] = { 0 };
    char special_file_dir[128] = { 0 };
    char port_str[32] = { 0 };

    if (csfp->minor_num >= PSI_DRIVER_SPECIAL_MINOR) {
        kTrc(KTR_ERR, csfp,
             "ERROR: minor_num must be less than or equal to %d",
             PSI_DRIVER_SPECIAL_MINOR);
        return (-1);
    }

    /* At a minimum, slot_value_str must be valid */
    if (csfp->slot_value_str == NULL) {
        kTrc(KTR_ERR, csfp, "ERROR: invalid slot_value_str is NULL");
        return (-1);
    }

    /* At a minimum, slot_value_str must be valid */
    if (strlen(csfp->slot_value_str) == 0) {
        kTrc(KTR_ERR, csfp, "ERROR: invalid strlen(slot_value_str)=%d",
             strlen(csfp->slot_value_str));
        return (-1);
    }

    if (csfp->port_value == PSI_CHAN_LOCATION_ERROR) {
        kTrc(KTR_ERR, csfp, "ERROR: invalid port_value");
        return (-1);
    }

    /* 
     * If port value is valid, create a port string 
     * Specify PSI_CHAN_LOCATION_INVALID for single port
     * cards that do not require the port designator.
     */
    if (csfp->port_value != PSI_CHAN_LOCATION_INVALID) {
        snprintf(port_str, sizeof(port_str), "%s%d", PSI_PORT_DESIGNATOR,
                 csfp->port_value);
    }

    /* Build the special_file_dir from the dev_base_dir and the slot_prefix_dir_str */
    snprintf(special_file_dir, sizeof(special_file_dir), "%s%s",
             csfp->dev_base_dir, csfp->slot_prefix_dir_str);

    /* Build the special_file_name from the slot_value_str and port_str */
    snprintf(special_file_name, sizeof(special_file_name), "%s%s",
             csfp->slot_value_str, port_str);

    /* Call generic special file creation routine */
    rc = psi_create_special_file(special_file_dir, special_file_name,
                                 csfp->major_num, csfp->minor_num,
                                 csfp->type_str);

    return (rc);
}

/*
 * REmove a special file for a specific channel instance.
 *
 * /dev/[dev_base_dir]/[slot_prefix_dir_str/]slot_XX[_portXX]
 *
 * slot_prefix_dir_str, and portXX are only created depending
 * on platform and HBA type.
 *
 * Returns 0 on success, -1 on failure.
 *
 * ( Note, since the actual special file is removed by the  
 * devfile helper script asynchronously in user space, a 
 * return of 0 does not guarantee successful special file removal.)
 */
int psi_chan_remove_special_file(psi_chan_remove_special_file_t * rsfp)
{
    int rc = 0;
    char special_file_name[128] = { 0 };
    char special_file_dir[128] = { 0 };
    char port_str[32] = { 0 };


    /* At a minimum, slot_value_str must be valid */
    if (rsfp->slot_value_str == NULL) {
        kTrc(KTR_ERR, rsfp, "ERROR: invalid slot_value_str is NULL");
        return (-1);
    }

    /* At a minimum, slot_value_str must be valid */
    if (strlen(rsfp->slot_value_str) == 0) {
        kTrc(KTR_ERR, rsfp, "ERROR: invalid strlen(slot_value_str)=%d",
             strlen(rsfp->slot_value_str));
        return (-1);
    }

    if (rsfp->port_value == PSI_CHAN_LOCATION_ERROR) {
        kTrc(KTR_ERR, rsfp, "ERROR: invalid port_value");
        return (-1);
    }

    /*
     * If port value is valid, create a port string
     * Specify PSI_CHAN_LOCATION_INVALID for single port
     * cards that do not require the port designator.
     */
    if (rsfp->port_value != PSI_CHAN_LOCATION_INVALID) {
        snprintf(port_str, sizeof(port_str), "%s%d", PSI_PORT_DESIGNATOR,
                 rsfp->port_value);
    }

    /* Build the special_file_dir from the dev_base_dir and the slot_prefix_dir_str */
    snprintf(special_file_dir, sizeof(special_file_dir), "%s%s",
             rsfp->dev_base_dir, rsfp->slot_prefix_dir_str);

    /* Build the special_file_name from the slot_value_str and port_str */
    snprintf(special_file_name, sizeof(special_file_name), "%s%s",
             rsfp->slot_value_str, port_str);

    /* Call generic special file creation routine */
    rc = psi_remove_special_file(special_file_dir, special_file_name);

    return (rc);
}



/*
 * Generic create special file routine.
 * 
 * Returns the result of psi_call_devfile_helper()
 */
int
psi_create_special_file(char *special_file_dir,
                        char *special_file_name, int major, int minor,
                        char *type)
{
    int rc = 0;
    char *envp[10];
    char event_id_str[16] = { 0 };
    char major_str[32] = { 0 };
    char minor_str[32] = { 0 };
    char file_name[128] = { 0 };
    char file_dir[128] = { 0 };
    char file_type[32] = { 0 };
    char action_str[64] = { 0 };

    atomic_inc(&event_id);

    snprintf(event_id_str, sizeof(event_id_str), "PSI_EVENT_ID=%d",
             atomic_read(&event_id));

    snprintf(action_str, sizeof(action_str), "PSI_CHAN_ACTION=%s",
             "ADD_SPEC_FILE");
    snprintf(file_name, sizeof(file_name), "PSI_CHAN_FILE=%s",
             special_file_name);
    if (special_file_dir) {
        snprintf(file_dir, sizeof(file_dir), "PSI_CHAN_DIR=%s",
                 special_file_dir);
    }
    snprintf(major_str, sizeof(major_str), "PSI_CHAN_MAJOR=%d", major);
    snprintf(minor_str, sizeof(minor_str), "PSI_CHAN_MINOR=%d", minor);
    snprintf(file_type, sizeof(file_type), "PSI_CHAN_TYPE=%s", type);

    envp[0] = "HOME=/";
    envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
    envp[2] = event_id_str;
    envp[3] = action_str;
    envp[4] = file_name;
    envp[5] = major_str;
    envp[6] = minor_str;
    envp[7] = file_type;
    if (special_file_dir) {
        envp[8] = file_dir;
    } else {
        envp[8] = NULL;
    }
    envp[9] = NULL;

    kTrcPFS(KTR_CONF, NULL, "file_name=\"%s\"", file_name);
    kTrcPFS(KTR_CONF, NULL, "file_dir=\"%s\"", file_dir);

    rc = psi_call_devfile_helper(envp);

    return (rc);
}

/*
 * Generic remove special file routine.
 *
 * Returns the result of psi_call_devfile_helper()
 */
int
psi_remove_special_file(char *special_file_dir, char *special_file_name)
{
    int rc = 0;
    char *envp[10];
    char event_id_str[16] = { 0 };
    char file_name[128] = { 0 };
    char file_dir[128] = { 0 };
    char action_str[64] = { 0 };

    if (!special_file_name) {
        kTrc(KTR_ERR, NULL, "special_file_name is NULL");
        return (-1);
    }

    atomic_inc(&event_id);

    snprintf(event_id_str, sizeof(event_id_str), "PSI_EVENT_ID=%d",
             atomic_read(&event_id));

    snprintf(action_str, sizeof(action_str), "PSI_CHAN_ACTION=%s",
             "REMOVE_SPEC_FILE");

    if (special_file_name) {
        snprintf(file_name, sizeof(file_name), "PSI_CHAN_FILE=%s",
                 special_file_name);
    }

    if (special_file_dir) {
        snprintf(file_dir, sizeof(file_dir), "PSI_CHAN_DIR=%s",
                 special_file_dir);
    }

    envp[0] = "HOME=/";
    envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
    envp[2] = event_id_str;
    envp[3] = action_str;
    if (special_file_dir && special_file_name) {
        envp[4] = file_name;
        envp[5] = file_dir;
    } else if (special_file_dir) {
        envp[4] = file_dir;
        envp[5] = NULL;
    } else if (special_file_name) {
        envp[4] = file_name;
        envp[5] = NULL;
    } else {
        envp[4] = NULL;
        envp[5] = NULL;
    }
    envp[6] = NULL;
    envp[7] = NULL;
    envp[8] = NULL;
    envp[9] = NULL;

    kTrcPFS(KTR_CONF, NULL, "file_name=\"%s\"", file_name);

    kTrcPFS(KTR_CONF, NULL, "file_dir=\"%s\"", file_dir);

    rc = psi_call_devfile_helper(envp);

    return (rc);
}


/* 
 * Returns zero on success, else negative error code 
 * 
 * The device special file wrapper script
 * is "psi_devfile_helper"
 *
 * Returns the result of call_usermodehelper()
 */
static int psi_call_devfile_helper(char *envp[])
{
    int rc = 0;
    char dir_and_name[256] = { 0 };
    char *argv[5];

    snprintf(dir_and_name, sizeof(dir_and_name), "%s/%s",
             psi_devfile_helper_dir, psi_devfile_helper_name);

    kTrcPFS(KTR_CONF, NULL, "dir_and_name=%s", dir_and_name);

    argv[0] = dir_and_name;
    argv[1] = psi_devfile_helper_name;
    argv[2] = NULL;

    /* FIXME 2_6 In 2.6 call_usermodehelper() takes 4 arguments. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    rc = call_usermodehelper(argv[0], argv, envp, 0);
#else
    rc = call_usermodehelper(argv[0], argv, envp);
#endif
    if (rc) {
        kTrc(KTR_ERR, envp, "ERROR: call_usermodehelper, rc=%d", rc);
    }

    return (rc);
}

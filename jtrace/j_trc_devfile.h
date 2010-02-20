
#ifndef _PSI_CHAN_DEVFILE_H
#define _PSI_CHAN_DEVFILE_H

/* 
 * Use the maximum for lazy special file minor. That way,
 * the rest of the minor numbers will match board instance
 * numbers, and dynamic add/remove online/offline issues
 * with HBAs trying to share lazy instance special file will
 * be avoided.
 * 
 * This is the driver lazy special file which can be
 * used to access the driver without specifying a
 * particular device minor.
 */
#define PSI_DRIVER_SPECIAL_MINOR 255

#define PSI_FICON_DEV_BASE_DIR "ficon"

#define PSI_CHAN_LOCATION_INVALID -1
#define PSI_CHAN_LOCATION_ERROR   -2

#define PSI_PORT_DESIGNATOR "_port"

/*
 * Information needed for 
 * psi_chan_create_special_file() 
 */
typedef struct _psi_chan_create_special_file {
    /* /dev/[dev_base_dir] */
    char *dev_base_dir;

    /* Special file major number */
    int major_num;

    /* Special file minor number, must be < PSI_DRIVER_SPECIAL_MINOR */
    int minor_num;

    /* "c" for character or "b" for block */
    char *type_str;

    /* Slot prefix string, e.g. cabinetXX/bayXX/chassis/XX */
    char *slot_prefix_dir_str;

    /* Slot value string */
    char *slot_value_str;

    /* 
     * Port value 
     * Designating a port value of PSI_CHAN_LOCATION_INVALID
     * should be used for cards with only 1 port. If 
     * PSI_CHAN_LOCATION_INVALID is specified, the port
     * suffix will not be created.
     */
    int port_value;
} psi_chan_create_special_file_t;

/* 
 * Based on information in psi_chan_create_special_file_t, a special
 * file will be created in the /dev directory of the form:
 *
 * Designating a port value of PSI_CHAN_LOCATION_INVALID
 * should be used for cards with only 1 port. If
 * PSI_CHAN_LOCATION_INVALID is specified, the port
 * suffix will not be created.
 * 
 * /dev/<dev_base_dir>/[<slot_prefix_dir_str>/]slot<slot_value>[port<port_value>]
 *
 * Returns 0 on success, -1 on failure.
 *
 * ( Note, since the actual special file is created by the 
 * devfile helper script asynchronously in user space, a 
 * return of 0 does not guarantee successful special 
 * file creation.)
 */
extern int psi_chan_create_special_file(psi_chan_create_special_file_t *
                                        csfp);

/*
 * Information needed for
 * psi_chan_remove_special_file()
 */
typedef struct _psi_chan_remove_special_file {
    /* /dev/[dev_base_dir] */
    char *dev_base_dir;

    /* Slot prefix string, e.g. cabinetXX/bayXX/chassis/XX */
    char *slot_prefix_dir_str;

    /* Slot value string */
    char *slot_value_str;

    /*
     * Port value
     * Designating a port value of PSI_CHAN_LOCATION_INVALID
     * should be used for cards with only 1 port. If
     * PSI_CHAN_LOCATION_INVALID is specified, the port
     * suffix will not be created.
     */
    int port_value;
} psi_chan_remove_special_file_t;


extern int psi_chan_remove_special_file(psi_chan_remove_special_file_t *
                                        rsfp);


/*
 * Generic create special file routine. 
 * Can be used to create the lazy special files.
 * (no formatting enforced like psi_chan_create_special_file())
 */
extern int psi_create_special_file(char *special_file_dir,
                                   char *special_file_name, int major,
                                   int minor, char *type);

/*
 * Generic remove special file routine
 */
extern int psi_remove_special_file(char *special_file_dir,
                                   char *special_file_name);


#endif


#include "jtrace.h"
#include "jtrace_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/param.h>
#include <assert.h>

#define MAX_NAME_LEN 1024
#define MAX_TRC_FILES 8

pthread_spinlock_t jtrc_config_lock;

/* Todo: make this figure out where tmpfs is...? */
char *tmpfs_path = "/tmpfs";

#define DEFAULT_DIR_MODE  (S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)

void __free_jtrace_instance(jtrace_instance_t *jt)
{
	munmap(jt->jtrc_cb.jtrc_buf, jt->jtrc_cb.jtrc_buf_size);
	munmap(jt, sizeof(*jt));
}

/**
 * map_trc_buf()
 *
 * User space function to map a trace buffer
 */
int
map_user_trc_buf(const char *instancename,
		 int num_entries,
		 jtrace_instance_t **addr)
{
	int rc;
	pid_t mypid = getpid();
	DIR *dir;
	char *trcfilename = malloc(MAX_NAME_LEN);
	int meta_fd, trc_fd;
	jtrace_instance_t *jtri;

	snprintf(trcfilename, MAX_NAME_LEN, "%s/jtrace", tmpfs_path);

	/* Create the jtrace directory if it's not already there */
	dir = opendir(trcfilename); /* This is just the dir path */
	if (!dir) {
		/* try to make dir and reopen */
		rc = mkdir(trcfilename, DEFAULT_DIR_MODE);
		if (rc) {
			fprintf(stderr,"mkdir(%s): %s\n",
				trcfilename, strerror(errno));
			return -1;
		}
		dir = opendir(trcfilename);
		if (!dir) {
			fprintf(stderr,"opendir(%s): %s\n",
				trcfilename, strerror(errno));
			return -1;
		}
		closedir(dir);
		/* We have a trace directory */
	}

	/**
	 * Now create the trace files
	 *
	 * path/pid.instance_name.meta - Meta file (4K mmaaped)
	 * path/pid.instance_name.jtr0 - Trace buffer 0
	 * path/pid.instance_name.jtrn - Trace buffer n
	 *
	 */
	/* Meta file */
	snprintf(trcfilename, MAX_NAME_LEN, "%s/jtrace/%d.%s.meta",
		 tmpfs_path, mypid, instancename);
	meta_fd = open(trcfilename, O_RDWR|O_CREAT, 00644);
	if (meta_fd <= 0) {
		fprintf(stderr,"failed to create meta file %s\n",
			trcfilename);
		return -1;
	}
	ftruncate(meta_fd, MAX(sizeof(jtrace_instance_t), 4096));
	jtri = (jtrace_instance_t *)mmap(NULL, sizeof(jtrace_instance_t),
					 PROT_READ|PROT_WRITE, MAP_SHARED,
					 meta_fd, 0);
	if (MAP_FAILED == (void *)jtri) {
		fprintf(stderr, "failed to map meta file\n");
		return -1;
	}
	memset(jtri, 0, sizeof(jtrace_instance_t));
	*addr = jtri;

	jtri->jtrc_cb.jtrc_context = USER;
	jtri->jtrc_cb.jtrc_num_entries = num_entries;
	jtri->jtrc_cb.jtrc_buf_size = num_entries* sizeof(jtrc_element_t);

	/* Trace file(s) */
	snprintf(trcfilename, MAX_NAME_LEN, "%s/jtrace/%d.%s.jtr0",
		 tmpfs_path, mypid, instancename);
	trc_fd = open(trcfilename, O_RDWR|O_CREAT, 00644);
	if (trc_fd <= 0) {
		fprintf(stderr,"failed to create meta file %s\n",
			trcfilename);
		return -1;
	}
	ftruncate(trc_fd, jtri->jtrc_cb.jtrc_buf_size);
	jtri->jtrc_cb.jtrc_buf = mmap(NULL, jtri->jtrc_cb.jtrc_buf_size,
		     PROT_READ|PROT_WRITE, MAP_SHARED, trc_fd, 0);
	return 0;
}

jtrace_instance_t *jtri = 0;

struct list_head jtrc_instance_list;

jtrace_instance_t *
jtrace_init(const char *name, int num_entries)
{
	jtrace_instance_t *jtri;

	if (strlen(name) > (JTRC_MOD_NAME_SIZE - 1)) {
		fprintf(stderr, "jtrace_init: invalid name (%s)\n", name);
		return NULL;
	}

	if (map_user_trc_buf(name, num_entries, &jtri))
		return NULL;

	printf("jtrace_init: jtri %p\n", jtri);

	memset(jtri, 0, sizeof(*jtri));
	strncpy(jtri->jtrc_cb.jtrc_name, name, JTRC_MOD_NAME_SIZE-1);

	/* XXX Take the config lock */
	list_add_tail(&jtri->jtrc_list, &jtrc_instance_list);
	/* XXX free config lock */
	return jtri;
}


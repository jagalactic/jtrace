#
# NOTE: Makefile runs on RedHat Enterprise Linux 4 system running appropriate kernel build
#
MODULE_NAME = jtrace

obj-m := $(MODULE_NAME).o


#$(MODULE_NAME)-objs := j_trc.o j_trc_mod.o j_trc_devfile.o
$(MODULE_NAME)-objs := j_trc.o j_trc_mod.o 

#KDIR	:= /lib/modules/$(shell uname -r)/build
#PWD	:= $(shell pwd)

#default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules


$(MODULE_NAME)-y := j_trc.o j_trc_mod.o



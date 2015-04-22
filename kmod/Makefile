
MODULE_NAME = jtrace

obj-m += $(MODULE_NAME).o

KDIR  := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

$(MODULE_NAME)-objs = jtrace_main.o \
	jtrace_mod.o \
	jtrace_common.o


# There isn't much point in building the jtrace kernel module without
# JTRC_ENABLE. However, modules that can use jtrace should only depend on
# this module if build with -DJTRC_ENABLE.
EXTRA_CFLAGS = -DJTRC_ENABLE

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

MODPATH=lib/modules/`uname -r`/updates/kernel/drivers/misc
INCPATH=include

install:
	mkdir -p $(PREFIX)/$(MODPATH) $(PREFIX)/$(INCPATH)
	install -t $(PREFIX)/$(MODPATH) jtrace.ko
	install -t $(PREFIX)/$(INCPATH) jtrace.h
	if [ ! $(PREFIX) ]; then \
		-depmod -a ; \
	fi


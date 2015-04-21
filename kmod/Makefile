
MODULE_NAME = jtrace

obj-m += $(MODULE_NAME).o

KDIR  := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

$(MODULE_NAME)-objs = jtrace_main.o \
	jtrace_mod.o \
	jtrace_common.o

#EXTRA_CFLAGS += -I $(PWD)/../common

jtrace_common.c:
	ln -s ../common/$@ $@

jtrace_common.h:
	ln -s ../common/$@ $@

all:	jtrace_common.c jtrace_common.h
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	-rm jtrace_common.[ch]
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

install:
	mkdir -p /lib/modules/`uname -r`/updates/kernel/drivers/misc
	cp jtrace.ko /lib/modules/`uname -r`/updates/kernel/drivers/misc
	cp jtrace.h /usr/include/linux
	cp jtrace_mod.h /usr/include/linux
	depmod -a


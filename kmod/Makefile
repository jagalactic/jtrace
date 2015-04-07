
MODULE_NAME = jtrace

obj-m += $(MODULE_NAME).o

$(MODULE_NAME)-objs = jtrace_main.o jtrace_mod.o

KDIR  := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

install:
	mkdir -p /lib/modules/`uname -r`/updates/kernel/drivers/misc
	cp jtrace.ko /lib/modules/`uname -r`/updates/kernel/drivers/misc
	cp jtrace.h /usr/include/linux
	cp jtrace_mod.h /usr/include/linux
	depmod -a


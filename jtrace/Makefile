
MODULE_NAME = jtrc

obj-m += $(MODULE_NAME).o

$(MODULE_NAME)-objs = j_trc.o j_trc_mod.o

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
	cp j_trc.h /usr/include/linux
	cp j_trc_mod.h /usr/include/linux
	depmod -a



MODULE_NAME = jtrace

obj-m += $(MODULE_NAME).o

KDIR  := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

$(MODULE_NAME)-objs = jtrace_main.o \
	jtrace_mod.o \
	jtrace_common.o

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

MODPATH=lib/modules/`uname -r`/updates/kernel/drivers/misc
INCPATH=usr/include

install:
	mkdir -p $(PREFIX)/$(MODPATH) $(PREFIX)/$(INCPATH)
	install -t $(PREFIX)/$(MODPATH) jtrace.ko
	install -t $(PREFIX)/$(INCPATH) jtrace.h
	if [ ! $(PREFIX) ]; then \
		-depmod -a ; \
	fi


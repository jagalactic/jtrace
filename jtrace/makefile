all:
	make -f Makefile -C /lib/modules/`uname -r`/build M=`pwd`

clean:
	make -f Makefile -C /lib/modules/`uname -r`/build M=`pwd` clean


install:
	mkdir -p /lib/modules/`uname -r`/updates/kernel/drivers/misc
	cp jtrace.ko /lib/modules/`uname -r`/updates/kernel/drivers/misc
	depmod -a




all:
	cd kmod; make -k
	cd jtrace_util;   make -k jtrace

clean:
	cd kmod; make -k clean
	cd jtrace_util;   make -k clean

install:
	cd kmod; make install
	cd jtrace_util; make install
#	cp jtrace/j_trc.h /usr/include/linux/j_trc.h

load:
	insmod kmod/jtrace.ko

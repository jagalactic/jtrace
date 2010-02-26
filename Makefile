

all:
	cd jtrace; make -k
	cd jtrace_util;   make -k jtrace

clean:
	cd jtrace; make -k clean
	cd jtrace_util;   make -k clean

install:
	cd jtrace; make install
	cd jtrace_util; make install
#	cp jtrace/j_trc.h /usr/include/linux/j_trc.h

load:
	insmod jtrace/jtrace.ko

unload:
	jgstub/jgstub_unload
	rmmod jtrace


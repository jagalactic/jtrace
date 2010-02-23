

all:
	cd jtrace; make -k
	cd jtrace_util;   make -k jtrace

clean:
	cd jtrace; make -k clean
	cd jtrace_util;   make -k clean

install:
	cd jtrace; make install
	cd jtrace_util; make install
load:
	insmod jtrace/jtrace.ko

unload:
	jgstub/jgstub_unload
	rmmod jtrace


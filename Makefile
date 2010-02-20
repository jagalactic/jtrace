

all:
	cd jtrace; make -k
	cd jtrace_util;   make -k jtrace

clean:
	cd jtrace; make -k clean
	cd jtrace_util;   make -k clean

load:
	insmod jtrace/jtrace.ko
	jgstub/jgstub_load

unload:
	jgstub/jgstub_unload
	rmmod jtrace


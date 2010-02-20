

all:
	cd jtrace; make -k V=1
	cd jtrace_util;   make -k jtrace


load:
	insmod jtrace/jtrace.ko
	jgstub/jgstub_load

unload:
	jgstub/jgstub_unload
	rmmod jtrace


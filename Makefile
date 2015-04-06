

all:
	cd kmod; make -k
	cd tools;   make -k jtrace

clean:
	cd kmod; make -k clean
	cd tools;   make -k clean

install:
	cd kmod; make install
	cd tools; make install
#	cp jtrace/j_trc.h /usr/include/linux/j_trc.h

load:
	insmod kmod/jtrace.ko

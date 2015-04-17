
all:
	mkdir -p builds
	cd builds; cmake -DCMAKE_BUILD_TYPE=Release ..; make
	cd kmod; make all

debug:
	mkdir -p builds
	cd builds; cmake -DCMAKE_BUILD_TYPE=Debug ..; make
	cd kmod; make all

oldall:
	cd kmod; make -k
	cd tools;   make -k jtrace

clean:
	rm -rf builds
	cd kmod; make -k clean
	cd tools;   make -k clean

install:
	cd kmod; make install
	cd tools; make install
#	cp jtrace/j_trc.h /usr/include/linux/j_trc.h

load:
	insmod kmod/jtrace.ko

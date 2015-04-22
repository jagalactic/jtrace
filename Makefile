#
# Makefile for jtrace
#
# Note: cmake is used for user space.  Executables and libs end up in ./builds
#       cmake is NOT currently used for ./kmod.
#

OUTPUT_PATH=builds
BINFILES = tools/jtrace \
	tools/usertest
LIBS = lib/libjtrace_lib.a


all:
	mkdir -p builds
	cd builds; cmake -DCMAKE_BUILD_TYPE=Release ..; make
	cd kmod; make all

allv:
	make VERBOSE=1 all

debug:
	mkdir -p builds
	cd builds; cmake -DCMAKE_BUILD_TYPE=Debug ..; make
	cd kmod; make all

debugv:
	make VERBOSE=1 debug

clean:
	rm -rf $(OUTPUT_PATH)
	cd kmod; make -k clean

install:
	cd kmod; make PREFIX=$(PREFIX) install
	mkdir -p $(PREFIX)/bin $(PREFIX)/lib
	cd $(OUTPUT_PATH) ; install -t $(PREFIX)/bin $(BINFILES)
	cd $(OUTPUT_PATH) ; install -t $(PREFIX)/lib $(LIBS)

load:
	insmod kmod/jtrace.ko

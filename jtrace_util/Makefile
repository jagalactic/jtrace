PWD := $(shell pwd)

#ifeq ($(MAIN_TOP_DIR),)
#export MAIN_TOP_DIR := $(PWD)/../../../..
#endif

#include $(MAIN_TOP_DIR)/io64-src/src/make_gnu.master

UTIL_INST_DIR:=/usr/bin

ifeq ("$(KREL)","2.4")
APP_KREL=24
else
APP_KREL=26
endif

USER_CFLAGS += -DAPP_KREL=$(APP_KREL)

INCLUDE_FLAGS=-I ../include

jtrace-objs := jtrace.o 

all: jtrace

# Default rule to compile .c files into .o files for source files in 
# local directory
%.o : %.c Makefile
	@echo $@
	$(CC) $(INCLUDE_FLAGS) $(USER_CFLAGS) -o $@ -c $<

jtrace: $(jtrace-objs)
	@echo $@ 
	$(CC) -o $@ $(jtrace-objs)

$(INSTDIR)/jtrace: jtrace
	cp jtrace $(INSTDIR)
	@chmod +x $(INSTDIR)/jtrace

install: $(INSTDIR)/jtrace

uninstall:
	@echo "Uninstall"
	@rm -f $(UTIL_INST_DIR)/jtrace 

modload:

modunload:

indent:
	@$(INDENT)

indent_clean:
	@rm -f *.$(INDENT_BACKUP_SUFFIX)	

clean-files += jtrace
clean:
	rm -rf $(clean-files)
	rm -f $(INSTDIR)/jtrace

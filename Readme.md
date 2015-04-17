
# jtrace - John's trace facility

This is the jtrace facility, which supports fairly high performance
debug and trace logging to one or more circular buffers. jtrace logging
can be done either from user or kernel space.  Both user and kernel tracing
can be viewed as a unified trace (by merge sorting kernel and user space
traces).

Source tree structure:

    kmod    - the kernel module to support jtrace logging from other modules
	          within the kernel and retrieving/expanding the log
	          (aka "snarfing")
    lib     - The user space library for tracing, retrieving and printing
	          traces
    common  - The common code which is linked into both the kernel and user
              space programs
    tools   - The command line tools for starting, stopping and snarfing
              traces
    include - jtrace include files that are not private to a single module

# Purpose and Strategy

The jtrace facility exists because the developers needed the following:

1. A reasonably performant way to debug kernel code before the ftrace
   facility existed
1. A way to debug kernel and user space code in a unified way.

(In many cases the very cool "ftrace" facility in the linux kernel
eliminates the first requirement, but not the second.)

Printing (printf/printk) works for some problems, but it has such a profound
impact on performance that many problems just can't be reproduced that way.

The jtrace facility puts traced entries into one or more circular buffers.
Entries placed into the buffers are fixed-size.  The idea is to get near
print[f|k] flexibility by storing a trace descriptor which can be expanded
later by using values and/or dereferencing pointers from each trace entry.
This removes
all string formatting and expansion from the critical path, and only requires
storing a few words in memory.

Trace entries have a mask associated with them, and the trace can be enabled
selectively via the mask (e.g. trace only one of several subsystems, while
masking out the rest).

# Architectural Concepts

When you initialize the jtrace facility, a default jtrace instance is created.
Additional jtrace instances can be created, such that unrelated applications
or kernel modules can be debugged independently.

In the kernel, it's possible for several different modules or drivers to share
the default instance of jtrace, since there is just one kernel address space.
In user space, however, a jtrace instance is local to a process.  This is
because entries in the trace buffer(s) only make sense in the context of
the process address space.

# Basic Usage

## Kernel Space

1. Build and load the kmod/jtrace.ko module
1. In the module you want to debug, copy the procedure in the jtrc_test function
   in jtrace_main.c from the jtrace kmod.

## User Space

1. The app to be traced must be linked with libjtrace_lib.a
2. Copy the trace usage and setup from the tools/usertest.c program.

Note that in user space, the program being traced must call print_trace().
I'm considering adding a signal handler, or a socket listener to trigger
calling print_trace.

Also note that the trace cannot currently be retrieved from a core dump.
(check the git history after April 2015 in case this statement is stale.)

## Tools

The kernel trace can be enabled, disabled and retrieved with the tools/jtrace
program.  This will print everything in the default instance of the
kernel trace:

    jtrace -D

# API
The following macros and functions are available in both user space and
kernel space.

## Control Macros

    jtrc_setmask  - Set the mask controlling which entries are stored in the
                    trace buffer and which are not.
    jtrc_off      - Turn off all tracing
    jtrc_setprint - Control whether trace entries are printed out to the log (or printk in the kernel)

## Trace Macros
The jtrace macros are used to put entries in the trace.  They are defined
in the jtrace.h include file, and they are the same in both user and kernel
space.

    jtrc            - Put an entry in the trace, with post-expansion
    jtrc_funcline   - Put an entry in the trace, overriding the function name
		              and line number with caller-supplied values
    jtrc_hexdump    - Put a hex dump into the trace buffer.  This may span trace buffer entries
    jtrc_pfs        - Print pre-formatted string to the trace.  Use this for
		              extra args, or for strings that are not statically defined
    jtrc_entry      - Trace entry to a function
    jtrc_exit       - Trace exit from a function
    jtrc_err        - Trace an error
    jtrc_errexit    - Trace error exit from a function
    jtrc_print_tail - Print the last N elements from the trace, via printf or
		          printk depending on context

# Plans

This version of jtrace only supports both user and kernel trace, with a
one trace buffer in user space, and one in kernel space.  Merging is reports
from user and kernel will be the work of a script (TBD).

## TODO

* Automate installation
* Review/revise default flags, and add code for setting and clearing
  custom flags
* When registering a jtrace_instance, provide a struct with function pointers
  (similar to struct file_operations in the kernel) for the functions that
  must differ in user/kernel space.  This would prevent user/kernel from having
  same-name functions (which confuses etags...).
* We use the TSC register to get trace entry time stamps quickly.  We should
  add code to convert between TSC and timeofday for (at least optional)
  display purposes.  That will going gettimeofday() and rdtsc() at about the
  same time and calculating the relationship.
  gettimeofday and get the TSC in order to resolve TSC to timeofday
* Retrieve trace from process core dumps
* Per-thread trace buffers in user space.  This will be needed to reduce
  lock contention for high performance apps.
* Retrieve trace from kernel crash dumps
* Optional per-cpu trace buffers in the kernel, to reduce trace buffer lock
  contention.  This will be needed for high performance tracing.  Or just
  use ftrace...



# Acknowledgements

This code originated at Groves Technology Corporation in the 2001-2003
time frame, and has the fingerprints of Damon Permezel, Jerry Chanek and
John Groves on it.

Damon wrote this sort of tool more than once that I'm aware of, and he
originated the term "snarf".

The first similar facility I encountered was in AIX during the early 90s;
the circular buffer thing was in the kernel, but the macro support was very
primitive. Howard Green wrote a great set of macros and a "snarf"
tool that gave near-printf-level flexibility to logging to the AIX kernel
trace facility.

This tool has some overlap with the linux ftrace subsystem (which is superior
in many ways.  But ftrace doesn't support coherent tracing in both user and
kernel space.



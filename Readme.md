
# jtrace - John's trace facility

This is the jtrace facility, which supports fairly high performance
debug and trace logging to one or more circular buffers. jtrace logging
can be done either from user or kernel space.  Both user and kernel tracing
can be viewed as a unified trace (by merge sorting kernel and user space
traces).

Source tree structure:

    kmod    - the kernel module to support logging from within the kernel
              and retrieving/expanding the log (aka "snarfing")
    lib     - The user space library for logging and dumping logs
    common  - The common code which is linked into both the kernel and user
              space programs
    tools   - The command line tools for starting, stopping and snarfing
              traces

# Purpose and Strategy

The jtrace facility exists because the developers needed a way to debug kernel
and user space code in a unified way.  Printing (printf/printk) works for
some problems, but it has such a profound impact on performance that many
problems just can't be reproduced that way.

The jtrace facility puts traced entries into one or more circular buffers.
Items placed into the buffers are fixed-size.  The idea is to get near
print[f|k] flexibility by storing a trace descriptor which can be expanded
later by dereferencing pointers from the trace descriptor.  This removes
all string formatting and expansion from the critical path, and only requires
storing a few words in memory.

Trace entries have a mask associated with them, and the trace can be enabled
selectively via the mask (e.g. trace only one of several subsystems, while
masking out the rest).



# API
The following macros and functions are available in both user space and
kernel space.

## Control Macros

    kTrc_setmask  - Set the mask controlling which entries are stored in the
                    trace buffer and which are not.
    kTrc_off      - Turn off all tracing
    kTrcPrintkSet - Enable printing all un-masked trace entries in real time
                    via printk (when in the kernel)

## Trace Macros

    kTrc         - Put an entry in the trace, with post-expansion
    kTrc_tm      - Put an entry in the trace, with caller-supplied time
    kTrcFuncLine - Put an entry in the trace, overriding the function name
                   and line number with caller-supplied values
    kTrcHexDump  - Put a hex dump into the trace buffer.  This may span
                   trace buffer entries
    kTrcPrintLastElems - Print the last N elements from the trace, via
                   printf or printk depending on context
    kTrcEntry    - Trace entry to a function
    kTrcExit     - Trace exit from a function
    kTrcErr      - Trace an error
    kTrcErrExit  - Trace error exit from a function

## Porcelain Functions

    j_trc_init   - Initialize the default-named jtrace facility
    j_trc_exit   - Uninitialize the default-named jtrace facility
    j_trc_cmd    -
    j_trc_register_trc_info - Register new module trace information
    j_trc_use_registered_trc_info - Use existing module trace information
    j_trc_unregister_trc_info - Unregister module trace information

## Plumbing Functions

    j_trc_find_trc_info_by_addr - locate the trace context
    j_trc_find_trc_info_by_name - locate the trace context by name
    _j_trace         - Put an entry a trace buffer (called by the kTrc* macros)
    _j_trc_hex_dump  - Put a hex dump in a trace buffer (called by kTrc*)
    _j_trace_preformated_str - Put a pre-formatted string into a trace buffer (called by kTrc* macros)
    _j_trc_print_last_elems


# Plans

This version of jtrace only supports kernel trace.  I intend to push commits
pretty soon which enable use of jtrace from user space as well.  Generating
a unified trace report will involve merge-sorting the user space trace
report(s) with the kernel space trace report(s).

## TODO

* Switch to TSC register instead of gettimeofday
* Convert TSC to timeofday when displaying (will need to periodically
  gettimeofday and get the TSC in order to resolve TSC to timeofday
* Make the trace buffer size a kmod parameter


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



# $FreeBSD$

LOCAL_CDDL=	${.CURDIR}/../../../..
CDDL_TOP=	${.CURDIR}/../../../../..
MDB_DIR=	${CDDL_TOP}/usr/src/cmd/mdb
LIBDISASM_DIR=	${CDDL_TOP}/usr/src/lib/libdisasm
LIBSAVEARGS_DIR=${CDDL_TOP}/usr/src/lib/libsaveargs
DIS_DIR=	${CDDL_TOP}/usr/src/common/dis

OSVERSION!=	awk '/^\#define[[:blank:]]__FreeBSD_version/ {print $$3}' < /usr/include/sys/param.h

PROG=	mdb
MAN=

CFLAGS+= -I${LOCAL_CDDL}/sys/cddl/compat/opensolaris \
	-I${FREEBSD_SRC_DIR}/sys/cddl/compat/opensolaris \
	-I${LOCAL_CDDL}/cddl/compat/opensolaris/include \
	-I${FREEBSD_SRC_DIR}/cddl/compat/opensolaris/include \
	-I${OPENSOLARIS_USR_DISTDIR}/head \
	-I${LIBDISASM_DIR}/common \
	-I${DIS_DIR}/i386 \
	-I${OPENSOLARIS_USR_DISTDIR}/lib/libctf/common \
	-I${OPENSOLARIS_SYS_DISTDIR}/uts/common

.if ${MACHINE_ARCH} == "amd64"
.PATH: ${MDB_DIR}/intel/amd64/mdb
.PATH: ${MDB_DIR}/intel/mdb

TODO+=	\
	proc_amd64dep.c

SRCS+=	kvm_amd64dep_freebsd.c \
	kvm_isadep.c \
	mdb_amd64util.c

CFLAGS+= -I${MDB_DIR}/intel/mdb
CFLAGS+= -I${MDB_DIR}/intel/amd64/mdb
CFLAGS+= -I${MDB_DIR}/intel

# ???: CPPFLAGS+= -D_ELF64

.PATH: ${LIBSAVEARGS_DIR}/amd64

SRCS+=	saveargs.c

CFLAGS+= -I${LIBSAVEARGS_DIR}/common
CWARNFLAGS.saveargs.c=	-Wno-missing-prototypes

.else
.error "Unsupported platform"
.endif

.PATH: ${MDB_DIR}/common/mdb

#	ffs.c \

SRCS += \
	mdb.c \
	mdb_addrvec.c \
	mdb_argvec.c \
	mdb_callb.c \
	mdb_cmdbuf.c \
	mdb_cmds.c \
	mdb_conf.c \
	mdb_context.c \
	mdb_create.c \
	mdb_ctf.c \
	mdb_ctf_open.c \
	mdb_debug.c \
	mdb_demangle.c \
	mdb_disasm.c \
	mdb_dump.c \
	mdb_err.c \
	mdb_evset.c \
	mdb_fdio.c \
	mdb_fmt.c \
	mdb_frame.c \
	mdb_gelf.c \
	mdb_help.c \
	mdb_io.c \
	mdb_kvm_freebsd.c \
	mdb_logio.c \
	mdb_list.c \
	mdb_macalias.c \
	mdb_main.c \
	mdb_memio.c \
	mdb_modapi.c \
	mdb_module.c \
	mdb_module_load.c \
	mdb_nm.c \
	mdb_nv.c \
	mdb_pipeio.c \
	mdb_print.c \
	mdb_pservice.c \
	mdb_rawfile.c \
	mdb_set.c \
	mdb_shell.c \
	mdb_signal.c \
	mdb_stdlib.c \
	mdb_string.c \
	mdb_strio.c \
	mdb_tab.c \
	mdb_target.c \
	mdb_termio.c \
	mdb_typedef.c \
	mdb_umem.c \
	mdb_value.c \
	mdb_vcb.c \
	mdb_wcb.c \
	mdb_whatis.c

TODO+= \
	mdb_proc.c \
# Requires illumos libproc interface.  Only needed
# for live process debugging and likely needs a lot
# of work
TODO+= \
	mdb_kproc.c \
# Will require quite a bit of porting and thinking.  FreeBSD's libkvm
# doesn't support the 'aread' interface to interface with a given user
# process' address space for example, so initially we may be stuck with
# a more constrained implementation.
TODO+= \
	mdb_tdb.c \
# I think we don't actually need this since we won't be using libthread_db
# on FreeBSD

# Other notes:
# - mdb_pservice.c might not be needed either.  Neither gdb nor lldb use
#   libthread_db on FreeBSD.  It doesn't support XSAVE/AVX either.  Probably
#   simpler to use ptrace() directly and just support "lwp" thread model
#   via direct ptrace()
# - should really use getcontextx() to handle XSAVE/AVX state instead of
#   getcontext()
# - no drop-in equivalent for libdemangle and demangle.h.  Would need to
#   use demangling bits from libcxxrt instead (__cxa_demangle)
# - "fault" events will need more work to implement

CFLAGS+= -D_MDB -I${MDB_DIR}/common

LDADD= -lcurses -lkvm -lproc -lrtld_db -lctf -lumem -lelf -lutil -lz

SRCS+=	mdb_lex.l \
	mdb_grammar.y

.PATH: ${LOCAL_CDDL}/cddl/compat/opensolaris/misc

SRCS+=	\
	fdwalk.c \
	proc_str2sig.c
.if ${OSVERSION} < 1500047
SRCS+=	sig2str.c
.endif

# For the "sys/kern/syscalls.c" include.
CFLAGS+= -I${FREEBSD_SRC_DIR}

# Just include libdisasm objects in mdb for now.
.PATH: ${LIBDISASM_DIR}/common
.PATH: ${DIS_DIR}/i386

SRCS+=	\
	libdisasm.c \
	dis_i386.c \
	dis_tables.c \
	dis_sparc.c \
	dis_sparc_fmt.c \
	dis_sparc_instr.c \
	dis_s390x.c

CWARNFLAGS.dis_s390x.c=-Wno-format

CFLAGS+= -DDIS_TEXT

# Convince mdb_types.h that FreeBSD always has uintptr_t defined.
CFLAGS+= -D_SYS_INT_TYPES_H

# Use 'aligned_alloc' from jemalloc for 'memalign'.
CFLAGS+= -Dmemalign=aligned_alloc

# Map FreeBSD termios ioctls to illumos names.
CFLAGS+= -DTCGETS=TIOCGETA -DTCSETSW=TIOCSETAW

# FreeBSD doesn't have an input mode like IUCLC
CFLAGS+= -DIUCLC=0

# Use ENOENT for ENODATA.
CFLAGS+= -DENODATA=ENOENT

LDFLAGS+= -Wl,--export-dynamic

.include <bsd.prog.mk>

CWARNFLAGS.clang+= \
	-Wno-bitwise-op-parentheses \
	-Wno-cast-align \
	-Wno-cast-qual \
	-Wno-char-subscripts \
	-Wno-incompatible-pointer-types \
	-Wno-incompatible-pointer-types-discards-qualifiers \
	-Wno-logical-op-parentheses \
	-Wno-missing-braces \
	-Wno-missing-field-initializers \
	-Wno-missing-variable-declarations \
	-Wno-shadow \
	-Wno-sign-compare \
	-Wno-strict-prototypes \
	-Wno-error=tautological-pointer-compare \
	-Wno-unused-parameter

.if ${COMPILER_TYPE} == "clang" && ${COMPILER_VERSION} >= 100000 || \
    ${COMPILER_TYPE} == "gcc" && ${COMPILER_VERSION} >= 60100
CWARNFLAGS.mdb_lex.c=-Wno-misleading-indentation
.endif

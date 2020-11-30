# $FreeBSD$

LOCAL_CDDL=	${.CURDIR}/../../../../..
CDDL_TOP=	${.CURDIR}/../../../../../..
MDB_DIR=	${CDDL_TOP}/usr/src/cmd/mdb

SHLIB_NAME?=	${MOD}.so
SHLIBDIR?=	${LIBDIR}/mdb/kvm/${MACHINE_ARCH}

CFLAGS+= -I${LOCAL_CDDL}/sys/cddl/compat/opensolaris \
	-I${FREEBSD_SRC_DIR}/sys/cddl/compat/opensolaris \
	-I${FREEBSD_SRC_DIR}/sys/contrib/openzfs/include \
	-I${LOCAL_CDDL}/cddl/compat/opensolaris/include \
	-I${FREEBSD_SRC_DIR}/cddl/compat/opensolaris/include \
	-I${OPENSOLARIS_USR_DISTDIR}/head \
	-I${OPENSOLARIS_USR_DISTDIR}/lib/libctf/common \
	-I${OPENSOLARIS_SYS_DISTDIR}/uts/common

CFLAGS+= -I${MDB_DIR}/common

CWARNFLAGS.clang+= \
	-Wno-missing-field-initializers \
	-Wno-missing-prototypes \
	-Wno-strict-prototypes \
	-Wno-unused-parameter

.include "../Makefile.inc"

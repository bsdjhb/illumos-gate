# $FreeBSD$

.if ${MACHINE_ARCH} == "amd64"
CFLAGS+= -D__amd64
.endif

CFLAGS+= -DIN_BASE

.include "../Makefile.inc"

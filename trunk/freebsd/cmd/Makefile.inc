.PATH:	${.CURDIR}/../../../usr
.PATH:	${.CURDIR}/../../../doc/manpages

CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -g -I${.CURDIR}/../../../include
CFLAGS += -D_GNU_SOURCE # required for glibc >= 2.8
CFLAGS += -DFREEBSD
CFLAGS += -DETC_DIR=\"${ETC_DIR}\"

PREFIX?=	/usr/local
BINDIR?=	${PREFIX}/sbin
MANDIR?=	${PREFIX}/man/man
ETC_DIR?=	${PREFIX}/etc/

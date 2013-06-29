.PATH:	${.CURDIR}/../../kernel

KMOD=	iet

SRCS=	vnode_if.h
SRCS+=	tio.c
SRCS+=	iscsi.c
SRCS+=	nthread.c
SRCS+=	config.c
SRCS+=	digest.c
SRCS+=	conn.c
SRCS+=	session.c
SRCS+=	target.c
SRCS+=	volume.c
SRCS+=	iotype.c
SRCS+=	null-io.c
SRCS+=	target_disk.c
SRCS+=	eventbsd.c
SRCS+=	param.c
SRCS+=	block-io.c
SRCS+=	wthread.c
SRCS+=	file-io.c
SRCS+=	ua.c
SRCS+=	persist.c

CFLAGS = -I${.CURDIR}/../../include/ -DFREEBSD

.include <bsd.kmod.mk>

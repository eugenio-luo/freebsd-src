.PATH: ${SRCTOP}/sys/netinet
.PATH: ${SRCTOP}/sys/netinet6

KMOD= sdtp
SRCS= sdtp_module.c sdtp_usrreq.c sdtp_structs.c sdtp_pcb.c

SRCS+= opt_inet.h opt_inet6.h

.include <bsd.kmod.mk>

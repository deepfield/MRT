#
# $Id: Makefile,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
#

include ../../Make.include

OBJS    = $(KERNEL_OBJS) common.o kernel_uii.o socket.o mroute.o igmp.o
ARCHIVE = $(RIBLIB)

include ../Make.include

#LIBS=$(EXTRA_LIBS) $(THREADLIBS) $(MRT_LIBS)
test: main.o $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) main.o -o $@ $(LIBS)

# DO NOT DELETE THIS LINE -- make depend depends on it.

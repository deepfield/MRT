#
# $Id: Makefile,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
#

include ../../Make.include

GOAL   = datadstl
OBJS   = dir.o publisher.o diskpublisher.o salypublisher.o driver.o bgp_db.o \
			util.o mytime.o daemon.c report_publisher.o flapSourcer.o \
			flapCounter.o asExplorerPublisher.o

LIBS	+= $(DATADSTL_LIBS) -lm ../SalyClient2/propertyList.o \
			../SalyClient2/salamanderUtil.o ../SalyClient2/salamanderInterface.o


all:  $(GOAL) 

$(GOAL): $(OBJS) $(MRT_LIBS)
#	@echo "Linking: $(LD) $(LDFLAGS) $(OBJS) -o $@"
	$(LD) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)
#	@$(CP) ./$@ $(EXEC_PREFIX)/bin/

$(GOAL).purify:	$(OBJS) $(MRT_LIBS)
	$(PURIFY) $(LD) $(LDFLAGS) $(OBJS) -o $@ $(LIBS) $(DB_LIB)

$(GOAL).quantify: $(OBJS) $(MRT_LIBS)
	$(QUANTIFY) $(LD) $(LDFLAGS) $(OBJS) -o $@ $(LIBS) $(KVM_LIB) $(DB_LIB)

install: $(GOAL)
	$(INSTALL) -m 755 -o root -g bin $(GOAL) $(DESTDIR)/$(GOAL)

clean:
	$(RM) *.o core *.core *~* *.purify *.quantify $(GOAL)

cleanobjs:
	$(RM) *.o core *.core *~* *.purify *.quantify

depend:
	$(MAKEDEP) $(CFLAGS) $(CPPFLAGS) $(DEFINES) *.c


# DO NOT DELETE THIS LINE -- make depend depends on it.

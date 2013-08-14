#
# $Id: Makefile,v 1.1.1.1 2000/08/14 18:46:14 labovit Exp $
#

include ../../Make.include

GOAL   = mrtd
OBJS   = mrtd.o $(CFGLIB) $(BGPLIB) $(RIPLIB) $(PIMLIB) $(RIBLIB) $(MRTLIB)


all:  $(GOAL)

$(GOAL): $(OBJS)
#	@echo "Linking: $(LD) $(LDFLAGS) $(OBJS) -o $@"
	$(LD) $(LDFLAGS) $(OBJS) -o $@ $(SYS_LIBS)
#	$(CP) ./$@ $(EXEC_PREFIX)/bin/

$(GOAL).purify: $(OBJS)
	$(PURIFY)  -cache-dir=/tmp $(LD) $(LDFLAGS) $(OBJS) -o $@ $(SYS_LIBS)

$(GOAL).quantify: $(OBJS)
	$(QUANTIFY) -cache-dir=/tmp $(LD) $(LDFLAGS) $(OBJS) -o $@ $(SYS_LIBS)

install: $(GOAL)
	$(INSTALL) -m 755 $(GOAL) $(DESTDIR)/$(GOAL)
	$(INSTALL) -m 444 mrtd.8 $(MANDIR)/man8/

clean:
	$(RM) *.o core *.core *~* $(GOAL) $(GOAL).purify $(GOAL).quantify

depend:
	$(MAKEDEP) $(CFLAGS) $(CPPFLAGS) $(DEFINES) *.c


# DO NOT DELETE THIS LINE -- make depend depends on it.

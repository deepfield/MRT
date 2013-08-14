#
# $Id: Makefile,v 1.1.1.1 2000/08/14 18:46:14 labovit Exp $
#

include ../../Make.include

GOAL   = ricd
OBJS   = ricd.o hqlip.o ricdconf.o area.o \
	 srsvp.o qif.o \
	 $(CFGLIB) $(RIBLIB) $(MRTLIB)


all:  $(GOAL)

$(GOAL): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $@ $(SYS_LIBS)

$(GOAL).purify: $(OBJS)
	$(PURIFY)  -cache-dir=/tmp $(LD) $(LDFLAGS) $(OBJS) -o $@ $(SYS_LIBS)

$(GOAL).quantify: $(OBJS)
	$(QUANTIFY) -cache-dir=/tmp $(LD) $(LDFLAGS) $(OBJS) -o $@ $(SYS_LIBS)

install: $(GOAL)
	$(INSTALL) -m 755 $(GOAL) $(DESTDIR)/$(GOAL)
	$(INSTALL) -m 444 ricd.8 $(MANDIR)/man8/

src-dist:
	test $(.CURDIR) && cd $(.CURDIR); version=ricd; \
	cd ../../../; rm -rf $$version && mkdir -p $$version && \
	tar cf - src/programs/ricd | (cd $$version; tar xpf -) && \
	find $$version -name CVS -exec rm -rf {} \; -prune && \
	find $$version -name '.#*' -exec rm -rf {} \; -prune && \
	find $$version -name '.nfs*' -exec rm -rf {} \; -prune && \
	(cd $$version; tar cf - src) | \
	gzip > $$version-src.tar.gz; rm -rf $$version

clean:
	$(RM) *.o core *.core *~* $(GOAL) $(GOAL).purify $(GOAL).quantify

depend:
	 $(MAKEDEP) $(CFLAGS) $(CPPFLAGS) $(DEFINES) *.c


# DO NOT DELETE THIS LINE -- make depend depends on i

#
# $Id: Makefile,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
#

include ../../Make.include

GOAL   = sbgp
OBJS   = simple_bgp.o $(BGPLIB) $(CFGLIB) $(RIBLIB) $(MRTLIB) $(BGPLIB)
# the above BGPLIB appears twice since there is a loop reference


all:  $(GOAL)

$(GOAL): $(OBJS)
#	@echo "Linking: $(LD) $(LDFLAGS) $(OBJS) -o $@"
	$(LD) $(LDFLAGS) $(OBJS) -o $@ $(SYS_LIBS)
#	$(CP) ./$@ $(EXEC_PREFIX)/bin	

install: $(GOAL)
	$(INSTALL) -m 755 $(GOAL) $(DESTDIR)/$(GOAL)

clean:
	$(RM) *.o core *.core *~* $(GOAL) $(GOAL).purify

depend:
	$(MAKEDEP) $(CFLAGS) $(CPPFLAGS) $(DEFINES) *.c


# DO NOT DELETE THIS LINE -- make depend depends on it.

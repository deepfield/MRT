#
# $Id: Makefile,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
#

include ../../Make.include

GOAL   = route_tracker
OBJS   = main.o config.o process.o telnet.o commands.o util.o load.o adj_rib.o


all:  $(GOAL)

#$(GOAL): $(OBJS) $(MRT_LIBS)
$(GOAL):
	@echo "nothing";
#	@echo "Linking: $(LD) $(LDFLAGS) $(OBJS) -o $@"
#	$(LD) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)
#	@$(CP) ./$@ $(EXEC_PREFIX)/bin/

$(GOAL).purify:	$(OBJS) $(MRT_LIBS)
	$(PURIFY) $(LD) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)

$(GOAL).quantify: $(OBJS) $(MRT_LIBS)
	$(QUANTIFY) $(LD) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)

install: $(GOAL)
	$(INSTALL) -m 755 -o root -g bin $(GOAL) $(DESTDIR)/$(GOAL)

clean:
	$(RM) *.o core *.core *~* *.purify *.quantify $(GOAL)

depend:
	$(MAKEDEP) $(CFLAGS) $(CPPFLAGS) $(DEFINES) *.c


# DO NOT DELETE THIS LINE -- make depend depends on it.

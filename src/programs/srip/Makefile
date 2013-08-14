#
# $Id: Makefile,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
#

include ../../Make.include

GOAL   = srip
OBJS   = simple_rip.o


nothing:

all:  srip 

$(GOAL): $(OBJS) $(MRT_LIBS)
#	@echo "Linking: $(LD) $(LDFLAGS) $(OBJS) -o $@"
	$(LD) $(LDFLAGS) $(OBJS) -o $@ $(LIBS) 
#	$(CP) ./$@ $(EXEC_PREFIX)/bin

clean:
	$(RM) *.o core *.core *~* $(GOAL)

depend:
	$(MAKEDEP) $(CFLAGS) $(CPPFLAGS) $(DEFINES) *.c


# DO NOT DELETE THIS LINE -- make depend depends on it.

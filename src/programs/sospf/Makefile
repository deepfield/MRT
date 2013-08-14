#
# $Id: Makefile,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
#

include ../../Make.include

GOAL   = sospf
OBJS   = hello.o database.o config.o packet.o neighbor.o ospf_thread.o link_state.o lsa_database.o interface.o net_map.o

all:  $(GOAL) 
#ospf_anal



$(GOAL):
	echo "Skip for now"

#$(GOAL): main.o $(OBJS) $(MRT_LIBS)
#	@echo "Linking: $(LD) $(LDFLAGS) main.o $(OBJS) -o $@"
#	$(LD) $(LDFLAGS) main.o $(OBJS) -o $@ $(LIBS)
#	$(CP) ./$@ $(EXEC_PREFIX)/bin	



#ospf_anal: ospf_anal.o $(OBJS) $(MRT_LIBS)
#	@echo "Linking: $(LD) $(LDFLAGS) ospf_anal.o $(OBJS) -o $@"
#	$(LD) $(LDFLAGS) ospf_anal.o $(OBJS) -o $@ $(LIBS)
#	$(CP) ./$@ $(EXEC_PREFIX)/bin		

ospf_anal.purify:  ospf_anal.o $(OBJS) $(MRT_LIBS)
	@echo "Linking: $(LD) $(LDFLAGS) ospf_anal.o $(OBJS) -o $@"
	@$(PURIFY) $(LD) $(LDFLAGS)  ospf_anal.o $(OBJS) -o $@ $(LIBS)

clean:
	$(RM) *.o core *.core *~* $(GOAL)

depend:
	$(MAKEDEP) $(CFLAGS) $(CPPFLAGS) $(DEFINES) *.c


# DO NOT DELETE THIS LINE -- make depend depends on it.

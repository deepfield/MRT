#
# $Id: Makefile,v 1.1.1.1 2000/08/14 18:46:16 labovit Exp $
#

include ../Make.include

CPPFLAGS= -I../../include -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS -DFUNCPROTO -I../include/
EXEC_PREFIX=    ../obj/solaris2.5.1


demo: demo.o
	@echo "Linking: $(LD) $(LDFLAGS) demo.o -o $@"
	@$(LD) $(LDFLAGS) demo.o -o $@ $(LIBS)

clean:
	$(RM) *.o core *.core *~* $(GOAL)

depend:
	$(MAKEDEP) $(CFLAGS) $(CPPFLAGS) $(DEFINES) *.c

# DO NOT DELETE THIS LINE -- make depend depends on it.

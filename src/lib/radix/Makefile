#
# $Id: Makefile,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
#

include ../../Make.include

OBJS    = radix.o
ARCHIVE = $(MRTLIB)

include ../Make.include

demo:   $(OBJS) demo.o
	@echo "Making demo.." 
	@$(LD) $(LDFLAGS) $(OBJS) -o $@ demo.o $(LIBS)
	@echo "demo done..."

# DO NOT DELETE THIS LINE -- make depend depends on it.

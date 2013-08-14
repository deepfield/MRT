#
# $Id: Makefile,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
#

include ../../Make.include

OBJS    = aspath.o bgp_attr.o as_regexp.o as_alist.o bgp_msg.o community.o
ARCHIVE = $(BGPLIB)

include ../Make.include

demo:   $(OBJS) demo.o
	@echo "Making demo.." 
	@$(LD) $(LDFLAGS) $(OBJS) -o $@ demo.o $(LIBS)
	@echo "demo done..."

# DO NOT DELETE THIS LINE -- make depend depends on it.

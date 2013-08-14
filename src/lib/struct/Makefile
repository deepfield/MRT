#
# $Id: Makefile,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
#

include ../../Make.include

OBJS    = New.o stack.o array.o linked_list.o hash.o
#CFLAGS += -D_LL_INTERNAL_DEBUG -DLL_DEBUG
ARCHIVE = $(MRTLIB)

DEBUG_OBJS=New_debug.o stack_debug.o array_debug.o list_debug.o hash_debug.o
INTERNAL_OBJS=list_int.o hash_int.o list_int_deb.o hash_int_deb.o
DEBUG_LIB=-lhash_debug -llist_debug -larray -lstack -lNew

include ../Make.include

# DO NOT DELETE THIS LINE -- make depend depends on it.

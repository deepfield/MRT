#
# $Id: Makefile,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
#

include ../Make.include

DIRS=$(PROGRAM_DIRS)
DIRS_MRT=$(PROGRAM_DIRS_MRT)

all:  make-programs

make-programs:
	@for i in $(DIRS); \
	do (echo "cd $$i; $(MAKE)"; cd $$i; $(MAKE); cd ..); done

mrt-program:
	@for i in $(DIRS_MRT); \
	do (echo "cd $$i; $(MAKE)"; cd $$i; $(MAKE); cd ..); done

install:
	@for i in $(DIRS); \
	do (echo "cd $$i; $(MAKE)"; cd $$i; $(MAKE) install; cd ..); done

mrt-install:
	@for i in $(DIRS_MRT); \
	do (echo "cd $$i; $(MAKE)"; cd $$i; $(MAKE) install; cd ..); done

clean:
	@for i in $(DIRS); \
	do (echo "cd $$i; $(MAKE) $@"; cd $$i; $(MAKE) $@; cd ..); done

depend:
	@for i in $(DIRS); \
	do (echo "cd $$i; $(MAKE) $@"; cd $$i; $(MAKE) $@; cd ..); done

depend-clean:
	@for i in $(DIRS); \
	do (echo "cd $$i; $(MKDEPCLEAN)"; cd $$i; $(MAKEDEPCLEAN); cd ..); done

#
# $Id: Makefile,v 1.1.1.1 2000/08/14 18:46:09 labovit Exp $
#

include Make.include

all::	
	@test $(.CURDIR) && cd $(.CURDIR); \
	if [ "$(NEED_CONFIGURE)" ]; then sh ./configure; fi && \
	$(MAKE) library program

mrt: library mrt-program

install: library
	@echo "Installing programs"; \
	    test $(.CURDIR) && cd $(.CURDIR); cd programs; $(MAKE) install

mrt-install: library mrt-program
	@echo "Installing MRT programs"; \
	    test $(.CURDIR) && cd $(.CURDIR); cd programs; $(MAKE) mrt-install

bin-dist:
	test $(.CURDIR) && cd $(.CURDIR); \
	version=`/bin/pwd` && version=`dirname $$version` && \
	version=`basename $$version` && \
	rm -rf $$version && mkdir -p $$version/conf && \
	mkdir -p $$version/bin && mkdir -p $$version/lib && \
	mkdir -p $$version/man && mkdir -p $$version/include && \
	ln ../README $$version && \
	for i in $(PROGRAMS); do \
	    ln programs/*/$$i $$version/bin; done ; \
	cp programs/*/route_atob.pl $$version/bin && \
	cp programs/*/route_btoa.pl $$version/bin && \
	ln lib/*.a $$version/lib && \
	ln ../src/programs/*/*.conf $$version/conf && \
	ln ../src/programs/*/*.1 $$version/man && \
	ln ../src/programs/*/*.8 $$version/man && \
	ln ../src/include/*.h $$version/include && \
	chmod -R u+w $$version; \
	tar cf - $$version | gzip > $$version-$(HOST_OS).tar.gz; \
	rm -rf $$version

# This only dumps tools defined in PROGRAM_DIRS_MRT
src-dist:
	test $(.CURDIR) && cd $(.CURDIR); \
	version=`/bin/pwd` && version=`dirname $$version` && \
	version=`basename $$version` && \
	(cd ..; rm -rf $$version && mkdir -p $$version) && \
	(cd ..; tar cf - src make-sym-links README TODO) | \
	(cd ../$$version; tar xpf -) && \
	(cd ../$$version/src/programs; mkdir .tmp; \
	 mv Makefile $(PROGRAM_DIRS_MRT) .tmp; rm -rf *; \
	 cd .tmp; mv * ..; cd ..; rm -rf .tmp) && \
	find ../$$version -name CVS -exec rm -rf {} \; -prune && \
	find ../$$version -name '.#*' -exec rm -rf {} \; -prune && \
	find ../$$version -name '.nfs*' -exec rm -rf {} \; -prune && \
	(cd ..; chmod -R u+w $$version; \
	 tar cf - $$version | gzip > $$version-src.tar.gz; \
	rm -rf $$version)

#
# I don't know the smart way to stop freebsd's make changing dir to ./obj 
#                                                               -- masaki

library:
	@echo "Making lib"; \
	    test $(.CURDIR) && cd $(.CURDIR); cd lib; $(MAKE) all

program:
	@echo "Making programs"; \
	    test $(.CURDIR) && cd $(.CURDIR); cd programs; $(MAKE) all

mrt-program:
	@echo "Making MRT programs"; \
	    test $(.CURDIR) && cd $(.CURDIR); cd programs; $(MAKE) mrt-program

clean:
	@$(RM) config.cache
	@echo "Cleaning up lib"; \
	test $(.CURDIR) && cd $(.CURDIR); cd lib; $(MAKE) $@
	@echo "Cleaning up programs"; \
	test $(.CURDIR) && cd $(.CURDIR); cd programs; $(MAKE) $@
	@test $(.CURDIR) && cd $(.CURDIR); $(RM) config.cache

depend:
	@echo "Making dependency in lib"; \
	test $(.CURDIR) && cd $(.CURDIR); cd lib; $(MAKE) $@
	@echo "Making dependency in programs"; \
	test $(.CURDIR) && cd $(.CURDIR); cd programs; $(MAKE) $@

depend-clean:
	@echo "Removing dependency in lib"; \
	test $(.CURDIR) && cd $(.CURDIR); cd lib; $(MAKE) $@
	@echo "Removing dependency in programs"; \
	test $(.CURDIR) && cd $(.CURDIR); cd programs; $(MAKE) $@

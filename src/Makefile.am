bin_PROGRAMS = tuncat
tuncat_SOURCES = tuncat.c tuncat.h
tuncat_CFLAGS = @CFLAGS@ @SNAPPY_CFLAGS@
tuncat_LDADD = @LIBS@ @SNAPPY_LIBS@

install-exec-hook:
	@if [ `id -u` -eq 0 ]; then \
	    setcap cap_net_admin=ep $(DESTDIR)$(bindir)/tuncat ; \
	fi

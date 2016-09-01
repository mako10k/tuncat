bin_PROGRAMS = tuncat
tuncat_SOURCES = tuncat.c tuncat.h
tuncat_LDFLAGS = -lsnappy

install-exec-hook:
	@if [ `id -u` -eq 0 ]; then \
	    setcap cap_net_admin=ep $(DESTDIR)$(bindir)/tuncat ; \
	fi

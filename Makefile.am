bin_PROGRAMS = tuncat
tuncat_SOURCES = tuncat.c tuncat.h
tuncat_LDFLAGS = -lsnappy

install-exec-hook:
	setcap cap_net_admin=ep $(DESTDIR)$(bindir)/tuncat

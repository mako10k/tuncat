bin_PROGRAMS = tuncat
tuncat_SOURCES = tuncat.c tuncat.h
tuncat_CFLAGS = @SNAPPY_CFLAGS@
tuncat_LDADD = @SNAPPY_LIBS@
CFLAGS = -Wall -Wextra -Werror

install-exec-hook:
	@if [ `id -u` -eq 0 ]; then \
	    setcap cap_net_admin=ep $(DESTDIR)$(bindir)/tuncat ; \
	fi

bin_PROGRAMS = tuncat
tuncat_SOURCES = tuncat.c tuncat.h
tuncat_CFLAGS = @SNAPPY_CFLAGS@
tuncat_LDADD = @SNAPPY_LIBS@
CFLAGS  = -Wall -Wextra -Werror -pedantic -std=gnu11 -O2 -g
CFLAGS += -Wformat=2 -Wconversion -Wsign-conversion -Wimplicit-fallthrough

install-exec-hook:
	@if [ `id -u` -eq 0 ]; then \
	    setcap cap_net_admin=ep $(DESTDIR)$(bindir)/tuncat ; \
	fi

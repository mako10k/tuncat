bin_PROGRAMS = tuncat
tuncat_SOURCES = \
  tuncat.c tuncat.h \
  tuncat_if.c tuncat_if.h \
  tuncat_net.c tuncat_net.h

tuncat_CFLAGS = @SNAPPY_CFLAGS@
tuncat_LDADD = @SNAPPY_LIBS@

CFLAGS = -Wall -Wextra -Werror

install-exec-hook:
	@if [ `id -u` -eq 0 ]; then \
		if [ -x /sbin/setcap ]; then \
			setcap cap_net_admin=ep "$(DESTDIR)$(bindir)/tuncat" ; \
		else \
			echo "setcap not found, falling back to setuid root" ; \
			chown root:root "$(DESTDIR)$(bindir)/tuncat" ; \
			chmod u+s "$(DESTDIR)$(bindir)/tuncat" ; \
		fi ; \
	fi

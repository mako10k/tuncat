#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([tuncat],[0.9.3],[mako10k@mk10.org])
AC_CONFIG_SRCDIR([src/tuncat.c])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS([config.h])
AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB(resolv, [inet_net_pton])
PKG_CHECK_MODULES(SNAPPY, [snappy])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h netinet/in.h netdb.h sys/socket.h stdlib.h string.h sys/ioctl.h unistd.h snappy-c.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_FORK
AC_CHECK_FUNCS([memmove memset select socket])

DX_OUTPUT_DIR=doxygen

AC_SUBST([DX_OUTPUT_DIR], [${DX_OUTPUT_DIR}])

AC_CONFIG_FILES([Makefile src/Makefile docs/Makefile])
AC_CONFIG_FILES([docs/Doxyfile])
AC_CONFIG_FILES([tuncat.spec])


DX_INIT_DOXYGEN([${PACKAGE_NAME}], [Doxyfile], [${DX_OUTPUT_DIR}])

DX_DOXYGEN_FEATURE([ON])
DX_DOT_FEATURE(ON)
DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)

AC_OUTPUT

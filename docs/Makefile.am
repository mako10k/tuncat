EXTRA_DIST = Doxyfile
DISTCLEAN_FILES = Doxyfile

@DX_RULES@

clean-local:
	rm -rf doxygen

doxygen-prepare:
	mkdir -p doxygen

all-local: doxygen-prepare doxygen-doc
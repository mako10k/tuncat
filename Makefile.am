SUBDIRS = src

EXTRA_DIST = Doxygen.config

# include Doxygen rules (requires autoconf-archive >2016-03-20)
@DX_RULES@

clean-local:
	-rm -rf $(abs_top_builddir)/docs/*

doxygen-prepare:
	mkdir -p $(abs_top_builddir)/docs/

docs: doxygen-prepare doxygen-doc

# Try to tell autotools to install documentation
htmldir = $(docdir)/html
html_DATA = $(abs_top_builddir)/docs/html

$(html_DATA): docs

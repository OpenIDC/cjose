SUBDIRS = . include src test doc
EXTRA_DIST = CHANGELOG.md README.md LICENSE

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = cjose.pc

doxygen:
	cd doc && $(MAKE) doxygen

clang-format:
	clang-format -i `find . -name *.[ch]`

docker-%: clean
	$(MAKE) -f test/Makefile $@

SUBDIRS = . include src test doc platform
EXTRA_DIST = CHANGELOG.md README.md LICENSE

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = cjose.pc

doxygen:
	cd doc && $(MAKE) doxygen

test : check
	cat test/check_cjose.log

clean-local :
	rm -rf dist/*

distclean-local :
	rm -rf dist/*

package-prepare : dist
	mkdir -p dist && \
	rm -rf dist/cjose-$(PACKAGE_VERSION).tar.gz && \
	cp cjose-$(PACKAGE_VERSION).tar.gz dist

package-local : package-prepare
	@echo packages built

clang-format:
	clang-format -i `find . -name *.[ch]`

TAG=cjose/test

docker: clean
	docker build --progress plain -f test/Dockerfile . -t $(TAG)

DOCKER_RUN_ARGS := -e CK_FORK=no -e LD_LIBRARY_PATH=/usr/local/lib:/root/cjose/src/.libs

docker-check: docker
	docker run -it $(DOCKER_RUN_ARGS) --rm $(TAG):latest bash -c "make check || cat test/test-suite.log"

docker-valgrind: docker
	docker run -it $(DOCKER_RUN_ARGS) --rm $(TAG):latest /usr/bin/valgrind --leak-check=full --show-leak-kinds=definite --read-inline-info=yes --keep-debuginfo=yes test/.libs/check_cjose

docker-gdb: docker
	docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it --rm $(DOCKER_RUN_ARGS) $(TAG):latest /usr/bin/gdb test/.libs/check_cjose

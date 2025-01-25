FROM debian:bookworm

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y pkg-config make gcc gdb lcov valgrind vim curl wget
RUN apt-get update && apt-get install -y autoconf automake libtool
RUN apt-get update && apt-get install -y libjansson-dev check
#RUN apt-get update && apt-get install -y libssl-dev 

RUN apt-get install -y build-essential checkinstall zlib1g-dev
WORKDIR /root
ARG OPENSSL_VERSION=3.4.0
RUN wget https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz
RUN tar xvf openssl-${OPENSSL_VERSION}.tar.gz
WORKDIR /root/openssl-${OPENSSL_VERSION}
RUN ./config
# make -s
RUN make install_sw install_ssldirs

ENV SRCDIR /root/cjose
RUN mkdir ${SRCDIR}
WORKDIR ${SRCDIR}

COPY . ${SRCDIR}

ARG CONFIGURE_ARGS=--with-rsapkcs1_5

#RUN autoreconf --force --install && rm -rf autom4te.cache/
RUN touch aclocal.m4 configure Makefile.am Makefile.in
RUN ./configure \
	--with-openssl=/usr/local \
	${CONFIGURE_ARGS}
RUN make all
RUN cd test && make check_cjose

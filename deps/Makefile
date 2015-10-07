all: libarchive/.libs/libarchive.a

libarchive/configure: libarchive/configure.ac
	cd libarchive && \
	    autoreconf --install

libarchive/Makefile: libarchive/configure
	cd libarchive && \
	    ./configure \
	    --disable-silent-rules \
	    --enable-shared=no \
	    --enable-static=yes \
	    --disable-bsdtar \
	    --disable-bsdcpio \
	    --disable-posix-regex-lib \
	    --without-zlib \
	    --without-bz2lib \
	    --without-lzmadec \
	    --without-iconv \
	    --without-lzma \
	    --without-lzo2 \
	    --without-nettle \
	    --without-openssl \
	    --without-xml2 \
	    --without-expat  
	test -f $@ && touch $@

libarchive/.libs/libarchive.a: libarchive/Makefile
	cd libarchive && \
	    make -j8
	test -f $@ && touch $@

clean:
	cd libarchive && git clean -fxd

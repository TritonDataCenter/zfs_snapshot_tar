

all:

libarchive-3.1.2/configure: libarchive-3.1.2.tar.gz
	gtar xfz libarchive-3.1.2.tar.gz

libarchive-3.1.2/Makefile: libarchive-3.1.2/configure
	cd libarchive-3.1.2 && \
	    ./configure \
	    --disable-silent-rules \
	    --enable-shared=yes \
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

libarchive-3.1.2/.libs/libarchive.a: libarchive-3.1.2/Makefile
	cd libarchive-3.1.2 && \
	    make -j8
	test -f $@ && touch $@


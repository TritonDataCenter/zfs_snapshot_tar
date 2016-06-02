#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright 2016 Joyent, Inc.
#

TOOLS_PROTO =		/ws/plat/projects/illumos/usr/src/tools/proto/root_i386-nd
CTFMERGE =		$(TOOLS_PROTO)/opt/onbld/bin/i386/ctfmerge-altexec
CTFCONVERT =		$(TOOLS_PROTO)/opt/onbld/bin/i386/ctfconvert-altexec

CC =			gcc
STRIP =			/usr/bin/strip

PROG =			zfs_snapshot_tar

OBJ =			cmd.o pipe_stream.o run_command.o custr.o list.o strlist.o avl.o

CFLAGS =		-gdwarf-2 \
			-fno-omit-frame-pointer \
			-Wall -Wextra -Werror \
			-Wno-unused-parameter \
			-std=gnu99 \
			-Ideps/illumos \
			-Ideps/smartos \
			-Ideps/libarchive/libarchive \
			-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

LIBS =			deps/libarchive/.libs/libarchive.a


$(PROG): $(OBJ:%=obj/%) $(LIBS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
	$(CTFCONVERT) -l $@ -o $@ $@
	$(STRIP) -x $@

obj/%.o: %.c | stamp-0-libarchive obj
	$(CC) $(CFLAGS) -c -o $@ $^

obj/%.o: deps/illumos/%.c | stamp-0-libarchive obj
	$(CC) $(CFLAGS) -c -o $@ $^

obj/%.o: deps/smartos/%.c | stamp-0-libarchive obj
	$(CC) $(CFLAGS) -c -o $@ $^

obj:
	mkdir -p $@

deps/libarchive/.libs/libarchive.a: stamp-0-libarchive

stamp-0-libarchive:
	git submodule update --init
	cd deps && $(MAKE) libarchive/.libs/libarchive.a
	touch $@

.PHONY: clean
clean:
	-rm -f $(OBJ:%=obj/%)
	-rm -f $(PROG)

.PHONY: clobber
clobber: clean
	cd deps && $(MAKE) clean
	-rm -f stamp-0-libarchive


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
			-Ideps/libarchive-3.1.2/libarchive \
			-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

LIBS =			deps/libarchive-3.1.2/.libs/libarchive.a


$(PROG): $(OBJ:%=obj/%)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
	$(CTFCONVERT) -l $@ -o $@ $@
	$(STRIP) -x $@

obj/%.o: %.c | obj
	$(CC) $(CFLAGS) -c -o $@ $^

obj/%.o: deps/illumos/%.c | obj
	$(CC) $(CFLAGS) -c -o $@ $^

obj/%.o: deps/smartos/%.c | obj
	$(CC) $(CFLAGS) -c -o $@ $^

obj:
	mkdir -p $@

clean:
	-rm -f $(OBJ:%=obj/%)
	-rm -f $(PROG)


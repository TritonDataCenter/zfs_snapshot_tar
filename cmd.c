

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <sys/stat.h>
#include <ftw.h>
#include <dirent.h>

#include <archive.h>
#include <archive_entry.h>

#include "custr.h"
#include "strlist.h"
#include "run_command.h"

#define	CMD_ZFS		"/sbin/zfs"

typedef enum diff_ent_flags {
	DE_F_COMPLETE = 0x01,
	DE_F_WHITEOUT = 0x02,
	DE_F_FILE = 0x04,
} diff_ent_flags_t;

typedef struct diff_ent diff_ent_t;

struct diff_ent {
	char *de_name;

	diff_ent_t *de_sibling;
	diff_ent_t *de_child;
	diff_ent_t *de_parent;

	diff_ent_flags_t de_flags;
};

typedef enum snaptar_flags {
	SNTR_F_FAILED = 0x01,
} snaptar_flags_t;

typedef struct {
	snaptar_flags_t st_flags;

	char *st_dataset;
	char *st_snap0;
	char *st_snap1;
	
	char *st_mountpoint;

	diff_ent_t st_root;

	int st_snapshot_fd;
	custr_t *st_errstr;

	struct archive *st_archive;
	struct archive_entry *st_archive_entry;
} snaptar_t;

typedef int ent_enum_cb(snaptar_t *, const char *, int, struct stat *);
typedef int walk_dir_func(snaptar_t *, ent_enum_cb *);

void
whiteout_path(const char *path, char **outp)
{
	char *out;

	if (strchr(path, '/') == NULL) {
		fprintf(stderr, "WHITEOUT: .wh.%s\n", path);
		return;
	}

	char *tmp0 = NULL, *tmp1 = NULL;
	const char *basen = NULL;
	const char *dirn = NULL;

	tmp0 = strdup(path);
	basen = basename(tmp0);

	tmp1 = strdup(path);
	dirn = dirname(tmp1);

	if (asprintf(&out, "%s/.wh.%s", dirn, basen) < 0) {
		err(1, "asprintf");
	}

	free(tmp0);
	free(tmp1);

	*outp = out;
}

static int
make_fullsnap(const char *dataset, const char *snap, char **fullsnap)
{
	VERIFY(dataset != NULL);
	VERIFY(snap != NULL);

	if (strchr(dataset, '@') != NULL || strchr(snap, '@') != NULL) {
		errno = EINVAL;
		return (-1);
	}

	if (asprintf(fullsnap, "%s@%s", dataset, snap) < 0) {
		return (-1);
	}

	return (0);
}

int
snaptar_init(snaptar_t **stp, char *errbuf, size_t errlen,
    const char *dataset, const char *snap0, const char *snap1)
{
	snaptar_t *st;
	custr_t *errstr = NULL;
	int e;

	if (custr_alloc_buf(&errstr, errbuf, errlen) != 0) {
		e = errno;
		snprintf(errbuf, errlen, "custr_alloc_buf failure: %s",
		    strerror(errno));
		goto errout;
	}

	if ((st = calloc(1, sizeof (*st))) == NULL) {
		e = errno;
		custr_append_printf(errstr, "calloc failure: %s",
		    strerror(errno));
		goto errout;
	}

	if ((st->st_snap1 = strdup(snap1)) == NULL ||
	    (st->st_dataset = strdup(dataset)) == NULL) {
		custr_append_printf(errstr, "strdup failure: %s",
		    strerror(errno));
		goto errout;
	}

	if (snap0 != NULL) {
		if ((st->st_snap0 = strdup(snap0)) == NULL) {
			custr_append_printf(errstr, "strdup failure: %s",
			    strerror(errno));
			goto errout;
		}
	}

	st->st_snapshot_fd = -1;

	*stp = st;
	custr_free(errstr);
	return (0);

errout:
	custr_free(errstr);
	errno = e;
	return (-1);
}

void
snaptar_fini(snaptar_t *st)
{
	if (st->st_snapshot_fd != -1) {
		VERIFY0(close(st->st_snapshot_fd));
	}

	free(st->st_dataset);
	free(st->st_snap0);
	free(st->st_snap1);

	VERIFY(st->st_archive == NULL);
	VERIFY(st->st_archive_entry == NULL);

	free(st);
}

boolean_t
strlist_match(strlist_t *sl, unsigned int idx, const char *check)
{
	if (strlist_get(sl, idx) == NULL) {
		return (B_FALSE);
	}

	if (strcmp(strlist_get(sl, idx), check) != 0) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

static int
get_child(diff_ent_t *dir, const char *comp, diff_ent_t **child)
{
	diff_ent_t *de;

	if (strchr(comp, '/') != NULL) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Look through the children of this directory for an entry that
	 * matches the component name.
	 */
	for (de = dir->de_child; de != NULL; de = de->de_sibling) {
		if (strcmp(de->de_name, comp) == 0) {
			/*
			 * This component matches, so just return it.
			 */
			*child = de;
			return (0);
		}
	}

	if ((de = calloc(1, sizeof (*de))) == NULL) {
		err(1, "calloc");
	}

	if ((de->de_name = strdup(comp)) == NULL) {
		err(1, "strdup");
	}

	de->de_parent = dir;
	de->de_sibling = dir->de_child;
	dir->de_child = de;

	*child = de;
	return (0);
}

static int
record_path(snaptar_t *st, const char *pfx, const char *path)
{
	strlist_t *sl = NULL;
	custr_t *cu = NULL;
	diff_ent_t *de = &st->st_root;
	size_t start = 0;

	if (strlist_alloc(&sl, 0) != 0 || custr_alloc(&cu) != 0) {
		err(1, "strlist_alloc/custr_alloc");
	}

	if (pfx != NULL) {
		size_t len = strlen(pfx);

		if (strncmp(path, pfx, len) != 0) {
			errno = EINVAL;
			return (-1);
		}

		start = len;
	}

	/*
	 * Split a path into components, e.g.:
	 *   a/b/c/d/  -->   "a", "b", "c", "d"
	 *   /e/f///g  -->   "e", "f", "g"
	 */
	for (const char *p = path + start; ; p++) {
		if (*p != '\0' && *p != '/') {
			if (custr_appendc(cu, *p) != 0) {
				err(1, "custr_appendc");
			}
			continue;
		}

		if (custr_len(cu) > 0) {
			if (strlist_set_tail(sl, custr_cstr(cu)) != 0) {
				err(1, "strlist_set_tail");
			}
			custr_reset(cu);
		}

		if (*p == '\0') {
			break;
		}
	}

	/*
	 * Ensure this path, and all parent directories, exist in the
	 * tree.
	 */
	for (unsigned i = 0; i < strlist_contig_count(sl); i++) {
		if (get_child(de, strlist_get(sl, i), &de) != 0) {
			err(1, "get_child");
		}
	}
	VERIFY(de != NULL);

	strlist_free(sl);
	custr_free(cu);
	return (0);
}

int
split_on(const char *line, char delim, strlist_t *sl)
{
	custr_t *cu = NULL;
	int error = 0;
	const char *c = line;

	if (custr_alloc(&cu) != 0) {
		error = errno;
		goto out;
	}

	for (;;) {
		char cc = *c++;

		if (cc == '\0') {
			if (custr_len(cu) > 0 && strlist_set_tail(sl,
			    custr_cstr(cu)) != 0) {
				error = errno;
			}
			goto out;
		} else if (cc == delim) {
			if (strlist_set_tail(sl, custr_cstr(cu)) != 0) {
				error = errno;
				goto out;
			}
			custr_reset(cu);
		} else {
			if (custr_appendc(cu, cc) != 0) {
				error = errno;
				goto out;
			}
		}
	}

out:
	custr_free(cu);
	errno = error;
	return (error == 0 ? 0 : -1);
}

void
run_zfs_diff_cb(const char *line, void *arg0)
{
	snaptar_t *st = arg0;
	strlist_t *sl;

	if (strlist_alloc(&sl, 0) != 0) {
		err(1, "strlist_alloc");
	}

	if (split_on(line, '\t', sl) != 0) {
		err(1, "split_on");
	}

	if (strlist_match(sl, 0, "-") ||
	    strlist_match(sl, 0, "+") ||
	    strlist_match(sl, 0, "M")) {
		/*
		 * Simple entry (removed/created/modified).
		 */
		if (strlist_contig_count(sl) != 3) {
			errx(1, "unexpected count (wanted 3, got %d)",
			    strlist_contig_count(sl));
		}
		VERIFY0(record_path(st, st->st_mountpoint, strlist_get(sl, 2)));

	} else if (strlist_match(sl, 0, "R")) {
		/*
		 * Rename entry (mentions two path names).
		 */
		if (strlist_contig_count(sl) != 4) {
			errx(1, "unexpected count (wanted 4, got %d)",
			    strlist_contig_count(sl));
		}
		VERIFY0(record_path(st, st->st_mountpoint, strlist_get(sl, 2)));
		VERIFY0(record_path(st, st->st_mountpoint, strlist_get(sl, 3)));

	} else {
		errx(1, "unknown change type \"%s\"", strlist_get(sl, 0));
	}

#if 0
	fprintf(stderr, "\n");
#endif

	strlist_free(sl);
}

int
run_zfs_diff(snaptar_t *st)
{
	char *fullsnap0 = NULL;
	char *fullsnap1 = NULL;
	char errbuf[512];

	VERIFY0(make_fullsnap(st->st_dataset, st->st_snap0, &fullsnap0));
	VERIFY0(make_fullsnap(st->st_dataset, st->st_snap1, &fullsnap1));

	char *const argv[] = {
		CMD_ZFS,
		"diff",
		"-F",
		"-H",
		fullsnap0,
		fullsnap1,
		NULL
	};
	char *const envp[] = {
		NULL
	};
	int code;

	if (run_command(CMD_ZFS, argv, envp, errbuf, sizeof (errbuf),
	    run_zfs_diff_cb, &code, st) != 0) {
		errx(1, "failed to run \"zfs diff\"");
	}

	if (code != 0) {
		errx(1, "zfs exited non-zero (%d) with: %s", code, errbuf);
	}

	free(fullsnap0);
	free(fullsnap1);
	return (0);
}

static int
cb_nftw(const char *path, const struct stat *stb, int flag, struct FTW *ftw)
{
	fprintf(stderr, "cb_nftw: [%d] %s\n", ftw->level, path);
	return (0);
}

int
run_ftw(snaptar_t *st)
{
	char *fullpath;

	if (asprintf(&fullpath, "%s/.zfs/snapshot/%s", st->st_mountpoint,
	    st->st_snap1) < 0) {
		err(1, "asprintf");
	}

	if (nftw(fullpath, cb_nftw, 0, FTW_MOUNT | FTW_PHYS) != 0) {
		err(1, "nftw");
	}

	free(fullpath);

	return (0);
}

static int
run_readdir_impl(snaptar_t *st, int dirfd, int level, const char *parent,
    ent_enum_cb *cbfunc)
{
	DIR *dir;
	struct dirent *d;
	int ret = -1;
	int e = 0;

	if ((dir = fdopendir(dirfd)) == NULL) {
		err(1, "fdopendir");
	}

	while ((d = readdir(dir)) != NULL) {
		struct stat stb;
		int chdirfd;
		char *path;

		if (strcmp(d->d_name, ".") == 0 ||
		    strcmp(d->d_name, "..") == 0) {
			continue;
		}

		if (asprintf(&path, "%s%s%s", parent != NULL ? parent : "",
		    parent != NULL ? "/" : "",
		    d->d_name) < 0) {
			err(1, "asprintf");
		}

		if (fstatat(dirfd, d->d_name, &stb, AT_SYMLINK_NOFOLLOW) != 0) {
			err(1, "fstatat");
		}

		/*
		 * Fire callback for this directory entry.
		 */
		if (cbfunc(st, path, level, &stb) != 0) {
			e = errno;
			goto out;
		}

		if (!S_ISDIR(stb.st_mode)) {
			/*
			 * This directory entry is not, itself, a directory; no
			 * more work is required.
			 */
			goto next;
		}

		if ((chdirfd = openat(dirfd, d->d_name, O_RDONLY |
		    O_LARGEFILE)) == -1) {
			err(1, "openat");
		}

		if (run_readdir_impl(st, chdirfd, level + 1, path,
		    cbfunc) != 0) {
			e = errno;
			goto out;
		}

next:
		free(path);
	}

	ret = 0;

out:
	VERIFY0(closedir(dir));
	errno = e;
	return (ret);
}

static int
print_entry(snaptar_t *st, const char *path, int level, struct stat *stp)
{
	char *whpath = NULL;
	char typ = '?';

	if (stp == NULL) {
		whiteout_path(path, &whpath);
		path = whpath;
		typ = '-';

	} else if (S_ISREG(stp->st_mode)) {
		typ = 'F';

	} else if (S_ISDIR(stp->st_mode)) {
		typ = 'D';

	}

	fprintf(stderr, "[%d] %c %s\n", level, typ, path);

	free(whpath);
	return (0);
}

int
run_readdir(snaptar_t *st, ent_enum_cb *cbfunc)
{
	int dirfd;
	int ret;

	if ((dirfd = openat(st->st_snapshot_fd, ".", O_RDONLY |
	    O_LARGEFILE)) == -1) {
		err(1, "openat");
	}

	ret = run_readdir_impl(st, dirfd, 1, NULL, cbfunc);

	return (ret);
}

void
get_zfs_mountpoint_cb(const char *line, void *arg0)
{
	snaptar_t *st = arg0;
	strlist_t *sl = NULL;

	if (st->st_flags & SNTR_F_FAILED) {
		return;
	}

	if (st->st_mountpoint != NULL) {
		/*
		 * There should have been at most one line of output from
		 * the zfs(1M) command.
		 */
		custr_append(st->st_errstr, "more than one line of output "
		    "from zfs(1M)");
		goto errout;
	}

	if (strlist_alloc(&sl, 0) != 0) {
		err(1, "strlist_alloc");
	}

	if (split_on(line, '\t', sl) != 0) {
		err(1, "split_on");
	}

	/*
	 * Verify that the dataset name we found was the one we were expecting.
	 */
	if (!strlist_match(sl, 0, st->st_dataset)) {
		custr_append(st->st_errstr, "unexpected dataset in list");
		goto errout;
	}

	/*
	 * Verify that we located a filesystem:
	 */
	if (!strlist_match(sl, 1, "filesystem")) {
		custr_append(st->st_errstr, "found dataset was not a "
		    "filesystem");
		goto errout;
	}

	/*
	 * Verify that the filesystem is mounted:
	 */
	if (!strlist_match(sl, 2, "yes")) {
		custr_append(st->st_errstr, "filesystem is not mounted");
		goto errout;
	}

	if ((st->st_mountpoint = strdup(strlist_get(sl, 3))) == NULL) {
		err(1, "strdup");
	}

	goto out;

errout:
	st->st_flags |= SNTR_F_FAILED;

out:
	strlist_free(sl);
}

static int
open_zfs_snap(snaptar_t *st, const char *snapname)
{
	char *path = NULL;

	if (asprintf(&path, "%s/.zfs/snapshot/%s", st->st_mountpoint,
	    snapname) < 0) {
		err(1, "asprintf");
	}

	if ((st->st_snapshot_fd = open(path, O_RDONLY | O_LARGEFILE)) == -1) {
		err(1, "open(%s)", path);
	}

	free(path);
	return (0);
}

int
get_zfs_mountpoint(snaptar_t *st)
{
	char *const argv[] = {
		CMD_ZFS,
		"list",
		"-H",
		"-p",
		"-o",
		"name,type,mounted,mountpoint",
		st->st_dataset,
		NULL
	};
	char *const envp[] = {
		NULL
	};
	int code;
	char errbuf[512];

	if (run_command(CMD_ZFS, argv, envp, errbuf, sizeof (errbuf),
	    get_zfs_mountpoint_cb, &code, st) != 0) {
		errx(1, "failed to run \"zfs list\"");
	}

	if (code != 0) {
		errx(1, "zfs exited non-zero (%d) with: %s", code, errbuf);
	}

	if (st->st_flags & SNTR_F_FAILED) {
		return (-1);
	}

	if (st->st_mountpoint == NULL) {
		custr_append(st->st_errstr, "could not find dataset");
		st->st_flags |= SNTR_F_FAILED;
		return (-1);
	}

	if (open_zfs_snap(st, st->st_snap1) != 0) {
		custr_append(st->st_errstr, "could not open snapdir");
		st->st_flags |= SNTR_F_FAILED;
		return (-1);
	}

	return (0);
}

static int
make_tarball_entry(snaptar_t *st, const char *path, int level,
    struct stat *statp)
{
	struct archive *a = st->st_archive;
	struct archive_entry *ae = st->st_archive_entry;
	char *whpath = NULL;
	int datafd = -1;

	VERIFY(a != NULL);
	VERIFY(ae != NULL);

	archive_entry_clear(ae);

	if (statp == NULL) {
		/*
		 * This file is absent from the target snapshot, so it has been
		 * deleted.  Insert the empty "whiteout" file that instructs
		 * the layering engine to remove the file when applying this
		 * layer.
		 */
		whiteout_path(path, &whpath);

		archive_entry_set_pathname(ae, whpath);
		archive_entry_set_filetype(ae, AE_IFREG);
		archive_entry_set_perm(ae, 0444);

	} else if (S_ISDIR(statp->st_mode)) {
		/*
		 * This is a directory.
		 */
		archive_entry_set_pathname(ae, path);
		archive_entry_copy_stat(ae, statp);

	} else if (S_ISREG(statp->st_mode)) {
		/*
		 * This is a regular file.  Open a file descriptor from which
		 * to read the data.
		 */
		archive_entry_set_pathname(ae, path);
		archive_entry_copy_stat(ae, statp);

		if ((datafd = openat(st->st_snapshot_fd, path, O_RDONLY |
		    O_LARGEFILE | O_NOFOLLOW)) == -1) {
			err(1, "open(%s)", path);
		}

	} else {
		/*
		 * XXX This file type is unknown.
		 */
		errx(1, "unknown file type: %x", (int)(statp->st_mode &
		    S_IFMT));
	}

	/*
	 * Write archive header:
	 */
	if (archive_write_header(a, ae) != ARCHIVE_OK) {
		errx(1, "archive_write_header: %s",
		    archive_error_string(a));
	}

	if (datafd != -1) {
		/*
		 * Archive data from datafd.
		 */
		for (;;) {
			char readbuf[8192];
			ssize_t rsz = sizeof (readbuf);
			ssize_t wsz;

			if ((rsz = read(datafd, readbuf, rsz)) < 0) {
				err(1, "read datafd");
			}

			if (rsz == 0) {
				break;
			}

			if ((wsz = archive_write_data(a, readbuf, rsz)) !=
			    rsz) {
				errx(1, "wsz (%d) != rsz (%d)", wsz, rsz);
			}
		}

		VERIFY0(close(datafd));
	}

	if (archive_write_finish_entry(a) != ARCHIVE_OK) {
		errx(1, "archive_write_finish_entry: %s",
		    archive_error_string(a));
	}

	free(whpath);
	return (0);
}

static int
make_tarball(snaptar_t *st, walk_dir_func *walker, const char *output)
{
	struct archive *a;
	struct archive_entry *ae;
	int ret;

	if ((a = archive_write_new()) == NULL ||
	    (ae = archive_entry_new()) == NULL) {
		errx(1, "archive_write_new: %s", archive_error_string(a));
	}

	if (archive_write_set_format_pax_restricted(a) != ARCHIVE_OK) {
		errx(1, "archive_write_set_format_pax_restricted: %s",
		    archive_error_string(a));
	}

	if (output != NULL) {
		if (archive_write_open_filename(a, "output.tar") !=
		    ARCHIVE_OK) {
			errx(1, "archive_write_open_filename: %s",
			    archive_error_string(a));
		}
	} else {
		if (archive_write_open_FILE(a, stdout) != ARCHIVE_OK) {
			errx(1, "archive_write_open_FILE: %s",
			    archive_error_string(a));
		}
	}

	fprintf(stderr, "PROCESSING...\n");
	st->st_archive = a;
	st->st_archive_entry = ae;
	if (walker(st, make_tarball_entry) != 0) {
		ret = -1;
		goto out;
	}

	if (archive_write_close(a) != ARCHIVE_OK) {
		errx(1, "archive_write_close: %s", archive_error_string(a));
	}

	ret = 0;

out:
	archive_entry_free(ae);
	archive_write_free(a);
	st->st_archive = NULL;
	st->st_archive_entry = NULL;

	return (ret);
}

static int
walk_diff_tree_impl(snaptar_t *st, diff_ent_t *de, int level,
    const char *parent, ent_enum_cb *cbfunc)
{
	boolean_t root = (de->de_name == NULL);
	struct stat stb;
	struct stat *stp = &stb;
	char *path = NULL;

	if (root) {
		/*
		 * We don't want to invoke the callback for the root entry
		 * in the tree.
		 */
		goto skip;
	}

	/*
	 * Visit directory itself, first.
	 */
	if (asprintf(&path, "%s%s%s", parent != NULL ? parent : "",
	    parent != NULL ? "/" : "", de->de_name) < 0) {
		err(1, "asprintf");
	}

	if (fstatat(st->st_snapshot_fd, path, &stb, AT_SYMLINK_NOFOLLOW) != 0) {
		if (errno != ENOENT) {
			err(1, "fstatat");
		}

		/*
		 * We signal a deleted file by passing a NULL "struct stat"
		 * pointer to the callback.
		 */
		stp = NULL;
	}

	if (cbfunc(st, path, level, stp) != 0) {
		free(path);
		return (-1);
	}

skip:
	/*
	 * Walk each child of this directory:
	 */
	for (diff_ent_t *ch = de->de_child; ch != NULL; ch = ch->de_sibling) {
		walk_diff_tree_impl(st, ch, level + 1, path, cbfunc);
	}

	free(path);
	return (0);
}

int
walk_diff_tree(snaptar_t *st, ent_enum_cb *cbfunc)
{
	return (walk_diff_tree_impl(st, &st->st_root, 0, NULL, cbfunc));
}

void
maybe_abort(snaptar_t *st)
{
	st = st;
	if (getenv("ABORT") != NULL) {
		abort();
	}
}

int
main(int argc, char *argv[])
{
	char errbuf[512];
	snaptar_t *st;
	int rv;
	boolean_t incremental;
	walk_dir_func *walker;

	if (argc == 3) {
		rv = snaptar_init(&st, errbuf, sizeof (errbuf), argv[1],
		    NULL, argv[2]);
		incremental = B_FALSE;

	} else if (argc == 4) {
		rv = snaptar_init(&st, errbuf, sizeof (errbuf), argv[1],
		    argv[2], argv[3]);
		incremental = B_TRUE;

	} else {
		errx(1, "usage: %s <dataset> [<parent_snapshot>] <snapshot>",
		    argv[0]);
	}

	if (rv != 0) {
		errx(1, "snaptar_init failure: %s\n", errbuf);
	}

	if (get_zfs_mountpoint(st) != 0) {
		goto out;
	}

	if (incremental) {
		if (run_zfs_diff(st) != 0) {
			goto out;
		}

		walker = walk_diff_tree;
	} else {
		walker = run_readdir;
	}

	if (getenv("JUST_PRINT") != NULL) {
		if (walker(st, print_entry) != 0) {
			goto out;
		}
	} else {
		if (make_tarball(st, walker, NULL) != 0) {
			goto out;
		}
	}

	fprintf(stderr, "DUMP:\n");
	fprintf(stderr, "\n");

	maybe_abort(st);

out:
	snaptar_fini(st);
	return (0);
}

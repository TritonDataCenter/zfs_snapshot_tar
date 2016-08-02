/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */


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
#include <dirent.h>
#include <sys/param.h>
#include <locale.h>

#include <archive.h>
#include <archive_entry.h>

#include "custr.h"
#include "strlist.h"
#include "run_command.h"

#define	CMD_ZFS		"/sbin/zfs"

typedef struct diff_ent diff_ent_t;
typedef struct snaptar snaptar_t;

struct diff_ent {
	char *de_name;

	diff_ent_t *de_sibling;
	diff_ent_t *de_child;
	diff_ent_t *de_parent;
};

typedef struct hardlink_ent {
	char *hle_path;
	ino_t hle_inode;
	dev_t hle_device;
	list_node_t hle_link;
} hardlink_ent_t;

typedef enum snaptar_flags {
	SNTR_F_FAILED = 0x01,
	SNTR_F_IGNORE_SPECIALS = 0x02,
	SNTR_F_IGNORE_UNKNOWNS = 0x04,
} snaptar_flags_t;

typedef enum snaptar_param {
	SNTR_P_ROOT_PREFIX = 1,
	SNTR_P_SNAPSHOT_PARENT,
	SNTR_P_SNAPSHOT,
	SNTR_P_EXPLICIT_PARENT,
	SNTR_P_EXPLICIT,
	SNTR_P_DATASET,
	SNTR_P_EXCLUDE_PATH,
} snaptar_param_t;

typedef struct {
	snaptar_t *stss_owner;
	char *stss_dataset;
	char *stss_snapshot;
	char *stss_mountpoint;
	int stss_fd;
	dev_t stss_device;
} snaptar_snapshot_t;

struct snaptar {
	snaptar_flags_t st_flags;

	char *st_root_prefix;
	strlist_t *st_exclude_paths;

	/*
	 * This program operates on either one or two ZFS snapshots.  In all
	 * cases, the snapshot to archive is in this array at index 1; if
	 * there is a "parent" snapshot for an incremental archive, that
	 * snapshot will be at index 0.
	 */
	snaptar_snapshot_t st_snapshots[2];

	diff_ent_t st_root;

	custr_t *st_errstr;

	struct archive *st_archive;
	struct archive_entry *st_archive_entry;

	list_t st_hardlinks;
};

/*
 * Function pointer types:
 */
typedef int ent_enum_cb(snaptar_t *, const char *, int, struct stat *,
    const char *, void *);
typedef int walk_dir_func(snaptar_t *, ent_enum_cb *);

/*
 * Forward declarations:
 */
static int run_readdir_impl(snaptar_t *, int, int, const char *, ent_enum_cb *,
    boolean_t, void *);
static int record_path_impl(snaptar_t *, const char *);


static hardlink_ent_t *
hardlinks_lookup(snaptar_t *st, struct stat *statp)
{
	hardlink_ent_t *hle;

	for (hle = list_head(&st->st_hardlinks); hle != NULL;
	    hle = list_next(&st->st_hardlinks, hle)) {
		if (hle->hle_inode == statp->st_ino &&
		    hle->hle_device == statp->st_dev) {
			return (hle);
		}
	}

	return (NULL);
}

static void
hardlinks_add(snaptar_t *st, const char *path, struct stat *statp)
{
	hardlink_ent_t *hle;

	if ((hle = hardlinks_lookup(st, statp)) != NULL) {
		errx(1, "duplicate hardlink entry %s, %s\n", path,
		    hle->hle_path);
	}

	if ((hle = calloc(1, sizeof (*hle))) == NULL) {
		err(1, "calloc");
	}
	if ((hle->hle_path = strdup(path)) == NULL) {
		err(1, "strdup");
	}
	hle->hle_inode = statp->st_ino;
	hle->hle_device = statp->st_dev;

	list_insert_tail(&st->st_hardlinks, hle);
}

void
whiteout_path(const char *path, char **outp)
{
	char *out;

	if (strchr(path, '/') == NULL) {
		if (asprintf(&out, ".wh.%s", path) < 0) {
			err(1, "asprintf");
		}
		goto done;
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

done:
	*outp = out;
}

static int
make_fullsnap(snaptar_snapshot_t *stss, char **fullsnap)
{
	VERIFY3P(stss->stss_dataset, !=, NULL);
	VERIFY3P(stss->stss_snapshot, !=, NULL);

	if (strchr(stss->stss_dataset, '@') != NULL ||
	    strchr(stss->stss_snapshot, '@') != NULL) {
		errno = EINVAL;
		return (-1);
	}

	if (asprintf(fullsnap, "%s@%s", stss->stss_dataset,
	    stss->stss_snapshot) < 0) {
		return (-1);
	}

	return (0);
}

int
snaptar_alloc(snaptar_t **stp, char *errstr, size_t errlen)
{
	snaptar_t *st;

	*stp = NULL;

	if ((st = calloc(1, sizeof (*st))) == NULL) {
		return (-1);
	}

	for (int i = 0; i < 2; i++) {
		st->st_snapshots[i].stss_owner = st;
		st->st_snapshots[i].stss_fd = -1;
	}

	st->st_flags |= SNTR_F_IGNORE_SPECIALS;

	if (strlist_alloc(&st->st_exclude_paths, 0) != 0) {
		return (-1);
	}

	if (custr_alloc_buf(&st->st_errstr, errstr, errlen) != 0) {
		return (-1);
	}

	list_create(&st->st_hardlinks, sizeof (hardlink_ent_t),
	    offsetof(hardlink_ent_t, hle_link));

	*stp = st;
	return (0);
}

static int
copy_snapshot_string(const char *src, snaptar_snapshot_t *stss)
{
	char *dset = NULL, *snap = NULL;
	const char *atp;

	/*
	 * Make sure we have a string that has an '@' character, denoting
	 * a fully qualified "dataset@snapshot" name.  Ensure also that
	 * the "dataset" and "snapshot" portions of the name are not
	 * empty strings.
	 */
	if ((atp = strchr(src, '@')) == NULL || src == atp ||
	    atp[1] == '\0' || strchr(atp + 1, '@') != NULL) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Split the string about the '@' separator:
	 */
	if ((dset = strndup(src, atp - src)) == NULL ||
	    (snap = strdup(atp + 1)) == NULL) {
		free(dset);
		free(snap);
		return (-1);
	}

	free(stss->stss_dataset);
	free(stss->stss_snapshot);
	stss->stss_dataset = dset;
	stss->stss_snapshot = snap;
	return (0);
}

static int
copy_string(const char *src, char **dstp)
{
	char *dst;

	if ((dst = strdup(src)) == NULL) {
		return (-1);
	}

	free(*dstp);
	*dstp = dst;
	return (0);
}

static int
copy_string_strlist(const char *src, strlist_t *sl)
{
	if (strlist_set_tail(sl, src) != 0) {
		return (-1);
	}

	return (0);
}

static boolean_t
is_valid_path_param(const char *desc, const char *val, size_t len)
{
	if (len == 0) {
		warnx("%s must be a non-empty string", desc);
		errno = EPROTO;
		return (B_FALSE);
	}
	if (val[0] == '/' || val[len - 1] == '/') {
		warnx("%s must not begin or end with a slash", desc);
		errno = EPROTO;
		return (B_FALSE);
	}
	return (B_TRUE);
}

int
snaptar_param_set(snaptar_t *st, snaptar_param_t p, const char *val)
{
	size_t len = strlen(val);

	switch (p) {
	case SNTR_P_ROOT_PREFIX:
		if (!is_valid_path_param("root prefix", val, len)) {
			return (-1);
		}
		return (copy_string(val, &st->st_root_prefix));

	case SNTR_P_EXPLICIT:
		return (copy_snapshot_string(val, &st->st_snapshots[1]));

	case SNTR_P_EXPLICIT_PARENT:
		return (copy_snapshot_string(val, &st->st_snapshots[0]));

	case SNTR_P_DATASET:
		/*
		 * Using the original argument format, one positional
		 * argument was used for both the parent and the child
		 * dataset.  To preserve this behaviour, we copy that
		 * argument into both st_dataset0 and st_dataset1.
		 */
		if (copy_string(val, &st->st_snapshots[0].stss_dataset) != 0) {
			return (-1);
		}
		return (copy_string(val, &st->st_snapshots[1].stss_dataset));

	case SNTR_P_SNAPSHOT:
		return (copy_string(val, &st->st_snapshots[1].stss_snapshot));

	case SNTR_P_SNAPSHOT_PARENT:
		return (copy_string(val, &st->st_snapshots[0].stss_snapshot));

	case SNTR_P_EXCLUDE_PATH:
		if (!is_valid_path_param("exclude paths", val, len)) {
			return (-1);
		}
		return (copy_string_strlist(val, st->st_exclude_paths));

	default:
		errno = EINVAL;
		return (-1);
	}
}

static void
snaptar_free_diffent(diff_ent_t *dir, boolean_t free_this)
{
	diff_ent_t *next;

	for (diff_ent_t *de = dir->de_child; de != NULL; de = next) {
		next = de->de_sibling;
		snaptar_free_diffent(de, B_TRUE);
	}

	free(dir->de_name);
	if (free_this)
		free(dir);
}

static void
snaptar_fini_snapshot(snaptar_t *st, snaptar_snapshot_t *stss)
{
	VERIFY3P(st, ==, stss->stss_owner);

	free(stss->stss_mountpoint);
	free(stss->stss_dataset);
	free(stss->stss_snapshot);
	if (stss->stss_fd != -1) {
		VERIFY0(close(stss->stss_fd));
	}
}

void
snaptar_fini(snaptar_t *st)
{
	hardlink_ent_t *hle;

	while ((hle = list_remove_tail(&st->st_hardlinks)) != NULL) {
		free(hle->hle_path);
		free(hle);
	}
	list_destroy(&st->st_hardlinks);

	snaptar_fini_snapshot(st, &st->st_snapshots[0]);
	snaptar_fini_snapshot(st, &st->st_snapshots[1]);

	strlist_free(st->st_exclude_paths);
	custr_free(st->st_errstr);
	snaptar_free_diffent(&st->st_root, B_FALSE);

	VERIFY3P(st->st_archive, ==, NULL);
	VERIFY3P(st->st_archive_entry, ==, NULL);

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

/*
 * Unprintable characters are emitted by "zfs diff" as an octal escape
 * sequence.  We need to convert these back into the binary representation of
 * the (potentially multibyte) string.
 */
static int
unescape_zfs_diff_path(const char *input, custr_t *unescaped)
{
	custr_t *seq = NULL;
	int ret = -1, e = 0;

	if (custr_alloc(&seq) != 0) {
		return (-1);
	}

	for (const char *p = input; ; p++) {
		if (custr_len(seq) > 0) {
			if (*p >= '0' && *p <= '7') {
				/*
				 * An octal digit.
				 */
				if (custr_appendc(seq, *p) != 0) {
					e = errno;
					goto out;
				}
			} else {
				goto invalid;
			}

			VERIFY3U(custr_len(seq), <, 5);
			if (custr_len(seq) == 4) {
				long val;

				/*
				 * This should be an entire escape sequence.
				 * Attempt to parse the octal number, starting
				 * at the character after the backslash.
				 */
				errno = 0;
				if ((val = strtol(custr_cstr(seq) + 1,
				    NULL, 8)) == 0 && errno != 0) {
					goto invalid;
				}

				if (val < 0 || val > 255) {
					goto invalid;
				}

				if (custr_appendc(unescaped,
				    (char)(uint8_t)val) != 0) {
					e = errno;
					goto out;
				}

				custr_reset(seq);
			}
			continue;
		}

		if (*p == '\\') {
			/*
			 * A backslash character starts the escape sequence.
			 */
			if (custr_appendc(seq, *p) != 0) {
				e = errno;
				goto out;
			}
			continue;
		}

		if (*p == '\0') {
			VERIFY3U(custr_len(seq), ==, 0);
			ret = 0;
			goto out;
		}

		if (custr_appendc(unescaped, *p) != 0) {
			e = errno;
			goto out;
		}
	}

invalid:
	errx(1, "invalid escape sequence from zfs diff: \"%s\"", input);

out:
	custr_free(seq);
	errno = e;
	return (ret);
}

struct check_links_arg {
	int cla_otherfd;
	dev_t cla_otherdev;
};

static int
check_links_cb(snaptar_t *st, const char *path, int level,
    struct stat *statp, const char *sympath, void *arg)
{
	struct stat sto;
	struct check_links_arg *cla = arg;

	if (!S_ISREG(statp->st_mode)) {
		return (0);
	}

	if (fstatat(cla->cla_otherfd, path, &sto, AT_SYMLINK_NOFOLLOW) != 0) {
		if (errno == ENOENT) {
#if 0
			fprintf(stderr, "\tDEBUG: %25s missing on other "
			    "side!\n", path);
#endif
			record_path_impl(st, path);
			return (0);
		}

		err(1, "fstatat(%s)", path);
	}

	if (sto.st_dev != cla->cla_otherdev) {
		errx(1, "file %s st_dev %lu outside of expected file system "
		    "(%ld)", path, sto.st_dev, cla->cla_otherdev);
	}

	if (statp->st_ino != sto.st_ino) {
#if 0
		fprintf(stderr, "\tDEBUG: %25s %lld vs %lld\n", path,
		    statp->st_ino, sto.st_ino);
#endif
		record_path_impl(st, path);
	}

	return (0);
}

static void
check_links_open_fds(snaptar_t *st, const char *path, int *fd0p, int *fd1p)
{
	if ((*fd0p = openat(st->st_snapshots[0].stss_fd, path, O_RDONLY |
	    O_LARGEFILE)) == -1) {
		err(1, "openat(%s)", path);
	}
	if ((*fd1p = openat(st->st_snapshots[1].stss_fd, path, O_RDONLY |
	    O_LARGEFILE)) == -1) {
		err(1, "openat(%s)", path);
	}
}

static void
check_links(snaptar_t *st, const char *path)
{
	struct stat st0, st1;
	int dirfd;
	struct check_links_arg cla;

	if (fstatat(st->st_snapshots[0].stss_fd, path, &st0,
	    AT_SYMLINK_NOFOLLOW) != 0 ||
	    fstatat(st->st_snapshots[1].stss_fd, path, &st1,
	    AT_SYMLINK_NOFOLLOW) != 0) {
		err(1, "fstatat(%s)", path);
	}

	if (!S_ISDIR(st1.st_mode) || st0.st_ino != st1.st_ino) {
		return;
	}

#if 0
	fprintf(stderr, "DEBUG: %s: st0 %lld %lu st1 %lld %lu\n",
	    path, st0.st_ino, st0.st_dev, st1.st_ino, st1.st_dev);
#endif

	if (st0.st_dev != st->st_snapshots[0].stss_device) {
		errx(1, "dir %s in snap %s st_dev %lu outside of expected %lu",
		    path, st->st_snapshots[0].stss_snapshot, st0.st_dev,
		    st->st_snapshots[0].stss_device);
	}
	if (st1.st_dev != st->st_snapshots[1].stss_device) {
		errx(1, "dir %s in snap %s st_dev %lu outside of expected %lu",
		    path, st->st_snapshots[1].stss_snapshot, st0.st_dev,
		    st->st_snapshots[1].stss_device);
	}

#if 0
	fprintf(stderr, "DEBUG: %s: dir: inodes st0 %lld st1 %lld\n", path,
	    st0.st_ino, st1.st_ino);
#endif

	/*
	 * Check each directory entry present in the parent snapshot against a
	 * potential entry in the target snapshot.  Note that this function
	 * will close fd0 as a side effect, but we must close fd1 ourselves.
	 */
	check_links_open_fds(st, path, &dirfd, &cla.cla_otherfd);
	cla.cla_otherdev = st0.st_dev;
	run_readdir_impl(st, dirfd, 1, path, check_links_cb, B_FALSE, &cla);
	VERIFY0(close(cla.cla_otherfd));

	/*
	 * Do the reverse for directory entries present in the child snapshot
	 * against potential entries in the parent.
	 */
	check_links_open_fds(st, path, &cla.cla_otherfd, &dirfd);
	cla.cla_otherdev = st1.st_dev;
	run_readdir_impl(st, dirfd, 1, path, check_links_cb, B_FALSE, &cla);
	VERIFY0(close(cla.cla_otherfd));
}

static int
record_path(snaptar_t *st, const char *path, boolean_t do_check_links)
{
	custr_t *unescaped = NULL;
	const char *start, *mountpoint;
	int rv;

	if (custr_alloc(&unescaped) != 0) {
		err(1, "custr_alloc");
	}

	/*
	 * Convert any octal escape sequences back into their binary
	 * representation:
	 */
	if (unescape_zfs_diff_path(path, unescaped) != 0) {
		err(1, "unescape_zfs_diff_path");
	}
	start = custr_cstr(unescaped);

	if ((mountpoint = st->st_snapshots[1].stss_mountpoint) != NULL) {
		size_t len = strlen(mountpoint);

		if (strncmp(start, mountpoint, len) != 0) {
			errno = EINVAL;
			rv = -1;
			goto done;
		}

		start += len;
	}

	while (start[0] == '/') {
		start++;
	}

	if (st->st_root_prefix != NULL) {
		char *x;
		ssize_t len;
		boolean_t match;

		if ((len = asprintf(&x, "%s/", st->st_root_prefix)) < 0) {
			err(1, "asprintf");
		}

		match = (strncmp(start, x, len) == 0);

		free(x);

		if (!match) {
			rv = 0;
			goto done;
		}
	}

	if (do_check_links) {
		check_links(st, start);
	}

	rv = record_path_impl(st, start);

done:
	custr_free(unescaped);
	return (rv);
}

static int
record_path_impl(snaptar_t *st, const char *path)
{
	custr_t *cu = NULL;
	strlist_t *sl = NULL;

	if (strlist_alloc(&sl, 0) != 0 || custr_alloc(&cu) != 0) {
		err(1, "strlist_alloc/custr_alloc");
	}

	/*
	 * Split a path into components, e.g.:
	 *   a/b/c/d/  -->   "a", "b", "c", "d"
	 *   /e/f///g  -->   "e", "f", "g"
	 */
	for (const char *p = path; ; p++) {
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
	diff_ent_t *de = &st->st_root;
	for (unsigned i = 0; i < strlist_contig_count(sl); i++) {
		if (get_child(de, strlist_get(sl, i), &de) != 0) {
			err(1, "get_child");
		}
	}
	VERIFY3P(de, !=, NULL);

	custr_free(cu);
	strlist_free(sl);
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

static void
strlist_render(strlist_t *sl, char *out, size_t outsz)
{
	custr_t *cu;

	out[0] = '\0';

	if (custr_alloc_buf(&cu, out, outsz) != 0) {
		return;
	}

	(void) custr_append(cu, "[");

	for (unsigned i = 0; i < strlist_contig_count(sl); i++) {
		if (i > 0) {
			(void) custr_append(cu, ", ");
		}

		(void) custr_append_printf(cu, "\"%s\"", strlist_get(sl, i));
	}

	(void) custr_append(cu, "]");

	custr_free(cu);
}

static void
errx_unexpected_zfs_diff(strlist_t *sl)
{
	char sl_render[2048];

	strlist_render(sl, sl_render, sizeof (sl_render));

	errx(1, "unexpected zfs diff output (%s, %d): %s", strlist_get(sl, 0),
	    strlist_contig_count(sl), sl_render);
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
		 * If this entry is marked "M", it could be a directory and
		 * we may need to do a more precise check for link changes.
		 */
		boolean_t check_links = strlist_match(sl, 0, "M");

		/*
		 * Simple entry (removed/created/modified).  May have a link
		 * count modification in an optional fourth column.
		 */
		if (strlist_contig_count(sl) != 3 &&
		    strlist_contig_count(sl) != 4) {
			errx_unexpected_zfs_diff(sl);
		}
		VERIFY0(record_path(st, strlist_get(sl, 2), check_links));

	} else if (strlist_match(sl, 0, "R")) {
		/*
		 * Rename entry (mentions two path names).
		 */
		if (strlist_contig_count(sl) != 4) {
			errx_unexpected_zfs_diff(sl);
		}
		VERIFY0(record_path(st, strlist_get(sl, 2), B_FALSE));
		VERIFY0(record_path(st, strlist_get(sl, 3), B_FALSE));

	} else {
		errx_unexpected_zfs_diff(sl);
	}

	strlist_free(sl);
}

int
run_zfs_diff(snaptar_t *st)
{
	char *fullsnap0 = NULL;
	char *fullsnap1 = NULL;
	char errbuf[512];

	VERIFY0(make_fullsnap(&st->st_snapshots[0], &fullsnap0));
	VERIFY0(make_fullsnap(&st->st_snapshots[1], &fullsnap1));

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
run_readdir_impl(snaptar_t *st, int dirfd, int level, const char *parent,
    ent_enum_cb *cbfunc, boolean_t recurse, void *arg)
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
		char buf[MAXPATHLEN];
		char *sympath = NULL;

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

		if (S_ISLNK(stb.st_mode)) {
			ssize_t sz;

			if ((sz = readlinkat(dirfd, d->d_name, buf,
			    sizeof (buf))) < 0) {
				err(1, "readlinkat");
			}
			buf[sz] = '\0';

			sympath = buf;
		}

		/*
		 * Fire callback for this directory entry.
		 */
		if (cbfunc(st, path, level, &stb, sympath, arg) != 0) {
			e = errno;
			goto out;
		}

		if (!recurse) {
			goto next;
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
		    cbfunc, recurse, arg) != 0) {
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

static boolean_t
path_is_excluded(snaptar_t *st, const char *path)
{
	size_t len = strlen(path);
	unsigned epcnt = strlist_contig_count(st->st_exclude_paths);

	for (unsigned i = 0; i < epcnt; i++) {
		const char *xpath = strlist_get(st->st_exclude_paths, i);
		size_t xlen = strlen(xpath);

		if (len < xlen) {
			/*
			 * If the path to check is shorter than this exclude
			 * path, it cannot be excluded.
			 *   e.g. "a/b" cannot exclude "a".
			 */
			continue;
		}

		if (len == xlen) {
			if (strcmp(xpath, path) == 0) {
				/*
				 * This exclude path matches the path to
				 * check exactly.
				 */
				return (B_TRUE);
			}
			continue;
		}

		/*
		 * This exclude path is shorter than the path to check.
		 * Check if the path is a file or directory underneath
		 * the exclude path:
		 */
		if (strncmp(xpath, path, xlen) == 0) {
			if (path[xlen] == '/') {
				return (B_TRUE);
			}
		}
	}

	return (B_FALSE);
}

static int
print_entry(snaptar_t *st, const char *path, int level, struct stat *stp,
    const char *sympath, void *arg)
{
	char *whpath = NULL;
	char typ = '?';
	boolean_t special = B_FALSE;
	boolean_t unknown = B_FALSE;
	const char *relpath = path;
	hardlink_ent_t *hle = NULL;

	if (st->st_root_prefix != NULL) {
		size_t len = strlen(st->st_root_prefix);

		VERIFY(st->st_root_prefix[0] != '/');
		VERIFY(st->st_root_prefix[len - 1] != '/');

		if (strncmp(path, st->st_root_prefix, len) != 0) {
			return (0);
		}

		relpath = path + len;
		while (relpath[0] == '/') {
			relpath++;
		}

		if (relpath[0] == '\0') {
			goto skip;
		}
	}

	if (path_is_excluded(st, relpath)) {
		goto skip;
	}

	if (stp == NULL) {
		whiteout_path(relpath, &whpath);
		relpath = whpath;
		typ = '-';

	} else if (S_ISREG(stp->st_mode)) {
		if ((hle = hardlinks_lookup(st, stp)) == NULL) {
			hardlinks_add(st, relpath, stp);
			typ = 'F';
		} else {
			typ = 'L';
		}

	} else if (S_ISDIR(stp->st_mode)) {
		typ = 'D';

	} else if (S_ISLNK(stp->st_mode)) {
		typ = 'L';

	} else if (S_ISSOCK(stp->st_mode)) {
		typ = 'S';

	} else if (S_ISFIFO(stp->st_mode)) {
		typ = 'P';

	} else if (S_ISCHR(stp->st_mode)) {
		typ = 'C';
		special = B_TRUE;

	} else if (S_ISBLK(stp->st_mode)) {
		typ = 'B';
		special = B_TRUE;

	} else if (S_ISDOOR(stp->st_mode)) {
		typ = 'O';
		special = B_TRUE;

	} else if (S_ISPORT(stp->st_mode)) {
		typ = 'V';
		special = B_TRUE;

	} else {
		typ = '?';
		unknown = B_TRUE;
	}

	fprintf(stderr, "%c %s", typ, relpath);
	if (hle != NULL) {
		fprintf(stderr, " -> %s", hle->hle_path);
	} else if (sympath != NULL) {
		fprintf(stderr, " -> %s", sympath);
	}
	if ((special && (st->st_flags & SNTR_F_IGNORE_SPECIALS)) ||
	    (unknown && (st->st_flags & SNTR_F_IGNORE_UNKNOWNS))) {
		fprintf(stderr, " (ignored)");
	}
	fprintf(stderr, "\n");

	if (special && !(st->st_flags & SNTR_F_IGNORE_SPECIALS)) {
		errx(1, "found special file type; aborting");
	}

	if (unknown && !(st->st_flags & SNTR_F_IGNORE_UNKNOWNS)) {
		errx(1, "found unknown file type; aborting");
	}

skip:
	free(whpath);
	return (0);
}

int
run_readdir(snaptar_t *st, ent_enum_cb *cbfunc)
{
	int dirfd;
	struct stat stb;
	const char *parent = NULL;
	const char *pfx = ".";

	if (st->st_root_prefix != NULL) {
		pfx = st->st_root_prefix;
		parent = st->st_root_prefix;
	}

	if ((dirfd = openat(st->st_snapshots[1].stss_fd, pfx, O_RDONLY |
	    O_LARGEFILE)) == -1) {
		err(1, "openat");
	}

	if (fstat(dirfd, &stb) != 0) {
		err(1, "fstat");
	}

	if (!S_ISDIR(stb.st_mode)) {
		errx(1, "\"%s\" (within snapshot) is not a directory", pfx);
	}

	return (run_readdir_impl(st, dirfd, 1, parent, cbfunc, B_TRUE, NULL));
}

void
get_zfs_mountpoint_cb(const char *line, void *arg0)
{
	snaptar_snapshot_t *stss = arg0;
	snaptar_t *st = stss->stss_owner;
	strlist_t *sl = NULL;

	if (st->st_flags & SNTR_F_FAILED) {
		return;
	}

	if (stss->stss_mountpoint != NULL) {
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
	if (!strlist_match(sl, 0, stss->stss_dataset)) {
		custr_append(st->st_errstr, "unexpected dataset in list");
		goto errout;
	}

	/*
	 * Verify that we located a filesystem:
	 */
	if (!strlist_match(sl, 1, "filesystem")) {
		custr_append_printf(st->st_errstr, "found dataset (%s) was "
		    "not a filesystem", stss->stss_dataset);
		goto errout;
	}

	/*
	 * Verify that the filesystem is mounted:
	 */
	if (!strlist_match(sl, 2, "yes")) {
		custr_append_printf(st->st_errstr, "filesystem (%s) is not "
		    "mounted", stss->stss_dataset);
		goto errout;
	}

	VERIFY(strlist_get(sl, 3)[0] == '/');
	if ((stss->stss_mountpoint = strdup(strlist_get(sl, 3))) == NULL) {
		err(1, "strdup");
	}

	goto out;

errout:
	st->st_flags |= SNTR_F_FAILED;

out:
	strlist_free(sl);
}

int
get_zfs_mountpoint(snaptar_snapshot_t *stss)
{
	snaptar_t *st = stss->stss_owner;
	char *const argv[] = {
		CMD_ZFS,
		"list",
		"-H",
		"-p",
		"-o",
		"name,type,mounted,mountpoint",
		stss->stss_dataset,
		NULL
	};
	char *const envp[] = {
		NULL
	};
	int code;
	char errbuf[512];
	char *path = NULL;
	struct stat stmp;

	VERIFY3P(stss->stss_dataset, !=, NULL);
	VERIFY3P(stss->stss_snapshot, !=, NULL);
	VERIFY3S(stss->stss_fd, ==, -1);

	if (run_command(CMD_ZFS, argv, envp, errbuf, sizeof (errbuf),
	    get_zfs_mountpoint_cb, &code, stss) != 0) {
		errx(1, "failed to run \"zfs list\"");
	}

	if (code != 0) {
		errx(1, "zfs exited non-zero (%d) with: %s", code, errbuf);
	}

	if (st->st_flags & SNTR_F_FAILED) {
		return (-1);
	}

	if (stss->stss_mountpoint == NULL) {
		custr_append_printf(st->st_errstr, "dataset not found: %s",
		    stss->stss_dataset);
		st->st_flags |= SNTR_F_FAILED;
		return (-1);
	}

	if (asprintf(&path, "%s/.zfs/snapshot/%s", stss->stss_mountpoint,
	    stss->stss_snapshot) < 0) {
		err(1, "asprintf");
	}

	if ((stss->stss_fd = open(path, O_RDONLY | O_LARGEFILE)) == -1) {
		custr_append_printf(st->st_errstr, "could not open snapshot "
		    "directory (%s): %s", path, strerror(errno));
		free(path);
		return (-1);
	}

	if (fstat(stss->stss_fd, &stmp) != 0) {
		custr_append_printf(st->st_errstr, "could not stat snapshot "
		    "directory (%s): %s", path, strerror(errno));
		free(path);
		return (-1);
	}
	stss->stss_device = stmp.st_dev;

	free(path);
	return (0);
}

static void
make_tarball_entry_empty_file(struct archive_entry *ae)
{
	time_t whenever;

	archive_entry_set_filetype(ae, AE_IFREG);
	archive_entry_set_size(ae, 0);

	/*
	 * The default (i.e. unset) timestamp for a synthetic file is zero.
	 * GNU tar interprets this as an "implausibly" old timestamp and,
	 * rather than do as it was instructed, fails the extraction process.
	 * We are already up to the waist in fiction at this point, so
	 * conjuring a mythical timestamp for our imaginary not-a-file will be
	 * a mere soiled drop in an already squalid ocean.
	 */
	if ((whenever = time(NULL)) == -1) {
		err(1, "could not read system time");
	}
	archive_entry_set_birthtime(ae, whenever, 0);
	archive_entry_set_atime(ae, whenever, 0);
	archive_entry_set_ctime(ae, whenever, 0);
	archive_entry_set_mtime(ae, whenever, 0);
}

static int
make_tarball_entry(snaptar_t *st, const char *path, int level,
    struct stat *statp, const char *sympath, void *arg)
{
	struct archive *a = st->st_archive;
	struct archive_entry *ae = st->st_archive_entry;
	char *whpath = NULL;
	int datafd = -1;
	const char *relpath = path;

	VERIFY3P(a, !=, NULL);
	VERIFY3P(ae, !=, NULL);

	if (st->st_root_prefix != NULL) {
		size_t len = strlen(st->st_root_prefix);

		VERIFY(st->st_root_prefix[0] != '/');
		VERIFY(st->st_root_prefix[len - 1] != '/');

		if (strncmp(path, st->st_root_prefix, len) != 0) {
			return (0);
		}

		relpath = path + len;
		while (relpath[0] == '/') {
			relpath++;
		}

		if (relpath[0] == '\0') {
			goto skip;
		}
	}

	if (path_is_excluded(st, relpath)) {
		goto skip;
	}

	archive_entry_clear(ae);

	if (statp == NULL) {
		/*
		 * This file is absent from the target snapshot, so it has been
		 * deleted.  Insert the empty "whiteout" file that instructs
		 * the layering engine to remove the file when applying this
		 * layer.
		 */
		whiteout_path(relpath, &whpath);

		if (archive_entry_update_pathname_utf8(ae, whpath) != 1) {
			errx(1, "invalid characters in filename: \"%s\"",
			    whpath);
		}

		archive_entry_set_perm(ae, 0444);
		make_tarball_entry_empty_file(ae);

	} else if (S_ISLNK(statp->st_mode) || S_ISDIR(statp->st_mode) ||
	    S_ISREG(statp->st_mode) || S_ISFIFO(statp->st_mode) ||
	    S_ISSOCK(statp->st_mode)) {
		hardlink_ent_t *hle;

		/*
		 * This is a regular file, directory, symbolic link, fifo or
		 * socket.  Metadata is copied from the stat(2) structure.
		 */
		if (archive_entry_update_pathname_utf8(ae, relpath) != 1) {
			errx(1, "invalid characters in filename: \"%s\"",
			    relpath);
		}
		archive_entry_copy_stat(ae, statp);

		if (S_ISREG(statp->st_mode) && (hle = hardlinks_lookup(st,
		    statp)) != NULL) {
			/*
			 * This link references an inode that we have included
			 * already.  Instead of including the contents a second
			 * time, we instruct tar to create a hard link to the
			 * first copy we included.
			 */
			archive_entry_set_hardlink(ae, hle->hle_path);
			archive_entry_set_size(ae, 0);

		} else if (S_ISREG(statp->st_mode)) {
			/*
			 * This is a regular file with an inode we have not yet
			 * seen.  Open the file as it exists in the snapshot so
			 * that its contents may be included in the archive.
			 */
			if ((datafd = openat(st->st_snapshots[1].stss_fd,
			    path, O_RDONLY | O_LARGEFILE | O_NOFOLLOW)) == -1) {
				err(1, "reg file open(%s)", path);
			}

			/*
			 * Record the relative path for this inode number in
			 * case it is included via an additional hard link
			 * later.
			 */
			hardlinks_add(st, relpath, statp);

		} else if (S_ISLNK(statp->st_mode)) {
			/*
			 * Specify the symbolic link target path.
			 */
			archive_entry_set_symlink(ae, sympath);

		} else if (S_ISSOCK(statp->st_mode)) {
			/*
			 * A socket cannot be represented in a tar file.  For
			 * compatibility with Docker, we create an empty file
			 * in its place.  Ownership and permissions of this
			 * empty file still come from the original socket.
			 */
			make_tarball_entry_empty_file(ae);
		}

	} else if (S_ISCHR(statp->st_mode) || S_ISBLK(statp->st_mode) ||
	    S_ISDOOR(statp->st_mode) || S_ISPORT(statp->st_mode)) {
		/*
		 * These are special files: block and character devices, event
		 * ports and doors.  Either we have been told to ignore these
		 * special files, or we should fail archive creation now.
		 */
		if (st->st_flags & SNTR_F_IGNORE_SPECIALS) {
			goto skip;
		}

		errx(1, "found a %s in snapshot; cannot represent",
		    S_ISCHR(statp->st_mode) ? "character device" :
		    S_ISBLK(statp->st_mode) ? "block device" :
		    S_ISDOOR(statp->st_mode) ? "door" :
		    S_ISPORT(statp->st_mode) ? "port" :
		    "file of unknown type");

	} else {
		/*
		 * This file type is unknown.
		 */
		warnx("unknown file type: %x", (int)(statp->st_mode & S_IFMT));
		abort();
	}

	/*
	 * Write archive header:
	 */
	if (archive_write_header(a, ae) != ARCHIVE_OK) {
		errx(1, "archive_write_header: path \"%s\": %s",
		    archive_entry_pathname(ae), archive_error_string(a));
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
				err(1, "read datafd: path \"%s\"",
				    archive_entry_pathname(ae));
			}

			if (rsz == 0) {
				break;
			}

			if ((wsz = archive_write_data(a, readbuf, rsz)) !=
			    rsz) {
				errx(1, "wsz (%d) != rsz (%d): path \"%s\"",
				    wsz, rsz, archive_entry_pathname(ae));
			}
		}

		VERIFY0(close(datafd));
	}

	if (archive_write_finish_entry(a) != ARCHIVE_OK) {
		errx(1, "archive_write_finish_entry: path \"%s\": %s",
		    archive_entry_pathname(ae), archive_error_string(a));
	}

skip:
	free(whpath);
	return (0);
}

static int
make_tarball(snaptar_t *st, walk_dir_func *walker, const char *output_file)
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

	if (output_file != NULL) {
		if (archive_write_open_filename(a, output_file) !=
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
    const char *parent, ent_enum_cb *cbfunc, void *cbarg)
{
	boolean_t root = (de->de_name == NULL);
	struct stat stb;
	struct stat *stp = &stb;
	char *path = NULL;
	char buf[MAXPATHLEN];
	char *sympath = NULL;
	int snapfd = st->st_snapshots[1].stss_fd;

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

	if (fstatat(snapfd, path, &stb, AT_SYMLINK_NOFOLLOW) != 0) {
		if (errno != ENOENT) {
			err(1, "fstatat");
		}

		/*
		 * We signal a deleted file by passing a NULL "struct stat"
		 * pointer to the callback.
		 */
		stp = NULL;
	}

	if (S_ISLNK(stb.st_mode)) {
		ssize_t sz;

		if ((sz = readlinkat(snapfd, path, buf, sizeof (buf))) < 0) {
			err(1, "readlinkat");
		}

		buf[sz] = '\0';

		sympath = buf;
	}

	if (cbfunc(st, path, level, stp, sympath, cbarg) != 0) {
		free(path);
		return (-1);
	}

skip:
	/*
	 * Walk each child of this directory:
	 */
	for (diff_ent_t *ch = de->de_child; ch != NULL; ch = ch->de_sibling) {
		walk_diff_tree_impl(st, ch, level + 1, path, cbfunc, cbarg);
	}

	free(path);
	return (0);
}

int
walk_diff_tree(snaptar_t *st, ent_enum_cb *cbfunc)
{
	return (walk_diff_tree_impl(st, &st->st_root, 0, NULL, cbfunc, NULL));
}

static void
usage(char *argv[], int rc)
{
	FILE *out = rc == 0 ? stdout : stderr;

	fprintf(out,
	    "Usage:\n"
	    "   %s [OPTIONS] <dataset> [<parent_snapshot>] <snapshot>\n"
	    "   %s [OPTIONS] -e <parentdataset@snapshot> <dataset@snapshot>\n"
	    "\n"
	    "   -h        This help message.\n"
	    "   -e        Use explicit \"dataset@snapshot\" arguments.\n"
	    "   -t        Print details about the archive that would be\n"
	    "             created without creating the archive itself.\n"
	    "   -f FILE   Output tarball name.  Without -f, output is to\n"
	    "             stdout.\n"
	    "   -r SUBDIR Subdirectory within dataset to consider as the\n"
	    "             root directory for the tarball\n"
	    "   -x PATH   Exclude a file or directory (and subdirectories)\n"
	    "             from the archive.  Takes effect after -r, if that\n"
	    "             option is used.\n"
	    "\n",
	    basename(argv[0]), basename(argv[0]));

	exit(rc);
}

int
main(int argc, char *argv[])
{
	snaptar_t *st;
	boolean_t incremental;
	walk_dir_func *walker;
	int c;
	boolean_t just_print = B_FALSE;
	boolean_t explicit_args = B_FALSE;
	const char *output_file = NULL;
	int posargc;
	char errstr[2048] = { 0 };
	int status = 10;

	/*
	 * We force ourselves to run in the en_US UTF-8 locale so that the OS
	 * multibyte string and wide character facilities (used by libarchive)
	 * are able to process UTF-8 sequences in filenames.
	 */
	if (setlocale(LC_ALL, "en_US.UTF-8") == NULL) {
		err(1, "setlocale(en_US.UTF-8)");
	}

	if (snaptar_alloc(&st, errstr, sizeof (errstr)) != 0) {
		err(1, "snaptar_alloc");
	}

	while ((c = getopt(argc, argv, ":hetf:r:x:")) != -1) {
		switch (c) {
		case 'h':
			usage(argv, 0);
			break;

		case 'e':
			explicit_args = B_TRUE;
			break;

		case 't':
			just_print = B_TRUE;
			break;

		case 'f':
			output_file = optarg;
			break;

		case 'r':
			if (snaptar_param_set(st, SNTR_P_ROOT_PREFIX,
			    optarg) != 0) {
				if (errno == EPROTO) {
					usage(argv, 1);
				}
				err(1, "snaptar_param_set");
			}
			break;

		case 'x':
			if (snaptar_param_set(st, SNTR_P_EXCLUDE_PATH,
			    optarg) != 0) {
				if (errno == EPROTO) {
					usage(argv, 1);
				}
				err(1, "snaptar_param_set");
			}
			break;

		case ':':
			warnx("Option -%c requires an operand", optopt);
			usage(argv, 1);
			break;

		case '?':
			warnx("Unrecognised option: %-c", optopt);
			usage(argv, 1);
			break;
		}
	}

	posargc = argc - optind;

	if (explicit_args) {
		/*
		 * The user has passed two fully qualified "dataset@snapshot"
		 * style names.
		 */
		if (posargc != 2) {
			warnx("Explicit mode requires 2 positional"
			    " arguments.");
			usage(argv, 1);
		}

		if (snaptar_param_set(st, SNTR_P_EXPLICIT_PARENT,
		    argv[optind]) != 0 ||
		    snaptar_param_set(st, SNTR_P_EXPLICIT,
		    argv[optind + 1]) != 0) {
			if (errno == EINVAL) {
				warnx("invalid snapshot arguments");
				usage(argv, 1);
			} else {
				err(1, "snaptar_param_set");
			}
		}

		incremental = B_TRUE;
		goto options_done;
	}

	if (posargc == 2) {
		incremental = B_FALSE;

	} else if (posargc == 3) {
		if (snaptar_param_set(st, SNTR_P_SNAPSHOT_PARENT,
		    argv[optind + 1]) != 0) {
			if (errno == EPROTO) {
				usage(argv, 1);
			}
			err(1, "snaptar_param_set");
		}
		incremental = B_TRUE;

	} else {
		warnx("This program requires 2 or 3 positional arguments.");
		usage(argv, 1);
	}

	if (snaptar_param_set(st, SNTR_P_DATASET, argv[optind]) != 0 ||
	    snaptar_param_set(st, SNTR_P_SNAPSHOT, argv[optind +
	    (posargc - 1)]) != 0) {
		if (errno == EPROTO) {
			usage(argv, 1);
		}
		err(1, "snaptar_param_set");
	}

options_done:
	if ((incremental && get_zfs_mountpoint(&st->st_snapshots[0]) != 0) ||
	    get_zfs_mountpoint(&st->st_snapshots[1]) != 0) {
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

	if (just_print) {
		if (walker(st, print_entry) != 0) {
			goto out;
		}
	} else {
		if (make_tarball(st, walker, output_file) != 0) {
			goto out;
		}
	}

	status = 0;

out:
	if (status != 0) {
		fprintf(stderr, "ERROR: zfs_snapshot_tar: %s\n", errstr);
	}
	snaptar_fini(st);
	if (getenv("ABORT_ON_EXIT") != NULL)
		abort();
	return (status);
}

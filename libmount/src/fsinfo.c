/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libmount from util-linux project.
 *
 * Copyright (C) 2020 Karel Zak <kzak@redhat.com>
 *
 * libmount is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */
#include "mountP.h"

#ifdef USE_LIBMOUNT_SUPPORT_FSINFO
/* libc fallback */
#ifndef HAVE_FSINFO
# include <sys/syscall.h>
# ifndef __NR_fsinfo
#  define __NR_fsinfo -1
# endif
static ssize_t fsinfo(int dfd, const char *filename,
	       struct fsinfo_params *params, size_t params_size,
	       void *result_buffer, size_t result_buf_size)
{
	return syscall(__NR_fsinfo, dfd, filename,
		       params, params_size,
		       result_buffer, result_buf_size);
}
#endif /* HAVE_FSINFO */

static int have_fsinfo = -1;

int mnt_get_target_id(const char *path, unsigned int *id, unsigned int flags)
{
	struct fsinfo_mount_info info;
	struct fsinfo_params params = {
		.flags		= FSINFO_FLAGS_QUERY_PATH,
		.request	= FSINFO_ATTR_MOUNT_INFO,
		.at_flags	= flags,
	};
	int rc = 0;

	DBG(UTILS, ul_debug("fsinfo: reading ID for %s", path));
	errno = 0;
	if (fsinfo(AT_FDCWD, path,
		    &params, sizeof(params), &info, sizeof(info)) < 0)
		rc = -errno;
	else
		*id = info.mnt_id;
	return rc;
}

/*
 * Call fsinfo(), fill @buf with the result, on success update @bufsz
 * to the real result size.
 */
int mnt_fsinfo(const char *query,
	       struct fsinfo_params *params,
	       size_t params_size,
	       char *buf,
	       size_t *bufsz)
{
	ssize_t res;
	int rc = 0;

	assert(buf);
	assert(bufsz);
	assert(params);

	DBG(UTILS, ul_debug("fsinfo(2) [query=%s, request=0x%02x, flags=0x%02x, at_flags=0x%02x]",
				query, params->request, params->flags, params->at_flags));
	errno = 0;
	res = fsinfo(AT_FDCWD, query, params, params_size, buf, *bufsz);
	if (res < 0) {
		rc = res;
		errno = -res;
	} else if ((size_t) res > *bufsz) {
		DBG(UTILS, ul_debug("fsinfo(2) ENAMETOOLONG: result=%lu, expected=%lu", res, *bufsz));
		rc = -ENAMETOOLONG;
	} else if (rc == 0)
		*bufsz = res;
	if (have_fsinfo == -1)
		have_fsinfo = rc == -ENOSYS ? 0 : 1;

	if (rc)
		DBG(UTILS, ul_debug("fsinfo(2) [res=%ld]", res));
	return rc;
}

static void *fsinfo_alloc_attrs(unsigned int id,
				unsigned int attr, unsigned int Nth,
				size_t *size)
{
	char idstr[sizeof(stringify_value(UINT_MAX))];
	struct fsinfo_params params = {
		.flags		= FSINFO_FLAGS_QUERY_MOUNT,
		.request	= attr,
		.Nth		= Nth,
	};
	size_t bufsz = BUFSIZ;
	void *buf = NULL;

	snprintf(idstr, sizeof(idstr), "%u", id);

	errno = 0;
	for (;;) {
		ssize_t ret;
		void *tmp;

		tmp = realloc(buf, bufsz);
		if (!tmp) {
			free(buf);
			break;
		}
		buf = tmp;

		errno = 0;
		ret = fsinfo(AT_FDCWD, idstr, &params, sizeof(params), buf, bufsz);
		if (ret < 0) {
			free(buf);
			break;
		}

		if ((size_t) ret <= bufsz) {
			*size = (size_t) ret;
			return buf;		/* sucess */
		}
		bufsz = (ret + BUFSIZ - 1) & ~(BUFSIZ - 1);
	}

	return NULL;	/* error */
}

/* Returns: 0 on success, <0 on error */
int mnt_fsinfo_get_children(unsigned int id,
			    struct fsinfo_mount_child **mounts,
			    size_t *count)
{
	size_t size = 0;

	assert(id);
	assert(mounts);
	assert(count);

	DBG(UTILS, ul_debug("fsinfo: reading children for id=%u", id));
	*mounts = fsinfo_alloc_attrs(id, FSINFO_ATTR_MOUNT_CHILDREN, 0, &size);
	if (!*mounts)
		return -errno;

	*count = size / sizeof((*mounts)[0]) - 1;
	return 0;
}

#endif /* USE_LIBMOUNT_SUPPORT_FSINFO */

/*
 * Public API
 */

/**
 * mnt_has_fsinfo:
 *
 * Returns: 1 is fsinfo() syscall is supported, or 0
 */
int mnt_has_fsinfo(void)
{
#ifdef USE_LIBMOUNT_SUPPORT_FSINFO
	if (have_fsinfo == -1) {
		struct fsinfo_mount_info info;
		struct fsinfo_params params = {
			.flags   = FSINFO_FLAGS_QUERY_PATH,
			.request = FSINFO_ATTR_MOUNT_INFO,
		};
		size_t sz = sizeof(info);
		long rc;

		rc = mnt_fsinfo("/", &params, sizeof(params), (char *)&info, &sz);
		if (rc != 1)
			have_fsinfo = 1;
		else
			have_fsinfo = 0;
	}
	return have_fsinfo;
#else
	return 0;
#endif
}


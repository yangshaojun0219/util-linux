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

#define _LINUX_FCNTL_H /* WORKAROUND to build against non-distro headers */
#include <linux/watch_queue.h>

#ifndef USE_LIBMOUNT_SUPPORT_WATCHQUEUE
int mnt_kernelwatch_is_mount(void *data __attribute__((__unused__)))
{
	return 0;
}
int mnt_kernelwatch_get_mount_id(void *data __attribute__((__unused__)))
{
	return -ENOSYS;
}
int mnt_kernelwatch_get_operation(void *data __attribute__((__unused__)))
{
	return -ENOSYS;
}
void *mnt_kernelwatch_next_data(void *data __attribute__((__unused__)),
				ssize_t *datasz __attribute__((__unused__)))
{
	return NULL;
}
int mnt_kernelwatch_is_valid(void *data __attribute__((__unused__)),
				size_t datasz __attribute__((__unused__)))
{
	return 0;
}

#else /* USE_LIBMOUNT_SUPPORT_WATCHQUEUE */

#define MNT_KERNELWATCH_MSG_MINSZ       sizeof(struct watch_notification)

/**
 * mnt_kernelwatch_is_valid:
 * @data: event data
 *
 * Returns: 1 if data seems valid as notification, or 0.
 */
int mnt_kernelwatch_is_valid(void *data, size_t datasz)
{
	struct watch_notification *n = (struct watch_notification *) data;
	size_t len;

	if (!n || !datasz) {
		DBG(WATCH, ul_debugobj(data, "no data"));
		return 0;
	}
	len = n->info & WATCH_INFO_LENGTH;
	if (len < MNT_KERNELWATCH_MSG_MINSZ || len > datasz) {
		DBG(WATCH, ul_debugobj(data, "invalid watch_notification.len"));
		return 0;
	}
	DBG(WATCH, ul_debugobj(data, "valid"));
	return 1;
}

/**
 * mnt_kernelwatch_is_mount:
 * @data: event data
 *
 * Returns: 1 if data contains mount node notification or 0.
 *
 * Since: v2.37
 */
int mnt_kernelwatch_is_mount(void *data)
{
	const struct watch_notification *n;

	if (!data)
		return 0;

	n = (const struct watch_notification *) data;
	return n->type == WATCH_TYPE_MOUNT_NOTIFY;
}

/**
 * mnt_kernelwatch_get_mount_id
 * @data: event data
 *
 * See also mnt_fs_set_id().
 *
 * Returns: mount ID or <0 on error.
 *
 * Since: v2.37
 */
int mnt_kernelwatch_get_mount_id(void *data)
{
	if (data && mnt_kernelwatch_is_mount(data)) {
		const struct mount_notification *m = (const struct mount_notification *) data;
		return m->auxiliary_mount;
	}
	return -EINVAL;
}

/**
 * mnt_kernelwatch_get_operation
 * @data: event data
 *
 * See mount_notification_subtype NOTIFY_MOUNT_* in linux/watch_queue.h.
 *
 * Returns: operation indentifier or <0 on error.
 *
 * Since: v2.37
 */
int mnt_kernelwatch_get_operation(void *data)
{
	const struct watch_notification *n;

	if (!data)
		return -EINVAL;
	n = (const struct watch_notification *) data;
	return n->subtype;
}

/**
 * mnt_kernelwatch_next_data
 * @data: event data
 * @datasz: the remaining size of the data
 *
 * Returns: pointer to the next kernel watch_queue message or NULL if not more messages in the buffer.
 *
 * Since: v2.37
 */
void *mnt_kernelwatch_next_data(void *data, ssize_t *datasz)
{
	struct watch_notification *n;
	size_t len;
	char *p;

	/* check the current message */
	if (!mnt_kernelwatch_is_valid(data, *datasz))
		return NULL;

	p = (char *) data;
	n = (struct watch_notification *) data;

	/* go to the next message */
	len = n->info & WATCH_INFO_LENGTH;
	*datasz -= len;

	if (*datasz < (ssize_t) MNT_KERNELWATCH_MSG_MINSZ) {
		DBG(WATCH, ul_debugobj(p, "no more messages"));
		return NULL;
	}

	p += len;

	/* check the next message */
	if (!mnt_kernelwatch_is_valid(p, *datasz))
		return NULL;

	DBG(WATCH, ul_debugobj(p, "next message"));
	return p;
}
#endif /* USE_LIBMOUNT_SUPPORT_WATCHQUEUE */

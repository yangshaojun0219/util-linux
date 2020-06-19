/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libmount from util-linux project.
 *
 * Copyright (C) 2014-2018 Karel Zak <kzak@redhat.com>
 *
 * libmount is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */

/**
 * SECTION: monitor
 * @title: Monitor
 * @short_description: interface to monitor mount tables
 *
 * For example monitor VFS (/proc/self/mountinfo) for changes:
 *
 * <informalexample>
 *   <programlisting>
 * const char *filename;
 * struct libmount_monitor *mn = mnt_new_monitor();
 *
 * mnt_monitor_enable_kernel(mn, TRUE));
 *
 * printf("waiting for changes...\n");
 * while (mnt_monitor_wait(mn, -1) > 0) {
 *    while (mnt_monitor_next_change(mn, &filename, NULL) == 0)
 *       printf(" %s: change detected\n", filename);
 * }
 * mnt_unref_monitor(mn);
 *   </programlisting>
 * </informalexample>
 *
 */

#include "mountP.h"
#include "pathnames.h"
#include "fileutils.h"

#include <sys/inotify.h>
#include <sys/epoll.h>

#ifdef USE_LIBMOUNT_SUPPORT_WATCHQUEUE
#define _LINUX_FCNTL_H				/* WORKAROUND to build against non-distro headers */
# include <sys/ioctl.h>
# include <linux/unistd.h>
# include <linux/watch_queue.h>
#endif


struct monitor_opers;

/*
 * The libmount supports multiple ways (channels) how to monitor mount table
 * changes -- each way is represented by one mount monitor entry.
 */
struct monitor_entry {
	int			fd;		/* private entry file descriptor */
	char			*path;		/* path to the monitored file */
	int			type;		/* MNT_MONITOR_TYPE_* */
	uint32_t		events;		/* wanted epoll events */

	char			*buf;		/* buffer to read from kernel */
	size_t			bufsz;		/* buffer size */
	ssize_t			bufrsz;		/* last read() size */

	const struct monitor_opers *opers;

	unsigned int		enabled : 1,
				keep_data : 1,	/* return read() buffer to caller */
				changed : 1;	/* change detected */

	struct list_head	ents;		/* libmnt_monitor->ents list item */
};

struct libmnt_monitor {
	int			refcount;
	int			fd;		/* public monitor file descriptor */

	struct list_head	ents;
};

struct monitor_opers {
	int (*op_get_fd)(struct libmnt_monitor *, struct monitor_entry *);
	int (*op_close_fd)(struct libmnt_monitor *, struct monitor_entry *);
	int (*op_event_read)(struct libmnt_monitor *, struct monitor_entry *);
};

static int monitor_modify_epoll(struct libmnt_monitor *mn,
				struct monitor_entry *me, int enable);

/**
 * mnt_new_monitor:
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the filesystem.
 *
 * Returns: newly allocated struct libmnt_monitor.
 */
struct libmnt_monitor *mnt_new_monitor(void)
{
	struct libmnt_monitor *mn = calloc(1, sizeof(*mn));
	if (!mn)
		return NULL;

	mn->refcount = 1;
	mn->fd = -1;
	INIT_LIST_HEAD(&mn->ents);

	DBG(MONITOR, ul_debugobj(mn, "alloc"));
	return mn;
}

/**
 * mnt_ref_monitor:
 * @mn: monitor pointer
 *
 * Increments reference counter.
 */
void mnt_ref_monitor(struct libmnt_monitor *mn)
{
	if (mn)
		mn->refcount++;
}

static void free_monitor_entry(struct monitor_entry *me)
{
	if (!me)
		return;
	list_del(&me->ents);
	if (me->fd >= 0)
		close(me->fd);
	free(me->path);
	free(me->buf);
	free(me);
}

/**
 * mnt_unref_monitor:
 * @mn: monitor pointer
 *
 * Decrements the reference counter, on zero the @mn is automatically
 * deallocated.
 */
void mnt_unref_monitor(struct libmnt_monitor *mn)
{
	if (!mn)
		return;

	mn->refcount--;
	if (mn->refcount <= 0) {
		mnt_monitor_close_fd(mn);	/* destroys all file descriptors */

		while (!list_empty(&mn->ents)) {
			struct monitor_entry *me = list_entry(mn->ents.next,
						  struct monitor_entry, ents);
			free_monitor_entry(me);
		}

		free(mn);
	}
}

static struct monitor_entry *monitor_new_entry(struct libmnt_monitor *mn, size_t bufsz)
{
	struct monitor_entry *me;

	assert(mn);

	me = calloc(1, sizeof(*me));
	if (!me)
		return NULL;
        INIT_LIST_HEAD(&me->ents);
	list_add_tail(&me->ents, &mn->ents);

	me->fd = -1;
	me->bufsz = bufsz;

	if (me->bufsz) {
		me->buf = malloc(bufsz);
		if (!me->buf) {
			free(me);
			return NULL;
		}
	}

	DBG(MONITOR, ul_debugobj(me, "alloc entry"));
	return me;
}

static int monitor_next_entry(struct libmnt_monitor *mn,
			      struct libmnt_iter *itr,
			      struct monitor_entry **me)
{
	int rc = 1;

	assert(mn);
	assert(itr);
	assert(me);

	*me = NULL;

	if (!itr->head)
		MNT_ITER_INIT(itr, &mn->ents);
	if (itr->p != itr->head) {
		MNT_ITER_ITERATE(itr, *me, struct monitor_entry, ents);
		rc = 0;
	}

	return rc;
}

/* returns entry by type */
static struct monitor_entry *monitor_get_entry(struct libmnt_monitor *mn, int type)
{
	struct libmnt_iter itr;
	struct monitor_entry *me;

	mnt_reset_iter(&itr, MNT_ITER_FORWARD);
	while (monitor_next_entry(mn, &itr, &me) == 0) {
		if (me->type == type)
			return me;
	}
	return NULL;
}


/*
 * Userspace monitor
 */

static int userspace_monitor_close_fd(struct libmnt_monitor *mn __attribute__((__unused__)),
				    struct monitor_entry *me)
{
	assert(me);

	if (me->fd >= 0)
		close(me->fd);
	me->fd = -1;
	return 0;
}

static int userspace_add_watch(struct monitor_entry *me, int *final, int *fd)
{
	char *filename = NULL;
	int wd, rc = -EINVAL;

	assert(me);
	assert(me->path);

	/*
	 * libmount uses rename(2) to atomically update utab, monitor
	 * rename changes is too tricky. It seems better to monitor utab
	 * lockfile close.
	 */
	if (asprintf(&filename, "%s.lock", me->path) <= 0) {
		rc = -errno;
		goto done;
	}

	/* try lock file if already exists */
	errno = 0;
	wd = inotify_add_watch(me->fd, filename, IN_CLOSE_NOWRITE);
	if (wd >= 0) {
		DBG(MONITOR, ul_debugobj(me, "  added lock inotify-watch [%s, fd=%d]", filename, wd));
		rc = 0;
		if (final)
			*final = 1;
		if (fd)
			*fd = wd;
		goto done;
	} else if (errno != ENOENT) {
		rc = -errno;
		goto done;
	}

	/* If the lock file does not exist yet, then watch the first
	 * avalable parental directory.
	 */
	while (strchr(filename, '/')) {
		stripoff_last_component(filename);
		if (!*filename)
			break;

		/* try directory where is the lock file */
		errno = 0;
		wd = inotify_add_watch(me->fd, filename, IN_CREATE|IN_ISDIR);
		if (wd >= 0) {
			DBG(MONITOR, ul_debugobj(me, "  added dir inotify-watch [%s, fd=%d]", filename, wd));
			rc = 0;
			if (fd)
				*fd = wd;
			break;
		} else if (errno != ENOENT) {
			rc = -errno;
			break;
		}
	}
done:
	free(filename);
	return rc;
}

static int userspace_monitor_get_fd(struct libmnt_monitor *mn __attribute__((__unused__)),
				    struct monitor_entry *me)
{
	int rc;

	if (!me || me->enabled == 0)	/* not-initialized or disabled */
		return -EINVAL;
	if (me->fd >= 0)
		return me->fd;		/* already initialized */

	assert(me->path);

	me->fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (me->fd < 0)
		goto err;

	if (userspace_add_watch(me, NULL, NULL) < 0)
		goto err;

	DBG(MONITOR, ul_debugobj(me, " new userspace monitor [%s, inotify fd=%d]",
				me->path, me->fd));
	return me->fd;
err:
	rc = -errno;
	if (me->fd >= 0)
		close(me->fd);
	me->fd = -1;
	DBG(MONITOR, ul_debugobj(me, "failed to create userspace monitor [rc=%d]", rc));
	return rc;
}

/*
 * verify and drain inotify buffer
 */
static int userspace_monitor_read(struct libmnt_monitor *mn,
					struct monitor_entry *me)
{
	int status = 0;
	int last_removed = -1;

	if (!me || me->fd < 0)
		return 0;

	DBG(MONITOR, ul_debugobj(me, "drain/verify userspace monitor"));

	/* the me->fd is non-blocking */
	do {
		char *p;
		const struct inotify_event *e;

		DBG(MONITOR, ul_debugobj(me, " reading inotify events"));
		me->bufrsz = read(me->fd, me->buf, me->bufsz);
		if (me->bufrsz <= 0)
			break;

		for (p = me->buf; p < me->buf + me->bufrsz;
		     p += sizeof(struct inotify_event) + e->len) {

			int fd = -1;

			e = (const struct inotify_event *) p;
			DBG(MONITOR, ul_debugobj(me, "  inotify event 0x%p [mask=0x%x, name=%s]\n",
						e, e->mask, e->len ? e->name : ""));

			if (e->mask & IN_CLOSE_NOWRITE)
				status = 1;
			else {
				/* event on lock file */
				userspace_add_watch(me, &status, &fd);

				if (fd != e->wd && e->wd != last_removed) {
					/*
					 * If the new watch (fd) is diffrent than already used e->wd
					 * than remove old watch. This is necessary for example when
					 * we move watch from /run/mount to /run/mount/utab/lock.
					 *
					 * The directory watch usually generates more events,
					 * call inotify_rm_watch() only first time.
					 */
					DBG(MONITOR, ul_debugobj(me, " removing watch [fd=%d]", e->wd));
					inotify_rm_watch(me->fd, e->wd);
					last_removed = e->wd;
				}
			}
		}

		if (status == 1 && me->keep_data)
			break;
	} while (1);

	DBG(MONITOR, ul_debugobj(mn, "%s", status == 1 ? " success" : " nothing"));
	return status;
}

/*
 * userspace monitor operations
 */
static const struct monitor_opers userspace_opers = {
	.op_get_fd	= userspace_monitor_get_fd,
	.op_close_fd	= userspace_monitor_close_fd,
	.op_event_read	= userspace_monitor_read
};

/**
 * mnt_monitor_enable_userspace:
 * @mn: monitor
 * @enable: 0 or 1
 * @filename: overwrites default
 *
 * Enables or disables userspace mount table monitoring. If the userspace monitor does not
 * exist and enable=1 then allocates new resources necessary for the monitor.
 *
 * If the top-level monitor has been already created (by mnt_monitor_get_fd()
 * or mnt_monitor_wait()) then it's updated according to @enable.
 *
 * The @filename is used only the first time when you enable the monitor. It's
 * impossible to have more than one userspace monitor. The recommended is to
 * use NULL as @filename.
 *
 * The userspace monitor is unsupported for systems with classic regular
 * /etc/mtab file.
 *
 * This monitor type is able to return inotify event data (as read() from
 * kernel), but it's disabled by default as it does not provide any details
 * about changed filesystems. See mnt_monitor_keep_data() for more details.
 *
 * Return: 0 on success and <0 on error
 */
int mnt_monitor_enable_userspace(struct libmnt_monitor *mn, int enable, const char *filename)
{
	struct monitor_entry *me;
	int rc = 0;

	if (!mn)
		return -EINVAL;

	me = monitor_get_entry(mn, MNT_MONITOR_TYPE_USERSPACE);
	if (me) {
		rc = monitor_modify_epoll(mn, me, enable);
		if (!enable)
			userspace_monitor_close_fd(mn, me);
		return rc;
	}
	if (!enable)
		return 0;

	DBG(MONITOR, ul_debugobj(mn, "allocate new userspace monitor"));

	if (!filename)
		filename = mnt_get_utab_path();		/* /run/mount/utab */
	if (!filename) {
		DBG(MONITOR, ul_debugobj(mn, "failed to get userspace mount table path"));
		return -EINVAL;
	}

	me = monitor_new_entry(mn, sizeof(struct inotify_event) + NAME_MAX + 1);
	if (!me)
		goto err;

	me->type = MNT_MONITOR_TYPE_USERSPACE;
	me->opers = &userspace_opers;
	me->events = EPOLLIN;
	me->path = strdup(filename);
	if (!me->path)
		goto err;

	return monitor_modify_epoll(mn, me, TRUE);
err:
	rc = -errno;
	free_monitor_entry(me);
	DBG(MONITOR, ul_debugobj(mn, "failed to allocate userspace monitor [rc=%d]", rc));
	return rc;
}


/*
 * Kernel monitor
 */

static int kernel_monitor_close_fd(struct libmnt_monitor *mn __attribute__((__unused__)),
				   struct monitor_entry *me)
{
	assert(me);

	if (me->fd >= 0)
		close(me->fd);
	me->fd = -1;
	return 0;
}

static int kernel_monitor_get_fd(struct libmnt_monitor *mn,
				 struct monitor_entry *me)
{
	int rc;

	if (!me || me->enabled == 0)	/* not-initialized or disabled */
		return -EINVAL;
	if (me->fd >= 0)
		return me->fd;		/* already initialized */

	assert(me->path);
	DBG(MONITOR, ul_debugobj(mn, " open kernel monitor for %s", me->path));

	me->fd = open(me->path, O_RDONLY|O_CLOEXEC);
	if (me->fd < 0)
		goto err;

	return me->fd;
err:
	rc = -errno;
	DBG(MONITOR, ul_debugobj(mn, "failed to create kernel  monitor [rc=%d]", rc));
	return rc;
}

/*
 * kernel monitor operations
 */
static const struct monitor_opers kernel_opers = {
	.op_get_fd		= kernel_monitor_get_fd,
	.op_close_fd		= kernel_monitor_close_fd,
};

/**
 * mnt_monitor_enable_kernel:
 * @mn: monitor
 * @enable: 0 or 1
 *
 * Enables or disables kernel VFS monitoring. If the monitor does not exist and
 * enable=1 then allocates new resources necessary for the monitor.
 *
 * If the top-level monitor has been already created (by mnt_monitor_get_fd()
 * or mnt_monitor_wait()) then it's updated according to @enable.
 *
 * Return: 0 on success and <0 on error
 */
int mnt_monitor_enable_kernel(struct libmnt_monitor *mn, int enable)
{
	struct monitor_entry *me;
	int rc = 0;

	if (!mn)
		return -EINVAL;

	me = monitor_get_entry(mn, MNT_MONITOR_TYPE_KERNEL);
	if (me) {
		rc = monitor_modify_epoll(mn, me, enable);
		if (!enable)
			kernel_monitor_close_fd(mn, me);
		return rc;
	}
	if (!enable)
		return 0;

	DBG(MONITOR, ul_debugobj(mn, "allocate new kernel monitor"));

	/* create a new entry */
	me = monitor_new_entry(mn, 0);
	if (!me)
		goto err;

	/* If you want to use epoll FD in another epoll then top level
	 * epoll_wait() will drain all events from low-level FD if the
	 * low-level FD is not added with EPOLLIN. It means without EPOLLIN it
	 * it's impossible to detect which low-level FD has been active.
	 *
	 * Unfortunately, use EPOLLIN for mountinfo is tricky because in this
	 * case kernel returns events all time (we don't read from the FD).
	 * The solution is to use also edge-triggered (EPOLLET) flag, then
	 * kernel generate events on mountinfo changes only. The disadvantage is
	 * that we have to drain initial event generated by EPOLLIN after
	 * epoll_ctl(ADD). See monitor_modify_epoll().
	 */
	me->events = EPOLLIN | EPOLLET;

	me->type = MNT_MONITOR_TYPE_KERNEL;
	me->opers = &kernel_opers;
	me->path = strdup(_PATH_PROC_MOUNTINFO);
	if (!me->path)
		goto err;

	return monitor_modify_epoll(mn, me, TRUE);
err:
	rc = -errno;
	free_monitor_entry(me);
	DBG(MONITOR, ul_debugobj(mn, "failed to allocate kernel monitor [rc=%d]", rc));
	return rc;
}

/*
 * kernel mount-watch monitor
 */
#ifdef USE_LIBMOUNT_SUPPORT_WATCHQUEUE

#ifndef HAVE_WATCH_MOUNT
# include <sys/syscall.h>
# ifndef __NR_watch_mount
#  define __NR_watch_mount -1
# endif
static int watch_mount(int dfd, const char *filename, int at_flags, int fd, int id)
{
	return syscall(__NR_watch_mount, dfd, filename, at_flags, fd, id);
}
#endif /* HAVE_WATCH_MOUNT */

/* watch specifig tags */
enum {
	MNT_KERNELWATCH_TAG_ROOTMOUNT	= 0x01
};

#define MNT_KERNELWATCH_QUEUE_SIZE	256	/* number of messages 1..512 */
#define MNT_KERNELWATCH_MSG_MINSZ	sizeof(struct watch_notification)

static int kernelwatch_monitor_close_fd(struct libmnt_monitor *mn __attribute__((__unused__)),
				    struct monitor_entry *me)
{
	assert(me);

	if (me->fd >= 0)
		close(me->fd);
	me->fd = -1;
	return 0;
}

static int kernelwatch_monitor_get_fd(struct libmnt_monitor *mn __attribute__((__unused__)),
				    struct monitor_entry *me)
{
	int rc;
	int pipefd[2];

	if (!me || me->enabled == 0)	/* not-initialized or disabled */
		return -EINVAL;
	if (me->fd >= 0)
		return me->fd;		/* already initialized */

	if (pipe2(pipefd, O_NOTIFICATION_PIPE | O_CLOEXEC | O_NONBLOCK) == -1)
		goto err;

	/* this is kernel design punk -- you need only one fd, but get two */
	close(pipefd[1]);

	me->fd = pipefd[0];
	if (me->fd < 0)
		goto err;

	if (ioctl(me->fd, IOC_WATCH_QUEUE_SET_SIZE, MNT_KERNELWATCH_QUEUE_SIZE) == -1)
		goto err;

	if (watch_mount(AT_FDCWD, "/", 0, me->fd, MNT_KERNELWATCH_TAG_ROOTMOUNT) == -1)
		goto err;

	DBG(MONITOR, ul_debugobj(me, " new kernelwatch monitor [watch fd=%d]", me->fd));
	return me->fd;
err:
	rc = -errno;
	if (me->fd >= 0)
		close(me->fd);
	me->fd = -1;
	DBG(MONITOR, ul_debugobj(me, "failed to create kernelwatch monitor [rc=%d]", rc));
	return rc;
}

/*
 * verify and drain inotify buffer
 */
static int kernelwatch_monitor_read(struct libmnt_monitor *mn,
				    struct monitor_entry *me)
{
	int status = 0;

	if (!me || me->fd < 0)
		return 0;

	do {
		char *p;
		size_t len = 0, rest = 0;

		DBG(MONITOR, ul_debugobj(me, "reading kernelwatch monitor"));

		me->bufrsz = read(me->fd, me->buf, me->bufsz);
		if (me->bufrsz <= 0
		    || me->bufrsz > (ssize_t) me->bufsz
		    || me->bufrsz < (ssize_t) MNT_KERNELWATCH_MSG_MINSZ) {
			DBG(MONITOR, ul_debugobj(me, " no data [rc=%zd]", me->bufrsz));
			break;
		}
		rest = me->bufrsz;

		for (p = me->buf; p < me->buf + me->bufrsz; p += len) {
			const struct watch_notification *n =
				(const struct watch_notification *) p;

			len = n->info & WATCH_INFO_LENGTH;
			if (len < MNT_KERNELWATCH_MSG_MINSZ || len > rest) {
				DBG(MONITOR, ul_debugobj(me, " invalid in-header lenght"));
				break;
			}
			rest -= len;

			DBG(MONITOR, ul_debugobj(me, " watch event 0x%p "
				"[len=%zu id=%d, info=%08x]",
				n, len, n->info & WATCH_INFO_ID, n->info));

			switch (n->type) {
			case WATCH_TYPE_META:
				switch (n->subtype) {
				case WATCH_META_REMOVAL_NOTIFICATION:
					DBG(MONITOR, ul_debugobj(me, "  meta: watchpoint removal"));
					break;
				case WATCH_META_LOSS_NOTIFICATION:
					DBG(MONITOR, ul_debugobj(me, "  meta: data loss"));
					break;
				default:
					DBG(MONITOR, ul_debugobj(me, "  meta: another subtype"));
					break;
				}
				break;
			case WATCH_TYPE_MOUNT_NOTIFY:
				DBG(MONITOR, ul_debugobj(me, " mount notify"));
				status = 1;
				break;
			case WATCH_TYPE_SB_NOTIFY:
				DBG(MONITOR, ul_debugobj(me, " superblock notify"));
				status = 1;
				break;
			default:
				DBG(MONITOR, ul_debugobj(me, " another notify type"));
				break;
			}
		}

		if (status == 1 && me->keep_data)
			break;
	} while (1);

	DBG(MONITOR, ul_debugobj(mn, "%s", status == 1 ? " success" : " nothing"));
	return status;
}

/*
 * kernelwatch monitor operations
 */
static const struct monitor_opers kernelwatch_opers = {
	.op_get_fd	= kernelwatch_monitor_get_fd,
	.op_close_fd	= kernelwatch_monitor_close_fd,
	.op_event_read	= kernelwatch_monitor_read
};

static int __enable_kernelwatch(struct libmnt_monitor *mn, int enable)
{
	struct monitor_entry *me;
	int rc = 0;

	if (!mn)
		return -EINVAL;

	me = monitor_get_entry(mn, MNT_MONITOR_TYPE_KERNELWATCH);
	if (me) {
		rc = monitor_modify_epoll(mn, me, enable);
		if (!enable)
			kernelwatch_monitor_close_fd(mn, me);
		return rc;
	}
	if (!enable)
		return 0;

	DBG(MONITOR, ul_debugobj(mn, "allocate new kernelwatch monitor"));

	assert(BUFSIZ > sizeof(struct watch_notification) + 128);

	me = monitor_new_entry(mn, BUFSIZ);
	if (!me)
		goto err;

	me->type = MNT_MONITOR_TYPE_KERNELWATCH;
	me->opers = &kernelwatch_opers;
	me->events = EPOLLIN | EPOLLET;
	me->keep_data = 1;

	/* it's kernelwatch_monitor_get_fd() where we setup 'fd' and add watchs */
	return monitor_modify_epoll(mn, me, TRUE);
err:
	rc = -errno;
	free_monitor_entry(me);
	DBG(MONITOR, ul_debugobj(mn, "failed to allocate kernelwatch monitor [rc=%d]", rc));
	return rc;
}

#endif /* USE_LIBMOUNT_SUPPORT_WATCHQUEUE */

/**
 * mnt_monitor_enable_kernelwatch:
 * @mn: monitor
 * @enable: 0 or 1
 *
 * Enables or disables kernelwatch mounts and superblock. If the kernelwatch monitor does not
 * exist and enable=1 then allocates new resources necessary for the monitor.
 *
 * If the top-level monitor has been already created (by mnt_monitor_get_fd()
 * or mnt_monitor_wait()) then it's updated according to @enable.
 *
 * This monitor type is able to return "struct watch_notification" event data
 * (as read() from kernel and it's enabled by default. See
 * mnt_monitor_keep_data() and  mnt_monitor_event_data() for more details.
 *
 * Return: 0 on success and <0 on error
 */
#ifdef USE_LIBMOUNT_SUPPORT_WATCHQUEUE
int mnt_monitor_enable_kernelwatch(struct libmnt_monitor *mn, int enable)
{
	return __enable_kernelwatch(mn, enable);
}
#else
int mnt_monitor_enable_kernelwatch(
		struct libmnt_monitor *mn __attribute__((__unused__)),
		int enable __attribute__((__unused__)))
{
	return -ENOSYS;
}
#endif

/*
 * Add/Remove monitor entry to/from monitor epoll.
 */
static int monitor_modify_epoll(struct libmnt_monitor *mn,
				struct monitor_entry *me, int enable)
{
	assert(mn);
	assert(me);

	me->enabled = enable ? 1 : 0;
	me->changed = 0;

	if (mn->fd < 0)
		return 0;	/* no epoll, ignore request */

	if (enable) {
		struct epoll_event ev = { .events = me->events };
		int fd = me->opers->op_get_fd(mn, me);

		if (fd < 0)
			goto err;

		DBG(MONITOR, ul_debugobj(mn, " add to epoll [%s, fd=%d]", me->path, fd));

		ev.data.ptr = (void *) me;

		if (epoll_ctl(mn->fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
			if (errno != EEXIST)
				goto err;
		}
		if (me->events & (EPOLLIN | EPOLLET)) {
			/* Drain initial events generated for /proc/self/mountinfo */
			struct epoll_event events[1];
			while (epoll_wait(mn->fd, events, 1, 0) > 0);
		}
	} else if (me->fd) {
		DBG(MONITOR, ul_debugobj(mn, " remove from epoll [%s, fd=%d]", me->path, me->fd));
		if (epoll_ctl(mn->fd, EPOLL_CTL_DEL, me->fd, NULL) < 0) {
			if (errno != ENOENT)
				goto err;
		}
	}

	return 0;
err:
	DBG(MONITOR, ul_debugobj(mn, " modify epoll faild"));
	return -errno;
}

/**
 * mnt_monitor_close_fd:
 * @mn: monitor
 *
 * Close monitor file descriptor. This is usually unnecessary, because
 * mnt_unref_monitor() cleanups all.
 *
 * The function is necessary only if you want to reset monitor setting. The
 * next mnt_monitor_get_fd() or mnt_monitor_wait() will use newly initialized
 * monitor.  This restart is unnecessary for mnt_monitor_enable_*() functions.
 *
 * Returns: 0 on success, <0 on error.
 */
int mnt_monitor_close_fd(struct libmnt_monitor *mn)
{
	struct libmnt_iter itr;
	struct monitor_entry *me;

	if (!mn)
		return -EINVAL;

	mnt_reset_iter(&itr, MNT_ITER_FORWARD);

	/* disable all monitor entries */
	while (monitor_next_entry(mn, &itr, &me) == 0) {

		/* remove entry from epoll */
		if (mn->fd >= 0)
			monitor_modify_epoll(mn, me, FALSE);

		/* close entry FD */
		me->opers->op_close_fd(mn, me);
	}

	if (mn->fd >= 0) {
		DBG(MONITOR, ul_debugobj(mn, "closing top-level epoll"));
		close(mn->fd);
	}
	mn->fd = -1;
	return 0;
}

/**
 * mnt_monitor_get_fd:
 * @mn: monitor
 *
 * The file descriptor is associated with all monitored files and it's usable
 * for example for epoll. You have to call mnt_monitor_event_cleanup() or
 * mnt_monitor_next_change() after each event.
 *
 * Returns: >=0 (fd) on success, <0 on error
 */
int mnt_monitor_get_fd(struct libmnt_monitor *mn)
{
	struct libmnt_iter itr;
	struct monitor_entry *me;
	int rc = 0;

	if (!mn)
		return -EINVAL;
	if (mn->fd >= 0)
		return mn->fd;

	DBG(MONITOR, ul_debugobj(mn, "creating top-level epoll"));
	mn->fd = epoll_create1(EPOLL_CLOEXEC);
	if (mn->fd < 0)
		return -errno;

	mnt_reset_iter(&itr, MNT_ITER_FORWARD);

	DBG(MONITOR, ul_debugobj(mn, " adding entries to epoll [epoll fd=%d]", mn->fd));
	while (monitor_next_entry(mn, &itr, &me) == 0) {
		if (!me->enabled)
			continue;
		rc = monitor_modify_epoll(mn, me, TRUE);
		if (rc)
			goto err;
	}

	DBG(MONITOR, ul_debugobj(mn, " epoll created"));
	return mn->fd;
err:
	rc = errno ? -errno : -EINVAL;
	close(mn->fd);
	mn->fd = -1;
	DBG(MONITOR, ul_debugobj(mn, "create epoll failed [rc=%d]", rc));
	return rc;
}

/**
 * mnt_monitor_wait:
 * @mn: monitor
 * @timeout: number of milliseconds, -1 block indefinitely, 0 return immediately
 *
 * Waits for the next change, after the event it's recommended to use
 * mnt_monitor_next_change() to get more details about the change and to
 * avoid false positive events.
 *
 * Returns: 1 success (something changed), 0 timeout, <0 error.
 */
int mnt_monitor_wait(struct libmnt_monitor *mn, int timeout)
{
	int rc;
	struct monitor_entry *me;
	struct epoll_event events[1];

	if (!mn)
		return -EINVAL;

	if (mn->fd < 0) {
		rc = mnt_monitor_get_fd(mn);
		if (rc < 0)
			return rc;
	}

	do {
		DBG(MONITOR, ul_debugobj(mn, "calling epoll_wait(), timeout=%d", timeout));
		rc = epoll_wait(mn->fd, events, 1, timeout);
		if (rc < 0)
			return -errno;		/* error */
		if (rc == 0)
			return 0;		/* timeout */

		me = (struct monitor_entry *) events[0].data.ptr;
		if (!me)
			return -EINVAL;

		if (me->opers->op_event_read == NULL ||
		    me->opers->op_event_read(mn, me) == 1) {
			me->changed = 1;
			break;
		}
	} while (1);

	return 1;			/* success */
}


static struct monitor_entry *get_changed(struct libmnt_monitor *mn)
{
	struct libmnt_iter itr;
	struct monitor_entry *me;

	mnt_reset_iter(&itr, MNT_ITER_FORWARD);
	while (monitor_next_entry(mn, &itr, &me) == 0) {
		if (me->changed)
			return me;
	}
	return NULL;
}


/**
 * mnt_monitor_next_change:
 * @mn: monitor
 * @filename: returns changed file (optional argument)
 * @type: returns MNT_MONITOR_TYPE_* (optional argument)
 *
 * The function does not wait and it's designed to provide details about changes.
 * It's always recommended to use this function to avoid false positives.
 *
 * Returns: 0 on success, 1 no change, <0 on error
 */
int mnt_monitor_next_change(struct libmnt_monitor *mn,
			    const char **filename,
			    int *type)
{
	int rc;
	struct monitor_entry *me;

	if (!mn || mn->fd < 0)
		return -EINVAL;

	/*
	 * if we previously called epoll_wait() (e.g. mnt_monitor_wait()) then
	 * info about unread change is already stored in monitor_entry.
	 *
	 * If we get nothing, then ask kernel.
	 */
	me = get_changed(mn);
	while (!me) {
		struct epoll_event events[1];

		DBG(MONITOR, ul_debugobj(mn, "asking for next changed"));

		rc = epoll_wait(mn->fd, events, 1, 0);	/* no timeout! */
		if (rc < 0) {
			DBG(MONITOR, ul_debugobj(mn, " *** error"));
			return -errno;
		}
		if (rc == 0) {
			DBG(MONITOR, ul_debugobj(mn, " *** nothing"));
			return 1;
		}

		me = (struct monitor_entry *) events[0].data.ptr;
		if (!me)
			return -EINVAL;

		if (me->opers->op_event_read != NULL &&
		    me->opers->op_event_read(mn, me) != 1)
			me = NULL;
	}

	me->changed = 0;

	if (filename)
		*filename = me->path;
	if (type)
		*type = me->type;

	DBG(MONITOR, ul_debugobj(mn, " *** success [changed: %s]", me->path));
	return 0;
}

/**
 * mnt_monitor_event_cleanup:
 * @mn: monitor
 *
 * This function cleanups (drain) internal buffers. It's necessary to call
 * this function after event if you do not call mnt_monitor_next_change().
 *
 * Returns: 0 on success, <0 on error
 */
int mnt_monitor_event_cleanup(struct libmnt_monitor *mn)
{
	int rc;

	if (!mn || mn->fd < 0)
		return -EINVAL;

	while ((rc = mnt_monitor_next_change(mn, NULL, NULL)) == 0);
	return rc < 0 ? rc : 0;
}

/**
 * mnt_monitor_event_data:
 * @mn: monitor
 * @type: wanted MNT_MONITOR_TYPE_* as returned by mnt_monitor_next_change()
 * @bufsz: returns size of the buffer
 *
 * The event data are not maintained by libmount and API/ABI does not guarantee
 * backward compatibility. Every monitor type returns different data or NULL
 * (MNT_MONITOR_TYPE_KERNEL does not provide any data).
 *
 * Returns: data read from kernel for the last event or NULL
 */
void *mnt_monitor_event_data(struct libmnt_monitor *mn, int type, ssize_t *bufsz)
{
	struct libmnt_iter itr;
	struct monitor_entry *me;

	if (!mn || mn->fd < 0)
		return NULL;;

	mnt_reset_iter(&itr, MNT_ITER_FORWARD);
	while (monitor_next_entry(mn, &itr, &me) == 0) {
		if (me->type == type) {
			if (bufsz)
				*bufsz = me->bufrsz;	/* read() return */
			if (me->bufrsz > 0)
				return me->buf;
			break;
		}
	}
	return NULL;
}


/**
 * mnt_monitor_keep_data:
 * @mn: monitor
 * @type: MNT_MONITOR_TYPE_*
 * @enable: 1 or 0
 *
 * Forces monitor to keep event data in memory and do not overwrite it until
 * not requested by caller (usually by next mnt_monitor_next_change() or
 * mnt_monitor_event_cleanup()).
 *
 * Returns: 0 on success, <0 on error.
 */
int mnt_monitor_keep_data(struct libmnt_monitor *mn, int type, int enable)
{
	struct libmnt_iter itr;
	struct monitor_entry *me;

	if (!mn)
		return -EINVAL;

	mnt_reset_iter(&itr, MNT_ITER_FORWARD);
	while (monitor_next_entry(mn, &itr, &me) == 0) {
		if (me->type == type) {
			me->keep_data = enable;
			return 0;
		}
	}

	return -EINVAL;
}

#ifdef TEST_PROGRAM

static struct libmnt_monitor *create_test_monitor(int argc, char *argv[])
{
	struct libmnt_monitor *mn;
	int i;

	mn = mnt_new_monitor();
	if (!mn) {
		warn("failed to allocate monitor");
		goto err;
	}

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "userspace") == 0) {
			if (mnt_monitor_enable_userspace(mn, TRUE, NULL)) {
				warn("failed to initialize userspace monitor");
				goto err;
			}

		} else if (strcmp(argv[i], "kernel") == 0) {
			if (mnt_monitor_enable_kernel(mn, TRUE)) {
				warn("failed to initialize kernel monitor");
				goto err;
			}
		} else if (strcmp(argv[i], "kernelwatch") == 0) {
			if (mnt_monitor_enable_kernelwatch(mn, TRUE)) {
				warn("failed to initialize kernelwatch monitor");
				goto err;
			}
		}
	}
	if (i == 1) {
		warnx("No monitor type specified");
		goto err;
	}

	return mn;
err:
	mnt_unref_monitor(mn);
	return NULL;
}

/*
 * create a monitor and add the monitor fd to epoll
 */
static int __test_epoll(struct libmnt_test *ts, int argc, char *argv[], int cleanup)
{
	int fd, efd = -1, rc = -1;
	struct epoll_event ev;
	struct libmnt_monitor *mn = create_test_monitor(argc, argv);

	if (!mn)
		return -1;

	fd = mnt_monitor_get_fd(mn);
	if (fd < 0) {
		warn("failed to initialize monitor fd");
		goto done;
	}

	efd = epoll_create1(EPOLL_CLOEXEC);
	if (efd < 0) {
		warn("failed to create epoll");
		goto done;
	}

	ev.events = EPOLLIN;
	ev.data.fd = fd;

	rc = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
	if (rc < 0) {
		warn("failed to add fd to epoll");
		goto done;
	}

	printf("waiting for changes...\n");
	do {
		const char *filename = NULL;
		struct epoll_event events[1];
		int n = epoll_wait(efd, events, 1, -1);

		if (n < 0) {
			rc = -errno;
			warn("polling error");
			goto done;
		}
		if (n == 0 || events[0].data.fd != fd)
			continue;

		printf(" top-level FD active\n");
		if (cleanup)
			mnt_monitor_event_cleanup(mn);
		else {
			while (mnt_monitor_next_change(mn, &filename, NULL) == 0)
				printf("  %s: change detected\n", filename);
		}
	} while (1);

	rc = 0;
done:
	if (efd >= 0)
		close(efd);
	mnt_unref_monitor(mn);
	return rc;
}

/*
 * create a monitor and add the monitor fd to epoll
 */
static int test_epoll(struct libmnt_test *ts, int argc, char *argv[])
{
	return __test_epoll(ts, argc, argv, 0);
}

static int test_epoll_cleanup(struct libmnt_test *ts, int argc, char *argv[])
{
	return __test_epoll(ts, argc, argv, 1);
}

/*
 * create a monitor and wait for a change
 */
static int test_wait(struct libmnt_test *ts, int argc, char *argv[])
{
	const char *filename;
	struct libmnt_monitor *mn = create_test_monitor(argc, argv);

	if (!mn)
		return -1;

	printf("waiting for changes...\n");
	while (mnt_monitor_wait(mn, -1) > 0) {
		printf("notification detected\n");

		while (mnt_monitor_next_change(mn, &filename, NULL) == 0)
			printf(" %s: change detected\n", filename);

	}
	mnt_unref_monitor(mn);
	return 0;
}

/*
 * create a monitor, wait for a change and use data
 */
static int test_data(struct libmnt_test *ts, int argc, char *argv[])
{
	const char *filename;
	struct libmnt_monitor *mn = create_test_monitor(argc, argv);

	if (!mn)
		return -1;

	mnt_monitor_keep_data(mn, MNT_MONITOR_TYPE_USERSPACE, 1);

	printf("waiting for changes...\n");
	while (mnt_monitor_wait(mn, -1) > 0) {
		int type = 0;

		printf("notification detected\n");

		while (mnt_monitor_next_change(mn, &filename, &type) == 0) {
			char *data, *p;
			ssize_t sz;
			size_t chunksz = 0;

			printf(" %s: change detected [type=%d]\n", filename, type);

			switch (type) {

			case MNT_MONITOR_TYPE_KERNEL: /* no data, just  epoll */
				break;

			case MNT_MONITOR_TYPE_KERNELWATCH:  /* watch_notification */
				data = mnt_monitor_event_data(mn, type, &sz);

				/* TODO: add functions to read mount-ID from data
				 *       and hide all "struct watch_notification" there */

				for (p = data; p && p < data + sz;
				     p += sizeof(struct watch_notification) + chunksz) {
					struct watch_notification *n =
							(struct watch_notification *) p;

					printf("  watch event %08x\n", n->info);
					chunksz = n->info & WATCH_INFO_LENGTH;
				}
				break;

			case MNT_MONITOR_TYPE_USERSPACE: /* inotify */
				data = mnt_monitor_event_data(mn, type, &sz);
				for (p = data; p && p < data + sz;
				     p += sizeof(struct inotify_event) + chunksz) {
					struct inotify_event *e =
							(struct inotify_event *) p;

					printf("  inotify event mask=0x%x, name=%s\n",
						e->mask, e->len ? e->name : "");

					chunksz = e->len;
				}
				break;
			}
		}
	}
	mnt_unref_monitor(mn);
	return 0;
}

int main(int argc, char *argv[])
{
	struct libmnt_test tss[] = {
		{ "--epoll", test_epoll, "<userspace kernel ...>  monitor in epoll" },
		{ "--epoll-clean", test_epoll_cleanup, "<userspace kernel ...>  monitor in epoll and clean events" },
		{ "--wait",  test_wait,  "<userspace kernel ...>  monitor wait function" },
		{ "--data",  test_data,  "<userspace kernel ...>  notification kernel data" },
		{ NULL }
	};

	return mnt_run_test(tss, argc, argv);
}

#endif /* TEST_PROGRAM */

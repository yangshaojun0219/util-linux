#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <libmount.h>
#include <ctype.h>
#include <signal.h>

#include "nls.h"
#include "c.h"
#include "bitops.h"
#include "env.h"
#include "strutils.h"
#include "closestream.h"
#include "canonicalize.h"
#include "fileutils.h"

#define XALLOC_EXIT_CODE MNT_EX_SYSERR
#include "xalloc.h"

#define OPTUTILS_EXIT_CODE MNT_EX_USAGE
#include "optutils.h"

#define MOUNTPOINT_FMT		"%05zu"
#define MOUNTPOINT_BUFSZ	sizeof(stringify_value(SIZE_MAX))

enum {
	CMD_MOUNT,
	CMD_UMOUNT,
	CMD_REMOUNT,
	CMD_DELAY,
	CMD_REPEAT
};

static const char *cmdnames[] = {
	[CMD_DELAY] = "delay",
	[CMD_MOUNT] = "mount",
	[CMD_REMOUNT] = "remount",
	[CMD_REPEAT] = "repeat",
	[CMD_UMOUNT] = "umount",
};

enum {
	CMD_TARGET_ALL,		/* default */

	CMD_TARGET_LAST,
	CMD_TARGET_NEXT,
	CMD_TARGET_PREV,
	CMD_TARGET_RAND,
};

static const char *targetnames[] = {
	[CMD_TARGET_ALL] = "all",

	[CMD_TARGET_LAST] = "last",
	[CMD_TARGET_NEXT] = "next",
	[CMD_TARGET_PREV] = "prev",
	[CMD_TARGET_RAND] = "rand",
};

struct bomber_cmd {
	size_t id;	/* CMD_ */
	size_t idx;
	size_t target;	/* CMD_TARGET_ */

	int last_mountpoint;

	char *args;	/* command options specified by user */

	uintmax_t	repeat_max_loops;
	uintmax_t	repeat_max_seconds;
};

struct bomber_worker {
	pid_t pid;
	int status;		/* status as returned by wait() */

	size_t pool_off;	/* first mountpoint */
	size_t pool_len;	/* number of mounpoints assigned to the worker */
	char *pool_status;

	struct timeval starttime;
};

struct bomber_ctl {
	size_t	nmounts;	/* --pool <size> */

	unsigned int freq;	/* number of operations per second */

	const char *dir;	/* --dir <dir> */

	struct bomber_cmd *commands;
	size_t ncommands;

	struct bomber_worker *workers;
	size_t nworkers;
	size_t nactive;

	unsigned int clean_dir : 1,
		     carriage_ret: 1,
		     no_cleanup : 1;
};

static volatile sig_atomic_t sig_die;

static void sig_handler_die(int dummy __attribute__((__unused__)))
{
	sig_die = 1;
}

static inline void mesg_cr_cleanup(struct bomber_ctl *ctl)
{
	if (ctl->carriage_ret)
		fputc('\n', stdout);
	ctl->carriage_ret = 0;
}

static void __attribute__ ((__format__ (__printf__, 2, 3)))
mesg_bar(struct bomber_ctl *ctl, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);

	fflush(stdout);
	fputc('\r', stdout);
	ctl->carriage_ret = 1;
}

static void
mesg_bar_done(struct bomber_ctl *ctl)
{
	mesg_cr_cleanup(ctl);
}

static void __attribute__ ((__format__ (__printf__, 2, 3)))
mesg_warn(struct bomber_ctl *ctl, const char *fmt, ...)
{
	va_list ap;

	mesg_cr_cleanup(ctl);
	va_start(ap, fmt);
	vwarn(fmt, ap);
	va_end(ap);
}

static void __attribute__ ((__format__ (__printf__, 2, 3)))
mesg_warnx(struct bomber_ctl *ctl, const char *fmt, ...)
{
	va_list ap;

	mesg_cr_cleanup(ctl);
	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);
}

static inline char *get_mountpoint_name(size_t i, char *buf, size_t bufsz)
{
	int len = snprintf(buf, bufsz, MOUNTPOINT_FMT, i);

	if (len < 0 || (size_t) len > bufsz)
		return NULL;
	return buf;
}

static int bomber_init_mountdir(struct bomber_ctl *ctl)
{
	int mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	size_t i;
	int rc = 0;

	assert(ctl->dir);

	if (access(ctl->dir, F_OK) != 0) {
		if (mkdir_p(ctl->dir, mode))
			err(EXIT_FAILURE, _("cannot create directory %s"), ctl->dir);
		ctl->clean_dir = 1;
	}

	if (chdir(ctl->dir)) {
		warn(_("cannot access directory %s"), ctl->dir);
		return rc;
	}

	for (i = 0; i < ctl->nmounts; i++) {
		int rc;
		char name[MOUNTPOINT_BUFSZ];

		get_mountpoint_name(i, name, sizeof(name));

		mesg_bar(ctl, _("initialize mountpoint: %05zu"), i + 1);

		rc = mkdir(name, mode);
		if (rc && errno != EEXIST) {
			mesg_warn(ctl, _("cannot create directory %s"), name);
			break;
		}
	}

	mesg_bar_done(ctl);
	return rc;
}

static void bomber_cleanup_dir(struct bomber_ctl *ctl)
{
	size_t i;

	if (!ctl->clean_dir)
		return;

	if (chdir(ctl->dir)) {
		mesg_warn(ctl, _("cannot access directory %s"), ctl->dir);
		return;
	}

	for (i = 0; i < ctl->nmounts; i++) {
		char name[MOUNTPOINT_BUFSZ];

		get_mountpoint_name(i, name, sizeof(name));

		mesg_bar(ctl, _("cleanup mountpoint: %05zu"), i + 1);

		if (rmdir(name)) {
			if (errno == EBUSY) {
				umount(name);
				errno = 0;
				rmdir(name);
			}
			if (errno != ENOENT)
				mesg_warn(ctl, _("connot remove directory %s"), name);
		}
	}

	mesg_bar_done(ctl);

	if (rmdir(ctl->dir) && errno != ENOENT)
		mesg_warn(ctl, _("connot remove directory %s"), ctl->dir);
}

static int last_mountpoint(struct bomber_ctl *ctl, size_t cur)
{
	size_t i;

	for (i = cur - 1; i > 0; i--) {
		if (ctl->commands[i - 1].last_mountpoint != -1)
			return ctl->commands[i - 1].last_mountpoint;
	}

	return -1;
}

static inline int is_mounted(struct bomber_worker *wrk, size_t mnt)
{
	return isset(wrk->pool_status, mnt - wrk->pool_off);
}

static inline int set_mounted(struct bomber_worker *wrk, size_t mnt)
{
	return setbit(wrk->pool_status, mnt - wrk->pool_off);
}

static int do_mount(struct bomber_worker *wrk, struct bomber_cmd *cmd, size_t mnt)
{
	char name[MOUNTPOINT_BUFSZ];
	int rc = 0;

	if (is_mounted(wrk, mnt))
		goto done;

	get_mountpoint_name(mnt, name, sizeof(name));
	rc = mount("tmpfs", name, "tmpfs", 0, NULL);
	if (rc)
		warn("mount failed");
	else
		set_mounted(wrk, mnt);
done:
	if (rc == 0)
		cmd->last_mountpoint = mnt;
	return rc;
}

static int do_umount(struct bomber_worker *wrk, struct bomber_cmd *cmd, size_t mnt)
{
	char name[MOUNTPOINT_BUFSZ];
	int rc = 0;

	if (!is_mounted(wrk, mnt))
		goto done;

	get_mountpoint_name(mnt, name, sizeof(name));
	rc = umount(name);
	if (rc)
		warn("umount failed");
	else
		set_mounted(wrk, mnt);
done:
	if (rc == 0)
		cmd->last_mountpoint = mnt;
	return rc;
}

static int get_mount_idx(struct bomber_ctl *ctl, struct bomber_worker *wrk, struct bomber_cmd *cmd)
{
	int mnt = -1;
	int lo = wrk->pool_off;
	int up = wrk->pool_off + wrk->pool_len - 1;

	switch (cmd->target) {
	case CMD_TARGET_RAND:
		mnt = (rand() % (up - lo + 1)) + lo;
		break;
	case CMD_TARGET_LAST:
		mnt = last_mountpoint(ctl, cmd->idx);
		if (mnt < 0)
			return 0;
		break;
	case CMD_TARGET_NEXT:
		mnt = last_mountpoint(ctl, cmd->idx) + 1;
		if (mnt < 0)
			return 0;
		if (mnt > up)
			mnt = lo;
		break;
	case CMD_TARGET_PREV:
		mnt = last_mountpoint(ctl, cmd->idx) - 1;
		if (mnt < 0)
			return 0;
		if (mnt < lo)
			mnt = up;
		break;
	default:
		mnt = -1;
		break;
	}

	return mnt;
}

static int cmd_mount(struct bomber_ctl *ctl, struct bomber_worker *wrk, struct bomber_cmd *cmd)
{
	int rc = 0;
	int mnt = get_mount_idx(ctl, wrk, cmd);

	if (mnt >= 0)
		rc = do_mount(wrk, cmd, mnt);

	else if (cmd->target == CMD_TARGET_ALL) {
		int lo = wrk->pool_off;
		int up = wrk->pool_off + wrk->pool_len - 1;

		for (mnt = lo; mnt <= up; mnt++) {
			rc += do_mount(wrk, cmd, mnt);
		}
	}

	return rc;
}

static int cmd_umount(struct bomber_ctl *ctl, struct bomber_worker *wrk, struct bomber_cmd *cmd)
{
	int rc = 0;
	int mnt = get_mount_idx(ctl, wrk, cmd);

	if (mnt >= 0)
		rc = do_umount(wrk, cmd, mnt);

	else if (cmd->target == CMD_TARGET_ALL) {
		int lo = wrk->pool_off;
		int up = wrk->pool_off + wrk->pool_len - 1;

		for (mnt = lo; mnt <= up; mnt++) {
			rc += do_umount(wrk, cmd, mnt);
		}
	}

	return rc;
}

static pid_t start_worker(struct bomber_ctl *ctl, struct bomber_worker *wrk)
{
	pid_t pid;
	size_t i;
	int rc = 0;

	switch ((pid = fork())) {
	case -1:
		warn(_("fork failed"));
		return -errno;
	case 0: /* child */
		break;
	default: /* parent */
		return pid;
	}

	/* init */
	wrk->pool_status = xcalloc(wrk->pool_len / NBBY + 1, sizeof(char));

	/* child main loop */
	for (i = 0; sig_die == 0 && i < ctl->ncommands; i++) {
		struct bomber_cmd *cmd = &ctl->commands[i];

		switch (cmd->id) {
		case CMD_MOUNT:
			rc = cmd_mount(ctl, wrk, cmd);
			break;
		case CMD_UMOUNT:
			rc = cmd_umount(ctl, wrk, cmd);
			break;
		case CMD_REMOUNT:
			break;
		case CMD_DELAY:
			break;
		case CMD_REPEAT:
			break;
		default:
			rc = -EINVAL;
			break;
		}
		if (rc)
			break;
	}

	if (rc)
		err(EXIT_FAILURE, _("worker %d: failed"), getpid());

	exit(EXIT_SUCCESS);
}

static int bomber_init_pool(struct bomber_ctl *ctl)
{
	size_t i, off = 0, len;

	assert(ctl);

	len = ctl->nmounts / ctl->nworkers;

	ctl->workers = xcalloc(ctl->nworkers, sizeof(struct bomber_worker));

	for (i = 0; i < ctl->nworkers; i++) {
		struct bomber_worker *w = &ctl->workers[i];

		w->pool_off = off;
		w->pool_len = len;
		w->pid = start_worker(ctl, w);
		if (w->pid <= 0)
			return w->pid;
		off += len;
		ctl->nactive++;

		mesg_bar(ctl, _("starting worker: %04zu"), i + 1);
	}

	mesg_bar_done(ctl);
	return 0;
}

static void unlink_child(struct bomber_ctl *ctl, pid_t pid, int status)
{
	size_t i;

	for (i = 0; i < ctl->nworkers; i++) {
		struct bomber_worker *w = &ctl->workers[i];

		if (w->pid == pid) {
			w->pid = 0;
			w->status = status;
			ctl->nactive--;
			break;
		}
	}
}

static int bomber_wait_pool(struct bomber_ctl *ctl, int flags)
{
	while (ctl->nactive > 0) {
		int status = 0;
		pid_t pid;

		mesg_bar(ctl, _("active workers ... %04zu (waiting)"), ctl->nactive);

		pid = waitpid(-1, &status, flags);
		if (pid == 0 && (flags & WNOHANG))
			return 0;
		if (pid < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			if (errno == ECHILD)
				break;
			mesg_warn(ctl, _("waitpid failed"));
			continue;
		}
		if (WIFEXITED(status) || WIFSIGNALED(status))
			unlink_child(ctl, pid, status);
	}

	mesg_bar(ctl, _("active workers ... %04zu"), ctl->nactive);
	mesg_bar_done(ctl);

	return 1;	/* no more childs */
}

static int bomber_cleanup_pool(struct bomber_ctl *ctl)
{
	size_t i;

	for (i = 0; i < ctl->nworkers; i++) {
		struct bomber_worker *w = &ctl->workers[i];
		if (w->pid > 0)
			kill(w->pid, SIGTERM);
	}

	bomber_wait_pool(ctl, 0);

	return 0;
}

static int parse_command_args(struct bomber_ctl *ctl, struct bomber_cmd *cmd)
{
	assert(ctl);
	assert(cmd);
	assert(cmd->args);

	switch (cmd->id) {
	case CMD_REPEAT:
		if (isdigit_string(cmd->args))
			cmd->repeat_max_loops = strtou64_or_err(cmd->args,
						_("repeat(): failed to parse arguments"));
		else if (mnt_optstr_get_uint(cmd->args,
					"loops", &cmd->repeat_max_loops) == 0)
			;
		else if (mnt_optstr_get_uint(cmd->args,
					"seconds", &cmd->repeat_max_seconds) == 0)
			;
		else
			errx(EXIT_FAILURE, _("repeat(): failed to parse arguments"));
		break;
	default:
		break;
	}

	return 0;
}

static inline size_t name2idx(const char *name, const char **ary, size_t arysz, const char *errmsg)
{
	size_t i;

	for (i = 0; i < arysz; i++) {
		if (strcmp(name, ary[i]) == 0)
			return i;
	}

	errx(EXIT_FAILURE, errmsg, name);
	return 0;
}

static int bomber_add_command(struct bomber_ctl *ctl, const char *str)
{
	char *cmdstr = xstrdup(str);
	char *xstr = cmdstr;

	while (xstr && *xstr) {
		struct bomber_cmd *cmd;
		char *name, *end, *args = NULL, *target = NULL;

		ctl->commands = xrealloc(ctl->commands,
					(ctl->ncommands + 1) * sizeof(struct bomber_cmd));

		cmd = &ctl->commands[ctl->ncommands];
		memset(cmd, 0, sizeof(*cmd));

		cmd->idx = ctl->ncommands;
		cmd->last_mountpoint = -1;
		ctl->ncommands++;

		name = xstr;
		end = (char *) skip_alnum(xstr);

		/* name terminator */
		switch (*end) {
		case '(':
			args = end + 1;
			break;
		case ':':
			target = end + 1;
			break;
		case ',':
		case '\0':
			break;
		default:
			errx(EXIT_FAILURE, _("failed to parse command name '%s'"), name);
			break;
		}

		xstr = *end ? end + 1 : end;
		*end = '\0';
		cmd->id = name2idx(name, cmdnames, ARRAY_SIZE(cmdnames),
					_("unknown command name '%s'"));
		if (args) {
			end = strchr(args, ')');
			if (!end)
				errx(EXIT_FAILURE, _("missing terminating ')' in '%s'"), args);
			*end = '\0';
			cmd->args = xstrdup(args);
			xstr = end + 1;

			if (*xstr == ':')
				target = xstr + 1;

			parse_command_args(ctl, cmd);
		}

		if (target) {
			end = (char *) skip_alnum(target);
			xstr = *end ? end + 1 : end;
			*end = '\0';
			cmd->target = name2idx(target, targetnames,
						ARRAY_SIZE(targetnames),
						_("unknown command target '%s'"));
		}
	}

	free(cmdstr);
	return 0;
}

int main(int argc, char *argv[])
{
	struct bomber_ctl _ctl = {
		.nmounts = 100
	}, *ctl = &_ctl;
	struct sigaction sa;
	int rc = 0, c;
	static const struct option longopts[] = {
		{ "pool",       required_argument, NULL, 'p' },
		{ "parallel",   required_argument, NULL, 'x' },
		{ "freq",       required_argument, NULL, 'f' },
		{ "dir",	required_argument, NULL, 'd' },
		{ "oper",       required_argument, NULL, 'O' },
		{ "no-cleanup", optional_argument, NULL, 'N' },
		{ NULL, 0, NULL, 0 }
	};

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	close_stdout_atexit();

	while ((c = getopt_long(argc, argv, "p:x:f:d:O:N", longopts, NULL)) != -1) {

		switch(c) {
		case 'p':
			ctl->nmounts = strtou32_or_err(optarg, _("failed to parse pool argument"));
			break;
		case 'x':
			ctl->nworkers = strtou32_or_err(optarg, _("failed to parse parallel argument"));
			break;
		case 'f':
			ctl->freq = strtou32_or_err(optarg, _("failed to parse freq argument"));
			break;
		case 'd':
			ctl->dir = xstrdup(optarg);
			break;
		case 'O':
			bomber_add_command(ctl, optarg);
			break;
		case 'N':
			ctl->no_cleanup = 1;
			break;
		}
	}

	mnt_init_debug(0);

	if (!ctl->nmounts)
		errx(EXIT_FAILURE, _("pool size cannot be zero"));
	if (!ctl->dir)
		ctl->dir = xstrdup("/mnt/bomber");
	if (!ctl->nworkers)
		ctl->nworkers = ctl->nmounts > 10 ? ctl->nmounts / 10 : ctl->nmounts;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = sig_handler_die;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	rc = bomber_init_mountdir(ctl);
	if (rc == 0)
		rc = bomber_init_pool(ctl);
	if (rc == 0)
		bomber_wait_pool(ctl, 0);
	if (sig_die)
		mesg_warnx(ctl, _("interrupted by signal"));

	bomber_cleanup_pool(ctl);

	if (!ctl->no_cleanup)
		bomber_cleanup_dir(ctl);

	return EXIT_SUCCESS;
}

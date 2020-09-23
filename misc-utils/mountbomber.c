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
#include <sys/time.h>
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
#include "monotonic.h"

#define XALLOC_EXIT_CODE MNT_EX_SYSERR
#include "xalloc.h"

#define OPTUTILS_EXIT_CODE MNT_EX_USAGE
#include "optutils.h"

#define MOUNTPOINT_FMT		"%05zu"
#define MOUNTPOINT_BUFSZ	sizeof(stringify_value(SIZE_MAX))

enum {
	CMD_DELAY,
	CMD_LABEL,
	CMD_MOUNT,
	CMD_REMOUNT,
	CMD_REPEAT,
	CMD_UMOUNT,
};

static const char *cmdnames[] = {
	[CMD_DELAY] = "delay",
	[CMD_LABEL] = "label",
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

	CMD_TARGET_NONE,
};

static const char *targetnames[] = {
	[CMD_TARGET_ALL] = "all",

	[CMD_TARGET_LAST] = "last",
	[CMD_TARGET_NEXT] = "next",
	[CMD_TARGET_PREV] = "prev",
	[CMD_TARGET_RAND] = "rand",

	[CMD_TARGET_NONE] = "none",
};

struct bomber_cmd {
	size_t id;	/* CMD_ */
	size_t idx;
	size_t target;	/* CMD_TARGET_ */

	char *args;	/* command options specified by user */

	uintmax_t	repeat_max_loops;
	time_t		repeat_max_seconds;
	size_t		repeat_nloops;
	char		*repeat_label;
	suseconds_t	delay_usec;
};

struct bomber_worker {
	pid_t pid;
	int status;		/* status as returned by wait() */

	size_t pool_off;	/* first mountpoint */
	size_t pool_len;	/* number of mounpoints assigned to the worker */
	char *pool_status;

	struct timeval	starttime;
	int last_mountpoint;
};

struct bomber_ctl {
	size_t	nmounts;	/* --pool <size> */

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
static int verbose;

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

static void __attribute__ ((__format__ (__printf__, 1, 2)))
mesg_verbose(const char *fmt, ...)
{
	va_list ap;

	if (!verbose)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
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
		}
	}

	mesg_bar_done(ctl);

	if (rmdir(ctl->dir) && errno != ENOENT)
		mesg_warn(ctl, _("connot remove directory %s"), ctl->dir);
}

static inline int is_mounted(struct bomber_worker *wrk, size_t mnt)
{
	return isset(wrk->pool_status, mnt - wrk->pool_off);
}

static inline int set_mounted(struct bomber_worker *wrk, size_t mnt)
{
	return setbit(wrk->pool_status, mnt - wrk->pool_off);
}

static inline int set_umounted(struct bomber_worker *wrk, size_t mnt)
{
	return clrbit(wrk->pool_status, mnt - wrk->pool_off);
}

static int do_mount(struct bomber_worker *wrk, struct bomber_cmd *cmd, size_t mnt)
{
	char name[MOUNTPOINT_BUFSZ];
	int rc = 0;

	assert(wrk);
	assert(cmd);

	if (is_mounted(wrk, mnt)) {
		mesg_verbose("  ignore target %ju (mounted)", mnt);
		goto done;
	}
	get_mountpoint_name(mnt, name, sizeof(name));
	rc = mount("tmpfs", name, "tmpfs", 0, NULL);
	if (rc)
		warn("mount failed");
	else
		set_mounted(wrk, mnt);
done:
	if (rc == 0)
		wrk->last_mountpoint = mnt;
	return rc;
}

static int do_umount(struct bomber_worker *wrk, struct bomber_cmd *cmd, size_t mnt)
{
	char name[MOUNTPOINT_BUFSZ];
	int rc = 0;

	assert(wrk);
	assert(cmd);

	if (!is_mounted(wrk, mnt)) {
		mesg_verbose("  ignore target %ju (not mounted)", mnt);
		goto done;
	}
	get_mountpoint_name(mnt, name, sizeof(name));
	rc = umount(name);
	if (rc)
		warn("umount failed");
	else
		set_umounted(wrk, mnt);
done:
	if (rc == 0)
		wrk->last_mountpoint = mnt;
	return rc;
}

static int get_mount_idx(struct bomber_worker *wrk, struct bomber_cmd *cmd)
{
	int mnt = -1;
	int lo = wrk->pool_off;
	int up = wrk->pool_off + wrk->pool_len - 1;

	switch (cmd->target) {
	case CMD_TARGET_RAND:
		mnt = (rand() % (up - lo + 1)) + lo;
		break;
	case CMD_TARGET_LAST:
		mnt = wrk->last_mountpoint;
		if (mnt < 0)
			mnt = 0;
		break;
	case CMD_TARGET_NEXT:
		mnt = wrk->last_mountpoint + 1;
		if (mnt < 0)
			mnt = 0;
		if (mnt > up)
			mnt = lo;
		break;
	case CMD_TARGET_PREV:
		mnt = wrk->last_mountpoint - 1;
		if (mnt < 0)
			mnt = 0;
		if (mnt < lo)
			mnt = up;
		break;

	case CMD_TARGET_ALL:
		mesg_verbose("  target: all");
		break;
	}

	if (mnt >= 0)
		mesg_verbose("  target: %d", mnt);
	return mnt;
}

static int cmd_mount(struct bomber_ctl *ctl, struct bomber_worker *wrk, struct bomber_cmd *cmd)
{
	int rc = 0;
	int mnt;

	assert(ctl);
	assert(wrk);
	assert(cmd);

	mnt = get_mount_idx(wrk, cmd);
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
	int mnt;

	assert(ctl);
	assert(wrk);
	assert(cmd);

	mnt = get_mount_idx(wrk, cmd);
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

static int cmd_repeat(struct bomber_ctl *ctl, struct bomber_worker *wrk,
		      struct bomber_cmd *cmd, size_t *idx)
{
	size_t idx0 = *idx;

	if (cmd->repeat_max_seconds) {
		struct timeval rest, now;

		gettime_monotonic(&now);
		timersub(&now, &wrk->starttime, &rest);

		if (rest.tv_sec < cmd->repeat_max_seconds)
			goto repeat;
	} else if (cmd->repeat_max_loops) {

		if (cmd->repeat_nloops < cmd->repeat_max_loops) {
			cmd->repeat_nloops++;
			goto repeat;
		}
		cmd->repeat_nloops = 0;
	}

	return 0;
repeat:
	if (cmd->repeat_label) {
		size_t i;

		for (i = *idx; i > 0; i--) {
			struct bomber_cmd *xc = &ctl->commands[i - 1];
			if (xc->id == CMD_LABEL &&
			    xc->args && strcmp(xc->args, cmd->repeat_label) == 0) {
				*idx = i - 1;
				break;
			}
		}
	} else
		*idx = 0;

	mesg_verbose("  repeating %zu --> %zu", *idx, idx0);
	return 0;
}

static int cmd_delay(struct bomber_cmd *cmd)
{
	xusleep(cmd->delay_usec);
	return 0;
}

static pid_t start_worker(struct bomber_ctl *ctl, struct bomber_worker *wrk)
{
	pid_t pid;
	size_t i = 0;
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

	gettime_monotonic(&wrk->starttime);

	/* init */
	wrk->pool_status = xcalloc(wrk->pool_len / NBBY + 1, sizeof(char));

	/* child main loop */
	while (sig_die == 0) {
		struct bomber_cmd *cmd;
		size_t idx = i;

		if (i >= ctl->ncommands)
			break;

		cmd = &ctl->commands[idx];

		if (cmd->target != CMD_TARGET_NONE)
			mesg_verbose("COMMAND[%zu] %s:%s", idx,
				cmdnames[cmd->id],
				targetnames[cmd->target]);
		else
			mesg_verbose("COMMAND[%zu] %s", idx, cmdnames[cmd->id]);

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
			rc = cmd_delay(cmd);
			break;
		case CMD_REPEAT:
			rc = cmd_repeat(ctl, wrk, cmd, &idx);
			break;
		case CMD_LABEL:
			break;
		default:
			rc = -EINVAL;
			break;
		}
		if (rc)
			break;

		if (idx == i)
			i++;
		else
			i = idx; /* modified by function (e.g. CMD_REPEAT) */
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

		mesg_bar(ctl, _("active workers ... %04zu (waiting)"), ctl->nactive);
	}

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
	uintmax_t x;
	char *opt;
	size_t optsz;

	assert(ctl);
	assert(cmd);
	assert(cmd->args);

	switch (cmd->id) {
	case CMD_REPEAT:
		/* unnamed argument */
		if (isdigit_string(cmd->args)) {
			cmd->repeat_max_loops = strtou64_or_err(cmd->args,
						_("repeat(): failed to parse arguments"));
			break;
		}
		/* named arguments */
		if (mnt_optstr_get_uint(cmd->args, "loops", &cmd->repeat_max_loops) == 0) {
			;
		}
		if (mnt_optstr_get_uint(cmd->args, "seconds", &x) == 0)
			cmd->repeat_max_seconds = (time_t) x;
		if (mnt_optstr_get_option(cmd->args, "label", &opt, &optsz) == 0 && optsz)
			cmd->repeat_label = xstrndup(opt, optsz);
		break;
	case CMD_DELAY:
		if (isdigit_string(cmd->args)) {
			cmd->delay_usec = strtou64_or_err(cmd->args,
					_("delay(): failed to parse arguments"));
			break;
		}
		errx(EXIT_FAILURE, _("delay(): failed to parse arguments"));
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
		ctl->ncommands++;

		name = xstr;
		if (*xstr == '@')
			xstr++;
		else if (startswith(name, "->"))
			xstr += 2;

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

		if (*name == '@') {
			cmd->id = CMD_LABEL;
			cmd->args = xstrdup(name + 1);
		} else if (startswith(name, "->")) {
			cmd->id = CMD_REPEAT;
			cmd->repeat_label = xstrdup(name + 2);
		} else
			cmd->id = name2idx(name, cmdnames, ARRAY_SIZE(cmdnames),
					_("unknown command name '%s'"));
		if (args) {
			end = strchr(args, ')');
			if (!end)
				errx(EXIT_FAILURE, _("missing terminating ')' in '%s'"), args);
			*end = '\0';
			if (!cmd->args)
				cmd->args = xstrdup(args);
			xstr = end + 1;

			if (*xstr == ':')
				target = xstr + 1;
			else if (*xstr == ',')
				xstr++;

			parse_command_args(ctl, cmd);
		}

		if (target) {
			end = (char *) skip_alnum(target);
			xstr = *end ? end + 1 : end;
			*end = '\0';
			cmd->target = name2idx(target, targetnames,
						ARRAY_SIZE(targetnames),
						_("unknown command target '%s'"));
		} else switch (cmd->id) {
			case CMD_REPEAT:
			case CMD_LABEL:
			case CMD_DELAY:
				cmd->target = CMD_TARGET_NONE;
				break;
		}
	}

	if (verbose) {
		size_t i;

		mesg_verbose("parsed commands:");
		for (i = 0; i < ctl->ncommands; i++) {
			struct bomber_cmd *cmd = &ctl->commands[i];

			mesg_verbose("[%zu]  %10s : target=%-7s args=\"%s\"",
					i,
					cmdnames[cmd->id],
					targetnames[cmd->target],
					cmd->args ? : "");
		}
	}


	free(cmdstr);
	return 0;
}

static void __attribute__((__noreturn__)) usage(void)
{
	FILE *out = stdout;

	fputs(USAGE_HEADER, out);
	fprintf(out, _(" %s [options]\n"), program_invocation_short_name);

	fputs(USAGE_SEPARATOR, out);
	fputs(_("Generate large number of mount operations.\n"), out);

	fputs(USAGE_OPTIONS, out);
	fputs(_(" -p, --pool <num>       number of the mountpoints (default: 100)\n"), out);
	fputs(_(" -x, --parallel <num>   number of the parallel processes (default: 10 or 1)\n"), out);
	fputs(_(" -d, --dir <path>       directory for mountpoints (default: /mnt/bomber)\n"), out);
	fputs(_(" -O, --oper <list>      requested mount operations\n"), out);
	fputs(_(" -N, --no-cleanup       don't remove mountpoints\n"), out);
	fputs(_(" -V, --verbose          verbose output\n"), out);
	printf(USAGE_HELP_OPTIONS(24));

	fputs(USAGE_SEPARATOR, out);
	fputs(_("Operation syntax (--oper):\n"), out);
	fputs(_("  command[(arg, ...)[:target]], ...\n"), out);
	fputs(_("  @name specifies label and ->name repeats all from label \n"), out);
	fputs(_("   * ->name loop may be restricted by <num>, loops=<num> or seconds=<num>\n"), out);
	fputs(_("   * for example repeat 100 times command foo: @A,foo,->A(100)\n"), out);
	fputs(_("   * or repeat command foo for 3600 seconds: @A,foo,->A(seconds=3600)\n"), out);

	fputs(USAGE_SEPARATOR, out);
	fputs(_("Operation commands:\n"), out);
	fputs(_("   mount          call mount(2) syscall\n"), out);
	fputs(_("   umount         call umount(2) syscall\n"), out);
	fputs(_("   delay(<num>)   wait for <num> microseconds\n"), out);

	fputs(USAGE_SEPARATOR, out);
	fputs(_("Operation targets:\n"), out);
	fputs(_("   all            all mountpoints in the pool\n"), out);
	fputs(_("   rand           random mountpoint from pool\n"), out);
	fputs(_("   last           previously used mountpoint\n"), out);
	fputs(_("   next           <last>+1\n"), out);
	fputs(_("   prev           <last>-1\n"), out);
	fputs(USAGE_SEPARATOR, out);
	fputs(_("Examples:\n"), out);
	fputs(_("  mountbomber --pool 200 --oper \"mount:all,@A,umount:rand,mount:last,->A(1000),umount:all\"\n"), out);
	fputs(_("   * mount 200 mountpoints\n"), out);
	fputs(_("   * 1000 times call umount and mount on random mountpoint\n"), out);
	fputs(_("   * after that umount all\n"), out);
	fputs(_("  mountbomber --verbose --parallel 1 --oper \"mount:all,@A,umount:rand,mount:last,delay(500000),->A(10),umount:all\"\n"), out);
	fputs(_("   * user and system friendly way to develop your testing scenario\n"), out);

	fputs(USAGE_SEPARATOR, out);
	fputs(_("Notes:\n"), out);
	fputs(_("  The pool is split by number of paraller processes and the process uses\n"
		"  only a subset of the pool. For example \"--paralell 10 --pool 1000\"\n"
	        "  means 100 mountpoints for the each process.\n"), out);



	fputs(USAGE_SEPARATOR, out);
	exit(EXIT_SUCCESS);
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
		{ "dir",	required_argument, NULL, 'd' },
		{ "oper",       required_argument, NULL, 'O' },
		{ "no-cleanup", no_argument,       NULL, 'N' },
		{ "verbose",    no_argument,       NULL, 'V' },
		{ "version",    no_argument,       NULL, 'v' },
		{ "help",       no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	close_stdout_atexit();

	while ((c = getopt_long(argc, argv, "hp:x:f:d:O:NVv", longopts, NULL)) != -1) {

		switch(c) {
		case 'p':
			ctl->nmounts = strtou32_or_err(optarg, _("failed to parse pool argument"));
			break;
		case 'x':
			ctl->nworkers = strtou32_or_err(optarg, _("failed to parse parallel argument"));
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
		case 'V':
			verbose = 1;
			break;

		case 'h':
			usage();
		case 'v':
			print_version(EXIT_SUCCESS);
		default:
			errtryhelp(EXIT_FAILURE);
		}
	}

	mnt_init_debug(0);

	if (!ctl->nmounts)
		errx(EXIT_FAILURE, _("pool size cannot be zero"));
	if (!ctl->dir)
		ctl->dir = xstrdup("/mnt/bomber");
	if (!ctl->nworkers)
		ctl->nworkers = ctl->nmounts > 10 ? 10 : 1;

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

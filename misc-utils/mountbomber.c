#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <libmount.h>
#include <ctype.h>
#include <signal.h>

#include "nls.h"
#include "c.h"
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
	BOMBER_OPER_NONE = 0,
	BOMBER_OPER_MOUNT,
	BOMBER_OPER_UMOUNT,
	BOMBER_OPER_REMOUNT
};

struct bomber_oper {
	int	type;	/* BOMBER_OPER_ */

	struct libmnt_fs *fs;
};

struct bomber_ctl {
	size_t	nmounts;	/* --pool <size> */
	size_t	nparallels;	/* --parallel <number> */

	unsigned int freq;	/* number of operations per second */

	const char *dir;	/* --dir <dir> */

	struct bomber_oper	*opers;
	size_t			nopers;

	unsigned int clean_dir : 1,
		     carriage_ret: 1,
		     mesg_section : 1;
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

static void __attribute__ ((__format__ (__printf__, 2, 3)))
mesg_start(struct bomber_ctl *ctl, const char *fmt, ...)
{
	va_list ap;

	mesg_cr_cleanup(ctl);

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fputs(" ... ", stdout);

	ctl->mesg_section = 1;
}

static void
mesg_done(struct bomber_ctl *ctl)
{
	mesg_cr_cleanup(ctl);
	fputs(_("done\n"), stdout);
	ctl->mesg_section = 0;
}

static void __attribute__ ((__format__ (__printf__, 2, 3)))
mesg_warn(struct bomber_ctl *ctl, const char *fmt, ...)
{
	va_list ap;

	mesg_cr_cleanup(ctl);
	if (ctl->mesg_section)
		fputs("   ", stdout);

	va_start(ap, fmt);
	vwarn(fmt, ap);
	va_end(ap);
}

static void __attribute__ ((__format__ (__printf__, 2, 3)))
mesg_warnx(struct bomber_ctl *ctl, const char *fmt, ...)
{
	va_list ap;

	mesg_cr_cleanup(ctl);
	if (ctl->mesg_section)
		fputs("   ", stdout);

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

	mesg_start(ctl, _("Initialize mount directories"));

	for (i = 0; i < ctl->nmounts; i++) {
		int rc;
		char name[MOUNTPOINT_BUFSZ];

		get_mountpoint_name(i, name, sizeof(name));

		rc = mkdir(name, mode);
		if (rc && errno != EEXIST) {
			mesg_warn(ctl, _("cannot create directory %s"), name);
			break;
		}
	}

	mesg_done(ctl);
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

	mesg_start(ctl, _("Cleaning mount directories"));

	for (i = 0; i < ctl->nmounts; i++) {
		char name[MOUNTPOINT_BUFSZ];

		get_mountpoint_name(i, name, sizeof(name));

		if (rmdir(name) && errno != ENOENT)
			mesg_warn(ctl, _("connot remove directory %s"), name);
	}

	if (rmdir(ctl->dir) && errno != ENOENT)
		mesg_warn(ctl, _("connot remove directory %s"), ctl->dir);

	mesg_done(ctl);
}

static int bomber_init_pool(struct bomber_ctl *ctl)
{
	assert(ctl);

	return 0;
}

static int bomber_get_status(struct bomber_ctl *ctl, size_t *done, size_t *active)
{
	assert(ctl);
	assert(done);
	assert(active);

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
		{ "operation",  required_argument, NULL, 'O' },
		{ NULL, 0, NULL, 0 }
	};

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	close_stdout_atexit();

	while ((c = getopt_long(argc, argv, "p:x:f:d:O", longopts, NULL)) != -1) {

		switch(c) {
		case 'p':
			ctl->nmounts = strtou32_or_err(optarg, _("failed to parse pool argument"));
			break;
		case 'x':
			ctl->nparallels = strtou32_or_err(optarg, _("failed to parse parallel argument"));
			break;
		case 'f':
			ctl->freq = strtou32_or_err(optarg, _("failed to parse freq argument"));
			break;
		case 'd':
			ctl->dir = xstrdup(optarg);
			break;
		case 'O':
			break;
		}
	}

	mnt_init_debug(0);

	if (!ctl->nmounts)
		errx(EXIT_FAILURE, _("pool size cannot be zero"));
	if (!ctl->dir)
		ctl->dir = xstrdup("/mnt/bomber");
	if (!ctl->nparallels)
		ctl->nparallels = ctl->nmounts / 10;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = sig_handler_die;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	rc = bomber_init_mountdir(ctl);
	if (rc == 0)
		bomber_init_pool(ctl);

	while  (rc == 0 && sig_die == 0) {
		size_t done = 0, active = 0;

		rc = bomber_get_status(ctl, &done, &active);
		if (rc || sig_die)
			continue;

		mesg_bar(ctl, _("active: %zu, all: %zu, done: %zu"), active, ctl->nmounts, done);
		if (!sig_die)
			xusleep(250000);
	}

	if (sig_die)
		mesg_warnx(ctl, _("interrupted by signal"));

	bomber_cleanup_dir(ctl);

	return EXIT_SUCCESS;
}

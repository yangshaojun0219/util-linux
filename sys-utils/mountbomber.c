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

#include "nls.h"
#include "c.h"
#include "env.h"
#include "strutils.h"
#include "closestream.h"
#include "canonicalize.h"

#define XALLOC_EXIT_CODE MNT_EX_SYSERR
#include "xalloc.h"

#define OPTUTILS_EXIT_CODE MNT_EX_USAGE
#include "optutils.h"

enum {
	BOMBER_OPER_NONE = 0,
	BOMBER_OPER_MOUNT,
	BOMBER_OPER_UMOUNT,
	BOMBER_OPER_REMOUNT
};

enum {
	BOMBER_FILL_SEQUEN,
	BOMBER_FILL_PARALLEL
};

struct bomber_oper {
	int	type;	/* BOMBER_OPER_ */

	struct libmnt_fs *fs;
};

struct bomber_ctl {
	size_t	nmounts;	/* --pool <size> */
	size_t	nparallels;	/* --parallel <number> */

	unsigned int freq;	/* number of operations per second */

	int	fillmode;	/* BOMBER_FILL_* --poll-fill-mode <mode> */

	const char *dir;	/* --dir <dir> */

	size_t	duration;	/* --duration <sec> */
	size_t postpone;	/* --postpone <sec> */

	struct bomber_oper	*opers;
	size_t			nopers;

	unsigned int	touch : 1,	/* open(O_CREAT) on mounted FS */
			readdir : 1;	/* readdir() on mounted FS */
};

int main(int argc, char *argv[])
{
	struct bomber_ctl _ctl, *ctl = &_ctl;
	static const struct option longopts[] = {
		{ "pool",       required_argument, NULL, 'p' },
		{ "parallel",   required_argument, NULL, 'x' },
		{ "freq",       required_argument, NULL, 'f' },
		{ "fillmode",   required_argument, NULL, 'm' },
		{ "dir",	required_argument, NULL, 'd' },
		{ "duration",   required_argument, NULL, 'D' },
		{ "postpone",   required_argument, NULL, 'P' },
		{ "operation",  required_argument, NULL, 'O' },
		{ "readdir",    no_argument,	   NULL, 'r' },
		{ "touch",      no_argument,       NULL, 't' },
		{ NULL, 0, NULL, 0 }
	};

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	close_stdout_atexit();

	while ((c = getopt_long(argc, argv, "p:x:f:m:d:D:P:O:rt", longopts, NULL)) != -1) {

		switch(c) {
		case 'p':
			cxt->nmounts = strtou32_or_err(oprarg, _("failed to parse pool argument"));
			break;
		case 'x':
			cxt->nparallels = strtou32_or_err(oprarg, _("failed to parse parallel argument"));
			break;
		case 'f':
			cxt->freq = strtou32_or_err(oprarg, _("failed to parse freq argument"));
			break;
		case 'm':
			if (strcmp(oprarg, "parallel") == 0)
				cxt->fillmode = BOMBER_FILL_PARALLEL;
			else if (strcmp(oprarg, "sequential") == 0)
				cxt->fillmode = BOMBER_FILL_SEQUEN;
			else
				errx(EXIT_FAILURE, _("unknown fill mode: %s", optarg));
			break;
		case 'd':
			cxt->dir = xtrsdup(optarg);
			break;
		case 'D':
			cxt->duration = strtou32_or_err(oprarg, _("failed to parse duration argument"));
			break;
		case 'P':
			cxt->postpone = strtou32_or_err(oprarg, _("failed to parse postpone argument"));
			break;
		case 'O':
			break;
		case 'r':
			cxt->readdir = 1;
			break;
		case 't':
			cxt->touch = 1;
			break;
		}
	}

	mnt_init_debug(0);

	return EXIT_SUCCESS;
}

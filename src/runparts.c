#include <ctype.h>		/* isdigit() */
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#ifdef _LIBITE_LITE
# include <libite/conio.h>
# include <libite/lite.h>
#else
# include <lite/conio.h>
# include <lite/lite.h>
#endif

#include "log.h"
#include "sig.h"
#include "util.h"

#ifdef __FINIT__
#include "helpers.h"
#else
#include <sys/prctl.h>

const char *active_msg = NULL;
int interactive = 1;
int debug;

static void print_desc(const char *prefix, const char *msg)
{
	if (interactive)
		fprintf(stderr, "\e[1m[\e[0m\e[1;33m ⋯  \e[0m\e[1m]\e[0m %s %s", prefix, msg);
	else
		fprintf(stderr, "%s %s ...\n", prefix, msg);
	active_msg = msg;
}
static void print_result(int rc)
{
	if (interactive) {
		if (rc)
			fputs("\r\e[1m[\e[0m\e[1;31mFAIL\e[0m\e[1m]\e[0m\n", stderr);
		else
			fputs("\r\e[1m[\e[0m\e[1;32m OK \e[0m\e[1m]\e[0m\n", stderr);
	} else
		fprintf(stderr, "[%s]  %s\n", rc ? "FAIL" : " OK ", active_msg ?: "");
}

void sig_unblock(void)
{
	struct sigaction sa;
	sigset_t nmask;
	int i;

	sigemptyset(&nmask);
	sigaddset(&nmask, SIGHUP);
	sigaddset(&nmask, SIGCHLD);
	sigaddset(&nmask, SIGINT);
	sigaddset(&nmask, SIGPWR);
	sigaddset(&nmask, SIGSTOP);
	sigaddset(&nmask, SIGTSTP);
	sigaddset(&nmask, SIGCONT);
	sigaddset(&nmask, SIGTERM);
	sigaddset(&nmask, SIGUSR1);
	sigaddset(&nmask, SIGUSR2);
	sigprocmask(SIG_UNBLOCK, &nmask, NULL);

	/* Reset signal handlers that were set by the parent process */
	for (i = 1; i < NSIG; i++)
		DFLSIG(sa, i, 0);
}
#endif /* __FINIT__ */

static void run_env(const char *env[])
{
	size_t i = 0;

	if (!env)
		return;

	while (env[i]) {
		size_t j = i + 1;

		if (!env[j])
			break;

		setenv(env[i], env[j], 1);
		i += 2;
	}
}

int run_parts(char *dir, char *cmd, const char *env[], int progress, int sysv)
{
	size_t cmdlen = cmd ? strlen(cmd) : strlen("start");
	struct dirent **d = NULL;
	int i, num;
	int rc = 0;

	num = scandir(dir, &d, NULL, alphasort);
	if (num < 0) {
		dbg("No files found in %s, skipping ...", dir);
		return -1;
	}

	for (i = 0; i < num; i++) {
		char path[strlen(dir) + strlen(d[i]->d_name) + 3 + cmdlen];
		const char *name = d[i]->d_name;
		char *argv[4] = {
			"sh",
			"-c",
			path,
			NULL
		};
		struct stat st;
		int result = 0;
		pid_t pid = 0;
		int status;

		/* skip backup files */
		if (name[strlen(name) - 1] == '~')
			continue;

		/* cannot rely on d_type, not supported on all filesystems */
		paste(path, sizeof(path), dir, name);
		if (stat(path, &st)) {
			warn("failed stat(%s)", path);
			continue;
		}

		/* skip non-executable files and directories */
		if (!S_ISEXEC(st.st_mode) || S_ISDIR(st.st_mode)) {
			dbg("skipping %s not an executable or is a directory", path);
			continue;
		}

		if (sysv && name[0] != 'S' && name[0] != 'K') {
			dbg("S-only flag set, skipping non-SysV script: %s", name);
			continue;
		}

		/* If the callee didn't supply a run_parts() argument */
		if (!cmd) {
			/* Check if S<NUM>service or K<NUM>service notation is used */
			if (name[0] == 'S' && isdigit(name[1]))
				strlcat(path, " start", sizeof(path));
			else if (name[0] == 'K' && isdigit(name[1]))
				strlcat(path, " stop", sizeof(path));
		} else {
			strlcat(path, " ", sizeof(path));
			strlcat(path, cmd, sizeof(path));
		}

		if (progress)
			print_desc("Calling", path);

		pid = fork();
		if (!pid) {
			sig_unblock();
			run_env(env);

			_exit(execvp(_PATH_BSHELL, argv));
		}

		if (waitpid(pid, &status, 0) == -1) {
			warnx("failed starting %s, error %d: %s", path, errno, strerror(errno));
			result = 1;
		} else {
			if (WIFEXITED(status)) {
				result = WEXITSTATUS(status);
				dbg("%s exited with status %d", path, result);
			} else if (WIFSIGNALED(status)) {
				warnx("%s terminated by signal %d", path, WTERMSIG(status));
				result = 1;
			} else
				result = 1;
		}

		if (progress)
			print_result(result);
		rc += result;
	}

	while (num--)
		free(d[num]);
	free(d);

	return rc;
}

#ifndef __FINIT__
static int usage(int rc)
{
	fprintf(stderr,
		"Usage: runparts [OPTIONS] DIRECTORY\n"
		"\n"
		"Run all executable scripts in DIRECTORY in alphabetical order.\n"
		"Scripts prefixed S<NUM> are called with 'start', K<NUM> with 'stop'.\n"
		"\n"
		"Options:\n"
		"  -b    Batch mode, disable progress output and ANSI colors\n"
		"  -d    Enable debug output\n"
		"  -h    This help text\n"
		"  -p    Show progress and exit status for each script\n"
		"  -s    SysV compat, only run S<NUM>name and K<NUM>name scripts\n"
		"\n");
	return rc;
}

int main(int argc, char *argv[])
{
	int rc, c, progress = 0, sysv = 0;
	char *dir;

	while ((c = getopt(argc, argv, "bdh?ps")) != EOF) {
		switch(c) {
		case 'b':	/* batch mode */
			interactive = 0;
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
		case '?':
			return usage(0);
		case 'p':
			progress = 1;
			break;
		case 's':
			sysv = 1;
			break;
		default:
			return usage(1);
		}
	}

	if (optind >= argc)
		return usage(1);

	dir = argv[optind];
	if (!fisdir(dir))
		return usage(1);

	prctl(PR_SET_CHILD_SUBREAPER, 1);

	rc = run_parts(dir, NULL, NULL, progress, sysv);
	if (rc == -1)
		err(1, "failed run-parts %s", dir);

	return rc;
}
#endif /* __FINIT__ */

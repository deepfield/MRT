/* extracted from Stevens' sample code */

#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdio.h>
#include <errno.h>

typedef	void	Sigfunc(int);	/* for signal handlers */

#define	MAXFD	sysconf(_SC_OPEN_MAX)

/* Miscellaneous constants */
#define	MAXLINE		4096	/* max text line length */

static int daemon_proc = 0;		/* set nonzero by daemon_init() */

/* Print a message and return to caller.
 * Caller specifies "errnoflag" and "level". */

static void err_doit(int errnoflag, int level, const char *fmt, va_list ap) {
	int		errno_save, n;
	char	buf[MAXLINE];

	errno_save = errno;		/* value caller might want printed */
#ifdef	HAVE_VSNPRINTF
	vsnprintf(buf, sizeof(buf), fmt, ap);	/* this is safe */
#else
	vsprintf(buf, fmt, ap);					/* this is not safe */
#endif
	n = strlen(buf);
	if (errnoflag)
		snprintf(buf+n, sizeof(buf)-n, ": %s", strerror(errno_save));
	strcat(buf, "\n");

	if (daemon_proc) {
		syslog(level, buf);
	} else {
		fflush(stdout);		/* in case stdout and stderr are the same */
		fputs(buf, stderr);
		fflush(stderr);
	}
	return;
}

/* Fatal error related to a system call.
 * Print a message and terminate. */

void err_sys(const char *fmt, ...) {
	va_list		ap;

	va_start(ap, fmt);
	err_doit(1, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}


pid_t Fork(void) {
	pid_t	pid;

	if ( (pid = fork()) == -1)
		err_sys("fork error");
	return(pid);
}

Sigfunc * signal(int signo, Sigfunc *func) {
	struct sigaction	act, oact;

	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (signo == SIGALRM) {
#ifdef	SA_INTERRUPT
		act.sa_flags |= SA_INTERRUPT;	/* SunOS 4.x */
#endif
	} else {
#ifdef	SA_RESTART
		act.sa_flags |= SA_RESTART;		/* SVR4, 44BSD */
#endif
	}
	if (sigaction(signo, &act, &oact) < 0)
		return(SIG_ERR);
	return(oact.sa_handler);
}

Sigfunc * Signal(int signo, Sigfunc *func) {	/* for our signal() function */
	Sigfunc	*sigfunc;

	if ( (sigfunc = signal(signo, func)) == SIG_ERR)
		err_sys("signal error");
	return(sigfunc);
}

void daemon_init() {
	int		i;
	pid_t	pid;

	if ( (pid = Fork()) != 0)
		exit(0);			/* parent terminates */

	/* 1st child continues */
	setsid();				/* become session leader */

	Signal(SIGHUP, SIG_IGN);
	if ( (pid = Fork()) != 0)
		exit(0);			/* 1st child terminates */

	/* 2nd child continues */
	daemon_proc = 1;
	chdir("/");				/* change working directory */
	umask(0);				/* clear our file mode creation mask */

	for (i = 0; i < MAXFD; i++)
		close(i);
		
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);
}

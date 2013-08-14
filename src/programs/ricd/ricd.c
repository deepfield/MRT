/*
 * $Id: ricd.c,v 1.1.1.1 2000/08/14 18:46:14 labovit Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef SETPGRP_VOID
#include <sys/termios.h>
#endif

#include "ricd.h"
#include "config_file.h"
#include "protoconf.h"
#include "version.h"

/* this pipe is used for reporting an exit code from a child to the parent.
   pthreads on linux and solaris are ok, but pthreads on freebsd seems
   to have different semantics in fork with pthread. To avoid this kind
   of diffrence, all pthread_create are called after fork to be a daemon */

static int channel[2];

static void
sigchild (int sig)
{
    fprintf (stderr, "configuration error\n");
    exit (1);
}


static void
daemonize ()
{
    int pid;
#ifndef HAVE_SETSID
    int t;
#endif /* HAVE_SETSID */
    int time_left = alarm (0);
    /* alarm's time may not inherited by fork */
    void *handler;

    if (pipe (channel) < 0) {
        perror ("pipe");
	exit (1);
    }
    handler = (void *)signal (SIGCHLD, sigchild);
    if ((pid = fork ()) == -1) {
	perror ("fork");
	exit (1);
    }
    else if (pid != 0) {	/* parent */
	int status = 1;
	if (read (channel[0], &status, sizeof (int)) < 0)
	    perror ("read");
	exit (status);
    }
    /* child */
    signal (SIGCHLD, handler);

#ifdef HAVE_SETSID
    (void) setsid ();
#else
#ifdef SETPGRP_VOID
    if ((t = setpgrp ()) < 0) {
	perror ("setpgrp");
	exit (1);
    }
    signal (SIGHUP, SIG_IGN);

    /* fork again so that not being a process group leader */
    if ((pid = fork ()) == -1) {
	perror ("fork");
	exit (1);
    }
    else if (pid != 0) {	/* parent */
	exit (0);
    }
#else /* !SETPGRP_VOID */
    if ((t = setpgrp (0, getpid ())) < 0) {
	perror ("setpgrp");
	exit (1);
    }

    /* Remove our association with a controling tty */
    if ((t = open ("/dev/tty", O_RDWR, 0)) >= 0) {
	if (ioctl (t, TIOCNOTTY, NULL) < 0) {
	    perror ("TIOCNOTTY");
	    exit (1);
	}
	(void) close (t);
    }
#endif /* SETPGRP_VOID */

#ifdef notdef
    /* Close all open files --- XXX need to check for logfiles */
    for (t = 0; t < 2; t++)
	(void) close (t);
#endif
#endif /* HAVE_SETSID */

    /*  chdir ("/"); code rewrite needed in some places */
    umask (022);
    if (time_left)
        alarm (time_left);
    mrt_update_pid ();
}


ricd_t *RICD;
ricd_t *RICD6;

static void
ricd_init (trace_t *tr, int family)
{
    ricd_t *ricd;

    ricd = New (ricd_t);
#ifdef HAVE_IPV6
    if (family == AF_INET6) {
	assert (RICD6 == NULL);
	RICD6 = ricd;
    }
    else
#endif /* HAVE_IPV6 */
    {
	assert (RICD == NULL);
	RICD = ricd;
    }
    ricd->family = family;
    ricd->trace = trace_copy (tr);
    hqlip_init (ricd);
    srsvp_init (ricd);
}


static void
ricd_start (int family)
{
    ricd_t *ricd = RICD;

#ifdef HAVE_IPV6
    if (family == AF_INET6)
	ricd = RICD6;
    else
#endif /* HAVE_IPV6 */
    schedule_event2 ("hqlip_start",
                     ricd->hqlip->schedule,
                     (event_fn_t) hqlip_start,
                     1, ricd->hqlip);
    schedule_event2 ("srsvp_start",
                     ricd->srsvp->schedule,
                     (event_fn_t) srsvp_start,
                     1, ricd->srsvp);
}


void
main (int argc, char *argv[])
{
    char c, *p, *name = argv[0];
    extern char *optarg;	/* getopt stuff */
    extern int optind;		/* getopt stuff */
    int errors = 0;
    int daemon = 0;
    char *port = "ricd";
    char *rib_file = NULL;

    int kernel_read_flag = 1;
    int kernel_install_flag4 = 1;
    int kernel_install_flag6 = 1;
    int rib_install_flag = 1;

    char *usage = "Usage: %s [-f config_file] [-p uii_port ] [-v] [-n]\n";
    char *config_file = NULL;
    trace_t *default_trace;


    if ((p = strrchr (name, '/')) != NULL) {
	name = p + 1;
    }
    if (strcasecmp (name, "ricd") == 0 ||
        strcasecmp (name, "ricd.purify") == 0) {
	config_file = "/etc/ricd.conf";		/* unix convension */
	daemon = 1;
    }
#ifdef MCHECK
    mcheck (0);
#endif
    default_trace = New_Trace2 ("RICd");
    set_trace (default_trace, TRACE_PREPEND_STRING, "RICD", 0);
    set_trace (default_trace, TRACE_MAX_ERRORS, DEFAULT_MAX_ERRORS, 0);

    /* set_trace (default_trace, TRACE_FLAGS, TR_ALL, 0); */

    while ((c = getopt (argc, argv, "46rhnkvf:p:l:i:")) != -1)
	switch (c) {
	case 'v':		/* verbose */
	    set_trace (default_trace, TRACE_FLAGS, TR_ALL,
		       TRACE_LOGFILE, "stdout",
		       0);
	    daemon = 0;
	    break;
	case 'f':		/* config file */
	    config_file = optarg;
	    break;
	case '4':
	    kernel_install_flag4 = 0;
	    break;
	case '6':
	    kernel_install_flag6 = 0;
	    break;
	case 'n':		/* no kernel installation */
	    kernel_install_flag4 = 0;
	    kernel_install_flag6 = 0;
	    daemon = 0;
	    break;
	case 'k':		/* no kernel read */
	    kernel_read_flag = 0;
	    break;
	case 'r':		/* no rib installation */
	    rib_install_flag = 0;
	    break;
	case 'p':		/* uii port number */
	    port = optarg;
	    break;
	case 'l':		/* load rib on disk (mainly for testing) */
	case 'i':		/* load rib on disk (mainly for testing) */
	    rib_file = optarg;
	    break;
	case 'h':
	default:
	    errors++;
	    break;
	}


    if (errors) {
	fprintf (stderr, usage, name);
	printf ("\nMRT %s compiled on %s\n\n",
		RICD_VERSION, __DATE__);
	exit (1);
    }

#ifdef notdef
    if (getuid ()) {
	fprintf (stderr, "must be root\n");
	exit (1);
    }
#endif

    /* init_trace (name, daemon); */
    init_trace (name, 1);	/* always syslog */
    /* no thread creates here */
    init_mrt (default_trace);
    init_uii (default_trace);
    init_uii_port (port);
    init_mrt_reboot (argc, argv);
    trace (TR_INFO, MRT->trace, "%s compiled on %s started\n",
	   MRT->version, MRT->date);

    if (daemon) {
	/*
	 * Now going into daemon mode 
	 */
	MRT->daemon_mode = 1;
	daemonize ();
    }

    /* read information on all interfaces from the kernel */
    init_interfaces (default_trace);
    init_mrtd_config (default_trace);

    ricd_init (default_trace, AF_INET);
#ifdef HAVE_IPV6
    ricd_init (default_trace, AF_INET6);
#endif /* HAVE_IPV6 */

    set_uii (UII, UII_PROMPT, UII_UNPREV, "Password: ", 0);
    set_uii (UII, UII_PROMPT, UII_NORMAL, "RICD> ", 0);

    kernel_init ();		/* open routing socket */

    /*
     * read configuration here
     */

    ricd_init_config ();

    /* default_trace may be modified by debug statement in config file */
    if (config_from_file (default_trace, config_file) < 0) {
	config_create_default ();
    }

/* CONFIGURATION DEPENDENT INITIALIZATION PART */

    ricd_start (AF_INET);
#ifdef HAVE_IPV6
    ricd_start (AF_INET6);
#endif /* HAVE_IPV6 */
    listen_uii2 (NULL);

    if (daemon) {
 	int status = 0;
	if (write (channel[1], &status, sizeof (int)) < 0)
	    perror ("write");
    }

    /* timers never fire until going into loop */
    /* select never fire until going into loop */
    mrt_main_loop ();
    exit (0);
}

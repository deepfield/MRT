/* 
 * $Id: simple_bgp.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $ 
 */

/* sbgp: Simple BGP4 speaker and listner. Provides way to dump
 * BGP routing stream to other MRT tools, as well as to save stream
 * to file. Can also inject BGP information into peering with real
 * router */

#include <mrt.h>
#include <bgp.h>

/*
 * GLOBALS
 */
io_t *IO;
trace_t *default_trace;
mtimer_t *timer;
long last = 0;			/* last time we sent a packet */
int bgp4plus_version = DEFAULT_BGP4PLUS_VERSION;
int nothing = 1;
char *usage = 
    "Usage: sbgp [-01av] [-i binary_data_in_file] [-o binary_data_out_file]\n"
    "\t    [-l log_file] [-f config_file] [-c port] [-d port] [-s src_addr]\n"
    "\t    [-E seconds_idle_after_in_file_EOF]\n"
    "\t    [ASmy_as] [peer_ip ASpeer_as]...\n";

/*
static void sbgp_process_update (bgp_peer_t * peer, u_char * cp, u_int len);
static int sbgp_peer_established (bgp_peer_t * peer);
static int sbgp_process_input ();
static int process_command_line_args (int argc, char *argv[]);
static void io_timer (mtimer_t * timer);
*/

/*
 * Normally sbgp continues sending KEEPALIVE after input file EOF.
 * This is fine for most cases, but it makes it hard to run sbgp
 * from scrips. With
 *   "-E seconds_idle_after_in_file_EOF"
 * sbgp sends KEEPALIVE for that period of time and then exits.
 */
static int	eof_timeout;

bgp_local_t *local_bgp = NULL;

/* 
 *  Just write update as MRT output mesage
 */
static void
sbgp_process_update (bgp_peer_t * peer, u_char * buf, u_int len)
{
    u_char tmp[MAX_MSG_SIZE], *cp;

    cp = tmp;

    /* from */
    BGP_PUT_SHORT (peer->gateway->AS, cp);

#ifdef HAVE_IPV6
    if (peer->gateway->prefix->family == AF_INET6) {
	memcpy (cp, prefix_tochar (peer->gateway->prefix), 16);
	cp += 16;
    }
    else
#endif /* HAVE_IPV6 */
	BGP_PUT_NETLONG (prefix_tolong (peer->gateway->prefix), cp);

    /* to */
    BGP_PUT_SHORT (peer->local_bgp->this_as, cp);

#ifdef HAVE_IPV6
    if (peer->local_addr->family == AF_INET6) {
	memcpy (cp, prefix_tochar (peer->local_addr), 16);
	cp += 16;
    }
    else
#endif /* HAVE_IPV6 */
	BGP_PUT_NETLONG (prefix_tolong (peer->local_addr), cp);

    memcpy (cp, buf, len);
    len += (cp - tmp);

#ifdef HAVE_IPV6
    if (peer->gateway->prefix->family == AF_INET6) {
	io_write (IO, 0,
		  (bgp4plus_version == 0) ? MSG_PROTOCOL_BGP4PLUS :
		  MSG_PROTOCOL_BGP4PLUS_01,
		  MSG_BGP_UPDATE, len, tmp);
    }
    else
#endif /* HAVE_IPV6 */
	io_write (IO, 0, MSG_PROTOCOL_BGP, MSG_BGP_UPDATE, len, tmp);
}


#ifdef notdef
static int
sbgp_peer_down (bgp_peer_t * peer)
{
    Timer_Turn_ON (peer->timer_Start);
    select_delete_fd (IO->in.fd);	/* this should really be in IO routines ... */
    return (1);
}
#endif


/*
 * called by IO. Read a packet and send it on its way via BGP
 */
static void
sbgp_process_input (mrt_msg_t * msg)
{
    bgp_peer_t *peer;
    u_char *buf;
    static int	eof_timer = 0;

    /*while ((msg = (mrt_msg_t *) io_read (IO)) != NULL) { */
    if ((msg = (mrt_msg_t *) io_read (IO)) == NULL) {
	if ((eof_timeout > 0) && (eof_timer < eof_timeout))
	{
	    trace (NORM, BGP->trace, "IO in_file EOF, timer %d/%d\n",
					    eof_timer, eof_timeout);
	    eof_timer += 10;
	    Timer_Set_Time (timer, 10);
	    Timer_Turn_ON (timer);
	}
	else
	{
	    select_delete_fd (IO->in.fd);
	    if (eof_timeout > 0)
	    {
		trace (NORM, BGP->trace,
				"IO in_file EOF, timer %d/%d, exit\n",
					    eof_timer, eof_timeout);
		exit(0);
	    }
	}
	return;
    }

    if (msg->subtype != MSG_BGP_UPDATE) {
	select_enable_fd (IO->in.fd);
	return;
    }

    LL_Iterate (local_bgp->ll_bgp_peers, peer) {
	u_char *cp = (u_char *) msg->value;
	int length = msg->length;

	if (peer->state != BGPSTATE_ESTABLISHED) {
	    continue;
	}

	if (msg->type == MSG_PROTOCOL_BGP4PLUS ||
	    msg->type == MSG_PROTOCOL_BGP4PLUS_01) {
	    length -= (2 + 16 + 2 + 16);
	    cp += (2 + 16 + 2 + 16);
	}
	else {
	    length -= (2 + 4 + 2 + 4);
	    cp += (2 + 4 + 2 + 4);
	}

	buf = NewArray (u_char, length);
	memcpy (buf, cp, length);

	bgp_send_update (peer, length, (u_char *) buf);
    }

    if (last > 0) {
	/* another packet at same second */
	if (msg->tstamp == last) {
	    select_enable_fd (IO->in.fd);
	}
	else {
	    Timer_Set_Time (timer, msg->tstamp - last);
	    Timer_Turn_ON (timer);
	    trace (NORM, BGP->trace, "IO waiting for %d seconds\n",
		   msg->tstamp - last);
	}

    }
    else {
	select_enable_fd (IO->in.fd);
    }
    last = msg->tstamp;

    /* free memory here */
    Delete (msg);
}


static int
sbgp_peer_established (bgp_peer_t * peer)
{
    if (IO->io_input_type != IO_NONE) {
        select_add_fd_event ("sbgp_process_input", IO->in.fd,
                             SELECT_READ, TRUE,
                             BGP->schedule, sbgp_process_input, 0);
    /* io_set_notify (IO, 1, sbgp_process_input); */
    }
    return (1);
}


/*
 * renable timer after x seconds so we can recreate time-based events
 */
static void
io_timer (void)
{
    select_enable_fd (IO->in.fd);
}

int
main (int argc, char *argv[])
{
    char c;
    extern char *optarg;	/* getopt stuff */
    extern int optind;		/* getopt stuff */
    prefix_t *prefix;
    prefix_t *src_addr = NULL;
    int as = DEFAULT_LOCAL_AS /* must be set */;
    u_long id = htonl (DEFAULT_ROUTER_ID);
    int aflag = 0, vflag = 0;
    int lport = 0, cport = 0;
    char *ofilename = NULL, *wfilename = NULL;
    char *ifilename = NULL, *rfilename = NULL;
    char *lfilename = NULL;

    while ((c = getopt (argc, argv, "ar:w:hvo:i:l:s:c:d:E:")) != -1) {
	switch (c) {
	case '0':
	    bgp4plus_version = 0;
	    break;
	case '1':
	    bgp4plus_version = 1;
	    break;
	case 'a':		/* accept all incoming connections */
	    aflag++;
	    break;
	case 's':
	    src_addr = ascii2prefix (0, optarg);
	    break; 
	case 'd':		/* port for BGP daemon to listen on */
	    lport = atol (optarg);
	    break;
	case 'c':		/* port for BGP to connect to  */
	    cport = atol (optarg);
	    break;
	case 'o':		/* out data file name */
	    ofilename = (char *) optarg;
	    break;
	case 'w':		/* out message key name */
	    wfilename = (char *) optarg;
	    break;
	case 'i':		/* in data file name */
	    ifilename = (char *) optarg;
	    break;
	case 'r':		/* in message key */
	    rfilename = (char *) optarg;
	    break;
	case 'l':		/* log file name */
	    lfilename = (char *) optarg;
	    break;
	case 'v':		/* verbose */
	    vflag++;
	    break;
	case 'E':		/* time interval after ifilename EOF */
	    eof_timeout = atol (optarg);
	    break;
	case 'f':		/* config file */
	    fprintf (stdout, "Config file option not yet supported");
	case 'h':
	default:
	    fprintf (stderr, usage);
	    fprintf (stderr, "MRT version (%s) compiled on %s\n",
		    MRT_VERSION, __DATE__);
	    exit (1);
	    break;
	}
    }

    init_trace (NULL, 0);
    default_trace = New_Trace2 ("SBGP");
    if (vflag) {
	set_trace (default_trace, TRACE_FLAGS, TR_ALL,
		   TRACE_LOGFILE, "stdout", NULL);
        set_trace_global (default_trace);
    }

    init_mrt (default_trace);
    init_interfaces (default_trace);
    init_BGP (default_trace);
    if (aflag)
	set_BGP (BGP_ACCEPT_ALL_PEERS, 1, 0);
    if (lport > 0)
	BGP->lport = lport;
    if (cport > 0)
	BGP->cport = cport;

    IO = New_IO (default_trace);
    if (ofilename) {
	if (io_set (IO, IO_OUTFILE, ofilename, NULL) < 0) {
	    fprintf (stderr, "Error setting outfile %s\n", ofilename);
	    exit (1);
	}
    }
    if (wfilename) {
	if (io_set (IO, IO_OUTMSGQ, wfilename, NULL) < 0) {
	    fprintf (stderr, "Error setting outmsg %s\n", wfilename);
	    exit (1);
	}
    }
    if (ifilename) {
	if (io_set (IO, IO_INFILE, ifilename, NULL) < 0) {
	    fprintf (stderr, "Error setting infile %s\n", ifilename);
	    exit (1);
	}
    }
    if (rfilename) {
	if (io_set (IO, IO_INMSGQ, rfilename, NULL) < 0) {
	    fprintf (stderr, "Error setting inmsg %s\n", rfilename);
	    exit (1);
	}
    }
    if (lfilename) {
	set_trace (default_trace, TRACE_LOGFILE, lfilename, NULL);
	set_trace_global (default_trace);
    }

    timer = New_Timer2 ("IO timer", 1, TIMER_ONE_SHOT,
                         BGP->schedule, io_timer, 0);

    set_BGP (BGP_PEER_ESTABLISHED_FN, sbgp_peer_established,
	     BGP_RECV_UPDATE_FN, sbgp_process_update,
	     NULL);

    /* set my AS number */
    if ((optind < argc) && (!strncasecmp ("AS", argv[optind], 2)))
        as = atoi (2 + argv[optind++]);

    if (id == 0)
	id = MRT->default_id;
    local_bgp = init_bgp_local (as, id);
    
    /* add peers: peer_ip [peer_AS] */
    while (optind < argc) {
	bgp_peer_t *peer;
	int AS = 0;

	prefix = ascii2prefix (0, argv[optind++]);
	if (prefix == NULL) {
	    fprintf (stderr, "Unknown host %s\n", argv[optind - 1]);
	    exit (0);
	}
 	if (optind < argc && strncasecmp ("AS", argv[optind], 2) == 0) {
	    AS = atoi (2 + argv[optind++]);
	}
	peer = Add_BGP_Peer (local_bgp, NULL, prefix, AS, 0, BGP->trace);
	peer->bind_addr = src_addr;
	start_bgp_peer (peer);
	nothing = 0;
    }

    if (aflag) {
	init_BGP_listen (src_addr, NULL);
	nothing = 0;
    }

    if (nothing) {
	fprintf (stderr, usage);
	fprintf (stderr, "MRT version (%s) compiled on %s\n",
		MRT_VERSION, __DATE__);
	exit (1);
    }

    start_bgp ();
    mrt_main_loop ();
    return (1);
}

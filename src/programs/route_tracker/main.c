/*
 * $Id: main.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

#include <stdio.h>
#include <string.h>
#include <mrt.h>
#include <trace.h>
#include <interface.h>
#include <rip.h>
#include <time.h>
#include <bgp.h>
#include <signal.h>
#include <config_file.h>
#include <fcntl.h>
#include "rtracker.h"


bgp_t *BGP;
rip_t *RIP;
rtracker_t RTR;

trace_t *default_trace;


void main (int argc, char *argv[])
{
    char c, *name = argv[0];
    extern char *optarg;	/* getopt stuff */
    extern int optind;		/* getopt stuff */
    int errors = 0;
    char *port = "route_tracker";
    rtr_database_t tmp;

    char *usage = "Usage: %s [-f config_file] [-p uii_port ] [-v] [-n]\n";
    char *config_file = "/etc/route_tracker.conf";

    /* defaults */
    default_trace = New_Trace ();
    RTR.max_connections = 8;
    RTR.rtr_port = 5670;
    RTR.bgp_log_dir = "/cache";       
    RTR.ll_database = LL_Create (LL_Intrusive, True, 
				 LL_NextOffset, LL_Offset (&tmp, &tmp.next),
				 LL_PrevOffset, LL_Offset (&tmp, &tmp.prev),
				 0);

    while ((c = getopt (argc, argv, "rhnkvf:p:d")) != -1)
      switch (c) {
      case 'v':		/* verbose */
	set_trace (default_trace, TRACE_FLAGS, NORM |TR_ERROR,
		   TRACE_LOGFILE, "stdout",
		   NULL);
	break;
	case 'f':		/* config file */
	    config_file = optarg;
	    break;
	case 'p':		/* uii port number */
	    port = optarg;
	    break;
      case 'h':
      default:
	errors++;
	break;
      }


    if (errors) {
	fprintf (stderr, usage, name);
	printf ("\nMRT %s compiled on %s\n\n",
		MRT_VERSION, __DATE__);
	exit (1);
    }

    init_trace (name, 0);
    init_mrt (default_trace);
    init_uii (default_trace);
    init_mrt_reboot (argc, argv);
    init_interfaces (default_trace);

    /*init_rip (default_trace);
    init_BGP (default_trace);*/

    UII->initial_state = 1;
    uii_add_command (0, "", uii_check_passwd);
    set_uii (UII, UII_PROMPT, 0, "password> ", 0);
    set_uii (UII, UII_PROMPT, 1, "route_tracker> ", 0);
    set_uii (UII, UII_PROMPT, 2, "config> ", 0);
    set_uii (UII, UII_PORT, 5669, 0);

    uii_add_command2 (UII_NORMAL, COMMAND_NORM, "config", 
		      (void *) start_config, 
		      "Configure route_tracker");
    uii_add_command2 (UII_NORMAL, COMMAND_NORM, "write", (void *) config_write, 
		      "Save configuration to disk");
    uii_add_command2 (UII_NORMAL, COMMAND_NORM, "reboot", (void *) mrt_reboot,
		      "Reboot route_tracker");
    uii_add_command2 (UII_NORMAL, COMMAND_NORM,
		      "show config", show_config, "Display current configuration");
    
    /* configuration commands */
    uii_add_command2 (UII_CONFIG, COMMAND_NORM, "rtr_database %s %s path %s", 
		      (void *) config_rtr_database,
		      "RouteTracker database/repository");
    /*
     * read configuration here
     */
    if (config_from_file (default_trace, config_file) < 0) {
      config_create_default ();
    }


    listen_uii2 (port);

    if (listen_telnet () < 0) {
      fprintf (stderr, "**** Error could not bind to port %d\n", RTR.rtr_port);
      fprintf (stderr, "Is another route_tracker running?\n");
      exit (-1);
    }

    mrt_main_loop ();
    /* NOT REACHED */
}





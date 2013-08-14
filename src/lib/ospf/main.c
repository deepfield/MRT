/* 
 * $Id: main.c,v 1.1.1.1 2000/08/14 18:46:12 labovit Exp $
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <mrt.h>
#include <select.h>
#include <interface.h>
#include <config_file.h>
#include "sospf.h"


/*
 * GLOBALS
 */
trace_t *default_trace;
ospf_t	OSPF;

void main (int argc, char *argv[]) {
  char c;
  extern char *optarg;	/* getopt stuff */
  extern int optind;		/* getopt stuff */
  ospf_interface_t *network;

  int errors = 0;
  char *usage = "Usage: sospf [-v]\n";
  char *config_file = "/etc/sospf.conf";

  default_trace = New_Trace ();
  init_ospf ();

  while ((c = getopt (argc, argv, "vf:")) != -1)
    switch (c) {
    case 'v':		/* verbose */
      set_trace (default_trace, TRACE_FLAGS, TR_PACKET | NORM,
		 TRACE_LOGFILE, "stdout", NULL);
      break;
    case 'f':		/* config file */
      config_file = optarg;
      break;
    case 'h':
    default:
      errors++;
      break;
    }
  printf("Using config file: %s\n", config_file);

  if (errors) {
    fprintf (stderr, usage);
    printf ("\nMRT version (%s) compiled on %s\n\n",
	    MRT_VERSION, __DATE__);
    exit (0);
  }

  init_mrt (default_trace);
  init_uii (default_trace);
  init_interfaces (default_trace);

  OSPF.router_id = prefix_tolong (INTERFACE_MASTER->default_interface->primary->prefix);

  /* user commands */
  uii_add_command2 (UII_NORMAL, COMMAND_NORM, "config", 
		      (void *) start_config, 
		    "Configure sospf");
  uii_add_command2 (UII_NORMAL, COMMAND_NORM, "write", (void *) config_write, 
		    "Save configuration to disk");
  uii_add_command2 (UII_NORMAL, COMMAND_NORM,
		    "show config", show_config, "Display current configuration");
  uii_add_command2 (UII_NORMAL, COMMAND_NORM,
		    "show ip ospf neighbors", (void *) show_ospf_neighbors, 
		    "Show status of OSPF nieghbors");
  uii_add_command2 (UII_NORMAL, COMMAND_NORM, 
		    "show ip ospf database", (void *) show_ospf_database,
		    "Database summary");
  uii_add_command2 (UII_NORMAL, COMMAND_NORM,
		    "show ip ospf netmap", (void *) show_ospf_net_map,
		    "Network Map");

  /* configuration */
  uii_add_command2 (UII_CONFIG, COMMAND_NORM, "router ospf %d", 
		    (void *) config_router_ospf,
		    "Enable an OSPF process");
  uii_add_command2 (UII_CONFIG_ROUTER, COMMAND_NODISPLAY | COMMAND_MATCH_FIRST, 
		    "!", config_comment, " ");
  uii_add_command2 (UII_CONFIG_ROUTER, COMMAND_NORM, "network %p area %d", 
		    config_router_network, 
		    "Configure OSPF on network/interface");
  uii_add_command2 (UII_CONFIG_ROUTER, COMMAND_NORM, "area %d virtual-link %d", 
		    config_ospf_area_virtual_link, 
		    "Configure OSPF area parameters");
  uii_add_command2 (UII_CONFIG, COMMAND_NORM, "ip ospf hello-interval %d", 
		    (void *) config_ip_ospf_hello_interval, 
		    "Set the default OSPF hello interval");
  uii_add_command2 (UII_CONFIG, COMMAND_NORM, "ip ospf dead-interval %d", 
		    (void *) config_ip_ospf_dead_interval, 
		    "Set the default OSPF dead interval");
  uii_add_command2 (UII_CONFIG, COMMAND_NORM, "ip ospf router-id %p", 
		    (void *) config_ip_ospf_routerid, 
		    "Set the OSPF router-id");
  uii_add_command2 (UII_CONFIG_ROUTER, COMMAND_NORM, "network %p authentication-key %s", 
		    (void *) config_network_ospf_password, NULL);
  uii_add_command2 (UII_CONFIG, COMMAND_NORM, "dump ospf updates %s %s", 
		    config_dump_ospf_updates,
		    "Record OSPF LSA updates to disk");
  uii_add_command2 (UII_CONFIG, COMMAND_NORM, "dump ospf table %s %s", 
		    config_dump_ospf_table,
		    "Periodically dump OSPF LSA database to disk");

  config_from_file (default_trace, config_file);

  set_uii (UII, UII_INITIAL_STATE, 1);
  set_uii (UII, UII_PROMPT, UII_UNPREV, "Password> ", 0);
  set_uii (UII, UII_PROMPT, UII_NORMAL, "sOSPF> ", 0);
  set_uii (UII, UII_PROMPT, UII_CONFIG, "Config> ", 0);
  set_uii (UII, UII_PROMPT, UII_CONFIG_ROUTER, "Router> ", 0);
  listen_uii2 ("sospf");

  start_ospf_thread ();
  create_ospf_socket ();
  
  LL_Iterate (OSPF.ll_ospf_interfaces, network) {
    Timer_Turn_ON ((mtimer_t *) network->hello_timer);
    ospf_send_hello (NULL, network);
  }


  mrt_main_loop ();

  /* NOT REACHED */
}




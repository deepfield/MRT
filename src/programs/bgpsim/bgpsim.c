/* 
 * $Id: bgpsim.c,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
 */

#include <ctype.h>
#include <mrt.h>
#include <config_file.h>
#include <protoconf.h>
#include "bgpsim.h"


simulation_t *SIMULATION;
io_t *IO;
gateway_t *local_gateway;
trace_t *default_trace;
#ifdef HAVE_IPV6
gateway_t *local_gateway6;
#endif /* HAVE_IPV6 */

int show_simulation (uii_connection_t * uii);
void start_simulation (trace_t * trace);
int stop_simulation_schedule (uii_connection_t * uii);

typedef struct _config_bgpsim_t {
    struct _network_t *network;
} config_bgpsim_t;

static config_bgpsim_t *CONFIG_BGPSIM;


static network_t *
config_find_network (int num)
{
    network_t *network;

    LL_Iterate (SIMULATION->ll_networks, network) {
	if (network->num == num)
	    return (network);
    }

    return (NULL);
}


static void
get_config_network_list (int num)
{
    network_t *network;
    range_t *range;
    int i;

	if ((network = config_find_network (num)) == NULL)
		return;

    config_add_output ("network-list %d\n", num);
    LL_Iterate (network->ll_range, range) {
	config_add_output ("  range %s %s\n", prefix_toax (range->start), 
					      prefix_toa (range->end));
    }
    if (network->timer_stability) {
        if (network->stability_jitter != 0)
            config_add_output ("  stability %d jitter %d\n", network->stability,
		               network->stability_jitter);
        else
            config_add_output ("  stability %d\n", network->stability);
    }
    if (network->timer_change) {
        if (network->change_jitter != 0)
            config_add_output ("  change %d jitter %d\n", 
			       network->change_interval, 
			       network->change_jitter);
        else
            config_add_output ("  change %d\n", network->change_interval);
    }
    if (network->max_set > 0) {
        config_add_output ("  map");
        for (i = 1; i <= network->max_set; i++) {
	    config_add_output (" %d", network->sets[i]);
        }
        config_add_output ("\n");
    }
    if (!ifzero (&network->view_mask, sizeof (network->view_mask))) {
        config_add_output ("  view");
        for (i = 0; i < MAX_BGP_VIEWS; i++) {
	    if (BITX_TEST (&network->view_mask, i))
	        config_add_output (" %d", i);
        }
        config_add_output ("\n");
    }
}


static int 
config_network_list (uii_connection_t * uii, int num)
{
    network_t *network;

	network = config_find_network (num);
	if (uii->negative) {
	    LL_Iterate (SIMULATION->ll_networks, network) {
		if (network->num == num) {
		    LL_Remove (SIMULATION->ll_networks, network);
		    LL_Destroy (network->ll_range);
		    Delete (network);
	    	    config_add_module (0, "network-list", 
				       get_config_network_list, (void *)num);
		    return (1);
		}
	    }
	    return (0);
	}
	else {
	    if (network == NULL) {
                network = New (network_t);
	        network->num = num;
	        memset (&network->view_mask, 0, sizeof (network->view_mask));
	        network->the_as = 0 /* BGP->current_bgp->this_as */;
	        memset (network->sets, 0, sizeof (network->sets));
	        LL_Add (SIMULATION->ll_networks, network);
	        config_add_module (0, "network-list", get_config_network_list,
			          (void *)num);
	    }
	    CONFIG_BGPSIM->network = network;
	    uii->previous[++uii->prev_level] = uii->state;
    	    uii->state = UII_CONFIG_NETWORK_LIST;
	    return (1);
        }
}


static void
delete_range (range_t *range)
{
    Deref_Prefix (range->start);
    Deref_Prefix (range->end);
    Delete (range);
}


static int
network_list_range (uii_connection_t * uii, prefix_t *start, prefix_t *end)
{
	range_t *range;

	if (start->family != end->family) {
	    Deref_Prefix (start);
	    Deref_Prefix (end);
	    return (-1);
	}

	/* check to make sure end is after start range */
	if (prefix_compare_wolen (start, end) > 0) {
	  
	    Deref_Prefix (start);
	    Deref_Prefix (end);
	    return (-1); 
	}
	
	if (uii->negative) {
	    LL_Iterate (CONFIG_BGPSIM->network->ll_range, range) {
		if (prefix_compare (range->start, start) == 0 &&
		    prefix_compare (range->end, end) == 0)
			break;
	    }
	    if (range) {
		Deref_Prefix (range->start);
		Deref_Prefix (range->end);
		range->start = start;
		range->end = end;
		return (1);
	    }
	    return (0);
	}

	if (CONFIG_BGPSIM->network->ll_range == NULL)
            CONFIG_BGPSIM->network->ll_range = 
			LL_Create (LL_DestroyFunction, delete_range, 0);

	range = New (range_t);
	range->start = start;
	range->end = end;
	LL_Add (CONFIG_BGPSIM->network->ll_range, range);
	return (1);
}


static int
network_list_gateway (uii_connection_t * uii, prefix_t *prefix, int as)
{
    if (uii->negative) {
	CONFIG_BGPSIM->network->gateway = NULL;
	return (1);
    }

    CONFIG_BGPSIM->network->gateway = add_gateway (prefix, as, NULL);
    return (1);
}


static int
network_list_stability (uii_connection_t * uii, int stability, int jitter)
{
    char tmpx[MAXLINE];

    if (uii->negative) {
        CONFIG_BGPSIM->network->stability = 0;
        CONFIG_BGPSIM->network->stability_jitter = 0;
        Destroy_Timer (CONFIG_BGPSIM->network->timer_stability);
	CONFIG_BGPSIM->network->timer_stability = NULL;
	return (1);
    }
    /* stability */
    sprintf (tmpx, "Network Stability %d", CONFIG_BGPSIM->network->num);
    CONFIG_BGPSIM->network->stability = stability;
    CONFIG_BGPSIM->network->stability_jitter = jitter;
    if (CONFIG_BGPSIM->network->timer_stability == NULL)
        CONFIG_BGPSIM->network->timer_stability =
          New_Timer (network_schedule_stability, stability, tmpx, 
		     CONFIG_BGPSIM->network);
    else
	Timer_Set_Time (CONFIG_BGPSIM->network->timer_stability, stability);
    timer_set_jitter ( CONFIG_BGPSIM->network->timer_stability, jitter);
    return (1);
}

static int
network_list_stability2 (uii_connection_t * uii, int stability)
{
    return (network_list_stability (uii, stability, 0));
}


static int 
network_list_load_file (uii_connection_t *uii, char *filename) {
  
  /* don't allow both range and filename to be configured */

  /*if (CONFIG_BGPSIM->network->ll_routes == NULL)
    CONFIG_BGPSIM->network->ll_routes = LL_Create (0);*/

  if (CONFIG_BGPSIM->network->filename)
    Delete (CONFIG_BGPSIM->network->filename);
  CONFIG_BGPSIM->network->filename = strdup (filename);

  return (1);
}


static int
network_list_change (uii_connection_t * uii, int change, int jitter)
{
    char tmpx[MAXLINE];

    if (uii->negative) {
	CONFIG_BGPSIM->network->change_interval = 0;
	CONFIG_BGPSIM->network->change_jitter = 0;
	Destroy_Timer (CONFIG_BGPSIM->network->timer_change);
	CONFIG_BGPSIM->network->timer_change = NULL;
    }

	sprintf (tmpx, "Network Change %d", CONFIG_BGPSIM->network->num);
	CONFIG_BGPSIM->network->change_interval = change;
	CONFIG_BGPSIM->network->change_jitter = jitter;
	if (CONFIG_BGPSIM->network->timer_change == NULL)
	    CONFIG_BGPSIM->network->timer_change = 
		New_Timer (network_schedule_change, change, tmpx,
			   CONFIG_BGPSIM->network);
	else
	    Timer_Set_Time (CONFIG_BGPSIM->network->timer_change, change);
	timer_set_jitter ( CONFIG_BGPSIM->network->timer_change, jitter);
	return (1);
}


static int
network_list_change2 (uii_connection_t * uii, int change)
{
    return (network_list_change (uii, change, 0));
}


static int
network_list_set (uii_connection_t * uii, char *arg)
{
    char *list = arg;
    char tmpx[MAXLINE], *cp;

	int set;

    if (uii->negative) {
	CONFIG_BGPSIM->network->max_set = 0;
	return (1);
    }

	while ((cp = uii_parse_line2 (&list, tmpx)) != NULL) {
	  
	    if (!isdigit (cp[0])) {
		Delete (arg);
		return (0);
	    }

	    set = atoi (cp);

	    if (set <= 0) {
		trace (ERROR, CONFIG.trace, "CONFIG set number should be > 0\n");
		Delete (arg);
		return (-1);
	    }
	    if (CONFIG_BGPSIM->network->max_set >= MAX_SETS - 1) {
		trace (ERROR, CONFIG.trace, 
		       "CONFIG too many sets %d (should be < %d)\n", 
		       CONFIG_BGPSIM->network->max_set, MAX_SETS);
		Delete (arg);
		return (-1);
	    }
	    CONFIG_BGPSIM->network->sets[++CONFIG_BGPSIM->network->max_set] 
		= set;
	    trace (NORM, CONFIG.trace, 
		   "CONFIG new set %d for network-list %d\n", 
		   set, CONFIG_BGPSIM->network->num);
	}
	Delete (arg);
	return (1);
}


static int
network_list_view (uii_connection_t * uii, char *arg)
{
    char *list = arg;
    char tmpx[MAXLINE], *cp;
	int viewno;

    if (uii->negative) {
	memset (&CONFIG_BGPSIM->network->view_mask, 0, 
		sizeof (CONFIG_BGPSIM->network->view_mask));
	return (1);
    }

	while ((cp = uii_parse_line2 (&list, tmpx)) != NULL) {
	  
	    if (!isdigit (cp[0])) {
		Delete (arg);
		return (0);
	    }

	    viewno = atoi (cp);

	    if (viewno < 0 || viewno >= MAX_BGP_VIEWS) {
		trace (ERROR, CONFIG.trace, 
			"CONFIG view number should be 0 <= and < %d\n",
			MAX_BGP_VIEWS);
		Delete (arg);
		return (-1);
	    }
	    BITX_SET (&CONFIG_BGPSIM->network->view_mask, viewno);
	    trace (NORM, CONFIG.trace, 
		   "CONFIG new view %d for network-list %d\n", 
		   viewno, CONFIG_BGPSIM->network->num);
	}
	Delete (arg);
	return (1);
}


static int
network_list_set_as (uii_connection_t * uii, int as)
{
  if (CONFIG_BGPSIM->network->the_as) {
    config_notice (TR_TRACE, uii, "AS already set for this Network List.\n");
    return (1);
  }

  CONFIG_BGPSIM->network->the_as = as;
  config_notice (TR_TRACE, uii, "Network List %d local AS set to: AS%d\n",
		 CONFIG_BGPSIM->network->num,
		 CONFIG_BGPSIM->network->the_as);
  return (1);
}


#ifdef notdef
static int
route_set_compare (u_int *a, u_int *b)
{
   return (*a - *b);
}
#endif


/* neighbor xx.xx.xx.xx stability %d down %d */
static int 
config_router_neighbor_stability (uii_connection_t *uii,
				  char *name, int stability, int down) {
  bgp_peer_t *peer;
  peer_flap_t *flap;

    if ((peer = name2peer (uii, name)) == NULL) {   
        config_notice (TR_ERROR, uii, "No peer %s\n", name);
        Delete (name);
        return (-1);
    }
    Delete (name);    

    if (uii->negative) {
        LL_Iterate (SIMULATION->ll_peer_flaps, flap) {
            if (flap->peer == peer) {
		LL_Remove (SIMULATION->ll_peer_flaps, flap);
		return (1);
	    }
	}
	return (0);
    }

  if (SIMULATION->ll_peer_flaps == NULL)
    SIMULATION->ll_peer_flaps =  LL_Create (0);

  LL_Iterate (SIMULATION->ll_peer_flaps, flap) {
    if (flap->peer == peer) {
      Timer_Set_Time (flap->timer, stability);
      return (1);
    }
  }

  flap = New (peer_flap_t);
  flap->peer = peer;
  flap->timer = New_Timer (bgpsim_flap_peer, stability, "Flap Peer", peer);

  LL_Add (SIMULATION->ll_peer_flaps, flap);
  return (1);
}


static void 
add_bgpsim_config (void) {

    CONFIG_BGPSIM = New (config_bgpsim_t);
    set_uii (UII, UII_PROMPT, UII_CONFIG_NETWORK_LIST, "Network-List> ", 0);

    uii_add_command2 (UII_CONFIG, 0, "network-list %d", 
		config_network_list, "Defines a network list");
    uii_add_command2 (UII_CONFIG, 0, "no network-list %d", 
		config_network_list, "Deletes a network list");

    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, "range %m %m", 
		     network_list_range, "Prefix range to generate");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, "no range %m %m", 
		     network_list_range, "Remove range");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, "gateway %M as %d", 
		     network_list_gateway, "Define gateway");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, "no gateway", 
		     network_list_gateway, "Remove gateway");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, 
		      "stability %d", 
		     network_list_stability2, "Flapping interval (sec)");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, 
		      "no stability", 
		     network_list_stability2, "Stop Flapping");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, 
		      "stability %d jitter %d", 
		     network_list_stability, "Flapping interval (sec)");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, 
		      "change %d", 
		     network_list_change2, "Rotates route-maps");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, 
		      "no change", 
		     network_list_change2, "No route-maps rotation");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, 
		      "change %d jitter %d", 
		     network_list_change, "Rotates route-maps");
#if 1
    /* those two command will be obsolete */
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, 
		      "route-map %S",
		      network_list_set, "Lists route-map to use");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, 
		      "no route-map",
		      network_list_set, "Deletes route-map to use");
    CONFIG.state_eof = 1;
#endif
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, 
		      "map %S",
		      network_list_set, "Lists route-map to use");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, 
		      "no map",
		      network_list_set, "Deletes route-map to use");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, 
		      "view %S",
		      network_list_view, "Lists views to inject");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, 
		      "no view",
		      network_list_view, "Deletes views to inject");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, "file %sfilename",
		      network_list_load_file, 
		      "Load routes from routing table dump");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, "file %sfilename",
		      network_list_load_file, 
		      "Load routes from routing table dump");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "neighbor (%M|%n) stability %d [slow]",  
		      config_router_neighbor_stability,
		      "Set stability of TCP peering session with neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "no neighbor (%M|%n) stability", 
		      config_router_neighbor_stability,
		      "Reset stability of TCP peering session with neighbor");
    uii_add_command2 (UII_CONFIG_NETWORK_LIST, 0, "local-as %d",
		      network_list_set_as,
		      "Set local AS that this network-list affects");
}


int
main (int argc, char *argv[])
{
    char c, *p, *name = argv[0];
    extern char *optarg;	/* getopt stuff */
    extern int optind;		/* getopt stuff */
    int errors = 0;
    int dump_new_format = 0;
    /* Ok, DEFAULT_CURRENT_ID is a bad name, but we'll fix that later.
       -- binkertn */
    u_long id = 0;
    char *port = "bgpsim";
    char *usage = "Usage: bgpsim [-i router_id] [-p port] "
		  "[-f file] [-v] [-o output]\n";
    char *config_file = "./bgpsim.conf";
    prefix_t *prefix;

    default_trace = New_Trace2 ("BGPsim");
    set_trace (default_trace, TRACE_PREPEND_STRING, "BGPsim", 0);
    set_trace (default_trace, TRACE_MAX_ERRORS, DEFAULT_MAX_ERRORS, 0);

    /* must be root -- I guess the BGP code requires this somewhere?? */
    /* probably no. listening at port 179 requires it, 
       but it would be ok only initiating (and port can be changed now) */

    if ((p = strrchr (name, '/')) != NULL) {
        name = p + 1;
    }

    /* init simulation */
    SIMULATION = New (simulation_t);
    SIMULATION->ll_networks = LL_Create (0);
    BGPSIM_TRANSPARENT = 1; /* do not include our own AS and nexthop */

    while ((c = getopt (argc, argv, "vf:i:sp:h")) != -1)
      switch (c) {
      case 'v':		/* verbose */
	set_trace (default_trace, TRACE_FLAGS, TR_ALL,
		   TRACE_LOGFILE, "stdout",
		   NULL);
	break;
      case 'f':		/* config file */
	  config_file = strdup (optarg);
	  break;
      case 'i':
	  if (inet_pton (AF_INET, optarg, &id) > 0) {
	      /* ok */
	  }
	  break;
      case 's':  /* by default, bgpsim is transparent. set nexthop, origin... */
	BGPSIM_TRANSPARENT = 0;
	break;
      case 'm':
        dump_new_format = 1;
        break;
      case 'p':
        port = optarg;
        break;

      case 'h':
	default:
	    errors++;
	    break;
	}

    if (errors) {
      fprintf (stderr, usage);
	printf ("\nBGPSIM version (%s) compiled on %s\n\n",
		MRT_VERSION, __DATE__);
	exit (0);
    }

    init_trace (name, 0);
    init_mrt (default_trace);
    init_uii (default_trace);
    init_uii_port (port);
    init_mrt_reboot (argc, argv);

    trace (TR_INFO, MRT->trace, "%s compiled on %s started\n",
           MRT->version, MRT->date);

    init_interfaces (default_trace); 
    init_mrtd_config (default_trace);

    init_BGP (default_trace);
    if (id)
        set_BGP (BGP_MY_ID, id, 0);
    BGP->dump_new_format = dump_new_format;

    /* drop all updates */
    set_BGP (BGP_RECV_UPDATE_FN, NULL, 0);
    set_BGP (BGP_DUMP_DIRECTION, DUMP_DIR_SEND, 0); /* sending side only */
    /* state change may be dumped */

    set_uii (UII, UII_PROMPT, UII_NORMAL, "Bgpsim> ", 0);
    set_uii (UII, UII_PROMPT, UII_ENABLE, "Bgpsim# ", 0);
    /* set_uii (UII, UII_PROMPT, UII_CONFIG, "Bgpsim-Config> ", 0); */

    config_bgp_init ();
    config_rtmap_init ();
    /* config_rip_init (); */
    add_bgpsim_config ();

    if (config_from_file (default_trace, config_file) < 0) {
      config_create_default ();
    }
    /* This is a somewhat strange hack.  Only one AS gets the loopback
       interface, though how do I give each AS a loopback?  Maybe
       I need to have a virtual address for a loopback for each
       AS?  For now, we'll go with the cheezy hack.  -- binkertn */
    prefix = ascii2prefix (AF_INET, "127.0.0.1/32");
    /* don't need to set the interface 
       since it is used for all routes being generated */
    local_gateway = add_gateway (prefix,
				 0 /* BGP->current_bgp->this_as */, 
				 NULL);
    Deref_Prefix (prefix);

#ifdef HAVE_IPV6
    prefix = ascii2prefix (AF_INET6, "::1/128");
    local_gateway6 = add_gateway (prefix, /* BGP->my_as */ 0, NULL);
    Deref_Prefix (prefix);
#endif /* HAVE_IPV6 */

    uii_add_command2 (UII_NORMAL, 0, "show simulation", 
		     show_simulation, "Show status of simulation");
    uii_add_command2 (UII_NORMAL, 0, "stop", 
		     stop_simulation_schedule, "Stop simulation");

    listen_uii2 (NULL);

    /* timers never fire until going into loop */
    /* select never fire until going into loop */
    start_simulation (default_trace);
    mrt_main_loop ();
    exit (0);
}

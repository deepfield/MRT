/*
 * $Id: simulate.c,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
 */

#include <mrt.h>
#include <config_file.h>
#include <protoconf.h>
#include "bgpsim.h"

extern simulation_t *SIMULATION;
extern io_t *IO;
extern gateway_t *local_gateway;
extern trace_t *default_trace;
#ifdef HAVE_IPV6
extern gateway_t *local_gateway6;
#endif /* HAVE_IPV6 */


static void
memadd (u_char * a, u_char * b, int l)
{
    int i, c;
    int carry = 0;

    for (i = l - 1; i >= 0; i--) {
	c = a[i] + b[i] + carry;
	carry = (c >> 8);
	a[i] = (c & 0xff);
	
    }
}


static prefix_t *
copy_prefix_plus (prefix_t * prefix)
{

    int bitlen = prefix->bitlen;
    u_char plus1[16];
    int len = 4;

    prefix = copy_prefix (prefix);
    if (bitlen == 0)
	return (prefix);
    if (prefix->family == AF_INET) {
	assert (0 <= bitlen && bitlen <= 32);
    }
#ifdef HAVE_IPV6
    else if (prefix->family == AF_INET6) {
	assert (0 <= bitlen && bitlen <= 128);
	len = 16;
    }
#endif /* HAVE_IPV6 */
    else
	assert (0);

    memset (plus1, 0, sizeof plus1);
    plus1[(bitlen - 1) / 8] |= (0x80 >> ((bitlen - 1) % 8));
    memadd (prefix_touchar (prefix), plus1, len);
    return (prefix);
}


static int
precmp (prefix_t * p1, prefix_t * p2)
{
    int len = 4;

#ifdef HAVE_IPV6
    if (p1->family == AF_INET6) {
	len = 16;
	assert (p2->family == AF_INET6);
    }
#endif /* HAVE_IPV6 */
    return (memcmp (prefix_tochar (p1), prefix_tochar (p2), len));
}


int 
show_simulation (uii_connection_t * uii)
{
    char tmpx[MAXLINE];
    u_int hours, minutes, seconds;

    seconds = time (NULL) - SIMULATION->time_start;
    minutes = seconds / 60;
    hours = minutes / 60;
    minutes = minutes - hours * 60;
    seconds = seconds - hours * 60 * 60 - minutes * 60;

    sprintf (tmpx, "%02d:%02d:%02d", hours, minutes, seconds);

    if (SIMULATION->on_off == 1)
	uii_send_data (uii, "BGP Simulation\t\t[Status: RUNNING]\n");
    else
	uii_send_data (uii, "BGP Simulation\t\t[Status: STOPPED]\n");
    uii_send_data (uii, "Time:%s\t\tEnd: Indefinite\n", tmpx);
    uii_send_data (uii, "Packets:0\t\tEnd Total: Indefinite\n");

    return (1);
}


/*
 * if change == 1, use alternate aspath and nexthop 
 * if change == -1, delete the route
 */
static void
simulate_add_routes (network_t * network, int change)
{
    bgp_attr_t *attr, *atto;
#ifdef HAVE_IPV6
    bgp_attr_t *attr6, *atto6;
#endif /* HAVE_IPV6 */
    bgp_route_t *route;
    prefix_t *prefix;
    range_t *range;
    int i, set = network->sets[network->current];
    int count = 0;
    int all = 0;
    LINKED_LIST *ll_prefixes = LL_Create (LL_DestroyFunction, Deref_Prefix, 0);
    LINKED_LIST *ll_attrs = LL_Create (LL_DestroyFunction, bgp_deref_attr, 0);

    /* this is required to keep compatible to old versions */
    /* if view is specified in network-list, inject into all views */
    if (ifzero (&network->view_mask, sizeof (network->view_mask)))
	all++;

    /* use disk file */
    if (network->filename != NULL) {
      load_rib_from_disk (network->filename);
      return;
    }

    if (change == 1 && network->max_set > 1) {
	do {
	    if (++network->current > network->max_set) {
	        network->current = 1;
	    }
	    set = network->sets[network->current];
	} while (set <= 0);

	trace (TR_PACKET, SIMULATION->trace,
               "Simulating network list %d changed to set %d\n", 
	       network->num, set);
    }

    attr = bgp_new_attr (PROTO_BGP);
    if (network->gateway)
	attr->gateway = network->gateway;
    else
        attr->gateway = local_gateway;
    atto = bgp_copy_attr (attr);

    /* set 1 is default */
    if (set != 1)
        attr = apply_route_map (1, attr, NULL, 1);
    attr = apply_route_map (set, attr, NULL, 1);

#ifdef HAVE_IPV6
    attr6 = bgp_new_attr (PROTO_BGP);
    if (network->gateway)
	attr6->gateway = network->gateway;
    else
        attr6->gateway = local_gateway6;
    atto6 = bgp_copy_attr (attr6);

    /* set 1 is default */
    if (set != 1)
        attr6 = apply_route_map (1, attr6, NULL, 1);
    attr6 = apply_route_map (set, attr6, NULL, 1);
#endif /* HAVE_IPV6 */

    LL_Iterate (network->ll_range, range) {
	prefix = Ref_Prefix (range->start);
	while (precmp (prefix, range->end) <= 0) {
	    prefix_t *ptmp;
	    LL_Add (ll_prefixes, prefix);
	    ptmp = copy_prefix_plus (prefix);
	    prefix = ptmp;

	    if (change >= 0) {
    		bgp_attr_t *attx = NULL;
    		if (set != 1) {
        	    if (apply_route_map_alist (1, prefix)) {
			if (attx == NULL) {
#ifdef HAVE_IPV6
			    if (prefix->family == AF_INET6)
    		    	        attx = bgp_copy_attr (atto6);
			    else
#endif /* HAVE_IPV6 */
    		    	    attx = bgp_copy_attr (atto);
			}
			attx = apply_route_map (1, attx, prefix, 1);
		    }
		}
        	if (apply_route_map_alist (set, prefix)) {
		    if (attx == NULL) {
#ifdef HAVE_IPV6
			if (prefix->family == AF_INET6)
    		    	    attx = bgp_copy_attr (atto6);
			else
#endif /* HAVE_IPV6 */
    		    	attx = bgp_copy_attr (atto);
		    }
		    attx = apply_route_map (set, attx, prefix, 1);
		}
		if (attx != NULL) {
		    LL_Add (ll_attrs, attx);
		}
		else {
#ifdef HAVE_IPV6
		    if (prefix->family == AF_INET6)
		        LL_Add (ll_attrs, bgp_ref_attr (attr6));
		    else
#endif /* HAVE_IPV6 */
		    LL_Add (ll_attrs, bgp_ref_attr (attr));
		}
	    }
	    else {
#ifdef HAVE_IPV6
		if (prefix->family == AF_INET6)
		    LL_Add (ll_attrs, bgp_ref_attr (attr6));
		else
#endif /* HAVE_IPV6 */
		LL_Add (ll_attrs, bgp_ref_attr (attr));
	    }
	}
	Deref_Prefix (prefix);
    }

    bgp_deref_attr (attr);
    bgp_deref_attr (atto);
#ifdef HAVE_IPV6
    bgp_deref_attr (attr6);
    bgp_deref_attr (atto6);
#endif /* HAVE_IPV6 */

    for (i = 0; i < MAX_BGP_VIEWS; i++) {
	view_t *view = BGP->views[i];

	if (view == NULL)
	    continue;
	if (view->local_bgp == NULL)
	    continue;

	if (!all && !BITX_TEST (&network->view_mask, i))
	    continue;

	/* this is not what the_as initially intented, though. -- masaki */
	if (network->the_as > 0 && view->local_bgp->this_as != network->the_as)
	    continue;

	view_open (view);

	attr = NULL;
	LL_Iterate (ll_prefixes, prefix) {

	    if (view->afi != family2afi (prefix->family))
	        continue;

	    attr = LL_GetNext (ll_attrs, attr);
	    if (change >= 0) {
		route = bgp_add_route (view, prefix, attr);
	    }
	    else {
#ifdef notdef
		route = view_find_bgp_active (view, prefix);
		view_delete_bgp_route (view, route);
#else
		bgp_del_route (view, prefix, attr);
#endif
	    }

	    /* spread out processing 
	     * don't block while generarting large changes 
	     * Masaki -- does this introduce any new bugs?? */
#define BGPSIM_COUNT 10
	    if (count++ > BGPSIM_COUNT) {
		bgp_process_changes (view);
		view_close (view);
#ifndef HAVE_LIBPTHREAD
		/* force to switch */
		mrt_switch_schedule ();
#endif /* HAVE_LIBPTHREAD */
	        count = 0;
		view_open (view);
	    }
	}

	bgp_process_changes (view);
	view_close (view);
    }
    LL_Destroy (ll_prefixes);
    LL_Destroy (ll_attrs);
}


static void 
simulate (void)
{
    network_t *network;
    peer_flap_t *peer_flap;

    init_mrt_thread_signals ();

    LL_Iterate (SIMULATION->ll_networks, network) {
	network->current = 1;
	simulate_add_routes (network, 0);
	network->flag = 1;

	if (network->stability > 0) {
	    Timer_Turn_ON (network->timer_stability);
	}

	if (network->change_interval > 0) {
	    Timer_Turn_ON (network->timer_change);
	}
    }

    if (SIMULATION->ll_peer_flaps) {
      LL_Iterate (SIMULATION->ll_peer_flaps, peer_flap) {
	Timer_Turn_ON (peer_flap->timer);
      }
    }

#ifdef HAVE_LIBPTHREAD
    while (1)
	schedule_wait_for_event (SIMULATION->schedule);
    /* NOT REACHED */
#endif /* HAVE_LIBPTHREAD */
}


void start_simulation (trace_t * trace)
{
    SIMULATION->schedule = New_Schedule ("BGP Simulation", trace);
    SIMULATION->trace = trace;
    SIMULATION->on_off = 1;
    SIMULATION->time_start = time (NULL);

#ifdef notdef
    mrt_thread_create ("BGP Simulation", SIMULATION->schedule,
		       (thread_fn_t) simulate, trace);
#else
    mrt_thread_create2 ("BGP Simulation", SIMULATION->schedule, NULL, NULL);
    schedule_event2 ("simulate", SIMULATION->schedule, simulate, 0);
#endif
}


static void 
stop_simulation (uii_connection_t * uii)
{
    network_t *network;

    SIMULATION->on_off = 0;

    uii_send_data (uii, "\nStopping Simulation...\n");

    LL_Iterate (SIMULATION->ll_networks, network) {
	Timer_Turn_OFF (network->timer_stability);
	Timer_Turn_OFF (network->timer_change);
	uii_send_data (uii, " Simulation network %d OFF\n", network->num);
    }
}



static void 
network_stability (network_t * network)
{
    if (network->flag == 1) {
	trace (NORM, SIMULATION->trace,
	       "Simulating network list %d being withdrawn\n", network->num);
	simulate_add_routes (network, -1);
	network->flag = 0;
    }
    else {
	trace (NORM, SIMULATION->trace,
	       "Simulating network list %d being announced\n", network->num);
	simulate_add_routes (network, 0);
	network->flag = 1;
    }
}


static void 
network_change (network_t * network)
{
    trace (NORM, SIMULATION->trace,
	   "Simulating network list %d change\n", network->num);
    simulate_add_routes (network, 1);
    network->flag = 1;
}



int stop_simulation_schedule (uii_connection_t * uii)
{
    schedule_event2 ("stop_simulation",
	    SIMULATION->schedule, stop_simulation, 1, uii);
    return (1);
}


/* public */
void 
network_schedule_stability (mtimer_t * timer, network_t * network)
{
    schedule_event2 ("network_stability",
      SIMULATION->schedule, network_stability, 1, network);
}


/* public */
void 
network_schedule_change (mtimer_t * timer, network_t * network)
{
    schedule_event2 ("network_change",
	 SIMULATION->schedule, network_change, 1, network);
}


void bgpsim_flap_peer (mtimer_t * timer, bgp_peer_t * peer) {

  trace (NORM, SIMULATION->trace, "Flapping peer\n");

  /* make sure peer stays down for a while */
  timer_set_flags (peer->timer_Start, TIMER_EXPONENT_SET, 6);

  bgp_stop_peer (peer);
}
 


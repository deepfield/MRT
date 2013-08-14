/*
 * $Id: bgpsim.h,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
 */

#ifndef _BGPSIM_H
#define _BGPSIM_H

typedef struct _range_t {
    prefix_t *start;
    prefix_t *end;
} range_t;


/* use either a range (e.g rane 192.32.0.0/24 192.32.255.0) or
 * load routes from a file (e.g. file "./mae-east.980720")
 */
typedef struct _network_t {
    int num;
    int the_as;
    bgp_bitset_t view_mask;

    LINKED_LIST *ll_range;      /* range of network prefixes */
  
    char *filename;
    LINKED_LIST *ll_routes;	/* routes loaded from file */

    u_int stability;		/* interval of up/down in seconds */
    u_int stability_jitter;
    u_int change_interval;	/* interval of change in seconds */
    u_int change_jitter;
    u_char flag;		/* 1 = up, 0 = down */

    mtimer_t *timer_stability;
    mtimer_t *timer_change;

#define MAX_SETS 100
    int sets[MAX_SETS];
    int max_set;
    int current;		/* current attrib number */

    LINKED_LIST *ll_sets;	/* ll_list of range_t */
    gateway_t *gateway;
} network_t;


typedef struct _peer_flap_t {
  bgp_peer_t	*peer;
  mtimer_t	*timer;
} peer_flap_t;


typedef struct _simulation_t {
    schedule_t *schedule;
    LINKED_LIST *ll_networks;
    LINKED_LIST *ll_peer_flaps;   /*  neighbor 198.108.60.20 stability 20 */

    /* stats */
    u_char on_off;		/* 0 = off */
    time_t time_start;
    u_long packets;

    trace_t *trace;
} simulation_t;

extern simulation_t *SIMULATION;

void network_schedule_stability (mtimer_t * timer, network_t * network);
void network_schedule_change (mtimer_t * timer, network_t * network);
void bgpsim_flap_peer (mtimer_t * timer, bgp_peer_t * peer);

#endif /* _BGPSIM_H */

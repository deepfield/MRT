/*
 * $Id: pim.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _PIM_H
#define _PIM_H

#include <mrt.h>
#include <igmp.h>
#include <cache.h>

#if defined(HAVE_MROUTING) || defined(HAVE_MROUTING6)
#undef MRT_VERSION
#include <net/route.h>
/*#include <netinet/ip_mroute.h>*/

#define PIM_VERSION		2
#define PIM_MAX_PDU		4096

#define IPPROTO_PIM         103
#undef YIXIN_PIMV6
#ifdef YIXIN_PIMV6
/* I don't know, but gated pimv6 uses 104 which is allocated for another */
#define IPPROTO_PIMV6       104
#else
#define IPPROTO_PIMV6       103
#endif /* YIXIN_PIMV6 */

/*
 * PIM Message Types
 */
#define PIM_HELLO                             0
#define PIM_REGISTER                          1
#define PIM_REGISTER_STOP                     2
#define PIM_JOIN_PRUNE                        3
#define PIM_BOOTSTRAP                         4
#define PIM_ASSERT                            5
#define PIM_GRAFT                             6
#define PIM_GRAFT_ACK                         7
#define PIM_CANDIDATE_RP_ADVERTISEMENT        8
#define PIM_MAX_TYPE        		      9

#define PIM_DATA_TIMEOUT                210
#define PIM_TIMER_HELLO_PERIOD           30
#define PIM_JOIN_PRUNE_HOLDTIME         210
#define PIM_RANDOM_DELAY_JOIN_TIMEOUT     3
#define PIM_GRAFT_RETRANS_PERIOD          3
#define PIM_TIMER_HELLO_HOLDTIME (PIM_TIMER_HELLO_PERIOD * 3 + \
                                        PIM_TIMER_HELLO_PERIOD / 2)
#define PIM_ASSERT_TIMEOUT              210

#define PIM_VIF_LEAF 0x80

#define MAX_PIM_NEIGHBORS 256
typedef struct _pim_neighbor_bitset_t {
        bitx_mask_t bits[(MAX_PIM_NEIGHBORS+BITX_NBITS-1)/BITX_NBITS];
} pim_neighbor_bitset_t;


#define PIM_NEIGHBOR_DELETE 0x01
#define PIM_NEIGHBOR_MYSELF 0x02

typedef struct _pim_neighbor_t {
    prefix_t *prefix;
    interface_t *interface;
    time_t ctime;
    int holdtime;
    int index;
    mtimer_t *timeout;
    u_long flags;
} pim_neighbor_t;


typedef struct _pim_interface_t {     
    interface_t *interface;     
    pim_neighbor_bitset_t neighbor_mask;    
    u_long flags;
    LINKED_LIST *ll_neighbors;
    mtimer_t *hello;		/* sending hellos */
    int nbr_count;
} pim_interface_t;


#define PIM_PRUNE_RUN 0x01

typedef struct _pim_prune_t {
    pim_neighbor_t *neighbor;
    int holdtime;
    time_t received;
    time_t expire;
    cache_entry_t *entry;
    u_long flags;
} pim_prune_t;

typedef struct _pim_join_t {
    pim_neighbor_t *neighbor;
    int holdtime;
    time_t received;
    time_t expire;
    cache_entry_t *entry;
    u_long flags;
} pim_join_t;

typedef struct _pim_graft_t {
    pim_neighbor_t *neighbor;
    int holdtime;
    time_t received;
    time_t expire;
    cache_entry_t *entry;
    u_long flags;
} pim_graft_t;


typedef struct _pim_t {
    int proto;			/* PROTO_PIM or PROTO_PIMV6 */
    interface_bitset_t interface_mask;	/* mask of interfaces configed for */
    interface_bitset_t interface_leaf;	/* mask of interfaces leaf */
    interface_bitset_t force_leaf_mask;  /* interfaces forced to be leaf */
    trace_t *trace;
    LINKED_LIST *ll_prunes;
    LINKED_LIST *ll_joins;
    LINKED_LIST *ll_grafts;
    mtimer_t *prune_timer;
    mtimer_t *join_timer;
    mtimer_t *graft_timer;
    mtimer_t *route_timer;

    schedule_t *schedule;

    LINKED_LIST *ll_pim_interfaces;	/* enabled pim interface */
    pim_interface_t *pim_interfaces[MAX_INTERFACES];
    pim_neighbor_t *index2neighbor[MAX_PIM_NEIGHBORS];

    int sockfd;
    prefix_t *all_routers;
} pim_t;


typedef struct _mc_route_t {
    prefix_t *group;
    prefix_t *source;
    interface_t *parent;		/* incoming interface */
    interface_bitset_t out_interfaces;		/* outgoing interfaces */
    interface_bitset_t pruned_interfaces;	/* prune received */
    interface_bitset_t leaf_interfaces;		/* there is a member */
    time_t ctime;			/* time created */
    u_char ttls[MAXVIFS];		/* ttl vector for forwarding */
} mc_route_t;


#ifdef HAVE_MROUTING
extern pim_t *PIM;
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
extern pim_t *PIMv6;
#endif /* HAVE_MROUTING6 */

int pim_init (int proto, trace_t * tr);
int pim_activate_interface (int proto, interface_t *interface, int on);
int pim_show_neighbors (uii_connection_t *uii, int proto);
#endif /* HAVE_MROUTING || HAVE_MROUTING6 */
#endif /* _PIM_H */

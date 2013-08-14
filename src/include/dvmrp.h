/*
 * $Id: dvmrp.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _DVMRP_H
#define _DVMRP_H

#include <mrt.h>
#include <igmp.h>
#include <cache.h>

#ifdef HAVE_MROUTING

#define DVMRP_VERSION		2
#define DVMRP_MAX_PDU		8192

/*
 * DVMRP message types (carried in the "code" field of an IGMP header)
 */
#define DVMRP_PROBE             1       /* for finding neighbors             */
#define DVMRP_REPORT            2       /* for reporting some or all routes  */
#define DVMRP_ASK_NEIGHBORS     3       /* sent by mapper, asking for a list */
                                        /* of this router's neighbors. */
#define DVMRP_NEIGHBORS         4       /* response to such a request */
#define DVMRP_ASK_NEIGHBORS2    5       /* as above, want new format reply */
#define DVMRP_NEIGHBORS2        6
#define DVMRP_PRUNE             7       /* prune message */
#define DVMRP_GRAFT             8       /* graft message */
#define DVMRP_GRAFT_ACK         9       /* graft acknowledgement */
#define DVMRP_INFO_REQUEST      10      /* information request */
#define DVMRP_INFO_REPLY        11      /* information reply */

/*
 * 'flags' byte values in DVMRP_NEIGHBORS2 reply.
 */
#define DVMRP_VIF_TUNNEL         0x01    /* neighbors reached via tunnel */
#define DVMRP_VIF_SRCRT          0x02    /* tunnel uses IP source routing */
#define DVMRP_VIF_PIM            0x04    /* neighbor is a PIM neighbor */
#define DVMRP_VIF_DOWN           0x10    /* kernel state of interface */
#define DVMRP_VIF_DISABLED       0x20    /* administratively disabled */
#define DVMRP_VIF_QUERIER        0x40    /* I am the subnet's querier */
#define DVMRP_VIF_LEAF           0x80    /* Neighbor reports that it is a leaf */

/*
 * Request/reply types for info queries/replies
 */
#define DVMRP_INFO_VERSION      1       /* version string */
#define DVMRP_INFO_NEIGHBORS    2       /* neighbors2 data */

/*
 * Limit on length of route data
 */
#define MAX_IP_PACKET_LEN       576
#define MIN_IP_HEADER_LEN       20
#define MAX_IP_HEADER_LEN       60
#define MAX_DVMRP_DATA_LEN \
                ( MAX_IP_PACKET_LEN - MAX_IP_HEADER_LEN - IGMP_MINLEN )


#define ROUTE_MAX_REPORT_DELAY  5       /* max delay for reporting changes  */
                                        /*  (This is the timer interrupt    */
                                        /*  interval; all times must be     */
                                        /*  multiples of this value.)       */

#define ROUTE_REPORT_INTERVAL   60      /* periodic route report interval   */
#define ROUTE_SWITCH_TIME       140     /* time to switch to equivalent gw  */
#define ROUTE_EXPIRE_TIME       200     /* time to mark route invalid       */
#define ROUTE_DISCARD_TIME      340     /* time to garbage collect route    */

#define LEAF_CONFIRMATION_TIME  200     /* time to consider subnet a leaf   */

#define NEIGHBOR_PROBE_INTERVAL 10      /* periodic neighbor probe interval */
#define NEIGHBOR_EXPIRE_TIME    30      /* time to consider neighbor gone   */
#define OLD_NEIGHBOR_EXPIRE_TIME 140    /* time to consider neighbor gone   */

#define DVMRP_UPDATE_INTERVAL 60
#define DVMRP_ROUTE_SWITCH_TIME 140
#define DVMRP_TIMEOUT_INTERVAL 200
#define DVMRP_GARBAGE_INTERVAL 140
#define DVMRP_METRIC_INFINITY 32
#define DVMRP_NEIGHBOR_PROBE_INTERVAL 10
#define DVMRP_TABLE_HASH_SIZE 1023
#define DVMRP_CACHE_HASH_SIZE 1023
#define DVMRP_NEIGHBOR_EXPIRE_TIME 30

#define DVMRP_UNREACHABLE       32      /* "infinity" metric, must be <= 64 */
#define DEFAULT_METRIC          1       /* default subnet/tunnel metric     */
#define DEFAULT_THRESHOLD       1       /* default subnet/tunnel threshold  */

#define MAX_RATE_LIMIT          100000  /* max rate limit                   */
#define DEFAULT_PHY_RATE_LIMIT  0       /* default phyint rate limit        */
#define DEFAULT_TUN_RATE_LIMIT  0       /* default tunnel rate limit        */

#define AVERAGE_PRUNE_LIFETIME  7200    /* average lifetime of prunes sent  */
#define MIN_PRUNE_LIFETIME      120     /* minimum allowed prune lifetime   */
#define GRAFT_TIMEOUT_VAL       5       /* retransmission time for grafts   */
#define PRUNE_REXMIT_VAL        3       /* initial time for prune rexmission*/


#define MAX_NEIGHBORS 256
typedef struct _neighbor_bitset_t {
        bitx_mask_t bits[(MAX_NEIGHBORS+BITX_NBITS-1)/BITX_NBITS];
} neighbor_bitset_t;


#define DVMRP_NEIGHBOR_DELETE 0x01
typedef struct _dvmrp_neighbor_t {
    prefix_t *prefix;
    interface_t *interface;
    time_t ctime, utime;
    u_long genid;
    u_long flags;
    u_long level;
    int index;
    mtimer_t *timeout;		/* neighbor timeout */
} dvmrp_neighbor_t;


typedef struct _dvmrp_interface_t {
    interface_t *interface;
    neighbor_bitset_t neighbor_mask;
    u_long flags;
    int metric_in;
    int metric_out;
    int threshold;
    LINKED_LIST *ll_neighbors;
    int dlist_in;    /* list num for input filtering */
    int dlist_out;   /* list num for output filtering */
    int nbr_count;
    mtimer_t *probe;		/* neighbor probe */
} dvmrp_interface_t;


typedef struct _dvmrp_t {
    int proto;			/* PROTO_DVMRP */
    interface_bitset_t interface_mask;	/* mask of interfaces configed for */
    interface_bitset_t force_leaf_mask;	/* interfaces forced to be leaf */
    radix_tree_t *radix;	/* radix tree of routes */
    trace_t *trace;

    schedule_t *schedule;
    mtimer_t *timer;		/* timer used for sending update */
    mtimer_t *age;		/* aging routes */
    mtimer_t *flash;		/* flash update */
    mtimer_t *expire;		/* prune expiration */

    LINKED_LIST *ll_networks;   /* prefix */
    LINKED_LIST *ll_networks2;  /* interface name */
    LINKED_LIST *ll_leafs;  	/* leaf if name */
    LINKED_LIST *ll_dlists;     /* distribute-list */

    LINKED_LIST *ll_dvmrp_interfaces;	/* enabled dvmrp interface */
    dvmrp_interface_t *dvmrp_interfaces[MAX_INTERFACES];
    dvmrp_neighbor_t *index2neighbor[MAX_NEIGHBORS];

    u_long genid;
    prefix_t *all_routers;
    int flash_update_waiting;
    time_t update_last_run;
    int changed;
    u_long level;
} dvmrp_t;


/* route flags */
#define DVMRP_RT_CHANGE  0x01
#define DVMRP_RT_DELETE  0x02

typedef struct _dvmrp_route_t {
    int proto;
    u_long flags;
    prefix_t *prefix; 
    interface_t *interface; /* this may be redundant but used for direct if */
    dvmrp_neighbor_t *neighbor;
    neighbor_bitset_t children;
    neighbor_bitset_t dominants;
    neighbor_bitset_t dependents;
    int metric;
    time_t ctime;               /* time created */
    time_t utime;               /* time updated */
    time_t dtime;               /* time started deletion process */
} dvmrp_route_t;


typedef struct _dvmrp_ann_rt_t {
    prefix_t *prefix;
    int metric; 
} dvmrp_ann_rt_t;


typedef struct _dvmrp_report_t {
    prefix_t *prefix;
    int metric;
    dvmrp_neighbor_t *neighbor;
} dvmrp_report_t;


typedef struct _dvmrp_prune_t {
    dvmrp_neighbor_t *neighbor;
    int lifetime;
    time_t received;
    time_t expire;
} dvmrp_prune_t;


extern dvmrp_t *DVMRP;

int dvmrp_init (trace_t * tr);
void dvmrp_start (void);
void dvmrp_stop (void);
void dvmrp_interface_recheck (void);
void dvmrp_distribute_list_recheck (void);
int dvmrp_show_routing_table (uii_connection_t * uii, int numopt, char *ifname);
int dvmrp_show_neighbors (uii_connection_t *uii, int numopt, char *ifname);

#endif /* HAVE_MROUTING*/
#endif /* _DVMRP_H */

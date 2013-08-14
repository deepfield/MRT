/* 
 * $Id: rib.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _RIB_H
#define _RIB_H

#include <stack.h>
#include <trace.h>
#include <radix.h>

#include <proto.h>
#include <interface.h>
#include <aspath.h>
#include <mrt_thread.h>

#ifdef notdef
/*
 * "State" of routing table entry.
 */
#define	RTS_ACTIVE		0x0100	/* Route is active */
#define RTS_INTERIOR    	0x08	/* an interior route */
#define RTS_EXTERIOR    	0x10	/* an exterior route */
#define	RTS_HOLDDOWN		0x20	/* Route is held down */


#define	RTS_DELETE		0x40	/* Route is deleted */
#define	RTS_FREE		0x80	/* Route memory scheduled for free */
#endif

#define CONNECTED_PREF		0
#define STATIC_PREF		1
#define BGP_PREF		20
#define EBGP_PREF		20
#define OSPF_PREF		110
#define RIP_PREF		120
#define RIPNG_PREF		120
#define IBGP_PREF		200
#define KERNEL_PREF		250
#define HOLD_PREF		255
#define NO_PREF			255

#define MRT_RTOPT_SUPPRESS      0x01
#define MRT_RTOPT_AGGREGATE     0x02
#define MRT_RTOPT_NOINSTALL     0x04
#define MRT_RTOPT_KERNEL 	0x08	/* this route is in kernel also */
#define MRT_RTOPT_UP	        0x10

struct _route_head_t;
typedef struct _route_node_t {
    struct _route_head_t *route_head;	/* pointer back to our route_head */
    /* int state; */		/* mask of state flags */
    int pref;			/* ripe181 - as_in preference */
    int protocol_mask;		/* bit mask of protocols using this route */
    generic_attr_t *attr;
    time_t time;		/* time last updated (as in RIP) */
    u_long flags;
} route_node_t;


typedef struct _route_head_t {
    prefix_t *prefix;
    route_node_t *active;	/* a pointer to best, or active route_node */
    LINKED_LIST *ll_route_nodes;
    /* u_long change_flag; */
    radix_node_t *radix_node;
} route_head_t;


/*
 * Change is routing table entry
 */
#define	RTCF_NEXTHOP	0x01	/* Next hop change */
#define	RTCF_METRIC	0x02	/* Metric change */
#define	RTCF_METRIC2	0x04	/* Metric change */
#define	RTCF_ASPATH	0x08	/* AS path change */
#define	RTCF_TAG	0x10	/* Tag change */

/*
typedef int (*kernel_update_route_t) (int cmd, prefix_t *dest,
              prefix_t *next_hop, prefix_t *old_hop, int index, int oldindex);
*/


typedef struct _rib_t {
    pthread_mutex_t mutex_lock;
    radix_tree_t *radix_tree;
    int afi;
    int safi;
#ifdef notdef
    HASH_TABLE *hash;
#endif
    trace_t *trace;
    LINKED_LIST *ll_changed_route_nodes;
    /* proto_update_route_t proto_update_route[PROTO_MAX]; */
    /* kernel_update_route_t kernel_update_route; */
    /* publish static, kernel, and conncted routes to other protocols */
    u_long redistribute_mask[PROTO_MAX + MAX_BGP_VIEWS + 1];
    u_long ll_networks_mask[PROTO_MAX + MAX_BGP_VIEWS + 1];
    LINKED_LIST *ll_networks[PROTO_MAX + MAX_BGP_VIEWS + 1];

#ifdef notdef
    int lock;		/* table is LOCKED -- do not modify while set */
    LINKED_LIST *ll_route_nodes; /* delete this ? */
    void *user;		/* hook for program or user specific data */
#endif
    int num_active_routes;
    int num_active_nodes;
    time_t time;	/* last time any active was updated */
    time_t nexthop_last_time;	/* last time nexthop was checked */
} rib_t;

/* types returned by ret in rm_insert on addition to radix tree */
enum RM_RETURN_TYPES {
    RM_ROUTE_ALREADY_EXISTS,
    RM_ROUTE_LOWER_PREF,
    RM_ROUTE_BEST_PREF,
    RM_ROUTE_SAME_PREF,
    RM_NO_ACTIVE_ROUTE
};


#define RIB_RADIX_WALK(Xview, Xroute_head) \
        do { \
            radix_node_t *Xnode; \
            RADIX_WALK (Xview->radix_tree->head, Xnode) { \
                Xroute_head = RADIX_DATA_GET (Xnode, route_head_t);

#define RIB_RADIX_WALK_END \
            } RADIX_WALK_END; \
        } while (0)


rib_t * New_Rib (int maxbitlen);
void rib_open (rib_t * rib);
void rib_close (rib_t * rib);

generic_attr_t *New_Generic_Attr (int proto);
generic_attr_t *Ref_Generic_Attr (generic_attr_t * attr);
void Deref_Generic_Attr (generic_attr_t * attr);

route_node_t *rib_add_route (rib_t *rib, prefix_t *prefix, 
		             generic_attr_t *attr, int pref, u_long flags);
int rib_del_route (rib_t * rib, prefix_t * prefix, generic_attr_t * attr);

void rib_show_route_head (uii_connection_t *uii, char *append);

int show_rib_status (uii_connection_t *uii);
void rib_show_route_line (uii_connection_t *uii, int c1, int c2, int type, 
	int pref, int elapsed, prefix_t *prefix, prefix_t *nexthop, 
	interface_t *interface, char *append);
void delete_all_route_with_type (int family, int type);

void init_rib (trace_t * tr);
void rib_update_route (prefix_t *prefix, generic_attr_t *new_attr,
                       generic_attr_t *old_attr, int pref, u_long flags, 
		       int safi);
int add_route_to_rib (int type, prefix_t *prefix, prefix_t *nexthop,
                  interface_t *interface, int pref);
int del_route_from_rib (int type, prefix_t *prefix);
int show_ip_routes (uii_connection_t * uii, char *cmd);
int trace_rib (uii_connection_t * uii, char *s);
int no_trace_rib (uii_connection_t * uii, char *s);
int trace_ip_rib (uii_connection_t *uii);
#ifdef HAVE_IPV6
int trace_ipv6_rib (uii_connection_t *uii);
#endif /* HAVE_IPV6 */

extern rib_t *RIB;
extern rib_t *RIBS[AFI_MAX][SAFI_MAX];
extern rib_t *RIBm;
extern rib_t *RIBv6;
extern rib_t *RIBv6m;
#ifdef HAVE_IPV6
int show_ipv6_routes (uii_connection_t * uii, char *cmd);
#endif /* HAVE_IPV6 */

#endif /* _RIB_H */

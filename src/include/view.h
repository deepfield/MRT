/*
 * $Id: view.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _VIEW_H
#define _VIEW_H

#include <stack.h>
#include <trace.h>
#include <hash.h>
#include <radix.h>
#include <mrt_thread.h>
#include <aspath.h>

/* 0 -- ip unicast, 1 -- ipv6 unicast, 2 -- ip multicast, 3 -- ipv6 multi */
#define BGP_VIEW_RESERVED 4

struct _bgp_route_head_t;

typedef struct _bgp_route_t {
    struct _bgp_route_head_t *head;	/* pointer back to our route_head */
    bgp_attr_t *attr;
    time_t time;
    u_short weight;			/* administrative weight */
    u_short flags;
} bgp_route_t;


typedef struct _bgp_route_in_t {
    bgp_attr_t *attr;
    bgp_bitset_t view_mask;	/* mask of views this route is accepted */
    time_t time;
} bgp_route_in_t;

#define BGP_RT_AGGREGATED 0x01

#define BGP_ORIGINATE_WEIGHT 32768
#define BGP_DEFAULT_WEIGHT 0

/* state bits */
#define VRTS_DELETE	 0x01	/* about to be deleted -- route is withdrawn */
#define VRTS_ACTIVE	 0x02
#define VRTS_CHANGE	 0x04
#define VRTS_SUPPRESS	 0x08
#define VRTS_SUMMARY	 0x10
#define VRTS_NO_INSTALL	 0x20
#define VRTS_HOLD	 0x40   /* removing it from active after withdraw */

/* the change bits explain what caused the change in state */
typedef struct _bgp_route_head_t {
    u_long state_bits;		/* active, holddown, withdrawn */
    /* u_long   change_bits;    new, change, withdrawn */
    bgp_bitset_t peer_mask;	/* mask of peers we sent this route to */
    bgp_bitset_t view_mask;	/* mask of views we are sending this route */
    prefix_t *prefix;
    bgp_route_t *active;	/* a pointer to best, or active route_node */
    /* bgp_route_t *last_active; *//* a pointer to last active route_node */
    LINKED_LIST *ll_routes;
    LINKED_LIST *ll_imported;	/* a pointer to imported route */
    radix_node_t *radix_node;
    time_t rtime;	/* last time next-hop was resolved */
} bgp_route_head_t;


#define BGP_AGGOPT_AS_SET 0x01
#define BGP_AGGOPT_SUMMARY_ONLY 0x02

typedef struct _aggregate_t {
    prefix_t *prefix;
    bgp_attr_t *attr;
    u_long option;
    radix_node_t *radix_node;
    bgp_route_t *route;
} aggregate_t;


typedef struct _view_t {
    pthread_mutex_t mutex_lock;
    int afi;
    int safi;
    int viewno;
    int explicit;

    radix_tree_t *radix_tree;
    trace_t *trace;
    LINKED_LIST *ll_ann_routes;	/* changed routed heads */
    LINKED_LIST *ll_with_routes;	/* deleted routed heads */
    /* void *user;               hook for program or user specific data */
    /* HASH_TABLE               peer_hash[MAX_BGP_PEERS]; */
    bgp_local_t *local_bgp;     /* local bgp session */

    radix_tree_t *agg_tree;

    LINKED_LIST *ll_networks;
#define DEFAULT_LOCAL_PREF 100
    int default_local_pref;
    u_long redistribute_mask;

    int lineno;
    char *filename;
    time_t utime;	/* time last update for next-hop checks */
    int doing;		/* doing nexthop processing */

    int num_bgp_routes;
    int num_imp_routes;
    int num_bgp_heads;
} view_t;

#define VIEW_RADIX_WALK(Xview, Xroute_head) \
	do { \
	    radix_node_t *Xnode; \
	    RADIX_WALK (Xview->radix_tree->head, Xnode) { \
		Xroute_head = RADIX_DATA_GET (Xnode, bgp_route_head_t);

#define VIEW_RADIX_WALK_END \
	    } RADIX_WALK_END; \
	} while (0)


typedef struct _update_bucket_t {
    LINKED_LIST *ll_prefix;
    bgp_attr_t *attr;
    /* nexthop_t *nexthop; */
    int safi;
    int prefix_depend;
} update_bucket_t;

void delete_update_bucket (update_bucket_t * update_bucket);

/* public functions */
view_t *New_View (trace_t *tr, int viewno, int afi, int safi);
void Destroy_View (view_t *view);
#ifdef notdef
int view_close (view_t * view);
int view_open (view_t * view);
#endif

bgp_route_t *
bgp_add_route (view_t * view, prefix_t * prefix, bgp_attr_t * attr);
int bgp_del_route (view_t * view, prefix_t * prefix, bgp_attr_t * attr);
void bgp_update_route (prefix_t * prefix, generic_attr_t * new_attr,
		      generic_attr_t * old_attr, int pref, int viewno);
bgp_route_t *view_find_bgp_active (view_t * view, prefix_t * prefix);
prefix_t *view_find_best_route (view_t * view, prefix_t * prefix);
int bgp_process_changes (view_t * view);
int process_bgp_update (bgp_peer_t * peer, u_char * cp, int length);

aggregate_t *
  view_add_aggregate (view_t * view,
		      prefix_t * prefix, u_long opt);
int view_del_aggregate (view_t * view, prefix_t * prefix);
void view_eval_aggregate (view_t *view, void (*fn) (), void *arg);

void bgp_establish_peer (bgp_peer_t * peer, int force_announce, int viewno);
void view_delete_peer (view_t * view, bgp_peer_t * peer);
void bgp_re_evaluate_in (bgp_peer_t * peer, int viewno);
void view_eval_nexthop (int viewno);
int bgp_nexthop_avail (bgp_attr_t *attr);

int show_view (uii_connection_t * uii, int view);
int trace_bgp_view (uii_connection_t * uii, char *s);
int no_trace_bgp_view (uii_connection_t * uii, char *s);
int trace_f_bgp (uii_connection_t * uii, int family);

void bgp_redistribute_request (int from, int to, int on);

#define view_close(view) {\
    pthread_mutex_unlock (&view->mutex_lock); \
    view->lineno = __LINE__; \
    view->filename = __FILE__; \
    trace (TR_DEBUG, view->trace, "closed at %d in %s\n", __LINE__, __FILE__);\
}

 
#define view_open(view) {\
    if (pthread_mutex_trylock (&view->mutex_lock) != 0) { \
        trace (TR_DEBUG, view->trace, \
	       "open blocked at %d in %s by %d in %s\n", __LINE__, __FILE__, \
	       view->lineno, view->filename); \
        pthread_mutex_lock (&view->mutex_lock); \
    } \
    view->lineno = __LINE__; \
    view->filename = __FILE__; \
    trace (TR_DEBUG, view->trace, "opened at %d in %s\n", __LINE__, __FILE__);\
}       

#endif /* _VIEW_H */

/*
 * $Id: cache.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _CACHE_H
#define _CACHE_H

#if defined(HAVE_MROUTING) || defined(HAVE_MROUTING6)

typedef struct _cache_t {
    int family;
    HASH_TABLE *hash;
    trace_t *trace;
    int_fn_t update_call_fn;
    schedule_t *schedule;
    mtimer_t *expire;
} cache_t;


#ifdef HAVE_MROUTING
extern cache_t *CACHE;
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
extern cache_t *CACHE6;
#endif /* HAVE_MROUTING6 */

#define CACHE_TABLE_HASH_SIZE 1023
#define CACHE_UPDATE_INTERVAL 10

#define DEFAULT_CACHE_LIFETIME  300     /* kernel route entry discard time  */
#define MIN_CACHE_LIFETIME      60      /* minimum allowed cache lifetime   */

#define CACHE_DELETE 0x01
#define CACHE_NEGATIVE 0x02
#define CACHE_PIM_PRUNE 0x04
#define CACHE_PIM_GRAFT 0x08

typedef struct _cache_entry_t {
    prefix_t *source; /* this must be here (see prefix_pait_t) */
    prefix_t *group; /* this must be here (see prefix_pait_t) */
    interface_t *parent; /* incoming interface */
    int parent_index;    /* RPF nexthop (pim) */
    interface_bitset_t children; /* direct members */
    interface_bitset_t routers;	/* routers (pim) */
    int count;
    int holdtime;
    time_t ctime;
    time_t expire;
    u_long flags;
    u_int use;
    u_int lastuse;
    LINKED_LIST *ll_prunes;	/* used in dvmrp and pim */
    LINKED_LIST *ll_joins;	/* used in pim */
    void *data;		/* pointer to route entry (dvmrp only?) */
} cache_entry_t;


void cache_update_mfc (cache_entry_t *entry);
cache_entry_t * cache_lookup (prefix_t *source, prefix_t *group);
void cache_update_to_leaf (int proto, int index);
void cache_update_to_router (int proto, int index);
void cache_update_to_down (int proto, int index);
void cache_update_parent_up (int proto, int index);
void cache_update_parent_down (int proto, int index);

cache_t *proto2cache (int proto);
void cache_init (int family, trace_t * tr);
int cache_control_from_kernel (int type, prefix_t *group, prefix_t *source,
                               interface_t *parent, int n);
int show_cache_entries (uii_connection_t * uii, int family, char *ifname);

#endif /* HAVE_MROUTING || HAVE_MROUTING6 */
#endif /* _CACHE_H */

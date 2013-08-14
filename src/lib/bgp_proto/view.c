/*
 * $Id: view.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <ctype.h>
#include <mrt.h>
#include <config_file.h>
#include <bgp.h>

#ifdef NT
#include <ntconfig.h>
#include <winsock2.h>
#ifdef HAVE_IPV6
#include <ws2ip6.h>
#endif /* HAVE_IPV6 */
#include <ws2tcpip.h>
#endif /* NT */


static bgp_route_t *
bgp_add_route2 (view_t * view, prefix_t * prefix, bgp_attr_t * attr, 
		int weight, u_long flags);
static void
bgp_pick_best (view_t * view, bgp_route_head_t * bgp_route_head, int force);
static aggregate_t *
view_check_aggregate (view_t * view, prefix_t *prefix, int withdraw);
static void
view_setup_attr (view_t *view, bgp_peer_t *peer, bgp_attr_t *attr,
                 LINKED_LIST *ll_ann_prefixes);
static int view_announce_peer (view_t *view, bgp_peer_t * peer);


int
bgp_nexthop_avail (bgp_attr_t *attr)
{
    if (!BIT_TEST (attr->options, BGP_INTERNAL|BGP_PEER_SELF|
				  BGP_EBGP_MULTIHOP))
	return (TRUE);
    return (attr->direct != NULL);
}


static generic_attr_t *
bgp2gen (bgp_attr_t *attr)
{
    generic_attr_t *gattr;

    if (attr == NULL)
	return (NULL);
    if (BIT_TEST (attr->options, BGP_EBGP_MULTIHOP) ||
	 BIT_TEST (attr->options, BGP_PEER_SELF) ||
	 BIT_TEST (attr->options, BGP_INTERNAL)) {
	if (attr->direct == NULL) {
      	    trace (TR_ERROR, BGP->trace, 
	       "next-hop unknown: nh %a proto %r via %s on %s\n",
	       attr->nexthop->prefix, attr->type, 
	       (attr->direct)? prefix_toa (attr->direct->prefix): "n/a",
	       (attr->direct && attr->direct->interface)? 
		  attr->direct->interface->name: "?");
	    return (NULL);
	}
    }
    gattr = New_Generic_Attr (attr->type);
    gattr->gateway = attr->gateway;

    if (BIT_TEST (attr->options, BGP_EBGP_MULTIHOP) ||
	 BIT_TEST (attr->options, BGP_PEER_SELF) ||
	 BIT_TEST (attr->options, BGP_INTERNAL)) {
	assert (attr->direct);
	gattr->parent = ref_nexthop (attr->nexthop);
	gattr->nexthop = ref_nexthop (attr->direct);
    }
#ifdef HAVE_IPV6
    else if (attr->link_local) {
        gattr->nexthop = ref_nexthop (attr->link_local);
    }
#endif /* HAVE_IPV6 */
    else {
	assert (attr->nexthop);
        gattr->nexthop = ref_nexthop (attr->nexthop);
    }
    return (gattr);
}


void static
bgp_rt_update_call (view_t *view, prefix_t * prefix, 
		    bgp_attr_t * new, bgp_attr_t * old)
{
    generic_attr_t *gnew;
    generic_attr_t *gold;
    int pref = BGP_PREF;
    u_long flags = 0;

    assert (prefix);

    if (new == NULL && old == NULL)
	return;
    if (MRT->rib_update_route == NULL)
        return;
    if (view->viewno >= BGP_VIEW_RESERVED)
	return;

    /* check to see if iBGP */
    if (new && BIT_TEST (new->options, BGP_INTERNAL)) {
	BIT_SET (flags, MRT_RTOPT_SUPPRESS);
	pref = IBGP_PREF;
    }
    gnew = bgp2gen (new);
    gold = bgp2gen (old);

    if (gnew || gold)
        MRT->rib_update_route (prefix, gnew, gold, pref, flags, 
			       view->safi);

    Deref_Generic_Attr (gnew);
    Deref_Generic_Attr (gold);
}


typedef struct { 
    prefix_t *prefix; 
    nexthop_t *nexthop; 
} bgp_nexthop_cache_t;


static void
bgp_delete_nexthop_cache (bgp_nexthop_cache_t *nexthop_cache)
{
    Deref_Prefix (nexthop_cache->prefix);
    deref_nexthop (nexthop_cache->nexthop);
    Delete (nexthop_cache);
}


static void
bgp_resolve_nexthop (bgp_attr_t *attr)
{
    nexthop_t *nexthop;
    bgp_nexthop_cache_t *nexthop_cache;

    if (MRT->rib_find_best_route == NULL)
	return;
    assert (attr->type == PROTO_BGP);
    if (!BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP))
	return;
    assert (attr->nexthop);

    if (!BIT_TEST (attr->options, BGP_EBGP_MULTIHOP|BGP_PEER_SELF|
				  BGP_INTERNAL))
	return;

    if (BGP->nexthop_hash_table == NULL) {
        bgp_nexthop_cache_t nexthop_cache_x;
#define BGP_NEXTHOP_HASH_SIZE 1023
        BGP->nexthop_hash_table = HASH_Create (BGP_NEXTHOP_HASH_SIZE,
                             HASH_KeyOffset,
                             HASH_Offset (&nexthop_cache_x, 
					  &nexthop_cache_x.prefix),
                             HASH_LookupFunction, ip_lookup_fn,
                             HASH_HashFunction, ip_hash_fn,
                             HASH_DestroyFunction, bgp_delete_nexthop_cache,
                             NULL);
    }
    nexthop_cache = HASH_Lookup (BGP->nexthop_hash_table, 
				 attr->nexthop->prefix);
    if (nexthop_cache == NULL) {
	interface_t *interface;

        nexthop_cache = New (bgp_nexthop_cache_t);
        nexthop_cache->prefix = Ref_Prefix (attr->nexthop->prefix);

	/* since rib_find_best_route doesn't return the type of route,
	   so I need to check interface route first in this way */
	interface = find_interface (attr->nexthop->prefix);
#ifdef NT
	/* a horrible, horrible hack 
	 * we need to pretend that MRTd did not find the interface so it will use the routing
	 * table to discover the IPv4 mapped ::198.108.0.3 address
	 * Otherwise, since it heard 3ffe:1cdb::3 on intf2, it will think it can use this
	 * address on that interface. Yuck.
	 */
	if ((interface->index == 2) && (!prefix_is_v4mapped (attr->nexthop->prefix)))
		interface = NULL;
#endif /* NT */



	if (interface == NULL || !BIT_TEST (interface->flags, IFF_UP)) {
	    interface = find_interface_local (attr->nexthop->prefix);
	    if (interface && !BIT_TEST (interface->flags, IFF_UP))
		interface = NULL;
	}

	if (interface != NULL) {
           /* direct interface route -- use it as it is with the interface */
            nexthop_cache->nexthop = add_nexthop (attr->nexthop->prefix, 
						  interface);
	}
	else {
            nexthop_cache->nexthop = 
		MRT->rib_find_best_route (attr->nexthop->prefix, SAFI_UNICAST);
            nexthop_cache->nexthop = ref_nexthop (nexthop_cache->nexthop);
	}
        HASH_Insert (BGP->nexthop_hash_table, nexthop_cache);
    }

    nexthop = nexthop_cache->nexthop;
	//printf ("CHL %s\n", prefix_toax (nexthop->prefix));
    if (nexthop != attr->direct) {
      trace (TR_TRACE, BGP->trace, 
	     "next-hop resolved: nh %a proto %r via %s on %s -> %s on %s\n",
	     attr->nexthop->prefix, attr->type, 
	     (attr->direct)? prefix_toa (attr->direct->prefix): "n/a",
	     (attr->direct && attr->direct->interface)? 
		attr->direct->interface->name: "?",
	     (nexthop)? prefix_toa (nexthop->prefix): "n/a",
	     (nexthop && nexthop->interface)? 
		nexthop->interface->name: "?");
    }

    deref_nexthop (attr->direct);
    attr->direct = ref_nexthop (nexthop_cache->nexthop);
}


static bgp_route_t *
New_Bgp_Route (view_t *view, bgp_route_head_t * bgp_route_head, 
	       bgp_attr_t * attr, int weight, u_long flags)
{
    bgp_route_t *route = New (bgp_route_t);

    route->head = bgp_route_head;
    assert (weight >= 0);
    route->weight = weight;
    route->attr = bgp_ref_attr (attr);
    route->flags = flags;

    /* this is actually pretty expensive call... what to do??? */
    time (&route->time); 

    BGP->bgp_num_active_route_node++;

    /* only bother converting to ASCII if tracing, otherwise it can be
     * really slow under bgpsim 
     */
      trace (TR_TRACE, BGP->trace, 
	     "New Route: %p nh %a proto %r weight %d flags 0x%x\n",
	     bgp_route_head->prefix,
	     attr->nexthop->prefix, attr->type, weight, flags);
    if (attr->type == PROTO_BGP) {
        if (BIT_TEST (attr->options, BGP_INTERNAL|BGP_PEER_SELF|
				     BGP_EBGP_MULTIHOP))
	    bgp_resolve_nexthop (attr);
        LL_Add (bgp_route_head->ll_routes, route);
	view->num_bgp_routes++;
    }
    else {
        LL_Add (bgp_route_head->ll_imported, route);
	view->num_imp_routes++;
    }
    return (route);
}


static void 
Delete_Bgp_Route (bgp_route_t * rt_node)
{

    trace (TR_TRACE, BGP->trace, "Delete Route: %p nh %a proto %r\n",
	   rt_node->head->prefix,
	   rt_node->attr->nexthop->prefix,
	   rt_node->attr->type);
    bgp_deref_attr (rt_node->attr);
    Delete (rt_node);
    BGP->bgp_num_active_route_node--;
}


static int
bgp_compare_routes (bgp_route_t * a, bgp_route_t * b)
{

    int a1, a2;

    if (bgp_nexthop_avail (a->attr) &&
       !bgp_nexthop_avail (b->attr))
	return (-1);
    if (!bgp_nexthop_avail (a->attr) &&
         bgp_nexthop_avail (b->attr))
	return (1);

    /* these values may be u_long, so I can't subtract them to compare */

    /* larger administrative weight wins */
    if (a->weight > b->weight)
	return (-1);
    if (a->weight < b->weight)
	return (1);

    /* tie breaking */

#ifdef notdef
    /* smaller pref2 wins */
    if (a->pref2 < b->pref2)
	return (-1);
    if (a->pref2 > b->pref2)
	return (1);
#endif

    /* check local preference */
    if (BGP4_BIT_TEST (a->attr->attribs, PA4_TYPE_LOCALPREF) &&
        BGP4_BIT_TEST (b->attr->attribs, PA4_TYPE_LOCALPREF)) {

        /* higer local_pref wins */
        if (a->attr->local_pref < b->attr->local_pref)
	    return (1);
        if (a->attr->local_pref > b->attr->local_pref)
	    return (-1);
    }

    /* shorter aspath wins */
    a1 = aspath_length (a->attr->aspath);
    a2 = aspath_length (b->attr->aspath);
    if (a1 < a2)
	return (-1);
    if (a1 > a2)
	return (1);

    /* lower origin code wins */
    if (a->attr->origin < b->attr->origin)
	return (-1);
    if (a->attr->origin > b->attr->origin)
	return (1);

    /* XXX should be configurable */
    /* lower metric wins */
    if (a->attr->multiexit < b->attr->multiexit)
        return (-1);
    if (a->attr->multiexit > b->attr->multiexit)
	return (1);

    if (a->attr->gateway && b->attr->gateway) {
        /* smaller routerid wins */
        if (ntohl (a->attr->gateway->routerid) < 
		ntohl (b->attr->gateway->routerid))
	    return (-1);
        if (ntohl (a->attr->gateway->routerid) > 
		ntohl (b->attr->gateway->routerid))
	    return (1);
    }

    return (0);
}


static bgp_route_head_t *
New_Bgp_Route_Head (view_t *view, prefix_t * prefix)
{
    bgp_route_head_t *route_head;

    assert (prefix);
    route_head = New (bgp_route_head_t);
    route_head->prefix = Ref_Prefix (prefix);
    route_head->ll_routes = LL_Create (LL_DestroyFunction, Delete_Bgp_Route, 
				       LL_CompareFunction, bgp_compare_routes,
                                       LL_AutoSort, True, 0);
    route_head->active = NULL;
    route_head->ll_imported = LL_Create (LL_DestroyFunction, Delete_Bgp_Route, 
				         LL_CompareFunction, bgp_compare_routes,
                                         LL_AutoSort, True, 0);
    BGP->bgp_num_active_route_head++;
    view->num_bgp_heads++;

    trace (TR_TRACE, BGP->trace, "Add Route Head: %p\n", prefix);
    return (route_head);
}


static void 
Delete_Bgp_Route_Head (bgp_route_head_t * head)
{
    /* This has done in view_delete_bgp_route */
    trace (TR_TRACE, BGP->trace, "Delete Route Head: %p\n", head->prefix);
    assert (LL_GetCount (head->ll_imported) <= 0);
    LL_Destroy (head->ll_imported);
    assert (LL_GetCount (head->ll_routes) <= 0);
    LL_Destroy (head->ll_routes);
    Deref_Prefix (head->prefix);
    Delete (head);
    BGP->bgp_num_active_route_head--;
}


static update_bucket_t *
New_Update_Bucket (int safi)
{
    update_bucket_t *bucket = New (update_bucket_t);

    /* NOTE: update bucket memory belongs to view */
    bucket->ll_prefix = LL_Create (LL_DestroyFunction, Deref_Prefix, 0);
    bucket->attr = NULL;
    bucket->safi = safi;
    return (bucket);
}


void 
delete_update_bucket (update_bucket_t * update_bucket)
{
    assert (update_bucket);
    assert (update_bucket->ll_prefix);
    LL_Destroy (update_bucket->ll_prefix);
    if (update_bucket->attr)
        bgp_deref_attr (update_bucket->attr);
    Delete (update_bucket);
}


static bgp_route_head_t *
view_find_route_head (view_t * view, prefix_t * prefix)
{
    radix_node_t *radix_node;

    radix_node = radix_search_exact (view->radix_tree, prefix);
    if (radix_node) {
	assert (radix_node->data);
	return (RADIX_DATA_GET (radix_node, bgp_route_head_t));
    }
    return (NULL);
}


static void
view_remove_route_head (view_t * view, bgp_route_head_t * route_head)
{
    assert (route_head->radix_node);
    assert (RADIX_DATA_GET (route_head->radix_node, bgp_route_head_t)
	    == route_head);
    view->num_bgp_routes -= LL_GetCount (route_head->ll_routes);
    view->num_imp_routes -= LL_GetCount (route_head->ll_imported);
    view->num_bgp_heads--;
    radix_remove (view->radix_tree, route_head->radix_node);
}


#ifdef notdef
static bgp_route_t *
bgp_find_best_route (bgp_route_head_t * bgp_route_head)
{

    bgp_route_t *best = NULL, *route;

    /* find new active route */
    LL_Iterate (bgp_route_head->ll_routes, route) {

	/* no best */
	if (best == NULL) {
	    best = route;
	    continue;
	}

	if (bgp_compare_routes (route, best) < 0) {
	    best = route;
	    continue;
	}

    }
    return (best);
}
#endif


static int
view_add_ll_list (view_t *view, bgp_route_head_t *bgp_route_head, int withdraw)
{
  /* bgp_route_head_t *rh; */
    LINKED_LIST *ll;

    assert (view);
    assert (bgp_route_head);

    ll = (withdraw)? view->ll_with_routes: view->ll_ann_routes;

#ifdef notdef
    LL_Iterate (ll, rh) {
	if (rh == bgp_route_head) {
	    /* this is warning for a while to check out this */
	    trace (TR_WARN, view->trace,
		   "Duplicate %s prefix: %p\n",
		   (withdraw)? "withdraw": "announce",
		   bgp_route_head->prefix);
	    if (withdraw)
		return (0);
	    LL_RemoveFn (ll, rh, NULL);
	    break;
	}
    }
#else
    if (BITX_TEST (&bgp_route_head->view_mask, view->viewno) != 0) {

      trace (TR_WARN, view->trace,
	     "Duplicate %s prefix: %p\n",
	     (withdraw)? "withdraw": "announce",
	     bgp_route_head->prefix);
      if (withdraw)
	return (0);
      LL_RemoveFn (ll, bgp_route_head, NULL);
    }
    else {
        BITX_SET (&bgp_route_head->view_mask, view->viewno);
    }
#endif
    /* we could check withdraw list because implicit withdraw is OK */
    LL_Append (ll, bgp_route_head);
    return (1);
}


static int
view_add_change_list (view_t * view, bgp_route_head_t * bgp_route_head,
		      int withdraw)
{
    aggregate_t *agg;

    agg = view_check_aggregate (view, bgp_route_head->prefix, withdraw);
    if (agg) {
        if (BIT_TEST (agg->option, BGP_AGGOPT_SUMMARY_ONLY)) {
	    BIT_SET (bgp_route_head->state_bits, VRTS_SUPPRESS);
	    
	      trace (TR_TRACE, view->trace,
		     "Change: %p (but suppressed by %p)\n",
		     bgp_route_head->prefix, agg->prefix);
	    return (-1);
        }
    }

    /* add the route head to the change list */
    view_add_ll_list (view, bgp_route_head, withdraw);
    
      trace (TR_TRACE, view->trace, "Change: %p (%s)\n",
	     bgp_route_head->prefix,
	     (withdraw) ? "withdraw" : "announce");

    return (1);
}


/* 
 * delete a route from view. If active route, set change list
 * and modify route_head
 */
static void
view_delete_bgp_route (view_t * view, bgp_route_t * bgp_route)
{
    bgp_route_head_t *bgp_route_head;
    bgp_route_t *old_best, *new_best;
    bgp_route_t *route;
    bgp_route_t *best = NULL;

    assert (bgp_route->attr->type == PROTO_BGP);
    best = NULL;
    bgp_route_head = bgp_route->head;
    old_best = LL_GetHead (bgp_route_head->ll_routes);
    if (old_best && !bgp_nexthop_avail (old_best->attr))
	old_best = NULL;

    /* this seach is for check only */
    LL_Iterate (bgp_route_head->ll_routes, route) {
	if (route == bgp_route)
	    break;
    }
    assert (route != NULL);

    /* remove from list in any case without destroying it */
    LL_RemoveFn (bgp_route_head->ll_routes, bgp_route, NULL);
    view->num_bgp_routes--;

    if (old_best == NULL) {
	/* nothing worry about */
        Delete_Bgp_Route (bgp_route);
	return;
    }

    /* we were NOT the best route - just delete */
    if (old_best != bgp_route) {
        Delete_Bgp_Route (bgp_route);
	return;
    }

    /* we were the best route in BGP */
    new_best = LL_GetHead (bgp_route_head->ll_routes);
    if (new_best && !bgp_nexthop_avail (new_best->attr))
	new_best = NULL;

    if (new_best != NULL) {
	bgp_rt_update_call (view, bgp_route_head->prefix,
			    new_best->attr, NULL);
    }
    else {
	bgp_rt_update_call (view, bgp_route_head->prefix,
			    NULL, old_best->attr);
    }

    /* we are removing so it's ok if it is not active */
    if (bgp_route_head->active != bgp_route) {
        Delete_Bgp_Route (bgp_route);
        return;
    }

    /* It was the active route -- need to send updates */
    /* the memory (active) has to be freed later */
    BIT_SET (bgp_route_head->state_bits, VRTS_DELETE);
    bgp_pick_best (view, bgp_route_head, 0);
}


/*
 * this will be called from rib, that is, they are called from
 * other threads. Schedule it.
 */

static void
bgp_import (prefix_t * prefix, bgp_attr_t * bgp_new, bgp_attr_t * bgp_old,
	    int viewno)
{
    view_t *view;

    assert (bgp_new == NULL || bgp_new->type != PROTO_BGP);
    assert (bgp_old == NULL || bgp_old->type != PROTO_BGP);

    if (bgp_new == NULL && bgp_old == NULL)
	return;

    view = BGP->views[viewno];
    if (view == NULL)
	return;
    /* deleted view */
    if (view->local_bgp == NULL)
	return;

    assert (view->afi == family2afi (prefix->family));

    view_open (view);

    if (bgp_old) {
	bgp_del_route (view, prefix, bgp_old);
    }

    if (bgp_new) {
	bgp_add_route (view, prefix, bgp_new);
    }

    bgp_process_changes (view);
    view_close (view);

    Deref_Prefix (prefix);
    if (bgp_new) {
	bgp_deref_attr (bgp_new);
    }
    if (bgp_old) {
	bgp_deref_attr (bgp_old);
    }
}


/* put all announce routes into peer->ll_update_out */
/* attributes are ready for send */
/* kick view_announce_peer() if needed */
static void
view_build_update_buckets (view_t *view, bgp_peer_t *peer, 
			   LINKED_LIST *ll_routes)
{
    LINKED_LIST *ll_update_buckets = LL_Create (0);
    update_bucket_t *update_bucket, *last_backet = NULL;
    bgp_route_t *route;

    LL_Iterate (ll_routes, route) {
	int found = 0;
	int prefix_depend = 0;

	if (peer->filters[view->viewno].route_map_out >= 0 &&
	    apply_route_map_alist (peer->filters[view->viewno].route_map_out, 
				    route->head->prefix)) {
	    prefix_depend++;
	}
	else {
	    update_bucket_t *last = NULL;
	    /* prefix independent route-map */
    	    /* replace this with a hash, or something a bit more reasonable */
	    LL_Iterate (ll_update_buckets, update_bucket) {
		if (update_bucket->prefix_depend)
		    continue;
	        if (update_bucket->attr == route->attr) {
		    LL_Add (update_bucket->ll_prefix,
			    Ref_Prefix (route->head->prefix));
		    found++;
		    break;
	        }
		last = update_bucket;
	    }
	    if (!found && last) {
		/* only check with the last bucket not to spend long time */
		if (bgp_compare_attr (last->attr, route->attr) > 0) {
		    LL_Add (last->ll_prefix,
			    Ref_Prefix (route->head->prefix));
		    found++;
		}
	    }
	}

	if (found == 0) {
	    update_bucket = New_Update_Bucket (view->safi);
	    update_bucket->attr = bgp_ref_attr (route->attr);
	    update_bucket->prefix_depend = prefix_depend;
	    LL_Add (ll_update_buckets, update_bucket);
	    LL_Add (update_bucket->ll_prefix,
		    Ref_Prefix (route->head->prefix));
	}
    }

    /* apply view_setup_attr() */
    LL_Iterate (ll_update_buckets, update_bucket) {
	bgp_attr_t *attr;
	attr = bgp_copy_attr (update_bucket->attr);
        bgp_deref_attr (update_bucket->attr);
	update_bucket->attr = attr;
	view_setup_attr (view, peer, attr, update_bucket->ll_prefix);
	if (update_bucket->prefix_depend && last_backet != NULL) {
	    /* route-map with match ip address */
	    /* only check with the last bucket not to spend long time */
	    if (bgp_compare_attr (last_backet->attr, 
		    update_bucket->attr) > 0) {
		prefix_t *prefix;
		assert (LL_GetCount (update_bucket->ll_prefix) == 1);
		prefix = LL_GetHead (update_bucket->ll_prefix);
		LL_Add (last_backet->ll_prefix, Ref_Prefix (prefix));
		LL_Remove (ll_update_buckets, update_bucket);
        	delete_update_bucket (update_bucket);
		update_bucket = last_backet;
		continue;
	    }
	}
	LL_Append (peer->ll_update_out, update_bucket);
	if (LL_GetCount (peer->ll_update_out) == 1) {
    	    schedule_event2 ("view_announce_peer", peer->schedule, 
   			     (event_fn_t) view_announce_peer, 2, view, peer);
	}
	last_backet = update_bucket;
    }

    LL_Destroy (ll_update_buckets);
}


/*
 * get "head" of routing table entry for a given prefix. Create a head
 * and radix-tree entry if one does not aleady exist
 */
static bgp_route_head_t *
view_get_route_head (view_t * view, prefix_t * prefix)
{
    bgp_route_head_t *bgp_route_head;
    radix_node_t *radix_node;

    assert (view);
    assert (prefix);
    radix_node = radix_search_exact (view->radix_tree, prefix);

    if (radix_node) {
	assert (radix_node->data);
	bgp_route_head = RADIX_DATA_GET (radix_node, bgp_route_head_t);
    }
    else {
	bgp_route_head = New_Bgp_Route_Head (view, prefix);
	radix_node = radix_lookup (view->radix_tree, prefix);
	assert (radix_node->data == NULL);
	RADIX_DATA_SET (radix_node, bgp_route_head);
	bgp_route_head->radix_node = radix_node;
    }
    return (bgp_route_head);
}


#ifdef notdef
static void
bgp_send_update_schedule (bgp_peer_t * peer, int len, u_char * data)
{
    schedule_event2 ("bgp_send_update", peer->schedule, 
    		      (event_fn_t) bgp_send_update, 3, peer, len, data);
}
#endif


void
view_set_nexthop_self (bgp_peer_t *peer, bgp_attr_t *attr)
{
    if (attr->nexthop) {
	deref_nexthop (attr->nexthop);
	attr->nexthop = NULL;
        BGP4_BIT_RESET (attr->attribs, PA4_TYPE_NEXTHOP);
    }

    attr->nexthop = add_nexthop (peer->local_addr, peer->gateway->interface);
    if (attr->nexthop != NULL) {
        BGP4_BIT_SET (attr->attribs, PA4_TYPE_NEXTHOP);
#ifdef HAVE_IPV6
        if (attr->nexthop->prefix->family == AF_INET6) {

	    if (peer && BIT_TEST (peer->options, BGP_PEER_CISCO)) {
	        /* BGP4+ doesn't require ipv4 nexthop for MP NLRI,
	           but some cisco expects */
                static prefix_t *my_id_prefix = NULL;

                if (my_id_prefix == NULL)
                    my_id_prefix = New_Prefix (AF_INET, 
			    (peer->local_bgp->this_id)? &peer->local_bgp->this_id:
				    &MRT->default_id, 32);
                if (attr->nexthop4)
	            deref_nexthop (attr->nexthop4);
                attr->nexthop4 = add_nexthop (my_id_prefix, find_interface (my_id_prefix));
	    }

            if (attr->link_local)
	        deref_nexthop (attr->link_local);
            if (peer->gateway && peer->gateway->interface &&
	        peer->gateway->interface->link_local &&

/* XXX Pedro's draft says link_local is sent in case the link is shared.
        (1) it's shared if not IFF_POINTOPOINT (ok)
	(2) it's shared if IFF_POINTOPOINT and masklen != 128 (I'm not sure)
	This is required at least by INRIA IPV6 implementation since
	if the nexthop is link-local in the routing table, 
	the source of originated packets may be a link-local. */

	(!BIT_TEST (peer->gateway->interface->flags, IFF_POINTOPOINT) ||
	   (peer->gateway->interface->primary6 &&
	    peer->gateway->interface->primary6->prefix->bitlen != 128)))

	        attr->link_local = 
	            add_nexthop (peer->gateway->interface->link_local->prefix,
				 peer->gateway->interface);
            else
	        attr->link_local = NULL;
	}
#endif /* HAVE_IPV6 */
    }
}


static int
view_attach_reflector_info (bgp_peer_t *peer, bgp_attr_t *attr)
{
    u_long my_cluster_id;

    if (!BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGINATOR_ID)) {
	prefix_t *my_id_prefix;
#ifdef notdef
	my_id_prefix = New_Prefix (AF_INET, &peer->local_bgp->this_as, 32);
#else
    /* use the router id which the route came from 
	-- the originator in this AS */
	my_id_prefix = New_Prefix (AF_INET, &attr->gateway->routerid, 32);
#endif /* notdef */
        attr->originator = my_id_prefix;
        BGP4_BIT_SET (attr->attribs, PA4_TYPE_ORIGINATOR_ID);
    }
    my_cluster_id = (peer->local_bgp->cluster_id)?
			peer->local_bgp->cluster_id: MRT->default_id;
    if (!BGP4_BIT_TEST (attr->attribs, PA4_TYPE_CLUSTER_LIST)) {
	attr->cluster_list = LL_Create (0);
	BGP4_BIT_SET (attr->attribs, PA4_TYPE_CLUSTER_LIST);
    }
    LL_Add (attr->cluster_list, (DATA_PTR) my_cluster_id);
    return (0);
}


/* attr will be modified */
static void
view_setup_attr (view_t *view, bgp_peer_t *peer, bgp_attr_t *attr,
		 LINKED_LIST *ll_ann_prefixes)
{
    if (!BGPSIM_TRANSPARENT) {
	/* attach reflector_id (iBGP -- iBGP) */
	if (BIT_TEST (peer->options, BGP_INTERNAL) &&
		BIT_TEST (attr->options, BGP_INTERNAL) &&
	        BIT_TEST (peer->options, BGP_ROUTE_REFLECTOR_CLIENT)) {
	    view_attach_reflector_info (peer, attr);
	}
	else {
	    /* drop them since ther are non-transitive */
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGINATOR_ID)) {
	        Deref_Prefix (attr->originator);
	        attr->originator = NULL;
	        BGP4_BIT_RESET (attr->attribs, PA4_TYPE_ORIGINATOR_ID);
	    }
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_CLUSTER_LIST)) {
	        Delete_cluster_list (attr->cluster_list);
	        attr->cluster_list = NULL;
	        BGP4_BIT_RESET (attr->attribs, PA4_TYPE_CLUSTER_LIST);
	    }
	}

	/* nexthop modification if needed */
	if (BIT_TEST (peer->options, BGP_TRANSPARENT_NEXTHOP)) {
	    /* OK, nothing to do */
	}
	else if (BIT_TEST (peer->options, BGP_NEXTHOP_SELF)) {
	    view_set_nexthop_self (peer, attr);
	}
	else if (attr->type == PROTO_CONNECTED) {
	   /*
	    * always set the next hop with a local address
	    */
	    view_set_nexthop_self (peer, attr);
	}
	else if (BIT_TEST (peer->options, BGP_EBGP_MULTIHOP)) {
	    view_set_nexthop_self (peer, attr);
#ifdef HAVE_IPV6
	    if (attr->link_local) {
		deref_nexthop (attr->link_local);
		attr->link_local = NULL;
	    }
#endif /* HAVE_IPV6 */
	}
	else if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP)) {
	    /* static route */
	    if (BIT_TEST (attr->nexthop->flags,  
			/* local includes loopback */
				GATEWAY_UNSPEC|GATEWAY_LOCAL|GATEWAY_LLOCAL)) {
	        view_set_nexthop_self (peer, attr);
	    }
	    else if (peer->gateway && peer->gateway->interface &&
                   is_prefix_on (attr->nexthop->prefix,
                                 peer->gateway->interface)) {
		/* third party next-hop. I need to use is_prefix_on()
		   since iBGP next-hop is not associated with an interface */
	    }
	    else if (BIT_TEST (peer->options, BGP_PEER_SELF)) {
		/* ok -- on the same host */
	    }
	    else if (BIT_TEST (peer->options, BGP_INTERNAL)) {
		/* ok -- ibgp -> ibgp and ebgp -> ibgp */
	    }
	    else if (BIT_TEST (attr->options, BGP_INTERNAL)) {
		/* ibgp -> ebgp */
	        if (peer->gateway && peer->gateway->interface &&
                       attr->direct && attr->direct->interface ==
                                     peer->gateway->interface) {
		    /* ok */
		    deref_nexthop (attr->nexthop);
		    attr->nexthop = ref_nexthop (attr->direct);
		}
		else {
                    view_set_nexthop_self (peer, attr);
		}
	    }
	    else {
		/* first party next-hop */
                view_set_nexthop_self (peer, attr);
	    }
	}
	else {
	    /* replace nexthop with local address */
	    view_set_nexthop_self (peer, attr);
	}

	/* bgpsim */
        if (!BGP4_BIT_SET (attr->attribs, PA4_TYPE_ORIGIN)) {
	    attr->origin = 2;
	    BGP4_BIT_SET (attr->attribs, PA4_TYPE_ORIGIN);
	}

        /* iBGP */
	if (BIT_TEST (peer->options, BGP_INTERNAL)) {
	    if (!BGP4_BIT_TEST (attr->attribs, PA4_TYPE_LOCALPREF)) {
	        attr->local_pref = BGP->default_local_pref;
	        BGP4_BIT_SET (attr->attribs, PA4_TYPE_LOCALPREF);
	    }
	}
	else {
	    BGP4_BIT_RESET (attr->attribs, PA4_TYPE_LOCALPREF);
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_METRIC))
	        BGP4_BIT_RESET (attr->attribs, PA4_TYPE_METRIC);
	}
    } /* !BGPSIM_TRANSPARENT */


	if (BIT_TEST (peer->options, BGP_REMOVE_PRIVATE_AS)) {
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH)) {
#define PRIVATE_AS_LOW  64512
#define PRIVATE_AS_HIGH 65534
	        attr->aspath = aspath_remove (attr->aspath, 
				    PRIVATE_AS_LOW, PRIVATE_AS_HIGH);
	    }
	}

	/* route map is applied at the last stage (strongest) */
	if (peer->filters[view->viewno].route_map_out > 0) {
	    prefix_t *prefix = LL_GetHead (ll_ann_prefixes);
	    assert (prefix);
	    bgp_trace_attr2 (attr, peer->trace);
            attr = apply_route_map (peer->filters[view->viewno].route_map_out, 
				    attr, prefix, 1);
	    trace (TR_TRACE, peer->trace,
		   "route-map %d applied for output %p%s\n", 
		   peer->filters[view->viewno].route_map_out,
		   prefix, (LL_GetCount (ll_ann_prefixes) > 1)? "...": "");
	}

    if (!BGPSIM_TRANSPARENT) {
        if (BIT_TEST (peer->options, BGP_TRANSPARENT_AS)) {
	    /* OK */
	}
	else {
	    /* automatic my as prepend is the last */
	    /* eBGP */
	    if (!BIT_TEST (peer->options, BGP_INTERNAL)) {

	        attr->aspath = aspath_prepend_as (attr->aspath, 
						  peer->local_bgp->this_as);
	        BGP4_BIT_SET (attr->attribs, PA4_TYPE_ASPATH);
	    }
	}
	} /* !BGPSIM_TRANSPARENT */
}


/* 
 * here is where we actually build update packets and 
 * schedule them to be sent off. NOTE: It is is the responsibility of
 * bgp peer to delete buffer memory!
 */
/* 
 * create packets, and schedule them
 */
static int 
view_announce_peer (view_t *view, bgp_peer_t * peer)
{
    LINKED_LIST * ll_with_prefixes = NULL;
    update_bucket_t * bucket;
    int wsafi = 0;

    assert (peer);

    pthread_mutex_lock (&peer->update_mutex_lock);
    assert (LL_GetCount (peer->ll_update_out) > 0);
    while ((bucket = LL_GetHead (peer->ll_update_out)) != NULL) {
	LL_RemoveFn (peer->ll_update_out, bucket, NULL);
	if (bucket->attr == NULL) {
	    if (ll_with_prefixes) {
    		bgp_create_pdu (ll_with_prefixes, NULL, NULL, wsafi,
			    peer, (void_fn_t) bgp_send_update, NULL, 0, 0);
		LL_Destroy (ll_with_prefixes);
	    }
	    ll_with_prefixes = bucket->ll_prefix;
	    wsafi = bucket->safi;
	    Destroy (bucket);
	    continue;
	}

	/* afi or safi is different from announce, flush out the withdraw */
	if (ll_with_prefixes) {
	    prefix_t *p1 = LL_GetHead (ll_with_prefixes);
	    prefix_t *p2 = LL_GetHead (bucket->ll_prefix);
	    assert (p1 && p2);
	    if (p1->family != p2->family || wsafi != bucket->safi) {
    		bgp_create_pdu (ll_with_prefixes, NULL, NULL, wsafi,
			    peer, (void_fn_t) bgp_send_update, NULL, 0, 0);
		LL_Destroy (ll_with_prefixes);
	        ll_with_prefixes = NULL;
	    }
	}
	/* it could be good if check to see if the next is withdraw or not */

        bgp_create_pdu (ll_with_prefixes, bucket->ll_prefix, bucket->attr, 
			bucket->safi, 
			peer, (void_fn_t) bgp_send_update, NULL, 0, 0);
	delete_update_bucket (bucket);
	if (ll_with_prefixes) {
	    LL_Destroy (ll_with_prefixes);
	    ll_with_prefixes = NULL;
	}
    }
    /* LL_ClearFn (peer->ll_update_out, free); */
    pthread_mutex_unlock (&peer->update_mutex_lock);
    if (ll_with_prefixes) {
	bgp_create_pdu (ll_with_prefixes, NULL, NULL, wsafi,
			peer, (void_fn_t) bgp_send_update, NULL, 0, 0);
	LL_Destroy (ll_with_prefixes);
    }
    return (0);
}


static void
bgp_pick_best (view_t * view, bgp_route_head_t * bgp_route_head, int force)
{
    bgp_route_t *new_bgp_best, *new_imp_best;
    bgp_route_t *new_best;

    /* when VRTS_DELETE is set, active must not be null */
    assert (!BIT_TEST (bgp_route_head->state_bits, VRTS_DELETE) ||
	    bgp_route_head->active != NULL);

    new_bgp_best = LL_GetHead (bgp_route_head->ll_routes);
    new_imp_best = LL_GetHead (bgp_route_head->ll_imported);

    if (new_bgp_best == NULL && new_imp_best == NULL) {
	/* no bgp routes nor imported routes */
	/* remove the head from the radix tree without destroying */
	view_remove_route_head (view, bgp_route_head);
	/* the memory will be freed later after sending withdraw */
	/* the route pointed by active has to be freed later, too */
    }

    if (new_bgp_best && !bgp_nexthop_avail (new_bgp_best->attr))
	new_bgp_best = NULL;

    new_best = new_bgp_best;
    if (new_best == NULL ||
            (new_imp_best && new_imp_best->weight > new_bgp_best->weight)) {
	new_best = new_imp_best;
    }

    if (new_best == bgp_route_head->active) {
	/* no change */

	/* active being deleted must not be chosen again */
	/* also the flag must not be set when active is null */
    	assert (!BIT_TEST (bgp_route_head->state_bits, VRTS_DELETE));

	if (new_best == NULL) {
	    return;
	}
	if (force) {
	    view_add_change_list (view, bgp_route_head, 0);
	}
	return;
    }

    if (new_best == NULL) {
	/* withdraw the previous active */
	/* bgp_route_head->active will be cleared later */
	/* if VRTS_DELETE is set, the memory will be also freed */
	view_add_change_list (view, bgp_route_head, 1);
	return;
    }

    if (BIT_TEST (bgp_route_head->state_bits, VRTS_DELETE)) {
	/* we can delete it right now */
	/* this active must not in the list */
	Delete_Bgp_Route (bgp_route_head->active);
        BIT_RESET (bgp_route_head->state_bits, VRTS_DELETE);
    }

    /* simply announce the active */
    /* it may update the previous */
    bgp_route_head->active = new_best;
    view_add_change_list (view, bgp_route_head, 0);
}


static bgp_route_t *
view_add_bgp_route (view_t * view, bgp_route_head_t * bgp_route_head,
		    bgp_attr_t * attr, int weight, u_long flags)
{
    bgp_route_t *bgp_route;
    bgp_route_t *old_best, *new_best, *new_bgp_route;

    assert (attr->type == PROTO_BGP);

    /* check to see if we already got this route from the gateway 
     *  if we have, then this is an implicit withdraw of the old route and
     *  we add the new route */
    LL_Iterate (bgp_route_head->ll_routes, bgp_route) {
	if (bgp_route->attr->gateway == attr->gateway)
	    break;
	/* set implicit withdraw flag */
	/* we need a special flag because a host due to policy may not
	   accept the new route, then we have to explicitly withdraw this
	   prefix */
    }

    if (bgp_route != NULL) {
	/* implicit withdraw */
        if (bgp_route->flags == flags && bgp_route->weight == weight &&
	        (bgp_route->attr == attr || 
		    bgp_compare_attr (bgp_route->attr, attr) > 0)) {

            trace (TR_TRACE, view->trace,
	           "Implicit withdraw but same: %p (ignore)\n",
	           bgp_route_head->prefix);
	    /* Do we need to update the time received? */
            return (bgp_route);
	}
    }
    else {
        /* first time we've heard from this gateway */
    }

    old_best = LL_GetHead (bgp_route_head->ll_routes);
    if (old_best && !bgp_nexthop_avail (old_best->attr))
	old_best = NULL;

    if (bgp_route != NULL) {
        /* remove but not destroy it */
        LL_RemoveFn (bgp_route_head->ll_routes, bgp_route, NULL);
        view->num_bgp_routes--;
    }

    new_bgp_route = New_Bgp_Route (view, bgp_route_head, attr, weight, flags);
    new_best = LL_GetHead (bgp_route_head->ll_routes);
    if (new_best && !bgp_nexthop_avail (new_best->attr))
	new_best = NULL;

    if (new_best == old_best) {
	/* there is no change in bgp routes */
	if (bgp_route != NULL)
            Delete_Bgp_Route (bgp_route);
        return (new_bgp_route);
    }

    if (new_best && bgp_nexthop_avail (new_best->attr))
    	bgp_rt_update_call (view, bgp_route_head->prefix,
			    new_best->attr, NULL);
    else if (old_best && bgp_nexthop_avail (old_best->attr))
    	bgp_rt_update_call (view, bgp_route_head->prefix,
			    NULL, old_best->attr);

    if (bgp_route != NULL) {
	if (bgp_route == bgp_route_head->active) {
	    /* we need to care in this case 
	       since it can not be freed right now */
	    BIT_SET (bgp_route_head->state_bits, VRTS_DELETE);
        }
        else {
	    /* ok. delete it */
            Delete_Bgp_Route (bgp_route);
        }
    }
    bgp_pick_best (view, bgp_route_head, 0);
    return (new_bgp_route);
}


/*
 * tentative for a bgp policy routing...
 */
static int
bgp_policy (view_t *view, prefix_t * prefix, bgp_attr_t * attr, 
	    bgp_peer_t * peer, int inout)
{
    int num;
    bgp_filters_t *filters;
    interface_t *interface;

    assert (peer);
    assert (view);
    assert (BITX_TEST (&peer->view_mask, view->viewno));

    filters = &peer->filters[view->viewno];

    if (inout == 0 /* announce */|| inout == 2 /* withdraw */) {
	/* input policy processing */

	/* verify the prefix */
#ifdef HAVE_IPV6
	if (prefix->family == AF_INET) {
#endif /* HAVE_IPV6 */

	    if (prefix->bitlen > 32) {
		trace (TR_PACKET, peer->trace,
		       "  x %p (invalid prefix length)\n", prefix);
		return (0);
	    }
#ifdef HAVE_IPV6
	}
	else {
	    assert (prefix->family == AF_INET6);

	    if (prefix->bitlen > 128) {
		trace (TR_PACKET, peer->trace,
		       "  x %p (invalid prefix length)\n", prefix);
		return (0);
	    }
	}
#endif /* HAVE_IPV6 */

#ifdef notdef
/* bgpsim doesn't put a gateway */
	if (attr->gateway == NULL)
	    return (1);
#endif

	assert (view->afi == family2afi (prefix->family));

	/* do not accept a route with own address as a nexthop */
	if ((interface = find_interface_local (attr->nexthop->prefix)) 
		!= NULL) {
	    trace (TR_PACKET, peer->trace,
		   "  x %p (nexthop %p is own on %s)\n",
		   prefix, attr->nexthop->prefix, interface->name);
	    return (0);
	}

	/* check distribute-list for in */
	if ((num = filters->dlist_in) > 0) {
	    if (apply_access_list (num, prefix) == 0) {
		trace (TR_PACKET, peer->trace,
		       "  x %p (d-list %d)\n", prefix, num);
		return (0);
	    }
	}

	/* check filter-list for in */
	/* apply for announce only */
	if (inout == 0 && (num = filters->flist_in) > 0) {
	    /* drop all updates without aspath XXX */
	    if (!BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH) ||
		apply_as_access_list (num, attr->aspath) == 0) {
		trace (TR_PACKET, peer->trace,
		       "  x %p (f-list %d)\n", prefix, num);
		return (0);
	    }
	}

	/* check community-list for in */
	/* apply for announce only */
	if (inout == 0 && (num = filters->clist_in) > 0) {
	    /* drop all updates without community XXX */
	    if (!BGP4_BIT_TEST (attr->attribs, PA4_TYPE_COMMUNITY) ||
		apply_community_list (num, attr->community) == 0) {
		trace (TR_PACKET, peer->trace,
		       "  x %p (c-list %d)\n", prefix, num);
		return (0);
	    }
	}

    }
    else {
	/* output policy processing */

#ifdef notdef
/* bgpsim doesn't put a gateway */
	if (attr->gateway == NULL)
	    return (1);
#endif

	/* BGPsim skips these checks */
        if (!BGPSIM_TRANSPARENT &&
		!BIT_TEST (peer->options, BGP_TRANSPARENT_AS)) {

	    /* do not announce to peer who gave us route */
	    if (attr->gateway == peer->gateway) {

		trace (TR_PACKET, peer->trace,
		       "  x %p (split horizon)\n", prefix);
		return (0);
	    }

	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGINATOR_ID)) {
		if (prefix_tolong (attr->originator) == 
			peer->gateway->routerid) {
		    trace (TR_PACKET, peer->trace,
		           "  x %p (originator %a)\n",
		           prefix, attr->originator);
		    return (0);
		}
	    }

	    /* do not announce to peer who once passed it */
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH) &&
	        bgp_check_aspath_loop (attr->aspath, 
				       peer->gateway->AS)) {

		trace (TR_PACKET, peer->trace,
		       "  x %p (peer as %d in path)\n",
		       prefix, peer->gateway->AS);
		return (0);
	    }

	    /* do not announce to iBGP if larned via iBGP */
	    if (BIT_TEST (peer->options, BGP_INTERNAL) &&
		BIT_TEST (attr->options, BGP_INTERNAL)) {
		/* iBGP -- iBGP case */
		/* non-client to non-client */
		if (!BIT_TEST (attr->options, BGP_ROUTE_REFLECTOR_CLIENT) &&
		    !BIT_TEST (peer->options, BGP_ROUTE_REFLECTOR_CLIENT)) {
		    trace (TR_PACKET, peer->trace,
		           "  x %p (iBGP - iBGP)\n", prefix);
		    return (0);
		}
	    }

	    /* do not announce to iBGP if larned via IGP */
	    if (BIT_TEST (peer->options, BGP_INTERNAL) &&
	           (attr->type == PROTO_RIPNG || attr->type == PROTO_RIP ||
	            attr->type == PROTO_OSPF)) {
		trace (TR_PACKET, peer->trace,
		       "  x %p (IGP - iBGP)\n", prefix);
		return (0);
	    }

	    /* do not announce connected route to peer on the interface */
	    if (attr->type == PROTO_CONNECTED && 
		    attr->nexthop->interface &&
		    peer->nexthop == NULL /* immediate neighbors */ &&
		    attr->nexthop->interface == 
			peer->gateway->interface) {

		trace (TR_PACKET, peer->trace,
		       "  x %p (on the interface %s)\n",
		       prefix, peer->gateway->interface->name);
		return (0);
	    }

	    /* do not announce a route with a peer's address as a nexthop */
	    if (address_equal (attr->nexthop->prefix, peer->gateway->prefix)) {

		trace (TR_PACKET, peer->trace,
		       "  x %p (nexthop %p is peer)\n",
		       prefix, attr->nexthop->prefix);
		return (0);
	    }

	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_COMMUNITY)) {
	        if (!BIT_TEST (peer->options, BGP_INTERNAL) &&
		        community_test (attr->community, 
				        COMMUNITY_NO_EXPORT)) {
		    trace (TR_PACKET, peer->trace,
		           "  x %p (no-export)\n", prefix);
		    return (0);
	        }
	        else if (community_test (attr->community, 
					 COMMUNITY_NO_ADVERTISE)) {
		    trace (TR_PACKET, peer->trace,
		           "  x %p (no-advertise)\n", prefix);
		    return (0);
	        }
	    }
        }

#ifdef notdef
	if (attr->type != PROTO_BGP &&
	    check_bgp_networks (prefix)) {
	    /* OK */
	}

	else if (attr->type != PROTO_BGP &&
	    !BIT_TEST (MRT->redist[attr->type], (1 << PROTO_BGP))) {
	    trace (TR_PACKET, peer->trace,
		   "  x %p (proto %r)\n", prefix, attr->type);
	    return (0);
	}
#endif

	/* check distribute-list for out */
	if ((num = filters->dlist_out) > 0) {
	    if (apply_access_list (num, prefix) == 0) {

		trace (TR_PACKET, peer->trace,
		       "  x %p (d-list %d)\n", prefix, num);
		return (0);
	    }
	}

	/* check filter-list for out */
	if ((num = filters->flist_out) > 0) {
	    if (!BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH) ||
	        apply_as_access_list (num, attr->aspath) == 0) {
		trace (TR_PACKET, peer->trace,
		       "  x %p (f-list %d)\n", prefix, num);
		return (0);
	    }
	}

	/* check community-list for out */
	if ((num = filters->clist_out) > 0) {
	    if (!BGP4_BIT_TEST (attr->attribs, PA4_TYPE_COMMUNITY) ||
	        apply_community_list (num, attr->community) == 0) {
		trace (TR_PACKET, peer->trace,
		       "  x %p (c-list %d)\n", prefix, num);
		return (0);
	    }
	}
    }
    return (1);
}


/*
 * process route changes - run policy, and then build and schedule 
 * updates to peers. This is call after receipt of update packets
 */
/* public */
int 
bgp_process_changes (view_t * view)
{
    bgp_peer_t *peer;
    bgp_route_head_t *head;

    /* maybe check that view is open? */

    /* update each peer of view with changes */
    pthread_mutex_lock (&view->local_bgp->peers_mutex_lock);
    LL_Iterate (view->local_bgp->ll_bgp_peers, peer) {
        update_bucket_t *wbucket = NULL; /* backet for withdraw */
        LINKED_LIST *ll_ann = NULL;

	/* if we are a test peer (ala RouteViews), skip all of this */
	if (BIT_TEST (peer->options, BGP_PEER_TEST))
		continue;


	if (!BITX_TEST (&peer->view_mask, view->viewno))
	    continue;

	/* see if peer is established */
	if (peer->state != BGPSTATE_ESTABLISHED)
	    continue;

	/* build withdraw list */
	LL_Iterate (view->ll_with_routes, head) {
    	    bgp_route_t *route;

	    /* 
	     * Withdraw 
	     */

	    route = head->active;
	    assert (route);

	    /* do not give withdraw to person who gave us the route */
	    /* if not announced, then do not withdraw */
	    if (route->attr->gateway == peer->gateway ||
		!BITX_TEST (&head->peer_mask, peer->index))
		continue;

	    BITX_RESET (&head->peer_mask, peer->index); /* reset announce bit */
	    if (wbucket == NULL)
	        wbucket = New_Update_Bucket (view->safi);
	    LL_Add (wbucket->ll_prefix, Ref_Prefix (head->prefix));
	}

	/* build announce list */
	LL_Iterate (view->ll_ann_routes, head) {
    	    bgp_route_t *route;

	    /* 
	     * Add
	     */

	    route = head->active;
	    assert (route);

	    /* policy */
	    if (!bgp_policy (view, head->prefix, route->attr, peer, 1)) {
		/* if policy fails and route announced, withdraw the puppy */
		if (BITX_TEST (&head->peer_mask, peer->index)) {
	    	    /* reset announce bit */
		    BITX_RESET (&head->peer_mask, peer->index); 
	    	    if (wbucket == NULL)
	                wbucket = New_Update_Bucket (view->safi);
	    	    LL_Add (wbucket->ll_prefix, Ref_Prefix (head->prefix));
		}
		continue;
	    }
	    BITX_SET (&head->peer_mask, peer->index);	/* set announce bit */
	    if (ll_ann == NULL)
		ll_ann = LL_Create (0);
	    LL_Add (ll_ann, route);
	}

	pthread_mutex_lock (&peer->update_mutex_lock);

	if (wbucket) {
	    LL_Append (peer->ll_update_out, wbucket);
	    if (LL_GetCount (peer->ll_update_out) == 1) {
    	        schedule_event2 ("view_announce_peer", peer->schedule, 
    		          (event_fn_t) view_announce_peer, 2, view, peer);
	    }
	}

	if (ll_ann) {
	    /* organize by attr type for easy building of packets */
	    view_build_update_buckets (view, peer, ll_ann);
	    LL_Destroy (ll_ann);
	}

	pthread_mutex_unlock (&peer->update_mutex_lock);
    }
    pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);

    LL_Iterate (view->ll_with_routes, head) {
        assert (BITX_TEST (&head->view_mask, view->viewno));
        BITX_RESET (&head->view_mask, view->viewno);
	/* now active is always connected to either of lists */
	/* freed active which may not in the lists */
	assert (head->active);
	if (BIT_TEST (head->state_bits, VRTS_DELETE)) {
	    /* this active must not be in the list */
	    Delete_Bgp_Route (head->active);
	}
	BIT_RESET (head->state_bits, VRTS_DELETE);
	head->active = NULL;
	if (LL_GetCount (head->ll_imported) <= 0 &&
		LL_GetCount (head->ll_routes) <= 0) {
	    Delete_Bgp_Route_Head (head);
	}
    }
    LL_Iterate (view->ll_ann_routes, head) {
        assert (BITX_TEST (&head->view_mask, view->viewno));
        BITX_RESET (&head->view_mask, view->viewno);
    }
    LL_ClearFn (view->ll_with_routes, NULL);
    LL_ClearFn (view->ll_ann_routes, NULL);

    return (1);
}


/* public */
int
process_bgp_update (bgp_peer_t * peer, u_char * cp, int length)
{
    prefix_t *prefix;
    int i;
    int weight = 0;
    bgp_attr_t *attr;
    LINKED_LIST *ll_announce, *ll_withdraw;
    int afi = 0;
    int safi = 0;
    view_t *view;
    LINKED_LIST *ll_accepted = NULL;

    assert (peer);

#ifdef notdef
if (!BGP->dump_new_format) {
    /*
     * Okay, first of all, we dump the packet and the current route table.
     * So, it may include a packet with errors.
     */
    /* view_open (BGP->views[peer->view]); */
    bgp_write_mrt_msg (peer, MSG_BGP_UPDATE, cp, length);
    /* view_close (BGP->views[peer->view]); */
}
#endif

    if (bgp_process_update_packet (cp, length, peer) < 0) {
	bgp_send_notification (peer, peer->code, peer->subcode);
	return (-1);
    }
    attr = peer->attr; peer->attr = NULL;
    ll_announce = peer->ll_announce; peer->ll_announce = NULL;
    ll_withdraw = peer->ll_withdraw; peer->ll_withdraw = NULL;
    safi = peer->safi;
    assert (ll_announce || ll_withdraw);

    if (ll_announce) {
	prefix = LL_GetHead (ll_announce);
	if (prefix && prefix->family == AF_INET)
	    afi = AFI_IP;
#ifdef HAVE_IPV6
	if (prefix && prefix->family == AF_INET6)
	    afi = AFI_IP6;
#endif /* HAVE_IPV6 */
    }
    if (ll_withdraw) {
	prefix = LL_GetHead (ll_withdraw);
	if (prefix && prefix->family == AF_INET) {
	    assert (afi <= 0 || afi == AFI_IP);
	    afi = AFI_IP;
	}
#ifdef HAVE_IPV6
	if (prefix && prefix->family == AF_INET6) {
	    assert (afi <= 0 || afi == AFI_IP6);
	    afi = AFI_IP6;
	}
#endif /* HAVE_IPV6 */
    }
    assert (afi > 0 && afi < AFI_MAX);
    assert (safi > 0 && safi < SAFI_MAX);

    if (ll_announce && attr) { /* announce */

        if (bgp_check_attr (peer, attr, peer->local_bgp->this_as) < 0) {
	    /* notification was sent */
	    bgp_deref_attr (attr);
	    attr = NULL;
            if (ll_announce) {
	      /* only discard the announcements, but eventually close 
		 the connection to withdraw all heard from the peer */
		if (LL_GetCount (ll_announce) == 1) {
		    prefix = LL_GetHead (ll_announce);
	    	    trace (TR_WARN, peer->trace,
	           	   "dropping off the announce: %p\n", prefix);
		}
		else if (LL_GetCount (ll_announce) > 1) {
	    	    trace (TR_WARN, peer->trace,
	           	    "dropping off the announce:\n");
		    LL_Iterate (ll_announce, prefix) {
        	        trace (TR_WARN, peer->trace, "  %p\n", prefix);
		    }
		}
	        LL_Destroy (ll_announce);
		ll_announce = NULL;
	    }
	    /* cisco sends me a route which has my own as,
	       so quietly discards them for now */
	    if (ll_withdraw == NULL)
		return (0);
	    /* go through if there is withdraw */
        }

	if (attr != NULL) {

	    /* copy peer's options */
	    attr->options = peer->options;

	    if (BIT_TEST (peer->options, BGP_NEXTHOP_PEER)) {
		if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP)) {
	            if (peer->nexthop) {
	                deref_nexthop (attr->nexthop);
	                attr->nexthop = ref_nexthop (peer->nexthop);
	                trace (TR_PACKET, peer->trace, 
			       "next-hop was modified to %a\n", 
			       attr->nexthop->prefix);
		    }
		}
	    }
	}
    }

    if (attr == NULL) {
	attr = bgp_new_attr (PROTO_BGP);
	trace (TR_PACKET, peer->trace,
	       "Creating a pseudo attribute for the withdraw\n");
    }
    attr->gateway = peer->gateway;

    if (ll_announce || ll_withdraw) {
	radix_tree_t *radix_tree;
	int maxbitlen = 32;
        if (afi == AFI_IP6)
	    maxbitlen = 128;
	if (peer->routes_in[afi][safi] == NULL)
	    peer->routes_in[afi][safi] = New_Radix (maxbitlen);
	radix_tree = peer->routes_in[afi][safi];

	if (ll_withdraw != NULL) {
	    LL_Iterate (ll_withdraw, prefix) {
	        radix_node_t *radix_node;
    	        radix_node = radix_search_exact (radix_tree, prefix);
    	        if (radix_node == NULL) {
		    trace (TR_TRACE, peer->trace,
	       	           "Withdraw never accepted %p\n", prefix);
	        }
	        else {
	            bgp_route_in_t *old;
    		    old = RADIX_DATA_GET (radix_node, bgp_route_in_t);
		    bgp_deref_attr (old->attr);
		    Delete (old);
    	            radix_remove (radix_tree, radix_node);
	        }
	    }
	}
	
	if (ll_announce != NULL) {
	    /* save routes */
	    LL_Iterate (ll_announce, prefix) {
	        radix_node_t *radix_node;
    	        radix_node = radix_search_exact (radix_tree, prefix);
    	        if (radix_node == NULL) {
	            bgp_route_in_t *new;
		    trace (TR_TRACE, peer->trace,
	       	           "New Announce %p\n", prefix);
    		    radix_node = radix_lookup (radix_tree, prefix);
		    new = New (bgp_route_in_t);
		    new->attr = bgp_ref_attr (attr);
		    time (&new->time);
		    if (ll_accepted == NULL)
		        ll_accepted = LL_Create (0);
		    LL_Add (ll_accepted, &new->view_mask);
    		    RADIX_DATA_SET (radix_node, new);
	        }
	        else {
	            bgp_route_in_t *old;
    		    old = RADIX_DATA_GET (radix_node, bgp_route_in_t);
    		    if (old->attr == attr ||
			    bgp_compare_attr (old->attr, attr) > 0) {
		        trace (TR_TRACE, peer->trace,
	       	               "Implicit Withdraw %p but same (ignore)\n", 
			       prefix);
		    }
		    else {
		        trace (TR_TRACE, peer->trace,
	       	               "Implicit Withdraw %p\n", prefix);
		        bgp_deref_attr (old->attr);
		        old->attr = bgp_ref_attr (attr);
		        time (&old->time);
    		        RADIX_DATA_SET (radix_node, old);
		    }
		    if (ll_accepted == NULL)
		        ll_accepted = LL_Create (0);
		    LL_Add (ll_accepted, &old->view_mask);
	        }
	    }
	}
	
	/* iterate through views adding the announce/withdraws */
	for (i = 0; i < MAX_BGP_VIEWS; i++) {

	    if (!BITX_TEST (&peer->view_mask, i))
		continue;
	    view = BGP->views[i];
	    assert (view);

	    if (view->afi != afi || view->safi != safi)
		continue;

    	    /* XXX */
    	    if (peer->default_weight[i] >= 0)
		weight = peer->default_weight[i];

	    view_open (view);

	    if (ll_withdraw) {

		LL_Iterate (ll_withdraw, prefix) {
#ifdef notdef
		    /* apply policy */
		    if (!bgp_policy (view, prefix, attr, peer, 2))
			continue;
#endif
		    bgp_del_route (view, prefix, attr);
		}
	    }

	    if (ll_announce) {
    		bgp_bitset_t *accepted = NULL;
		LL_Iterate (ll_announce, prefix) {
		    u_long flags = 0;

		    accepted = LL_GetNext (ll_accepted, accepted);
		    assert (accepted != NULL);
		    /* apply route_map_in first */
		    if (peer->filters[i].route_map_in > 0) {
		        attr = apply_route_map (peer->filters[i].route_map_in, 
						attr, prefix, 0);
			trace (TR_TRACE, peer->trace,
	       		       "route-map %d applied for input %p\n",
	       		       peer->filters[i].route_map_in, prefix);
			bgp_trace_attr2 (attr, peer->trace);
		    }
		    /* XXX weight should be changed by route map */
		    /* apply policy */
		    if (bgp_policy (view, prefix, attr, peer, 0)) {
			BITX_SET (accepted, view->viewno);
		        bgp_add_route2 (view, prefix, attr, weight, flags);
		    }
		}
	    }

	    /* process change list -- send out updates to peers */
	    bgp_process_changes (view);

	    view_close (view);
	}
    }

    if (attr)
	bgp_deref_attr (attr);
    if (ll_withdraw)
	LL_Destroy (ll_withdraw);
    if (ll_announce)
	LL_Destroy (ll_announce);
    if (ll_accepted)
	LL_Destroy (ll_accepted);

    return (1);
}


/* public */
void
bgp_re_evaluate_in (bgp_peer_t * peer, int viewno)
{
    int weight = 0;
    view_t *view;
    bgp_route_head_t *route_head;
    bgp_route_t *bgp_route;
    radix_tree_t *radix_tree;
    radix_node_t *radix_node;
    LINKED_LIST *ll_delete = NULL;

    assert (peer);
    if (peer->state != BGPSTATE_ESTABLISHED)
        return;

	/* if we are a test peer (ala RouteViews), skip all of this */
	if (BIT_TEST (peer->options, BGP_PEER_TEST))
		return;


    if (viewno < 0) {
	int i;
        for (i = 0; i < MAX_BGP_VIEWS; i++) {
	    if (!BITX_TEST (&peer->view_mask, i))
	        continue;
	    bgp_re_evaluate_in (peer, i);
	}
	return;
    }

    assert (BITX_TEST (&peer->view_mask, viewno));
    view = BGP->views[viewno];

    assert (view);
    assert (view->local_bgp);

    if (peer->default_weight[viewno] >= 0)
	weight = peer->default_weight[viewno];

    view_open (view);

    VIEW_RADIX_WALK (view, route_head) {

        LL_Iterate (route_head->ll_routes, bgp_route) {
	    if (bgp_route->attr->gateway == peer->gateway)
		break;
	}

	if (bgp_route) {
	    u_long flags = 0;
	    int changed = 0;
    	    prefix_t *prefix = route_head->prefix;
    	    bgp_attr_t *attr;

	    if (bgp_route->attr->original) {
		attr = bgp_ref_attr (bgp_route->attr->original);
		changed++;
	    }
	    else {
    	        attr = bgp_ref_attr (bgp_route->attr);
	    }

	    /* apply route_map_in first */
	    if (peer->filters[viewno].route_map_in > 0) {
		attr = apply_route_map (peer->filters[viewno].route_map_in, 
					attr, prefix, 0);
		trace (TR_TRACE, peer->trace,
	       	       "route-map %d applied for input %p\n",
	       		peer->filters[viewno].route_map_in, prefix);
		    	bgp_trace_attr2 (attr, peer->trace);
		changed++;
	    }

	    /* XXX should be effected by bgp_policy() */
	    if (bgp_route->weight != weight) {
	 	changed++;
	    }
    
	    /* apply policy */
	    if (!bgp_policy (view, prefix, attr, peer, 0)) {
		/* remove it later since it may destroy this radix tree 
		   I'm looping within */
    		if (ll_delete == NULL)
		    ll_delete = LL_Create (0);
		LL_Add (ll_delete, bgp_route);
	    }
	    else if (changed) {
		/* implicit withdraw */
		view_add_bgp_route (view, route_head, attr, weight, flags);
	    }
	    bgp_deref_attr (attr);
	}

    } VIEW_RADIX_WALK_END;

    radix_tree = peer->routes_in[view->afi][view->safi];
    if (radix_tree != NULL) {

        RADIX_WALK (radix_tree->head, radix_node) {
	    bgp_route_in_t *rtin;

            rtin = RADIX_DATA_GET (radix_node, bgp_route_in_t);
	    if (!BITX_TEST (&rtin->view_mask, viewno)) {
	        bgp_route_head_t *bgp_route_head;
    	        bgp_attr_t *attr = rtin->attr;
		prefix_t *prefix = radix_node->prefix;
	        u_long flags = 0;

	        /* apply route_map_in first */
	        if (peer->filters[viewno].route_map_in > 0) {
		    attr = apply_route_map (peer->filters[viewno].route_map_in, 
					    attr, prefix, 0);
		    trace (TR_TRACE, peer->trace,
	       	           "route-map %d applied for input %p\n",
	       		    peer->filters[viewno].route_map_in, prefix);
		    	    bgp_trace_attr2 (attr, peer->trace);
	        }

	        /* apply policy */
	        if (bgp_policy (view, prefix, attr, peer, 0)) {
    	            bgp_route_head = view_get_route_head (view, prefix);
	            view_add_bgp_route (view, bgp_route_head, attr, 
					weight, flags);
		    BITX_SET (&rtin->view_mask, viewno); /* accepted */
		}
	    }
        } RADIX_WALK_END;
    }

    if (ll_delete) {
        LL_Iterate (ll_delete, bgp_route) {
	    bgp_route_in_t *rtin;
	    prefix_t *prefix = bgp_route->head->prefix;

	    view_delete_bgp_route (view, bgp_route);
    	    radix_node = radix_search_exact (radix_tree, prefix);
            rtin = RADIX_DATA_GET (radix_node, bgp_route_in_t);
	    assert (BITX_TEST (&rtin->view_mask, viewno));
	    BITX_RESET (&rtin->view_mask, viewno);
        }
        LL_Destroy (ll_delete);
    }

    /* process change list -- send out updates to peers */
    bgp_process_changes (view);
    view_close (view);
}


/* public */
void
view_eval_nexthop (int viewno)
{
    view_t *view;
    bgp_route_head_t *route_head;
    int nn = 0;
    time_t start;

    if (viewno < 0) {

	/* clear hash table that intends to relax search in rib */
	if (BGP->nexthop_hash_table)
	    HASH_Clear (BGP->nexthop_hash_table);

        for (viewno = 0; viewno < MAX_BGP_VIEWS; viewno++) {
    	    if ((view = BGP->views[viewno]) == NULL)
		continue;
    	    if (view->local_bgp == NULL)
		continue;
	    schedule_event2 ("view_eval_nexthop", BGP->schedule, 
			      view_eval_nexthop, 1, viewno);
	}
	return;
    }

    view = BGP->views[viewno];
    assert (view);
    /* deleted view */
    if (view->local_bgp == NULL)
	return;

    if (!view->doing) {
        if (MRT->rib_time) {
	    time_t xtime;
	    xtime = MRT->rib_time (view->afi, view->safi);
	    if (xtime <= view->utime)
	        return;
	    view->utime = xtime;
	}
	else {
	    time (&view->utime);
	}
    }

    view_open (view);
    time (&start);
    view->doing++;
    VIEW_RADIX_WALK (view, route_head) {
        bgp_route_t *bgp_route;
	bgp_route_t *old_bgp_best;
	nexthop_t *old_bgp_direct = NULL;
	int old_bgp_avail = 0;
	int change = 0;

    if (route_head->rtime < view->utime) {

	old_bgp_best = LL_GetHead (route_head->ll_routes);
	if (old_bgp_best) {
	    old_bgp_direct = old_bgp_best->attr->direct;
	    old_bgp_avail = bgp_nexthop_avail (old_bgp_best->attr);
	}
        LL_Iterate (route_head->ll_routes, bgp_route) {
	    nexthop_t *direct = bgp_route->attr->direct;

	    if (!BIT_TEST (bgp_route->attr->options, 
		    BGP_INTERNAL|BGP_PEER_SELF|BGP_EBGP_MULTIHOP))
		continue;

	    bgp_resolve_nexthop (bgp_route->attr);
	    if (direct != bgp_route->attr->direct)
		change++;
	}

	route_head->rtime = view->utime;
	if (change) {
	    bgp_route_t *new_bgp_best;
	    nexthop_t *new_bgp_direct = NULL;
	    int new_bgp_avail = 0;

	    LL_Sort (route_head->ll_routes);
	    new_bgp_best = LL_GetHead (route_head->ll_routes);
	    if (new_bgp_best) {
	        new_bgp_direct = new_bgp_best->attr->direct;
	        new_bgp_avail = bgp_nexthop_avail (new_bgp_best->attr);
	    }

	    if (old_bgp_best == new_bgp_best) {
		assert (old_bgp_best);
		assert (new_bgp_best);
	        if (BIT_TEST (old_bgp_best->attr->options, 
		    BGP_INTERNAL|BGP_PEER_SELF|BGP_EBGP_MULTIHOP)) {
		    if (old_bgp_direct != new_bgp_direct) {
			/* direct nexthop changed */
	    	        bgp_rt_update_call (view, route_head->prefix,
					    new_bgp_best->attr, NULL);
    			bgp_pick_best (view, route_head, 1);
		    }
		}
	    }
	    else {
		/* one must be indirect */
	        assert (BIT_TEST (old_bgp_best->attr->options, 
			    BGP_INTERNAL|BGP_PEER_SELF|BGP_EBGP_MULTIHOP) ||
	        	BIT_TEST (new_bgp_best->attr->options, 
			    BGP_INTERNAL|BGP_PEER_SELF|BGP_EBGP_MULTIHOP));

		if (new_bgp_avail) {
	    	    bgp_rt_update_call (view, route_head->prefix,
					new_bgp_best->attr, NULL);
    		    bgp_pick_best (view, route_head, 0);
		}
		else if (old_bgp_avail) {
	    	    bgp_rt_update_call (view, route_head->prefix,
					NULL, old_bgp_best->attr);
    		    bgp_pick_best (view, route_head, 0);
		}
	    }
	}
	/* this loop may take time */
	if (++nn % 1000 == 0) {
	    time_t now;
	    time (&now);
	    if (now > start + 30 /* XXX */) {
      		trace (TR_INFO, view->trace, 
		       "Evaluated %d routes of view #%d (%d secs)\n", nn, 
			viewno, now - start);
		goto radix_loop_exit;
	    }
	}
    }
    } VIEW_RADIX_WALK_END;
    /* all done */
    view->doing = 0;
radix_loop_exit:

    /* process change list -- send out updates to peers */
    bgp_process_changes (view);
    view_close (view);
}


static int
origin_merge (o1, o2)
{
    int origin = 0;

    if (o1 >= 2 || o2 >= 2 /* incomplete */ )
	origin = 2;
    else if (o1 == 1 || o2 == 1 /* egp */ )
	origin = 1;
    return (origin);
}


/* merge attr into attn, then return attn */
static bgp_attr_t *
view_aggregate_attr_merge (bgp_attr_t *attn, bgp_attr_t *attr, 
			   aggregate_t *agg, aspath_t *tail)
{
	    assert (attn);
	    assert (attr);
#ifdef notdef
		if (attn->gateway != attr->gateway)
		    attn->gateway = NULL;
#endif

		if (BGP4_BIT_TEST (attn->attribs, PA4_TYPE_NEXTHOP) &&
		    BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP) &&
		    attn->nexthop == attr->nexthop) {
			/* OK */
		}
		else {
		    if (BGP4_BIT_TEST (attn->attribs, PA4_TYPE_NEXTHOP)) {
		        deref_nexthop (attn->nexthop);
		        attn->nexthop = NULL;
		        BGP4_BIT_RESET (attn->attribs, PA4_TYPE_NEXTHOP);
		    }
		}

		if (BGP4_BIT_TEST (attn->attribs, PA4_TYPE_ORIGIN) ||
		    BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGIN)) {
		    attn->origin = origin_merge (attn->origin, attr->origin);
		    BGP4_BIT_SET (attn->attribs, PA4_TYPE_ORIGIN);
		}

		if (BGP4_BIT_TEST (attn->attribs, PA4_TYPE_ASPATH) ||
		    BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH)) {
                    attn->aspath = aspath_merge (attn->aspath, attr->aspath, tail);
		    BGP4_BIT_SET (attn->attribs, PA4_TYPE_ASPATH);
		}

#ifdef notdef
		/* is it non-transitive ??? */
		if (BGP4_BIT_TEST (attn->attribs, PA4_TYPE_METRIC) &&
		    BGP4_BIT_TEST (attr->attribs, PA4_TYPE_METRIC) &&
		    attn->multiexit == attr->multiexit) {
			/* OK */
		}
		else {
		    BGP4_BIT_RESET (attn->attribs, PA4_TYPE_METRIC);
		}
#endif

		if (BGP4_BIT_TEST (attn->attribs, PA4_TYPE_LOCALPREF) &&
		    BGP4_BIT_TEST (attr->attribs, PA4_TYPE_LOCALPREF) &&
		    attn->local_pref == attr->local_pref) {
			/* OK */
		}
		else {
		    BGP4_BIT_RESET (attn->attribs, PA4_TYPE_LOCALPREF);
		}

		if (BGP4_BIT_TEST (attn->attribs, PA4_TYPE_DPA) &&
		    BGP4_BIT_TEST (attr->attribs, PA4_TYPE_DPA) &&
		    attn->dpa.as == attr->dpa.as &&
		    attn->dpa.value == attr->dpa.value) {
			/* OK */
		}
		else {
		    BGP4_BIT_RESET (attn->attribs, PA4_TYPE_DPA);
		}

		if (BGP4_BIT_TEST (attn->attribs, PA4_TYPE_ATOMICAGG) ||
		    BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ATOMICAGG))
        	    BGP4_BIT_SET (attn->attribs, PA4_TYPE_ATOMICAGG);

#ifdef HAVE_IPV6
		if (attn->link_local && attr->link_local &&
		    attn->link_local == attr->link_local) {
			/* OK */
		}
		else {
		    if (attn->link_local) {
		        deref_nexthop (attn->link_local);
		        attn->link_local = NULL;
		    }
		}
#endif /* HAVE_IPV6 */
		if (attn->nexthop4 && attr->nexthop4 &&
		    attn->nexthop4 == attr->nexthop4) {
			/* OK */
		}
		else {
		    if (attn->nexthop4) {
		        deref_nexthop (attn->nexthop4);
		        attn->nexthop4 = NULL;
		    }
		}
		if (attn->direct && attr->direct &&
		    attn->direct == attr->direct) {
			/* OK */
		}
		else {
		    if (attn->direct) {
		        deref_nexthop (attn->direct);
		        attn->direct = NULL;
		    }
		}
    		attn->options &= attr->options;
    return (attn);
}


/* finalize attn, then return attn */
static bgp_attr_t *
view_aggregate_attr_final (bgp_attr_t *attn, aggregate_t *agg, aspath_t *tail)
{
    assert (attn);

    /* local gateway */
    attn->gateway = agg->attr->gateway;

    /* do I have to keep them during merging? */
    if (BIT_TEST (attn->options, BGP_EBGP_MULTIHOP|BGP_PEER_SELF|
				 BGP_INTERNAL)) {
	/* forget the nexthop */
        if (BGP4_BIT_TEST (attn->attribs, PA4_TYPE_NEXTHOP)) {
            deref_nexthop (attn->nexthop);
            attn->nexthop = ref_nexthop (agg->attr->nexthop);
	    attn->direct = NULL;
	}
    }

    if (!BGP4_BIT_TEST (attn->attribs, PA4_TYPE_NEXTHOP)) {
        attn->nexthop = ref_nexthop (agg->attr->nexthop);
        BGP4_BIT_SET (attn->attribs, PA4_TYPE_NEXTHOP);
    }

    /* ignore aggregator of contributing route */
    if (BGP4_BIT_TEST (attn->attribs, PA4_TYPE_AGGREGATOR)) {
        Deref_Prefix (attn->aggregator.prefix);
        attn->aggregator.prefix = NULL;
        BGP4_BIT_RESET (attn->attribs, PA4_TYPE_AGGREGATOR);
    }

    if (BGP4_BIT_TEST (agg->attr->attribs, PA4_TYPE_AGGREGATOR)) {
        attn->aggregator.as = agg->attr->aggregator.as;
        attn->aggregator.prefix = Ref_Prefix (agg->attr->aggregator.prefix);
        BGP4_BIT_SET (attn->attribs, PA4_TYPE_AGGREGATOR);
    }

    /* ignore communities of contributing route */
    if (BGP4_BIT_TEST (attn->attribs, PA4_TYPE_COMMUNITY)) {
        Delete_community (attn->community);
        attn->community = NULL;
        BGP4_BIT_RESET (attn->attribs, PA4_TYPE_COMMUNITY);
    }

#ifdef HAVE_IPV6
    if (attn->link_local == NULL && agg->attr->link_local)
        attn->link_local = ref_nexthop (agg->attr->link_local);
#endif /* HAVE_IPV6 */
    if (attn->nexthop4 == NULL && agg->attr->nexthop4)
        attn->nexthop4 = ref_nexthop (agg->attr->nexthop4);

/* CHECK_AGG: */

    if (BIT_TEST (agg->option, BGP_AGGOPT_AS_SET)) {
	if (tail && LL_GetCount (tail)) {
	    attn->aspath = aspath_append (attn->aspath, tail);
            BGP4_BIT_SET (attn->attribs, PA4_TYPE_ASPATH);
	}
        return (attn);
    }

    /* atmoc-aggregate is already set if at least one of routes has */

    if (BGP4_BIT_TEST (attn->attribs, PA4_TYPE_ATOMICAGG))
        return (attn);

    if (BIT_TEST (agg->option, BGP_AGGOPT_SUMMARY_ONLY) &&
	    tail && LL_GetCount (tail)) {
	/* as path information lost, so set atomic-aggregate */
        BGP4_BIT_SET (attn->attribs, PA4_TYPE_ATOMICAGG);
    }

    return (attn);
}


static bgp_attr_t *
view_compute_agg (view_t *view, aggregate_t *agg, 
		  bgp_route_head_t *bgp_route_head)
{
    radix_node_t *node;
    aspath_t *tail = NULL;
    bgp_attr_t *attr = NULL;
    int n = 0;

    assert (view); assert (agg);
    assert (bgp_route_head);
    assert (bgp_route_head->radix_node);
    RADIX_WALK (bgp_route_head->radix_node, node) {

        if (n++ == 0) {
            /* the first iteration is aggregate route itself */
        }
        else {
	    bgp_route_head_t *route_head;
	    bgp_route_t *route;

	    route_head = RADIX_DATA_GET (node, bgp_route_head_t);
	if ((route = route_head->active) != NULL) {

	    if (BIT_TEST (agg->option, BGP_AGGOPT_SUMMARY_ONLY) &&
	       !BIT_TEST (bgp_route_head->state_bits, VRTS_SUPPRESS)) {
		if (!BIT_TEST (route_head->state_bits, VRTS_SUPPRESS)) {
    		    /* add the route head to the change list (withdraw) */
    		    view_add_ll_list (view, route_head, 1);
		    BIT_SET (route_head->state_bits, VRTS_SUPPRESS);
		}
	    }

	    trace (TR_TRACE, view->trace,
	           "AGG merge attr for %p from %p\n",
	           agg->prefix, route_head->prefix);

	    if (attr == NULL) {
	        attr = bgp_copy_attr (route->attr);
    	        if (attr->type == PROTO_CONNECTED &&
			BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP)) {
		    /* unspecified nexthop is not acceptable for aggragate */
        	    deref_nexthop (attr->nexthop);
        	    attr->nexthop = ref_nexthop (agg->attr->nexthop);
    	        }
	        attr->type = PROTO_BGP;
	    }
	    else {
		if (tail == NULL)
		    tail = New_ASPATH ();
	        attr = view_aggregate_attr_merge (attr, route->attr, agg, 
						  tail);

	        if (BIT_TEST (route->flags, BGP_RT_AGGREGATED))
		    RADIX_WALK_BREAK;
	    }
        }
	}
    } RADIX_WALK_END;

    if (attr == NULL)
	return (NULL);

    attr = view_aggregate_attr_final (attr, agg, tail);
    if (tail) Delete_ASPATH (tail);

    trace (TR_TRACE, view->trace, "AGG merge result for %p\n", agg->prefix);
    bgp_trace_attr2 (attr, view->trace);
    return (attr);
}


/* public */
aggregate_t *
view_add_aggregate (view_t * view, prefix_t * prefix, u_long opt)
{
    aggregate_t *agg;
    radix_node_t *radix_node;
    bgp_route_head_t *bgp_route_head;
    bgp_attr_t *attr;

    assert (view);
    assert (prefix);
    assert (view->afi == family2afi (prefix->family));

    radix_node = radix_lookup (view->agg_tree, prefix);
    assert (radix_node);

    if ((agg = RADIX_DATA_GET (radix_node, aggregate_t)) != NULL) {
	trace (TR_TRACE, view->trace,
	       "Aggregate Entry: %p already exist\n", prefix);
	return (agg);
    }

    agg = New (aggregate_t);
    agg->prefix = Ref_Prefix (prefix);
    agg->option = opt;
    RADIX_DATA_SET (radix_node, agg);
    agg->radix_node = radix_node;
    agg->route = NULL;

    {
	static prefix_t *my_id_prefix = NULL;
	static nexthop_t *my_id_nexthop = NULL;
	static nexthop_t *nexthop_self = NULL;
	static gateway_t *gateway_self = NULL;
#ifdef HAVE_IPV6
	static nexthop_t *nexthop_self6 = NULL;
	static nexthop_t *linklocal_self6 = NULL;
	static gateway_t *gateway_self6 = NULL;
#endif /* HAVE_IPV6 */
	prefix_t *prefix;

	if (my_id_prefix == NULL) {
	    my_id_prefix = New_Prefix (AF_INET, 
		(view->local_bgp->this_id)? &view->local_bgp->this_id:
					    &MRT->default_id, 32);
	    my_id_nexthop = add_nexthop (my_id_prefix, 
					 find_interface (my_id_prefix));
	    prefix = ascii2prefix (AF_INET, "127.0.0.1/32");
	    nexthop_self = add_nexthop (prefix, find_interface (prefix));
	    /* nexthop_self = ascii2prefix (AF_INET, "0.0.0.0/32"); */ /* ank */
	    /* to avoid iBGP loop */
	    gateway_self = add_gateway (prefix, view->local_bgp->this_as,
					nexthop_self->interface);
	    Deref_Prefix (prefix);
#ifdef HAVE_IPV6
	    prefix = ascii2prefix (AF_INET6, "::1/128");
	    nexthop_self6 = add_nexthop (prefix, find_interface (prefix));
	    /* linklocal_self6 = ascii2prefix (AF_INET6, "fe80::1/128"); */
	    /* nexthop_self6 = ascii2prefix (AF_INET6, "::/128"); */ /* ank */
	    /* linklocal_self6 = ascii2prefix (AF_INET6, "::/128"); */ /* ank */
	    /* to avoid iBGP loop */
	    gateway_self6 = add_gateway (prefix, view->local_bgp->this_as,
					 nexthop_self6->interface);
	    Deref_Prefix (prefix);
#endif /* HAVE_IPV6 */
	}

	agg->attr = bgp_new_attr (PROTO_BGP);
#ifdef HAVE_IPV6
	if (agg->prefix->family == AF_INET6) {
	    agg->attr->nexthop = ref_nexthop (nexthop_self6);
	    agg->attr->link_local = ref_nexthop (linklocal_self6);
	    agg->attr->nexthop4 = ref_nexthop (my_id_nexthop);
	    agg->attr->gateway = gateway_self6;
	}
	else
#endif /* HAVE_IPV6 */
	{
	    agg->attr->nexthop = ref_nexthop (nexthop_self);
	    agg->attr->gateway = gateway_self;
	}
	BGP4_BIT_SET (agg->attr->attribs, PA4_TYPE_NEXTHOP);
	agg->attr->aspath = NULL;
	BGP4_BIT_SET (agg->attr->attribs, PA4_TYPE_ASPATH);
	agg->attr->origin = 3; /* Invalid. Should not be exported in this form
                                  in any case! -- alexey */;
	BGP4_BIT_SET (agg->attr->attribs, PA4_TYPE_ORIGIN);
#ifdef notdef
	if (BIT_TEST (opt, BGP_AGGOPT_SUMMARY_ONLY))
	    BGP4_BIT_SET (agg->attr->attribs, PA4_TYPE_ATOMICAGG);
	/* BIT_TEST (opt, BGP_AGGOPT_AS_SET); */
#endif
	agg->attr->aggregator.as = view->local_bgp->this_as;
	agg->attr->aggregator.prefix = Ref_Prefix (my_id_prefix);
	BGP4_BIT_SET (agg->attr->attribs, PA4_TYPE_AGGREGATOR);
    }
    trace (TR_TRACE, view->trace, "AGG New Entry: %p\n", agg->prefix);
    bgp_trace_attr2 (agg->attr, view->trace);

    /* I need to add a route_head to locate it among the radix tree
       and to see if there are more specific routes below. */
    bgp_route_head = view_get_route_head (view, agg->prefix);
    if (BIT_TEST (agg->option, BGP_AGGOPT_SUMMARY_ONLY))
        BIT_SET (bgp_route_head->state_bits, VRTS_SUMMARY);

    attr = view_compute_agg (view, agg, bgp_route_head);
    if (attr == NULL) {
	if (LL_GetCount (bgp_route_head->ll_routes) <= 0 && 
		LL_GetCount (bgp_route_head->ll_imported) <= 0) {
	    view_remove_route_head (view, bgp_route_head);
            Delete_Bgp_Route_Head (bgp_route_head);
	}
	return (agg);
    }

    agg->route = view_add_bgp_route (view, bgp_route_head, attr, 0,
				     BGP_RT_AGGREGATED);
    bgp_deref_attr (attr);

    bgp_process_changes (view);
    return (agg);
}


/* public */
int
view_del_aggregate (view_t * view, prefix_t * prefix)
{
    aggregate_t *agg;
    radix_node_t *radix_node;

    assert (view);
    assert (prefix);
    assert (view->afi == family2afi (prefix->family));

    radix_node = radix_search_exact (view->agg_tree, prefix);
    if (radix_node == NULL) {
	trace (TR_TRACE, view->trace,
	       "Aggregate Entry: %p not found\n", prefix);
	return (-1);
    }

    radix_remove (view->agg_tree, radix_node);
    agg = RADIX_DATA_GET (radix_node, aggregate_t);

    if (agg->route) {
	radix_node_t *node;

	if (!BIT_TEST (agg->route->head->state_bits, VRTS_SUPPRESS) &&
    	     BIT_TEST (agg->option, BGP_AGGOPT_SUMMARY_ONLY)) {

            RADIX_WALK (agg->route->head->radix_node, node) {
                bgp_route_head_t *route_head;
                route_head = RADIX_DATA_GET (node, bgp_route_head_t);

		if (BIT_TEST (route_head->state_bits, VRTS_SUPPRESS)) {
    		    /* add the route head to the change list (announce) */
    		    view_add_ll_list (view, route_head, 0);
		    BIT_RESET (route_head->state_bits, VRTS_SUPPRESS);
		}
            } RADIX_WALK_END;
	}
	view_delete_bgp_route (view, agg->route);
        bgp_process_changes (view);
    }
    Deref_Prefix (agg->prefix);
    bgp_deref_attr (agg->attr);
    Delete (agg);
    return (1);
}


/* public */
void
view_eval_aggregate (view_t *view, void (*fn)(), void *arg)
{
    aggregate_t *agg;
    radix_node_t *node;

    if (view == NULL || view->agg_tree->head == NULL)
	return;

    RADIX_WALK (view->agg_tree->head, node) {
         agg = RADIX_DATA_GET (node, aggregate_t);
        (*fn) (agg->prefix, agg->option, arg);
   } RADIX_WALK_END;
}


#ifdef notdef
static int
prefix_compare_inclusive (prefix_t * prefix, prefix_t * it)
{
    if (prefix->family != it->family)
	return (0);
    if (prefix->bitlen >= it->bitlen)	/* should not the same */
	return (0);

    return (comp_with_mask (prefix_tochar (prefix),
			    prefix_tochar (it),
			    prefix->bitlen));
}
#endif


/* pseudo code Alexey (kuznet@ms2.inr.ac.ru) provide me:

> * If a route, contributing to an aggregate changes, added, removed, then:
>
>   * Find all routes, contributing to aggregate.
>   * Get the longest common AS_SEQ. Denote it AS_SEQ_HEAD.
>   * Tails of all aspathes are gathered to one AS_SET: AS_SEQ_TAIL.
>   * If AS_SEQ_TAIL is empty, goto CHECK_AAG
>   * If "as-set" is not specified, drop AS_SEQ_TAIL, set origin
>     to unspecified and goto CHECK_AAG
>
> CHECK_AAG:
>   * If atomic-aggregate is set at least on one route then
>       set atomic-agg on aggregate and RETURN.
>     * Now no routes have atomic-aggregate attr *
>   * If AS_SEQ_TAIL was empty or as-set was specified; RETURN
>   * If some routes are suppressed (by summary-only or by suppress-map),
>     and a suppresses route has AS in its aspath not present
>     in aspath of aggregate, set atomic-aggregate on aggregate.
>
> One more note: atomic aggregate should not be referenced anywhere outside
> this piece of pseudocode, because mrt does not make deaggregation.

*/


static aggregate_t *
view_check_aggregate (view_t * view, prefix_t *prefix, int withdraw)
{
    aggregate_t *agg;
    radix_node_t *node;
    bgp_route_head_t *bgp_route_head;
    bgp_attr_t *attr;

    assert (view);
    assert (prefix);

    node = radix_search_best2 (view->agg_tree, prefix, 0);
    if (node == NULL) {
	return (NULL);
    }
    assert (prefix_compare (prefix, node->prefix) == 0);

    agg = RADIX_DATA_GET (node, aggregate_t);
    assert (agg);

    trace (TR_TRACE, view->trace,
	   "AGG contribute: %p -> %p (%s)\n",
	   prefix, agg->prefix, (withdraw) ? "withdraw" : "announce");

    /* the first route causing the aggregate route */
    if (agg->route == NULL) {

	assert (withdraw == 0);
	trace (TR_TRACE, view->trace,
		"AGG activate %p triggered by %p\n", agg->prefix, prefix);

	bgp_route_head = view_get_route_head (view, agg->prefix);
        if (BIT_TEST (agg->option, BGP_AGGOPT_SUMMARY_ONLY))
	    BIT_SET (bgp_route_head->state_bits, VRTS_SUMMARY);
    }
    else {
	bgp_route_head = agg->route->head;
    }

    attr = view_compute_agg (view, agg, bgp_route_head);
    if (attr == NULL) {
	assert (withdraw);
	view_delete_bgp_route (view, agg->route);
	agg->route = NULL;
	/* reseting after deleting the route would be safer */
        if (BIT_TEST (agg->option, BGP_AGGOPT_SUMMARY_ONLY))
	    BIT_RESET (bgp_route_head->state_bits, VRTS_SUMMARY);
	return (NULL);
    }

    agg->route = view_add_bgp_route (view, bgp_route_head, 
				     attr, 0, BGP_RT_AGGREGATED);
    bgp_deref_attr (attr);
    return (agg);
}


static bgp_route_t *
bgp_add_route2 (view_t * view, prefix_t * prefix, bgp_attr_t * attr, 
		int weight, u_long flags)
{
    bgp_route_t *bgp_route;
    bgp_route_head_t *bgp_route_head;

    assert (view);
    assert (prefix);
    assert (attr);
    assert (view->afi == family2afi (prefix->family));

    assert (pthread_mutex_trylock (&view->mutex_lock));
    bgp_route_head = view_get_route_head (view, prefix);

    if (attr->type != PROTO_BGP) {	/* extern (imported) route */
        bgp_route_t *new_best, *old_best;
        bgp_route_t *new_bgp_route;

	old_best = LL_GetHead (bgp_route_head->ll_imported);

	LL_Iterate (bgp_route_head->ll_imported, bgp_route) {
	    if (bgp_route->attr->type == attr->type)
		break;
	}

	if (bgp_route) {
	    LL_RemoveFn (bgp_route_head->ll_imported, bgp_route, NULL);
    	    view->num_imp_routes--;
	}
	new_bgp_route = New_Bgp_Route (view, bgp_route_head, attr, weight, 
				       flags);
	new_best = LL_GetHead (bgp_route_head->ll_imported);

	if (old_best == new_best) {
	    /* no change */
	    if (bgp_route)
	        Delete_Bgp_Route (bgp_route);
	    return (bgp_route);
	}

	if (bgp_route) {
	    /* it's all right, but in case ... */
	    if (bgp_route_head->active == bgp_route) {
	        /* we need to care in this case 
	           since it can not be freed right now */
	        BIT_SET (bgp_route_head->state_bits, VRTS_DELETE);
            }
	    else {
	        Delete_Bgp_Route (bgp_route);
	    }
	}

        bgp_pick_best (view, bgp_route_head, 0);
	return (new_bgp_route);
    }

    return (view_add_bgp_route (view, bgp_route_head, attr, weight, flags));
}


/* public */
bgp_route_t *
bgp_add_route (view_t * view, prefix_t * prefix, bgp_attr_t * attr)
{
    int weight = 0;
    if (attr->type != PROTO_BGP)
	weight = BGP_ORIGINATE_WEIGHT;
    return (bgp_add_route2 (view, prefix, attr, weight, 0));
}


/* public */
int
bgp_del_route (view_t * view, prefix_t * prefix, bgp_attr_t * attr)
{
    bgp_route_t *bgp_route;
    bgp_route_head_t *bgp_route_head;

    assert (view);
    assert (prefix);
    assert (attr);
    assert (view->afi == family2afi (prefix->family));

    assert (pthread_mutex_trylock (&view->mutex_lock));

    bgp_route_head = view_find_route_head (view, prefix);
    if (bgp_route_head == NULL) {
	/* peer can not know if his announce was filtered or not */
	trace (TR_TRACE, view->trace, "Delete: %p not found\n", prefix);
	return (0);
    }

    if (attr->type != PROTO_BGP) {	/* extern (imported) route */

	LL_Iterate (bgp_route_head->ll_imported, bgp_route) {
	    if (bgp_route->attr->type == attr->type)
		break;
	}

	if (bgp_route == NULL) {
	    trace (TR_TRACE, view->trace,
		   "Delete: %p proto %r not found\n", prefix, attr->type);
	    return (-1);
	}

	LL_RemoveFn (bgp_route_head->ll_imported, bgp_route, NULL);
    	view->num_imp_routes--;

	if (bgp_route_head->active == bgp_route) {
	    /* we need to care in this case 
	       since it can not be freed right now */
	    BIT_SET (bgp_route_head->state_bits, VRTS_DELETE);
        }
        else {
	    /* ok. delete it */
            Delete_Bgp_Route (bgp_route);
	}
        bgp_pick_best (view, bgp_route_head, 1);
	return (1);
    }

    LL_Iterate (bgp_route_head->ll_routes, bgp_route) {
	if (bgp_route->attr->gateway == attr->gateway) {
	    view_delete_bgp_route (view, bgp_route);
	    return (1);
	}
    }
    trace (TR_WARN, view->trace,
	   "Delete: %p not found\n", prefix);
    return (0);
}


#ifdef notdef
/* public */
int 
view_close (view_t * view)
{

    pthread_mutex_unlock (&view->mutex_lock);
    return (1);
}


/* public */
int 
view_open (view_t * view)
{

    if (pthread_mutex_trylock (&view->mutex_lock) != 0) {
	trace (TR_DEBUG, view->trace, "Going to block in view_open\n");
	pthread_mutex_lock (&view->mutex_lock);
    }
    return (1);
}
#endif


/*
 * this is used in finding nexthop for multihop peer
 */
/* public */
prefix_t *
view_find_best_route (view_t * view, prefix_t * prefix)
{
    radix_node_t *radix_node;
    bgp_route_head_t *route_head;
    bgp_attr_t *attr = NULL;

    assert (view);
    assert (prefix);
    radix_node = radix_search_best (view->radix_tree, prefix);
    if (radix_node) {
	assert (radix_node->data);
	route_head = RADIX_DATA_GET (radix_node, bgp_route_head_t);
	assert (route_head);
	if (route_head->active) {
	    attr = route_head->active->attr;
	    if (attr && BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP))
	        return (attr->nexthop->prefix);
	}
    }
    return (NULL);
}


/* 
 * given a prefix, find route node entry
 * return NULL if one does not exist
 */
/* public */
bgp_route_t *
view_find_bgp_active (view_t * view, prefix_t * prefix)
{
    bgp_route_head_t *bgp_route_head;

    assert (view);
    assert (prefix);
    if ((bgp_route_head = view_find_route_head (view, prefix)) != NULL)
	return (bgp_route_head->active);
    return (NULL);
}


#ifdef notdef
/* view_find_bgp_route
 * given a prefix AND gateway, find route node entry
 * return NULL if one does not exist
 */
bgp_route_t *
view_find_bgp_route (view_t * view,
		     prefix_t * prefix, gateway_t * gateway)
{
    bgp_route_head_t *bgp_route_head;
    bgp_route_t *bgp_route;

    assert (view);
    assert (prefix);
    bgp_route_head = view_get_route_head (view, prefix);

    LL_Iterate (bgp_route_head->ll_routes, bgp_route) {
	if (bgp_route->attr->gateway == gateway) {
	    return (bgp_route);
	}
    }

    return (NULL);
}
#endif


#ifdef notdef
static int
bgp_keep_it (prefix_t *prefix, int type)
{
    assert (type != PROTO_BGP);
    /* network ... */
    if ((type == PROTO_CONNECTED || type == PROTO_STATIC) &&
	check_bgp_networks (prefix))
	return (1);
    /* redistribute */
    if (BIT_TEST (MRT->redist[type], (1 << PROTO_BGP)))
	return (1);
    return (0);
}
#endif


/* public */
void
bgp_update_route (prefix_t * prefix, generic_attr_t * new,
		  generic_attr_t * old, int pref, int viewno)
/* bgp doesn't use pref (administrative distance). 
   instead, it uses administrative weight */
{
    bgp_attr_t *bgp_new = NULL, *bgp_old = NULL;

    assert (prefix);

#ifdef notdef
    /*
     * BGP dones't need to hold routes that will not redistibute
     */
    if (new && !bgp_keep_it (prefix, new->type)) {
	new = NULL;
    }
    if (old && !bgp_keep_it (prefix, old->type)) {
	old = NULL;
    }
#endif
    if (new == NULL && old == NULL)
	return;

    assert (new == NULL || new->type != PROTO_BGP);
    assert (old == NULL || old->type != PROTO_BGP);

    if (old) {

	trace (TR_TRACE, BGP->trace, 
	       "Imported Delete: %p nh %a proto %r view %d\n",
	       prefix, old->nexthop->prefix, old->type, viewno);
	bgp_old = bgp_new_attr (old->type);
	bgp_old->gateway = old->gateway;
	if (old->nexthop) {
	    bgp_old->nexthop = ref_nexthop (old->nexthop);
            BGP4_BIT_SET (bgp_old->attribs, PA4_TYPE_NEXTHOP);
	}
    }
    if (new) {
	trace (TR_TRACE, BGP->trace, 
	       "Imported Add: %p nh %a proto %r view %d\n",
	       prefix, new->nexthop->prefix, new->type, viewno);
	bgp_new = bgp_new_attr (new->type);
	bgp_new->gateway = new->gateway;
	if (new->nexthop) {
	    bgp_new->nexthop = ref_nexthop (new->nexthop);
            BGP4_BIT_SET (bgp_new->attribs, PA4_TYPE_NEXTHOP);
	}

	assert (new->type != PROTO_BGP);
	/* XXX need to check if cisco makes even static routes igp */
	if ((new->type == PROTO_CONNECTED || new->type == PROTO_STATIC) 
		&& check_bgp_networks (prefix, viewno))
            bgp_new->origin = 0;
	else if (new->type == PROTO_RIPNG || new->type == PROTO_RIP ||
	         new->type == PROTO_OSPF)
            bgp_new->origin = 0;
        else
            bgp_new->origin = 2;
        BGP4_BIT_SET (bgp_new->attribs, PA4_TYPE_ORIGIN);

        if (!BGP4_BIT_TEST (bgp_new->attribs, PA4_TYPE_ASPATH)) {
	    bgp_new->aspath = NULL;
            BGP4_BIT_SET (bgp_new->attribs, PA4_TYPE_ASPATH);
	}
    }

    assert (bgp_new || bgp_old);

    prefix = Ref_Prefix (prefix);
    schedule_event2 ("bgp_import", BGP->schedule, bgp_import, 
		     4, prefix, bgp_new, bgp_old, viewno);
}


/* public */
view_t *
New_View (trace_t *ltrace, int viewno, int afi, int safi)
{
    int maxbitlen = 32;
    view_t *view = New (view_t);
    char str[MAXLINE];

    view->viewno = viewno;
    view->afi = afi;
    view->safi = safi;
#ifdef HAVE_IPV6
    if (afi == AFI_IP6)
	maxbitlen = 128;
#endif /* HAVE_IPV6 */
    view->ll_with_routes = LL_Create (0);
    view->ll_ann_routes = LL_Create (0);
    view->ll_networks = LL_Create (LL_DestroyFunction, Deref_Prefix, 0);
    view->agg_tree = New_Radix (maxbitlen);
    pthread_mutex_init (&view->mutex_lock, NULL);
    view->radix_tree = New_Radix (maxbitlen);
    view->trace = trace_copy (ltrace);
    view->local_bgp = NULL;
    sprintf (str, "BGP view %d", viewno);
    set_trace (view->trace, TRACE_PREPEND_STRING, str, 0);
    view->utime = 0;
    view->num_bgp_routes = 0;
    view->num_imp_routes = 0;
    view->num_bgp_heads = 0;
    return (view);
}


/* public */
void
Destroy_View (view_t *view)
{
    assert (view);
    LL_Destroy (view->ll_with_routes);
    LL_Destroy (view->ll_ann_routes);
    LL_Destroy (view->ll_networks);
    Destroy_Radix (view->agg_tree, NULL);
    pthread_mutex_destroy (&view->mutex_lock);
    Destroy_Radix (view->radix_tree, Delete_Bgp_Route_Head);
    Destroy_Trace (view->trace);
    Delete (view);
}


/*
 * withdraw all routes sent by a peer and reset peer bit
 * on all route given to peer when peer leaves established state
 */
/* public */
void
view_delete_peer (view_t * view, bgp_peer_t * peer)
{
    bgp_route_head_t *rt_head;
    bgp_route_t *route;
    LINKED_LIST *ll_route_with;

    assert (view);
    assert (peer);
    view_open (view);

    ll_route_with = LL_Create (0);

    /* find all routes announced by this peer */
    VIEW_RADIX_WALK (view, rt_head) {
	/* we may need to check family? */
	LL_Iterate (rt_head->ll_routes, route) {
	    if (route->attr->gateway == peer->gateway)
		LL_Add (ll_route_with, route);
	    /* reset announce bit */
	    BITX_RESET (&rt_head->peer_mask, peer->index);
	}
    }
    VIEW_RADIX_WALK_END;

    LL_Iterate (ll_route_with, route) {
	view_delete_bgp_route (view, route);
    }
    LL_Destroy (ll_route_with);
    bgp_process_changes (view);
    view_close (view);
}


/*
 * when a peer is first established, run through view and build
 * BGP updates for all routes per policy
 * now this can be used when the policy changed:
     if announce bit is not set and policy allows, announce it
     if announce bit is set and policy doesn't allows, withdraw it
 */
/* public */
void
bgp_establish_peer (bgp_peer_t * peer, int force_announce, int viewno)
{
    bgp_route_head_t *head;
    bgp_route_t *route;
    LINKED_LIST *ll_ann, *ll_with;
    update_bucket_t *bucket;
    view_t *view;
    int i = 0;


	/* if we are a test peer (ala RouteViews), skip all of this */
	if (BIT_TEST (peer->options, BGP_PEER_TEST))
		return;

    if (viewno < 0) {
        for (viewno = 0; viewno < MAX_BGP_VIEWS; viewno++) {
	    if (!BITX_TEST (&peer->view_mask, viewno))
		continue;
	    bgp_establish_peer (peer, force_announce, viewno);
	}
	return;
    }

    assert (peer);
    ll_ann = LL_Create (0);
    ll_with = LL_Create (0);

    view = BGP->views[viewno];
    assert (view);
    assert (view->local_bgp);
    view_open (view);

    VIEW_RADIX_WALK (view, head) {

    if ((++i) % 5000 == 0) {
      trace (TR_INFO, peer->trace, "Scanned %d routes of view #%d\n", 
		i - 1, viewno);
    }
    if ((route = head->active)) {

	assert (route);
	if (bgp_policy (view, head->prefix, route->attr, peer, 1)) {
	    if (!BIT_TEST (head->state_bits, VRTS_SUPPRESS)) {
		if (force_announce || 
			BITX_TEST (&head->peer_mask, peer->index) == 0) {
		    /* set announce bit */
	            BITX_SET (&head->peer_mask, peer->index);
		    LL_Add (ll_ann, route);
		}
	    }
	    else {
		/* must not be announced */
	        assert (BITX_TEST (&head->peer_mask, peer->index) == 0);
	    }
	}
	else {
	    if (!BIT_TEST (head->state_bits, VRTS_SUPPRESS)) {
		if (BITX_TEST (&head->peer_mask, peer->index) != 0) {
		    /* reset announce bit */
	            BITX_RESET (&head->peer_mask, peer->index);
		    LL_Add (ll_with, route);
		}
	    }
	    else {
		/* must not be announced */
	        assert (BITX_TEST (&head->peer_mask, peer->index) == 0);
	    }
	}
    }
    } VIEW_RADIX_WALK_END;

    /* In case that there are somthing changed already */
    LL_ClearFn (view->ll_with_routes, NULL);
    LL_ClearFn (view->ll_ann_routes, NULL);
    view_close (view);

    pthread_mutex_lock (&peer->update_mutex_lock);
    if (LL_GetCount (ll_with) > 0) {
	bucket = New_Update_Bucket (view->safi);
	LL_Destroy (bucket->ll_prefix); /* XXX */
	bucket->ll_prefix = ll_with;
	bucket->attr = NULL;
	LL_Append (peer->ll_update_out, bucket);
	if (LL_GetCount (peer->ll_update_out) == 1) {
    	    schedule_event2 ("view_announce_peer", peer->schedule, 
    		              (event_fn_t) view_announce_peer, 2, view, peer);
	}
    }

    view_build_update_buckets (view, peer, ll_ann);
    pthread_mutex_unlock (&peer->update_mutex_lock);

    LL_Destroy (ll_ann);
    LL_Destroy (ll_with);
}


static int 
trace_bgp_view_op (uii_connection_t * uii, char *s, int op)
{
    int i;
    view_t *view;

    if (strcasecmp (s, "*") == 0) {
        for (i = 0; i < MAX_BGP_VIEWS; i++) {
	    if ((view = BGP->views[i]) == NULL)
		continue;
    	    if (view->local_bgp == NULL)
		continue;
	    view_open (view);
            set_trace (view->trace, op, TR_ALL, NULL);
	    view_close (view);
	}
    }
    else if (isdigit (*s)) {
	i = atoi (s);
	if (i < 0 || i > MAX_BGP_VIEWS ||
	       (view = BGP->views[i]) == NULL ||
    	        (view->local_bgp == NULL)) {
	    config_notice (TR_ERROR, uii, 
		       "invalid or unconfigured view %d\n", i);
	    Delete (s);
	    return (-1);
	}
	view_open (view);
        set_trace (view->trace, op, TR_ALL, NULL);
	view_close (view);
    }
    else if (strcasecmp (s, "inet") == 0) {
        for (i = 0; i < MAX_BGP_VIEWS; i++) {
	    if ((view = BGP->views[i]) == NULL)
		continue;
    	    if (view->local_bgp == NULL)
		continue;
	    if (view->afi == AFI_IP) {
	        view_open (view);
        	set_trace (view->trace, op, TR_ALL, NULL);
		view_close (view);
	    }
	}
    }
#ifdef HAVE_IPV6
    else if (strcasecmp (s, "inet6") == 0) {
        for (i = 0; i < MAX_BGP_VIEWS; i++) {
	    if ((view = BGP->views[i]) == NULL)
		continue;
    	    if (view->local_bgp == NULL)
		continue;
	    if (view->afi == AFI_IP6) {
	        view_open (view);
        	set_trace (view->trace, op, TR_ALL, NULL);
		view_close (view);
	    }
	}
    }
#endif /* HAVE_IPV6 */
    else {
	config_notice (TR_ERROR, uii, "invalid or unconfigured view %s\n", s);
        Delete (s);
        return (-1);
    }
    Delete (s);
    return (1);
}

int 
trace_bgp_view (uii_connection_t * uii, char *s)
{
    return (trace_bgp_view_op (uii, s, TRACE_ADD_FLAGS));
}

int 
no_trace_bgp_view (uii_connection_t * uii, char *s)
{
    return (trace_bgp_view_op (uii, s, TRACE_DEL_FLAGS));
}


int 
trace_f_bgp (uii_connection_t * uii, int family)
{
    int op = TRACE_ADD_FLAGS;

    if (uii->negative)
	op = TRACE_DEL_FLAGS;

    if (family == 0 || family == AF_INET) {
        view_open (BGP->views[0]);
       	set_trace (BGP->views[0]->trace, op, TR_ALL, NULL);
	view_close (BGP->views[0]);
    }
#ifdef HAVE_IPV6
    if (family == 0 || family == AF_INET6) {
        view_open (BGP->views[1]);
       	set_trace (BGP->views[1]->trace, op, TR_ALL, NULL);
	view_close (BGP->views[1]);
    }
#endif /* HAVE_IPV6 */
    return (1);
}


#ifdef notdef
void
bgp_redistribute_request (int from, int to, int on)
{
    view_t *view = BGP->views[0];
    bgp_route_head_t *head;
    generic_attr_t *attr;

    assert (to == PROTO_BGP);
#ifdef HAVE_IPV6
    if (from == PROTO_RIPNG)
        view = BGP->views[1];
#endif /* HAVE_IPV6 */
    VIEW_RADIX_WALK (view, head) {
	if (head->active) {
	    assert (head->active->attr->type == PROTO_BGP);
	    if (BIT_TEST (head->active->attr->options, BGP_INTERNAL))
		continue;

	    if (BIT_TEST (head->state_bits, VRTS_SUPPRESS))
	        continue;

	    attr = bgp2gen (head->active->attr);
	    if (attr) {
	        if (on)
	            MRT->proto_update_route[to] (head->prefix, attr, NULL);
	        else
	            MRT->proto_update_route[to] (head->prefix, NULL, attr);
	    }
    	    Deref_Generic_Attr (attr);
	}
    } VIEW_RADIX_WALK_END;
}
#endif


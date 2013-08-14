/*
 * $Id: rib.c,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
 */

#include <mrt.h>
#include <rib.h>

#ifdef NT
#include <winsock2.h>
#include <ws2tcpip.h>
#endif /* NT */

int num_active_generic_attr = 0;
int num_active_route_head = 0;
int num_active_route_node = 0;

static rib_t *RIBS[AFI_MAX][SAFI_MAX];

static void rib_flush_route (int proto, int afi, int safi);
static nexthop_t *rib_find_best_route (prefix_t *prefix, int safi);


static int
generic_attr_equal (generic_attr_t *a, generic_attr_t *b)
{
    return (a->type == b->type &&
	    a->gateway == b->gateway &&
	    a->nexthop == b->nexthop &&
	    a->tag == b->tag);
}


static buffer_t *
route_toa_buffer (prefix_t *prefix, generic_attr_t *attr, int pref, 
		  u_long flags, buffer_t *buffer)
{
    if (buffer == NULL)
	buffer = New_Buffer (0);
    
    if (attr->nexthop !=  NULL) 
      buffer_printf (buffer, "%p nh %a", prefix, attr->nexthop->prefix);
    else
      buffer_printf (buffer, "%p nh unknown", prefix);

    if (attr->gateway) {
	if (attr->nexthop == NULL ||
		!prefix_equal (attr->gateway->prefix,
			       attr->nexthop->prefix)) {
	    buffer_printf (buffer, " gw %a", attr->gateway->prefix);
	}
    }
    buffer_printf (buffer, " proto %s pref %d",
	     	   proto2string (attr->type), pref);
    if (flags != 0)
        buffer_printf (buffer, " flags 0x%x", flags);
    return (buffer);
}


static route_node_t *
New_Route_Node (route_head_t *route_head, generic_attr_t *attr, int pref,
		u_long flags)
{

    route_node_t *route_node = New (route_node_t);
    route_node->route_head = route_head;
    route_node->attr = Ref_Generic_Attr (attr);
    route_node->pref = pref;
    route_node->flags = flags;
    time (&route_node->time);
    num_active_route_node++;
    
    return (route_node);
}


static void 
Delete_Route_Node (route_node_t * rt_node)
{
    Deref_Generic_Attr (rt_node->attr);
    Delete (rt_node);
    num_active_route_node--;
}


static int
rib_compare_routes (route_node_t * a, route_node_t * b)
{
    /* prefereable */
    if (nexthop_available (a->attr->nexthop) && 
	    !nexthop_available (b->attr->nexthop))
	return (-1);
    if (!nexthop_available (a->attr->nexthop) && 
	    nexthop_available (b->attr->nexthop))
	return (1);

#ifdef notdef
    /* not prefereable */
    if (BIT_TEST (a->flags, MRT_RTOPT_NOINSTALL) &&
            !BIT_TEST (b->flags, MRT_RTOPT_NOINSTALL))
	return (1);
    if (!BIT_TEST (a->flags, MRT_RTOPT_NOINSTALL) &&
            BIT_TEST (b->flags, MRT_RTOPT_NOINSTALL))
	return (-1);

    /* MRT_RTOPT_KERNEL means it was also seen in the kernel */
    if (BIT_TEST (a->flags, MRT_RTOPT_KERNEL) &&
            !BIT_TEST (b->flags, MRT_RTOPT_KERNEL))
	return (1);
    if (!BIT_TEST (a->flags, MRT_RTOPT_KERNEL) &&
            BIT_TEST (b->flags, MRT_RTOPT_KERNEL))
	return (-1);

    if (BIT_TEST (a->flags, MRT_RTOPT_SUPPRESS) &&
            !BIT_TEST (b->flags, MRT_RTOPT_SUPPRESS))
	return (1);
    if (!BIT_TEST (a->flags, MRT_RTOPT_SUPPRESS) &&
            BIT_TEST (b->flags, MRT_RTOPT_SUPPRESS))
	return (-1);
#endif

    /* smaller pref wins */
    if (a->pref < b->pref)
	return (-1);
    if (a->pref > b->pref)
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


static route_head_t *
New_Route_Head (prefix_t * prefix)
{
    route_head_t *route_head = New (route_head_t);

    route_head->prefix = Ref_Prefix (prefix);
    route_head->ll_route_nodes = LL_Create (
			LL_DestroyFunction, Delete_Route_Node, 
			LL_CompareFunction, rib_compare_routes,
                        LL_AutoSort, True, 0);
    route_head->active = NULL;

    num_active_route_head++;
    return (route_head);
}


static void 
Delete_Route_Head (route_head_t *route_head)
{
    Deref_Prefix (route_head->prefix);
    LL_Destroy (route_head->ll_route_nodes);
    Delete (route_head);
    num_active_route_head--;
}


generic_attr_t *
New_Generic_Attr (int proto)
{
    generic_attr_t *attr;

    attr = New (generic_attr_t);
    attr->type = proto;
    attr->gateway = NULL;
    attr->nexthop = NULL;
    attr->parent = NULL;
    attr->ref_count = 1;
    pthread_mutex_init (&attr->mutex_lock, NULL);

    num_active_generic_attr++;
    return (attr);
}


generic_attr_t *
Ref_Generic_Attr (generic_attr_t * attr)
{
    if (attr == NULL)
	return (attr);
    pthread_mutex_lock (&attr->mutex_lock);
    attr->ref_count++;
    assert (attr->ref_count > 0);
    pthread_mutex_unlock (&attr->mutex_lock);
    return (attr);
}


void 
Deref_Generic_Attr (generic_attr_t * attr)
{
    if (attr == NULL)
	return;
#ifdef notdef
    if (attr->type == PROTO_RIPNG)
        ripng_deref_attr ((ripng_attr_t *)attr);
    else if (attr->type == PROTO_BGP)
	bgp_deref_attr ((bgp_attr_t *)attr);
    else {
#else
    {
#endif
        pthread_mutex_lock (&attr->mutex_lock);
        if (--attr->ref_count <= 0) {
	    deref_nexthop (attr->nexthop);
	    deref_nexthop (attr->parent);
            pthread_mutex_destroy (&attr->mutex_lock);
	    Delete (attr);
    	    num_active_generic_attr--;
	    return;
	}
        pthread_mutex_unlock (&attr->mutex_lock);
    }
}


rib_t *
New_Rib (int maxbitlen)
{
    rib_t *rib = New (rib_t);

    /*rib->ll_route_nodes = LL_Create (0); */
    rib->ll_changed_route_nodes = LL_Create (0);

    /*if (LL_ATTR_MEMORY == NULL)
       init_attr_memory (); */

    if (pthread_mutex_init (&rib->mutex_lock, NULL) != 0) {
		perror ("rib pthread_mutex_init");
		//exit (0);
    }
    rib->radix_tree = New_Radix (maxbitlen);
    rib->num_active_routes = 0;
    rib->num_active_nodes = 0;
    time (&rib->time);
    return (rib);
}


static int
check_networks (prefix_t * prefix, LINKED_LIST * ll_networks)
{
    prefix_t *network;

    assert (ll_networks);
    LL_Iterate (ll_networks, network) {
	if (network->family == prefix->family &&
	    a_include_b (network, prefix))
	    return (1);
    }
    return (0);
}


/* on > 0 -- redistribute on, on == 0 -- off, on < 0 -- just stopping */
static int
rib_redistribute_request2 (rib_t *rib, int from, int from_viewno, 
			   int to, int on)
{
    route_head_t *route_head;
    route_node_t *route_node;

    assert (from == PROTO_BGP || from_viewno == 0);
    rib_open (rib);
    if (on <= 0) {
	if (!BGP4_BIT_TEST (rib->redistribute_mask[from + from_viewno], to)) {
	    rib_close (rib);
	    return (0);
	}
	BGP4_BIT_RESET (rib->redistribute_mask[from + from_viewno], to);
    }
    else {
	if (BGP4_BIT_TEST (rib->redistribute_mask[from + from_viewno], to)) {
	    rib_close (rib);
	    return (0);
	}
	BGP4_BIT_SET (rib->redistribute_mask[from + from_viewno], to);
    }

if (on >= 0) {
    RIB_RADIX_WALK (rib, route_head) {
	int skip = 0;

	if (BGP4_BIT_TEST (rib->ll_networks_mask[from + from_viewno], to)) {
	    assert (rib->ll_networks[from + from_viewno]);
	    if (check_networks (route_head->prefix, 
				rib->ll_networks[from + from_viewno]))
		skip++;
	}

if (!skip)
	LL_Iterate (route_head->ll_route_nodes, route_node) {
    	    if (BIT_TEST (route_node->flags, MRT_RTOPT_SUPPRESS))
	        continue;
    	    if (!nexthop_available (route_node->attr->nexthop))
	        continue;
	    if (route_node->attr->type != to)
		continue;

	    if (on)
    		MRT->proto_update_route[from] (route_head->prefix,
					       route_node->attr, NULL,
					       route_node->pref, from_viewno);
	    else
    		MRT->proto_update_route[from] (route_head->prefix,
					       NULL, route_node->attr,
					       0, from_viewno);
	} 
    } RIB_RADIX_WALK_END;
}
    rib_close (rib);
    return (1);
}


/* 
   router rip
   redistribute static
     => rib->redistribute_mask[RIP] |= (1 << STATIC)
*/
static int
rib_redistribute_request (int from, int from_viewno, int to, int on, 
			  int afi, int safi)
{
    rib_t *rib;

    assert (afi >= 0 && afi < AFI_MAX);
    if (afi <= 0)
	afi = AFI_IP;
    assert (safi >= 0 && safi < SAFI_MAX);
    if (safi <= 0)
	safi = SAFI_UNICAST;
    rib = RIBS[afi][safi];
    if (rib == NULL)
	return (0);

    return (rib_redistribute_request2 (rib, from, from_viewno, to,  on));
}


/* 
   router rip
   network 1.2.3.4
     => rib->ll_networks_mask[RIP] |= (1 << CONNECTED)
     => rib->ll_networks[RIP] += (1.2.3.4)
*/
static int
rib_redistribute_network (int from, int viewno, prefix_t *network, int on,
			  int safi)
{
    route_head_t *route_head;
    route_node_t *route_node;
    rib_t *rib;
    u_long mask = 0;
    int afi;

    assert (safi >= 0 && safi < SAFI_MAX);
    if (safi <= 0)
	safi = SAFI_UNICAST;
    assert (network);
    afi = family2afi (network->family);
    rib = RIBS[afi][safi];

    switch (from) {
    case PROTO_BGP:
	BGP4_BIT_SET (mask, PROTO_RIP);
	BGP4_BIT_SET (mask, PROTO_OSPF);
	BGP4_BIT_SET (mask, PROTO_STATIC);
#ifdef HAVE_IPV6
	BGP4_BIT_SET (mask, PROTO_RIPNG);
#endif /* HAVE_IPV6 */
	BGP4_BIT_SET (mask, PROTO_CONNECTED);
	break;
    default:
	assert (viewno == 0); /* XXX */
	BGP4_BIT_SET (mask, PROTO_CONNECTED);
	break;
    }
#ifdef HAVE_IPV6
    if (network->family == AF_INET6)
	rib = RIBv6;
#endif /* HAVE_IPV6 */

        rib_open (rib);
	if (on > 0) {
	    if (rib->ll_networks[from + viewno]) {
		prefix_t *prefix;
		LL_Iterate (rib->ll_networks[from + viewno], prefix) {
		    if (prefix_equal (prefix, network)) {
			rib_close (rib);
			return (-1);
		    }
		}
	    }
	    else {
		rib->ll_networks[from + viewno] = LL_Create (LL_DestroyFunction, 
						    Deref_Prefix, 0);
		BIT_SET (rib->ll_networks_mask[from + viewno], mask);
	    }
	    LL_Add (rib->ll_networks[from + viewno], Ref_Prefix (network));
	}
	else {
	    if (rib->ll_networks[from + viewno] == NULL) {
		rib_close (rib);
		return (-1);
	    }
	    else {
		prefix_t *prefix;
		LL_Iterate (rib->ll_networks[from + viewno], prefix) {
		    if (prefix_equal (prefix, network))
			break;
		}
		if (prefix == NULL) {
		    rib_close (rib);
		    return (-1);
		}
	        LL_Remove (rib->ll_networks[from + viewno], network);
		if (LL_GetCount (rib->ll_networks[from + viewno]) <= 0) {
		    LL_Destroy (rib->ll_networks[from + viewno]);
		    rib->ll_networks[from + viewno] = NULL;
		    rib->ll_networks_mask[from + viewno] = 0;
		}
	    }
	}

    if (on >= 0) {
        RIB_RADIX_WALK (rib, route_head) {
	    assert (route_head);

	    if (a_include_b (network, route_head->prefix)) {

	      LL_Iterate (route_head->ll_route_nodes, route_node) {

    		if (BIT_TEST (route_node->flags, MRT_RTOPT_SUPPRESS))
		    continue;
		if (!nexthop_available (route_node->attr->nexthop))
                    continue;

		if (!BGP4_BIT_TEST (rib->redistribute_mask[from + viewno], 
				   route_node->attr->type) &&
		    BGP4_BIT_TEST (rib->ll_networks_mask[from + viewno], 
				    route_node->attr->type)) {
		if (on)
    		    MRT->proto_update_route[from] (route_head->prefix,
					           route_node->attr, NULL,
					           route_node->pref, viewno);
		else
    		    MRT->proto_update_route[from] (route_head->prefix,
					           NULL, route_node->attr, 
					           0, viewno);
		}
	      }
	    }
        } RIB_RADIX_WALK_END;
    }
    rib_close (rib);
    return (1);
}


/*
 * get "head" of routing table entry for a given prefix. Create a head
 * and radix-tree entry if one does not aleady exist
 */
static route_head_t *
rib_get_route_head (rib_t * rib, prefix_t * prefix)
{
    route_head_t *route_head;
    radix_node_t *radix_node;

    assert (pthread_mutex_trylock (&rib->mutex_lock));
    assert (family2afi (prefix->family) == rib->afi);

    radix_node = radix_search_exact (rib->radix_tree, prefix);
    if (radix_node == NULL) {
	route_head = New_Route_Head (prefix);
	radix_node = radix_lookup (rib->radix_tree, prefix);
	assert (radix_node->data == NULL);
        RADIX_DATA_SET (radix_node, route_head);
	route_head->radix_node = radix_node;
	rib->num_active_routes++;

	if (TR_TRACE & rib->trace->flags)
	  trace (TR_TRACE, rib->trace, "new route head for %s\n",
		 prefix_toax (prefix));
    }
    else {
	route_head = RADIX_DATA_GET (radix_node, route_head_t);
    }

    return (route_head);
}


/*
 * given a prefix AND type, find route node entry
 * return NULL if one does not exist
 */
static route_node_t *
rib_find_route_node (rib_t * rib,
		     prefix_t * prefix, generic_attr_t * attr)
{
    route_head_t *route_head;
    route_node_t *route_node;
    radix_node_t *radix_node;

    assert (pthread_mutex_trylock (&rib->mutex_lock));

    if ((radix_node = radix_search_exact (rib->radix_tree, prefix)) != NULL) {
	route_head = RADIX_DATA_GET (radix_node, route_head_t);
	assert (route_head);
	LL_Iterate (route_head->ll_route_nodes, route_node) {
	    if (route_node->attr->type == attr->type)
		return (route_node);
	}
    }

    return (NULL);
}


static void
rib_kernel_call_fn (rib_t *rib, prefix_t *prefix, 
		    generic_attr_t *new, u_long flags, int pref,
		    generic_attr_t *old, u_long oflags)
{
    /* update the time active changed */
    time (&rib->time);

    /* XXX kernel handles unicast only */
    if (rib->safi != SAFI_UNICAST)
	return;
    if (MRT->kernel_update_route == NULL)
	return;

    if (new && (/* new->type == PROTO_KERNEL || */
             new->type == PROTO_CONNECTED))
	new = NULL;

    if (old && (/* old->type == PROTO_KERNEL || */
             old->type == PROTO_CONNECTED))
	old = NULL;

    if (BIT_TEST (flags, MRT_RTOPT_NOINSTALL))
	new = NULL;

    if (BIT_TEST (oflags, MRT_RTOPT_NOINSTALL))
	old = NULL;

    if (new != NULL || old != NULL)
	MRT->kernel_update_route (prefix, new, old, pref);
}


static void
rib_update_call_fn (rib_t *rib, prefix_t *prefix, 
		    generic_attr_t *new, u_long flags, int pref,
		    generic_attr_t *old, u_long oflags, int force)
{
    int type, i;

    assert (prefix);
    if (BIT_TEST (flags, MRT_RTOPT_SUPPRESS))
		new = NULL;
    if (new && (!force && !nexthop_available (new->nexthop)))
		new = NULL;
    if (BIT_TEST (oflags, MRT_RTOPT_SUPPRESS))
		old = NULL;
    if (old && (!force && !nexthop_available (old->nexthop)))
		old = NULL;
    if (new == NULL && old == NULL)
		return;
    if (new && old) {
		if (new->type != old->type) {
			/* kernel route may be replaced by others */
			/* add new then withdraw old */
			rib_update_call_fn (rib, prefix, new, flags, pref, NULL, 0, force);
			rib_update_call_fn (rib, prefix, NULL, 0, 0, old, oflags, force);
			return;
		}
		type = new->type;
		/* they can overwrite so that old is not required */
		old = NULL;
    }
    else if (new) {
		type = new->type;
    }
    else /* if (old) */ {
		assert (old);
		type = old->type;
    }

    for (i = PROTO_MIN; i < PROTO_MAX; i++) {
	if (BGP4_BIT_TEST (rib->redistribute_mask[i], type)) {
            MRT->proto_update_route[i] (prefix, new, old, pref, 0);
	    continue;
	}
	if (BGP4_BIT_TEST (rib->ll_networks_mask[i], type)) {
	    assert (rib->ll_networks[i]);
	    if (check_networks (prefix, rib->ll_networks[i]))
                MRT->proto_update_route[i] (prefix, new, old, pref, 0);
	}
    }

    /* XXXX I should improve the way... masaki */
    assert (i == PROTO_MAX);
    assert (i == PROTO_BGP);
    for (i = 0; i < MAX_BGP_VIEWS; i++) {
	if (BGP4_BIT_TEST (rib->redistribute_mask[i + PROTO_BGP], type)) {
            MRT->proto_update_route[PROTO_BGP] (prefix, new, old, pref, i);
	    continue;
	}
	if (BGP4_BIT_TEST (rib->ll_networks_mask[i + PROTO_BGP], type)) {
	    assert (rib->ll_networks[i + PROTO_BGP]);
	    if (check_networks (prefix, rib->ll_networks[i + PROTO_BGP]))
                MRT->proto_update_route[PROTO_BGP] (prefix, new, old, pref, i);
	}
    }
}


static void 
rib_replace_active (rib_t * rib, route_head_t * route_head, int force)
{
    route_node_t *best;

    best = LL_GetHead (route_head->ll_route_nodes);

    /* active must be nexthop_availavle */
    if (best != NULL && !nexthop_available (best->attr->nexthop))
	best = NULL;

    if (best == NULL) {	/* there is no other route nodes */
	/* active may be null */
	if (route_head->active) {
	    rib_kernel_call_fn (rib, route_head->prefix, NULL, 0, 0, 
			    route_head->active->attr, 
			    route_head->active->flags);
	    route_head->active = NULL;
	}
	if (LL_GetCount (route_head->ll_route_nodes) <= 0) {
	    trace (TR_TRACE, rib->trace, "delete route head for %p\n",
		   route_head->prefix);
	    radix_remove (rib->radix_tree, route_head->radix_node);
	    Delete_Route_Head (route_head);
	    rib->num_active_routes--;
	}
	return;
    }

    if (route_head->active == best) {
	if (force)
            rib_kernel_call_fn (rib, route_head->prefix, 
			        best->attr, best->flags, best->pref, NULL, 0);
	return;
    }

    /* route update */

    if (BIT_TEST (rib->trace->flags, TR_TRACE)) {
	buffer_t *buffer = New_Buffer (0);
	route_toa_buffer (route_head->prefix, best->attr, best->pref, 
			  best->flags, buffer);
        trace (TR_TRACE, rib->trace, "active: %s\n", buffer_data (buffer));
	Delete_Buffer (buffer);
    }

    if (route_head->active != NULL &&
	    route_head->active->attr->nexthop == 
			best->attr->nexthop /* nexthop unchange */) {
	/* they are the same, so it's OK if replaced. */
	/* this is required in case active is being deleted. */
	if (force) {
	    /* nexthop may be changed. overwriting */
            rib_kernel_call_fn (rib, route_head->prefix, 
			        best->attr, best->flags, best->pref, NULL, 0);
	}
    }
    else if (route_head->active != NULL) {
        rib_kernel_call_fn (rib, route_head->prefix, 
			best->attr, best->flags, best->pref,
			route_head->active->attr, route_head->active->flags);
    }
    else {
	assert (route_head->active == NULL);
        rib_kernel_call_fn (rib, route_head->prefix, 
			best->attr, best->flags, best->pref, NULL, 0);
    }
    route_head->active = best;
}


static void 
rib_delete_route_node (rib_t * rib, route_node_t * route_node)
{
    route_head_t *route_head;

    assert (pthread_mutex_trylock (&rib->mutex_lock));

    route_head = route_node->route_head;
    LL_RemoveFn (route_head->ll_route_nodes, route_node, 0);
    rib->num_active_nodes--;

    if (BIT_TEST (rib->trace->flags, TR_TRACE)) {
	buffer_t *buffer = New_Buffer (0);
	route_toa_buffer (route_head->prefix, route_node->attr, 
			  route_node->pref, route_node->flags, buffer);
        trace (TR_TRACE, rib->trace, "delete: %s\n", buffer_data (buffer));
	Delete_Buffer (buffer);
    }

    if (route_node->protocol_mask == 0) {
	/* what's protocol_mask? */
    }

   /* sometimes next-hop has been already unavailable */
    rib_update_call_fn (rib, route_head->prefix, NULL, 0, 0, 
			route_node->attr, route_node->flags, 1 /* force */);
    rib_replace_active (rib, route_head, 0);

    /* delete here */
    Delete_Route_Node (route_node);
}


static void 
rib_route_sweep (rib_t * rib, int type)
{
    route_head_t *route_head;
    route_node_t *route_node;
    LINKED_LIST *ll;

    assert (pthread_mutex_trylock (&rib->mutex_lock));

    ll = LL_Create (0);
    RIB_RADIX_WALK (rib, route_head) {
	LL_Iterate (route_head->ll_route_nodes, route_node) {
	    if (route_node->attr->type == type)
		LL_Add (ll, route_node);
	}
    } RIB_RADIX_WALK_END;

    LL_Iterate (ll, route_node) {
	rib_delete_route_node (rib, route_node);
    }
    LL_Destroy (ll);
}


static void 
rib_flush_route (int proto, int afi, int safi)
{
    rib_t *rib;

    assert (afi >= 0 && afi < AFI_MAX);
    if (afi <= 0)
	afi = AFI_IP;
    assert (safi >= 0 && safi < SAFI_MAX);
    if (safi <= 0)
	safi = SAFI_UNICAST;

    if ((rib = RIBS[afi][safi]) != NULL) {
        rib_open (rib);
        rib_route_sweep (rib, proto);
        rib_close (rib);
    }
}


void 
rib_update_route (prefix_t *prefix, generic_attr_t *new,  
		  generic_attr_t *old, int pref, u_long flags,
		  int safi)
{
    rib_t *rib;
    int afi;

    assert (safi >= 0 && safi < SAFI_MAX);
    if (safi <= 0)
	safi = SAFI_UNICAST;
    assert (prefix);
    afi = family2afi (prefix->family);
    assert (afi >= 0 && afi < AFI_MAX);
    rib = RIBS[afi][safi];
    if (rib == NULL)
	return;

    if (new && new->parent) {
	nexthop_t *nexthop;
	assert (new->type == PROTO_BGP);
	if (new->nexthop == NULL) {
	    /* the current version of bgp supplies this */
	    nexthop = rib_find_best_route (new->parent->prefix, SAFI_UNICAST);
	    if (nexthop && BIT_TEST (nexthop->flags, GATEWAY_UNSPEC)) {
	        /* direct interface route */
	        new->nexthop = add_nexthop (new->parent->prefix, 
				            nexthop->interface);
	    }
	    else {
	        new->nexthop = ref_nexthop (nexthop);
	    }
	}
    }

    rib_open (rib);
    if (new) {
	rib_add_route (rib, prefix, new, pref, flags);
    }
    else {
	assert (old);
	rib_del_route (rib, prefix, old);
    }
    rib_close (rib);
}


static time_t 
rib_time (int afi, int safi)
{
    rib_t *rib;

    assert (afi >= 0 && afi < AFI_MAX);
    assert (safi >= 0 && safi < SAFI_MAX);

    if ((rib = RIBS[afi][safi]) == NULL)
	return (0);
    return (rib->time);
}


static void 
rib_update_nexthop (int afi, int safi)
{
    route_head_t *route_head;
    route_node_t *route_node;
    rib_t *rib;

    assert (afi >= 0 && afi < AFI_MAX);
    assert (safi >= 0 && safi < SAFI_MAX);

    if ((rib = RIBS[afi][safi]) == NULL)
	return;
    if (rib->nexthop_last_time >= rib->time)
	return;

    rib_open (rib);
    RIB_RADIX_WALK (rib, route_head) {
	int change = 0;

        LL_Iterate (route_head->ll_route_nodes, route_node) {
	    radix_node_t *radix_node;
	    nexthop_t *old = route_node->attr->nexthop;

	    if (route_node->attr->parent == NULL)
		continue;
            trace (TR_TRACE, rib->trace, "nexthop checking: %a for %p\n", 
	           route_node->attr->parent->prefix, route_head->prefix);

    	    radix_node = radix_search_best (rib->radix_tree, 
					    route_node->attr->parent->prefix);
    	    if (radix_node != NULL) {
		route_head_t *head;

		head = RADIX_DATA_GET (radix_node, route_head_t);
		assert (head);
		if (head->active) {
		    assert (head->active->attr->nexthop);
		    assert (head->active->attr->nexthop->interface);
		    if (head->active->attr->nexthop &&
			BIT_TEST (head->active->attr->nexthop->flags, 
				  GATEWAY_UNSPEC)) {
	    		/* direct interface route */
	    	         route_node->attr->nexthop = 
			 	add_nexthop (route_node->attr->parent->prefix, 
				    head->active->attr->nexthop->interface);
		    }
		    else {
		        route_node->attr->nexthop = 
			    ref_nexthop (head->active->attr->nexthop);
		    }
		}
		else {
		    route_node->attr->nexthop = NULL;
		}
	    }
	    else {
		route_node->attr->nexthop = NULL;
	    }

	    if (old == route_node->attr->nexthop) {
		/* nexthop didn't change */
		deref_nexthop (old);
		continue;
	    }
            trace (TR_TRACE, rib->trace, 
		   "direct nexthop: %s on %s -> %s on %s for %p\n", 
	           (old)? prefix_toa (old->prefix): "n/a",
		   (old && old->interface)? old->interface->name: "?",
		   (route_node->attr->nexthop)?
		   prefix_toa (route_node->attr->nexthop->prefix): "n/a",
		   (route_node->attr->nexthop && 
			route_node->attr->nexthop->interface)? 
			route_node->attr->nexthop->interface->name: "?",
		   route_head->prefix);
	    deref_nexthop (old);
	    change++;

	    rib_update_call_fn (rib, route_head->prefix,
                    		route_node->attr, route_node->flags, 
				route_node->pref, NULL, 0, 1 /* force */);
	}

	if (change) 
	    rib_replace_active (rib, route_head, 1);

    } RIB_RADIX_WALK_END;
    rib_close (rib);
    rib->nexthop_last_time = rib->time;
}


static void 
rib_if_call_fn (int cmd, interface_t *interface, ll_addr_t *if_addr)
{
    rib_t *rib;
    int afi, safi;

    /* if up/down only */
    if (if_addr != NULL)
	return;

    for (afi = 0; afi < AFI_MAX; afi++) {
        for (safi = 0; safi < SAFI_MAX; safi++) {
    	    route_head_t *route_head;
    	    route_node_t *route_node;

    	    if ((rib = RIBS[afi][safi]) == NULL)
		continue;

    	    rib_open (rib);
    	    RIB_RADIX_WALK (rib, route_head) {
		int change = 0;

        	LL_Iterate (route_head->ll_route_nodes, route_node) {

	            if (route_node->attr->nexthop == NULL ||
			    route_node->attr->nexthop->interface != interface)
		        continue;

    		    if (cmd == 'A') {
			assert (BIT_TEST (interface->flags, IFF_UP));
			/* going up */
		        rib_update_call_fn (rib, route_head->prefix,
                        	        route_node->attr, route_node->flags, 
				        route_node->pref, 
				        NULL, 0, 0);
			change++;
		    }
    		    if (cmd == 'D') {
			assert (!BIT_TEST (interface->flags, IFF_UP));
			/* going down */
		        rib_update_call_fn (rib, route_head->prefix,
                        	        NULL, 0, 0, 
				        route_node->attr, route_node->flags,
					1 /* force */);
			change++;
		    }
		}
	   
		if (change) {
	            LL_Sort (route_head->ll_route_nodes);
		    /* force to update */
		    rib_replace_active (rib, route_head, 1);
		}
    	    } RIB_RADIX_WALK_END;
    	    rib_close (rib);
        }
    }
}


/*
 * create a route_node and add it to the appropriate route_head,
 * or create a route_head if not already exist. Returnthe new route_node.
 */

route_node_t *
rib_add_route (rib_t *rib, prefix_t *prefix, generic_attr_t *attr, int pref,
	       u_long flags)
{
    route_node_t *route_node;
    route_head_t *route_head;

    assert (rib);
    assert (prefix);
    assert (attr);
    assert (pthread_mutex_trylock (&rib->mutex_lock));

    route_head = rib_get_route_head (rib, prefix);

    /* check to see if we already got this route from the same proto */

    LL_Iterate (route_head->ll_route_nodes, route_node) {
        if (route_node->attr->type == attr->type)
	    break;
	/* kernel route with the same nexthop will be overwritten */
        if (route_node->attr->type == PROTO_KERNEL &&
#ifdef notdef
		/* interface info may be different but doesn't matter */
	        prefix_equal (route_node->attr->nexthop->prefix, 
				attr->nexthop->prefix)) {
#endif
		route_node->attr->nexthop == attr->nexthop) {
	    BIT_SET (flags, MRT_RTOPT_KERNEL);
	    break;
	}
	/* mark the route */
        if (attr->type == PROTO_KERNEL &&
#ifdef notdef
	        prefix_equal (route_node->attr->nexthop->prefix, 
				attr->nexthop->prefix)) {
#endif
		route_node->attr->nexthop == attr->nexthop) {
	    BIT_SET (route_node->flags, MRT_RTOPT_KERNEL);
	    return (route_node);
	}
    }

    if (route_node) {
	route_node_t *new_route;

	/* if the existing route has MRT_RTOPT_KERNEL,
	   it will be inherited to the new route */
	if (BIT_TEST (route_node->flags, MRT_RTOPT_KERNEL))
	    BIT_SET (flags, MRT_RTOPT_KERNEL);

	    /* protocol decides which is the best with its policy */
#ifdef notdef
	if (pref <= route_node->pref) {
	    /* equal or better preference */
#endif /* notdef */

	    if (pref == route_node->pref && flags == route_node->flags &&
		    generic_attr_equal (attr, route_node->attr)) {

	      if (BIT_TEST (rib->trace->flags, TR_TRACE)) {
        	  buffer_t *buffer = New_Buffer (0);
		  route_toa_buffer (prefix, route_node->attr, route_node->pref,
			            route_node->flags, buffer);
		  trace (TR_TRACE, rib->trace, "ignore: %s (same)\n", 
			 buffer_data (buffer));
        	  Delete_Buffer (buffer);
	      }
	      return (route_node);
	    }

	    /* implicit withdarw of old route -- delete it */
	    /* on deleting, 
		do I have to notify the proto engine which supplied? */

	    if (BIT_TEST (rib->trace->flags, TR_TRACE)) {
        	buffer_t *buffer = New_Buffer (0);
		route_toa_buffer (prefix, route_node->attr, route_node->pref, 
				  route_node->flags, buffer);
	        trace (TR_TRACE, rib->trace, 
		       "update: %s (new pref %d)\n", 
		       buffer_data (buffer), pref);
        	Delete_Buffer (buffer);
	    }

    	    new_route = New_Route_Node (route_head, attr, pref, flags);
    	    LL_Add (route_head->ll_route_nodes, new_route);
    	    rib->num_active_nodes++;
	    LL_RemoveFn (route_head->ll_route_nodes, route_node, 0);
    	    rib->num_active_nodes--;

    	    rib_update_call_fn (rib, prefix, attr, flags, pref, 
				route_node->attr, route_node->flags, 0);
	    rib_replace_active (rib, route_head, 0);

    	    Delete_Route_Node (route_node);
	    return (route_node);
#ifdef notdef
	}
	else {
	  /* same or bad .. ignore it */
	  if (BIT_TEST (rib->trace->flags, TR_TRACE)) {
	      buffer_t *buffer = New_Buffer (0);
	      route_toa_buffer (prefix, attr, pref, flags, buffer);
	      trace (TR_TRACE, rib->trace, "ignore: %s (now pref %d)\n",
		   buffer_data (buffer), route_node->pref);
              Delete_Buffer (buffer);
	   }
	   return (route_node);
	}
#endif /* notdef */
    }

    /* first time we've heard this in this proto */
    route_node = New_Route_Node (route_head, attr, pref, flags);
    LL_Add (route_head->ll_route_nodes, route_node);
    rib->num_active_nodes++;

    if (BIT_TEST (rib->trace->flags, TR_TRACE)) {
        buffer_t *buffer = New_Buffer (0);
	route_toa_buffer (prefix, attr, pref, flags, buffer);
        trace (TR_TRACE, rib->trace, "add: %s\n", buffer_data (buffer));
        Delete_Buffer (buffer);
    }
    rib_update_call_fn (rib, prefix, attr, flags, pref, NULL, 0, 0);
    rib_replace_active (rib, route_head, 0);

    return (route_node);
}


/* XXX
 * attr is not used seriously, only attr->type is unsed.
 */
int
rib_del_route (rib_t * rib, prefix_t * prefix, generic_attr_t * attr)
{
    route_node_t *route_node;

    assert (pthread_mutex_trylock (&rib->mutex_lock));
    if ((route_node = rib_find_route_node (rib, prefix, attr)) == NULL)
	return (-1);
    assert (route_node);
    rib_delete_route_node (rib, route_node);
    return (1);
}


void 
rib_open (rib_t * rib)
{
    if (pthread_mutex_trylock (&rib->mutex_lock) != 0) {
	trace (TR_DEBUG, rib->trace, "Going to block in rib_open\n");
	pthread_mutex_lock (&rib->mutex_lock);
    }
}


void 
rib_close (rib_t * rib)
{
    pthread_mutex_unlock (&rib->mutex_lock);
}


/* called from BGP to look up a nexthop for mutihop neighbor */
static nexthop_t *
rib_find_best_route (prefix_t *prefix, int safi)
{
    rib_t *rib;
    route_head_t *route_head;
    radix_node_t *radix_node;
    nexthop_t *nexthop = NULL;
    int afi;

    assert (safi >= 0 && safi < SAFI_MAX);
    if (safi <= 0)
	safi = SAFI_UNICAST;
    afi = family2afi (prefix->family);
    assert (afi >= 0 && afi < AFI_MAX);
    rib = RIBS[afi][safi];
    if (rib == NULL)
	return (NULL);

    rib_open (rib);
    radix_node = radix_search_best (rib->radix_tree, prefix);
    if (radix_node != NULL) {
	route_head = RADIX_DATA_GET (radix_node, route_head_t);
	assert (route_head);
	if (route_head->active)
	    nexthop = route_head->active->attr->nexthop;
    }
    rib_close (rib);
    trace (TR_DEBUG, rib->trace, "rib_find_best_route %p return %a on %s\n",
	   prefix, (nexthop)?nexthop->prefix:NULL, 
		(nexthop && nexthop->interface)?nexthop->interface->name:"?");
    return (nexthop);
}


/* called from multicast protocols to obtain an upstream for the source */
static nexthop_t *
rib_find_upstream (prefix_t *prefix, int safi)
{
    rib_t *rib;
    route_head_t *route_head;
    radix_node_t *radix_node;
    nexthop_t *nexthop = NULL;
    int afi;

    assert (safi >= 0 && safi < SAFI_MAX);
    if (safi <= 0)
	safi = SAFI_UNICAST;
    afi = family2afi (prefix->family);
    assert (afi >= 0 && afi < AFI_MAX);
    rib = RIBS[afi][safi];
    if (rib == NULL)
	return (NULL);

    rib_open (rib);
    radix_node = radix_search_best (rib->radix_tree, prefix);
    if (radix_node != NULL) {
	route_head = RADIX_DATA_GET (radix_node, route_head_t);
	assert (route_head);
	if (route_head->active)
	    nexthop = route_head->active->attr->nexthop;
    }
    rib_close (rib);
    return (nexthop);
}


void
init_rib (trace_t * tr)
{
    assert (RIB == NULL);
    RIB = New_Rib (32);
    RIB->afi = AFI_IP;
    RIB->safi = SAFI_UNICAST;
    RIB->trace = trace_copy (tr);
    set_trace (RIB->trace, TRACE_PREPEND_STRING, "RIB", 0);
    RIBS[AFI_IP][SAFI_UNICAST] = RIB;
#ifdef HAVE_MROUTING
    assert (RIBm == NULL);
    RIBm = New_Rib (32);
    RIBm->afi = AFI_IP;
    RIBm->safi = SAFI_MULTICAST;
    RIBm->trace = trace_copy (tr);
    set_trace (RIBm->trace, TRACE_PREPEND_STRING, "RIBm", 0);
    RIBS[AFI_IP][SAFI_MULTICAST] = RIBm;
#endif /* HAVE_MROUTING */

#ifdef HAVE_IPV6
    assert (RIBv6 == NULL);
    RIBv6 = New_Rib (128);
    RIBv6->afi = AFI_IP6;
    RIBv6->safi = SAFI_UNICAST;
    RIBv6->trace = trace_copy (tr);
    set_trace (RIBv6->trace, TRACE_PREPEND_STRING, "RIB6", 0);
    RIBS[AFI_IP6][SAFI_UNICAST] = RIBv6;
#ifdef HAVE_MROUTING6
    assert (RIBv6m == NULL);
    RIBv6m = New_Rib (128);
    RIBv6m->afi = AFI_IP6;
    RIBv6m->safi = SAFI_MULTICAST;
    RIBv6m->trace = trace_copy (tr);
    set_trace (RIBv6m->trace, TRACE_PREPEND_STRING, "RIB6m", 0);
    RIBS[AFI_IP6][SAFI_MULTICAST] = RIBv6m;
#endif /* HAVE_MROUTING6 */
#endif /* HAVE_IPV6 */
    MRT->rib_update_route = rib_update_route;
    MRT->rib_flush_route = rib_flush_route;
    MRT->rib_redistribute_request = rib_redistribute_request;
    MRT->rib_redistribute_network = rib_redistribute_network;
    MRT->rib_find_best_route = rib_find_best_route;
    MRT->rib_find_upstream = rib_find_upstream;
    MRT->rib_update_nexthop = rib_update_nexthop;
    MRT->rib_time = rib_time;
/*
    if (INTERFACE_MASTER)
        LL_Add (INTERFACE_MASTER->ll_call_fns, rib_if_call_fn);
*/
}


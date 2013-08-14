/*
 * $Id: rip_proto.c,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
 * routines shared by RIP-2 and RIPng
 */

#include <mrt.h>
#include <api6.h>
#include <array.h>
#include <config_file.h>
#include <rip.h>

#ifdef NT
#include <winsock2.h>
#ifdef HAVE_IPV6
#include <ws2ip6.h>
//#include <devioctl.h>
#endif /* HAVE_IPV6 */
#include <windows.h>
#include <ws2tcpip.h>
#endif /* NT */

#ifdef notdef
static DATA_PTR
LL_Add_uniq (LINKED_LIST *ll, DATA_PTR p)
{
    DATA_PTR q;

    LL_Iterate (ll, q) {
	if (p == q)
	    break;
    }
    if (q) LL_RemoveFn (ll, q, NULL);
    LL_Add (ll, p);
    return (p);
}
#endif


rip_attr_t *
rip_new_attr (rip_t * rip, int metric)
{
    rip_attr_t *attr;

    attr = New (rip_attr_t);
    attr->type = rip->proto;
    attr->metric = metric;
    attr->pref = RIP_PREF;
    attr->ctime = time (NULL);
    attr->utime = 0;
    attr->dtime = 0;

    return (attr);
}


void
rip_del_attr (rip_attr_t * attr)
{
    assert (attr);
    deref_nexthop (attr->nexthop);
    Delete (attr);
}


static int
rip_comp_attr (rip_attr_t *a, rip_attr_t *b)
{
    if (a->pref != b->pref)
	return (a->pref - b->pref);
    if ((a->type == PROTO_RIP || a->type == PROTO_RIPNG) 
	    && a->type == b->type)
        return (a->metric - b->metric);
    return (a->type - b->type);
}


/* 
 * create/allocate new rip_route_t structure and insert
 * it in the prefix route hash table
 */
rip_route_t *
rip_new_route (rip_t * rip, prefix_t * prefix, rip_attr_t * attr)
{
    rip_route_t *route;

    route = New (rip_route_t);
    route->prefix = Ref_Prefix (prefix);
    route->received = LL_Create (LL_CompareFunction, rip_comp_attr,
                                  LL_AutoSort, True,
				  LL_DestroyFunction, rip_del_attr, 0);
    route->imported = LL_Create (LL_CompareFunction, rip_comp_attr,
                                 LL_AutoSort, True,
				 LL_DestroyFunction, rip_del_attr, 0);
    if (attr->type == PROTO_RIP || attr->type == PROTO_RIPNG) {
	route->current = attr;
    }
    else {
        LL_Add (route->imported, attr);
    }
    route->active = attr;
    route->flags |= RT_RIP_CHANGE;
    HASH_Insert (rip->hash, route);
    rip->changed++;
    return (route);
}


/* 
 * free route memory and remove from hash
 */
static void
rip_delete_route (rip_route_t * route)
{
    Deref_Prefix (route->prefix);
    LL_Destroy (route->imported);
    LL_Destroy (route->received);
    if (route->current)
        rip_del_attr (route->current);
    Delete (route);
}


static void
rip_set_flash_update (rip_t * rip)
{
    time_t t;

    if (rip->flash_update_waiting) {
	trace (TR_TRACE, rip->trace, "flash timer already running\n");
	return;
    }
/* check to see the RIP and RIPNG */
    t = RIP_FLASH_DELAY_MIN +
	rand () % (RIP_FLASH_DELAY_MAX - RIP_FLASH_DELAY_MIN + 1);
    Timer_Set_Time (rip->flash, t);
    Timer_Turn_ON (rip->flash);
    rip->flash_update_waiting++;
}


static generic_attr_t *
rip2gen (rip_attr_t *attr)
{
    generic_attr_t *gattr;

    if (attr == NULL)
	return (NULL);
    gattr = New_Generic_Attr (attr->type);
    gattr->gateway = attr->gateway;
    gattr->nexthop = ref_nexthop (attr->nexthop);
    return (gattr);
}


static void
rip_update_call_fn (rip_t * rip, prefix_t * prefix, rip_attr_t * new, 
		    rip_attr_t *old)
{
    generic_attr_t *gnew;
    generic_attr_t *gold;
    rib_update_route_t fn;

    assert (prefix);
    if ((fn = MRT->rib_update_route) == NULL)
	return;

    gnew = rip2gen (new);
    gold = rip2gen (old);

    fn (prefix, gnew, gold, (gnew)? new->pref: 0, 0, 0);

    Deref_Generic_Attr (gnew);
    Deref_Generic_Attr (gold);
}


/*
 * 1) timoute routes (change metric to 16 and set change bit)
 * 2) garbage collect (delete route from hash, free memory and notify
 *    routing table 
 * Don't need to explicitly do outbound processing, as this will be picked up
 * by the regular 30 second timer
 */
static void
rip_timeout_routes (rip_t * rip)
{
    rip_route_t *route;
    time_t now, t;
    time_t nexttime = 0;

    trace (TR_TRACE, rip->trace, "timer (age) fired\n");

    time (&now);
    nexttime = now + RIP_TIMEOUT_INTERVAL;

    HASH_Iterate (rip->hash, route) {
	time_t t;

next_route:
	/* garbage collect and delete route (rip & imported) */
	if (BIT_TEST (route->flags, RT_RIP_DELETE)) {
	    assert (route->current != NULL ||
			LL_GetCount (route->imported) == 1);
	    if (now - route->active->dtime >= RIP_GARBAGE_INTERVAL) {
		rip_route_t *next = HASH_GetNext (rip->hash, route);
		trace (TR_TRACE, rip->trace,
		       "deleted %p nh %a proto %r (garbage collection)\n",
		       route->prefix, route->active->nexthop->prefix,
		       route->active->type);
		/* deleteing a hash item while looping */
    		HASH_Remove (rip->hash, route);
		if (next == NULL)
		    break;
		route = next;
		goto next_route;
	    }
	    else {
	        if ((t = route->active->dtime + RIP_GARBAGE_INTERVAL) 
			< nexttime)
		    nexttime = t;
	    }
	}
	/* timeout route -- set metric to 16 and set change flag */
	else if (route->current) { /* rip routes there */
	    rip_attr_t *attr;
	    LL_Iterate (route->received, attr) {
		rip_attr_t *prev;
		if (attr->utime > 0 /* timeout is on */ &&
		        now - attr->utime >= RIP_TIMEOUT_INTERVAL) {
	            trace (TR_TRACE, rip->trace,
		           "timing out %p nh %a\n",
		           route->prefix, attr->nexthop->prefix);
		    prev = LL_GetPrev (route->received, attr);
		    LL_Remove (route->received, attr);
		    attr = prev;
		}
	        else {			/* live routes */
	            /* see the earliest next time to be checked */
	            if ((t = attr->utime + RIP_TIMEOUT_INTERVAL) < nexttime)
		        nexttime = t;
		}
	    }

	    if (route->current->utime > 0 /* timeout is on */ &&
		    now - route->current->utime >= RIP_TIMEOUT_INTERVAL) {

	        trace (TR_TRACE, rip->trace,
		       "timing out %p nh %a (current)\n",
		       route->prefix, route->current->nexthop->prefix);
		if (LL_GetCount (route->received) > 0) {
		    rip_attr_t *imported = LL_GetHead (route->imported);

		    rip_del_attr (route->current);
		    route->current = LL_GetHead (route->received);
		    LL_RemoveFn (route->received, route->current, NULL);
		    rip_update_call_fn (rip, route->prefix, route->current, 
					NULL);
		    if (imported == NULL || 
			    imported->pref >= route->current->pref) {
			route->active = route->current;
		        route->flags |= RT_RIP_CHANGE;
		        rip->changed++;
		    }
		}
		else if (LL_GetCount (route->imported) > 0) {
		    /* no rip routes but imported one */
		    if (route->current == route->active) {
			route->active = LL_GetHead (route->imported);
		        route->flags |= RT_RIP_CHANGE;
		        rip->changed++;
		    }
		    rip_update_call_fn (rip, route->prefix, NULL, 
					route->current);
		    rip_del_attr (route->current);
		    route->current = NULL;
		}
		else { /* no other rip and no imported */
		    /* keep the current to send negative route */
		    assert (route->active == route->current);
		    route->current->metric = RIP_METRIC_INFINITY;
		    route->current->dtime = now;
		    route->flags |= RT_RIP_DELETE;
		    route->flags |= RT_RIP_CHANGE;
		    rip->changed++;
	            if ((t = route->current->dtime + RIP_GARBAGE_INTERVAL)
			    < nexttime) {
		        nexttime = t;
		    }
		}
	    }
	    else {
		/* live imported routes. nothing to do here */
	    }
	}
    }

    if (rip->changed)
	rip_set_flash_update (rip);

#define RIP_MIN_TIMEOUT_INTERVAL 5
    if ((t = nexttime - time (NULL)) <= 0)
	t = RIP_MIN_TIMEOUT_INTERVAL;	/* don't want so strict? */
    Timer_Set_Time (rip->age, t);
    Timer_Turn_ON (rip->age);
}


int
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


/* 
 * run policy on a rip route 
 * returns -1 when policy rejects it
 * otherwise returns new metric
 */
int
rip_policy (rip_t * rip, prefix_t * prefix, rip_attr_t * attr,
	    rip_interface_t * out)
{
    int cost, num;

#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6) {
	struct in6_addr *addr = (struct in6_addr *) prefix_tochar (prefix);

	if (prefix->bitlen > 128) {
	    trace (TR_PACKET, rip->trace,
		   "  x %p metric %d (invalid prefix length)\n",
		   prefix, attr->metric);
	    return (-1);
	}

	/* see if the destination prefix valid */
	if (IN6_IS_ADDR_MULTICAST (addr) ||
	    (IN6_IS_ADDR_V4COMPAT (addr) && prefix->bitlen > 0) ||
	    IN6_IS_ADDR_LINKLOCAL (addr)) {
	    trace (TR_PACKET, rip->trace,
		   "  x %p metric %d (non global)\n", prefix, attr->metric);
	}
    }
    else
#endif /* HAVE_IPV6 */
    if (prefix->family == AF_INET) {
		if (prefix->bitlen > 32) {
			trace (TR_PACKET, rip->trace,
		   "  x %p metric %d (invalid prefix length)\n",
			prefix, attr->metric);
			return (-1);
		}
		if (prefix_is_loopback(prefix)) {
			trace (TR_PACKET, rip->trace,
		   "  x %p metric %d (invalid -- loopback)\n",
			prefix, attr->metric);
			return (-1);
		}
    }
    else {
		assert (0);
    }


    if (out == NULL) {
	/* input policy processing */

	if (attr->metric < 1 || attr->metric > RIP_METRIC_INFINITY) {
	    trace (TR_PACKET, rip->trace,
		   "  x %p metric %d (invalid metric)\n",
		   prefix, attr->metric);
	    return (-1);
	}

	/* check distribute-list for in */
	if (attr->gateway && attr->gateway->interface) {
	    int index = attr->gateway->interface->index;
	    rip_interface_t *rip_interface = rip->rip_interfaces[index];

	    assert (rip_interface);
	    if ((num = rip_interface->dlist_in) >= 0) {
	        if (apply_access_list (num, prefix) == 0) {
		    trace (TR_PACKET, rip->trace,
		           "  x %p metric %d (a-list %d)\n",
		           prefix, attr->metric, num);
		    return (-1);
	        }
	    }
	    cost = attr->metric + rip_interface->metric_in;
	}
	else {
	    cost = attr->metric + 1;
	}
    }
    else {
#ifdef notdef
	if (attr->type == PROTO_CONNECTED &&
	    check_networks (prefix, rip->ll_networks)) {
	    /* OK */
	}
	else if (attr->type != rip->proto &&
		 !BIT_TEST (MRT->redist[attr->type], (1 << rip->proto))) {
	    trace (TR_PACKET, rip->trace,
		   "  x %p metric %d (proto %r)\n",
		   prefix, attr->metric, attr->type);
	    return (-1);
	}
#endif
	/* split horizon (without poisoned reverse) */
	/* do not send to the same interface on which we got the route */
	if (attr->type == rip->proto &&
	/* multicast capable and p-to-p interfaces */
	/* I'm not sure how NBMA will be supported */
	    ((BIT_TEST (out->interface->flags, IFF_MULTICAST) ||
	      BIT_TEST (out->interface->flags, IFF_POINTOPOINT)) &&
	     attr->gateway && attr->gateway->interface == out->interface)) {
	    /* No split horizon on NBMA which has not yet supported, though */
#ifdef RIP_POISONED_REVERSE
	    trace (TR_PACKET, rip->trace,
		   "  o %p metric %d (poisoned reverse)\n",
		   prefix, RIP_METRIC_INFINITY);
	    return (RIP_METRIC_INFINITY);
#else
	    trace (TR_PACKET, rip->trace,
		   "  x %p metric %d (split horion)\n", prefix, attr->metric);
	    return (-1);
#endif /* RIP_POISONED_REVERSE */
	}
	if (attr->type == PROTO_CONNECTED && attr->gateway &&
		attr->gateway->interface == out->interface) {
	    trace (TR_PACKET, rip->trace,
		   "  x %p metric %d (direct)\n", prefix, attr->metric);
	    return (-1);
	}
	/* check distribute-list for out */
	if ((num = out->dlist_out) >= 0) {
	    if (apply_access_list (num, prefix) == 0) {
		trace (TR_PACKET, rip->trace,
		       "  x %p metric %d (a-list %d)\n",
		       prefix, attr->metric, num);
		return (-1);
	    }
	}
	cost = attr->metric + out->metric_out;
    }

    if (cost > RIP_METRIC_INFINITY)
	cost = RIP_METRIC_INFINITY;

    return (cost);
}


/* if rip_interface == NULL, no policy will be applied */
static void
rip_prepare_routes (rip_t *rip, int all, rip_interface_t *rip_interface, 
		    LINKED_LIST **ll_rip_ann_rt_p)
{
    rip_route_t *route;
    LINKED_LIST *ll_rip_ann_rt = NULL;

    HASH_Iterate (rip->hash, route) {

	prefix_t *prefix = route->prefix;
	rip_attr_t *attr = route->active;
	rip_ann_rt_t *rip_ann_rt;
        char tagstr[MAXLINE];
	int metric = attr->metric;

	/* doing ouput processing and only sending changed routes */
	if (!all && !BIT_TEST (route->flags, RT_RIP_CHANGE))
	    continue;

	if (rip_interface) {
	    if ((metric = rip_policy (rip, prefix, attr, rip_interface)) < 0)
	    	continue;
	}

        tagstr[0] = '\0';
        if (attr->tag)
            sprintf (tagstr, " tag 0x%lx", attr->tag);
        trace (TR_PACKET, rip->trace, "  o %p metric %d%s\n",
               prefix, metric, tagstr);

	if (ll_rip_ann_rt == NULL)
	    ll_rip_ann_rt = LL_Create (LL_DestroyFunction, FDelete, 0);
	rip_ann_rt = New (rip_ann_rt_t);
	rip_ann_rt->prefix = prefix;
	rip_ann_rt->attr = attr;
	rip_ann_rt->metric = metric;
	LL_Add (ll_rip_ann_rt, rip_ann_rt);
    }
    *ll_rip_ann_rt_p = ll_rip_ann_rt;
}


void
rip_process_requst (rip_t *rip, LINKED_LIST *ll_rip_ann_rt,
		    rip_interface_t *rip_interface, prefix_t *from, int port)
{
    rip_ann_rt_t *rip_ann_rt;

    if (ll_rip_ann_rt == NULL) {
	rip_prepare_routes (rip, TRUE, 
                /* router's query, apply policy for that interface */
			   (port == rip->port)? rip_interface: NULL, 
			   &ll_rip_ann_rt);
    }
    else LL_Iterate (ll_rip_ann_rt, rip_ann_rt) {
        rip_route_t *route;
        if ((route = HASH_Lookup (rip->hash, rip_ann_rt->prefix)) == NULL) {
            if (port == rip->port) {
                /* router's query, apply policy for that interface */
                if ((rip_ann_rt->metric = rip_policy (rip, rip_ann_rt->prefix, 
						  rip_ann_rt->attr,
                                          	  rip_interface)) < 0) {
                    rip_ann_rt->metric = RIP_METRIC_INFINITY;
                }
            } 
            else {
                trace (TR_PACKET, rip->trace, "  o %p metric %d\n",  
                       rip_ann_rt->prefix, rip_ann_rt->metric);
            }      
        }
        else {
            trace (TR_PACKET, rip->trace, "  x %p metric %d (no exist)\n",
                   rip_ann_rt->prefix, rip_ann_rt->metric);
	    rip_ann_rt->metric = RIP_METRIC_INFINITY;
	}
    }
    if (ll_rip_ann_rt && rip->send_update_fn)  
        rip->send_update_fn (ll_rip_ann_rt, rip_interface, from, port);
    if (ll_rip_ann_rt) LL_Destroy (ll_rip_ann_rt);
}


void
rip_advertise_route (rip_t *rip, int all)
{
    interface_t *interface;
    rip_route_t *route;

    /* nothing changed */
    if (!rip->changed && !all)
	return;

    /* on flushing changes, this keeps locking the route table for a long time
       do we need to change our code ? XXX */

    /* announce routes */
    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
        LINKED_LIST *ll_rip_ann_rt;
        rip_interface_t *rip_interface;

	if (!BITX_TEST (&rip->interface_mask, interface->index))
	    continue;
	if (!BIT_TEST (interface->flags, IFF_UP))
	    continue;

	rip_interface = rip->rip_interfaces[interface->index];
	rip_prepare_routes (rip, all, rip_interface, &ll_rip_ann_rt);
	if (ll_rip_ann_rt) {
 	    if (rip->send_update_fn)
	        rip->send_update_fn (ll_rip_ann_rt, rip_interface, NULL, rip->port);
	    LL_Destroy (ll_rip_ann_rt);
	}
    }

    /* clearing change flag */
    HASH_Iterate (rip->hash, route) {
	route->flags &= ~(RT_RIP_CHANGE);
    }
    rip->changed = 0;
}


void
rip_response_route (rip_t *rip, rip_interface_t *rip_interface, 
		    prefix_t *from, int port)
{
    LINKED_LIST *ll_rip_ann_rt;

    rip_prepare_routes (rip, TRUE, rip_interface, &ll_rip_ann_rt);
    if (ll_rip_ann_rt) {
        if (rip->send_update_fn)
	    rip->send_update_fn (ll_rip_ann_rt, rip_interface, from, port);
	LL_Destroy (ll_rip_ann_rt);
    }
}


static int
rip_process_route (rip_t *rip, prefix_t *prefix, rip_attr_t *attr)
{
    rip_route_t *route;
    char nexthopstr[MAXLINE], tagstr[MAXLINE];
    time_t now;
    int metric;

    /* just for information */
    tagstr[0] = '\0';
    nexthopstr[0] = '\0';
    if (attr->nexthop && attr->nexthop != attr->gateway) {
	sprintf (nexthopstr, " -> %s",
		 prefix_toa (attr->nexthop->prefix));
    }
    if (attr->tag)
        sprintf (tagstr, " tag 0x%lx", attr->tag);

    /* see if valid and do policy to add cost to the metric */
    if ((metric = rip_policy (rip, prefix, attr, NULL)) < 0) {
        rip_del_attr (attr);  /* chl -- not sure if this is right! */
	return (0);
    }
    attr->metric = metric;
    assert (attr->metric >= 0);

    /* new route */
    if ((route = HASH_Lookup (rip->hash, prefix)) == NULL) {

	    if (attr->metric >= RIP_METRIC_INFINITY) {
		trace (TR_PACKET, rip->trace,
		       "  x %p metric %d (infinity)\n",
		       prefix, attr->metric);
		rip_del_attr (attr);
		return (0);
	    }

	    trace (TR_TRACE, rip->trace, "  o %p metric %d%s (new)\n",
		   prefix, attr->metric, tagstr);

	    route = rip_new_route (rip, prefix, attr);
	    route->flags |= RT_RIP_CHANGE;
	    rip->changed++;

	    assert (route->active == attr);
	    /* export the route */
	    rip_update_call_fn (rip, route->prefix, route->active, NULL);
	    return (1);
    }

    time (&now);

	    /* we already have a route for this prefix. Two cases:
	     *  1) from same gateway -- 
	     *     just update time, delete, or implicit withdraw.
	     *     if tag changed it should be updated and propagated -- masaki
	     *  2) from different gateway -- 
	     *     if metric better use this, otherwise
	     *     just ignore it. We'll hear about it again in 30 seconds...
	     */

	if (BIT_TEST (route->flags, RT_RIP_DELETE)) {

	    /* first process in case the route is being deleted */
	    	assert (LL_GetCount (route->received) == 0 &&
			   (route->current != NULL ||
			    LL_GetCount (route->imported) == 1));

	        if (attr->metric >= RIP_METRIC_INFINITY) {
		    trace (TR_PACKET, rip->trace,
		           "  x %p metric %d (infinity)\n",
		           route->prefix, attr->metric);
		    rip_del_attr (attr);
		    return (0);
	        }

		if (route->current) {
		    assert (LL_GetCount (route->imported) == 0);
		    assert (LL_GetCount (route->received) == 0);
		    rip_del_attr (route->current);
		}
		else {
		    assert (LL_GetCount (route->received) == 0);
		    assert (LL_GetCount (route->imported) == 1);
		    assert (route->active == LL_GetHead (route->imported));
		    LL_Remove (route->imported, route->active);
		}
		route->current = attr;
		rip_update_call_fn (rip, route->prefix, route->current, NULL);
		route->active = route->current;
		route->flags &= ~RT_RIP_DELETE;
		route->flags |= RT_RIP_CHANGE;
		trace (TR_PACKET, rip->trace,
		       "  o %p metric %d%s (delete -> active)\n",
		       route->prefix, attr->metric, tagstr);
		rip->changed++;
		return (1);
	}
	else if (route->current == NULL) {
	    /* imported route only */
	    assert (LL_GetCount (route->imported) > 0);
	    assert (route->active == LL_GetHead (route->imported));

	    if (attr->metric >= RIP_METRIC_INFINITY) {
		trace (TR_PACKET, rip->trace,
		       "  x %p metric %d (infinity)\n",
		       route->prefix, attr->metric);
		rip_del_attr (attr);
		return (0);
	    }

	    route->current = attr;
	    rip_update_call_fn (rip, route->prefix, route->current, NULL);
	    if (route->active->pref >= route->current->pref) {
	        route->active = route->current;
	        route->flags |= RT_RIP_CHANGE;
	        rip->changed++;
	        return (1);
	    }
	    return (0);
	}
	else if (route->current->gateway == attr->gateway) {
	    /* from the same gateway */
	    rip_attr_t *imported = LL_GetHead (route->imported);

	    /* new is infinity */
	    if (attr->metric >= RIP_METRIC_INFINITY) {

		trace (TR_TRACE, rip->trace,
			"  o %p%s metric %d%s (shift to delete)\n",
			route->prefix,
			nexthopstr, attr->metric, tagstr);

		rip_del_attr (attr);

		if (LL_GetCount (route->received) <= 0 &&
			LL_GetCount (route->imported) <= 0) {
		    assert (route->current == route->active);
		    route->current->metric = RIP_METRIC_INFINITY;
		    route->current->dtime = now;
	    	    rip_update_call_fn (rip, route->prefix, NULL, 
				        route->current);
		    route->flags |= RT_RIP_DELETE;
		    route->flags |= RT_RIP_CHANGE;
		    rip->changed++;
		    return (1);
		}
		else if (LL_GetCount (route->received) > 0) {

		    route->current = LL_GetHead (route->received);
		    LL_RemoveFn (route->received, route->current, NULL);
	    	    rip_update_call_fn (rip, route->prefix, route->current, 
					NULL);

		    if (route->active == imported) {
		        if (route->active->pref >= route->current->pref) {
			    route->active = route->current;
			    route->flags |= RT_RIP_CHANGE;
		    	    rip->changed++;
			    return (1);
			}
		    }
		    else {
			route->active = route->current; 
		        if (imported && route->active->pref > imported->pref)
			    route->active = imported;
			route->flags |= RT_RIP_CHANGE;
		    	rip->changed++;
			return (1);
		    }
		}
		else {
		    /* no dv, but imported */

		    assert (LL_GetCount (route->imported) > 0);
		    assert (LL_GetCount (route->received) == 0);

	    	    rip_update_call_fn (rip, route->prefix, NULL, 
					route->current);
		    rip_del_attr (route->current);
		    if (route->current == route->active) {
		        route->current = NULL;
			route->active = imported;
			route->flags |= RT_RIP_CHANGE;
		    	rip->changed++;
			return (1);
		    }
		    route->current = NULL;
		}
	        return (0);
	    }
	    /* new is not infinity */
	    else if (route->current->metric != attr->metric ||
		    /* ID says nothing about tag but I think it should be */
		    ((attr->type == PROTO_RIP || attr->type == PROTO_RIPNG) &&
		       (route->current->tag != attr->tag ||
			route->current->nexthop != attr->nexthop))) {

		    trace (TR_TRACE, rip->trace,
			   "  o %s%s metric %d%s (change)\n",
			   prefix_toax (route->prefix),
			   nexthopstr, attr->metric, tagstr);

		    rip_del_attr (route->current);
		    route->current = attr;
	    	    rip_update_call_fn (rip, route->prefix, route->current, 
					NULL);
		    if (route->active == imported) {
		        if (route->active->pref >= route->current->pref) {
			    route->active = route->current;
			    route->flags |= RT_RIP_CHANGE;
			    rip->changed++;
			    return (1);
			}
		    }
		    else {
			route->active = route->current;
			if (imported && route->active->pref > imported->pref)
			    route->active = imported;
			route->flags |= RT_RIP_CHANGE;
			rip->changed++;
			return (1);
		    }
		return (0);
	    }
	    else {
		/* update the time */
		trace (TR_PACKET, rip->trace,
			   "  x %p metric %d (same)\n",
			   route->prefix, attr->metric);
		route->current->utime = attr->utime;
		rip_del_attr (attr);
		return (0);
	    }
	}
	else {
	    /* from different gateway */
	    rip_attr_t *imported = LL_GetHead (route->imported);
	    rip_attr_t *rip_attr;

	    LL_Iterate (route->received, rip_attr) {
		if (rip_attr->gateway == attr->gateway)
		    break;
	    }

	    if (rip_attr) {
		/* remove the previous one */
		LL_Remove (route->received, rip_attr);
	    }

	    /* new is infinity */
	    if (attr->metric >= RIP_METRIC_INFINITY) {
		trace (TR_PACKET, rip->trace,
		       "  x %p metric %d (infinity)\n",
		       route->prefix, attr->metric);
		rip_del_attr (attr);
		return (0);
	    }

	    if (route->current->metric > attr->metric /* better metric */ ||
		(route->current->metric != RIP_METRIC_INFINITY &&
		/* suggested heuristic in case of the same metric */
		    (route->current->metric == attr->metric &&
		     (now - route->current->utime) >=
			 RIP_TIMEOUT_INTERVAL / 2))) {

		    trace (TR_TRACE, rip->trace,
			   "  o %p%s metric %d%s (change)\n",
			   route->prefix, nexthopstr, attr->metric, tagstr);
		    LL_Add (route->received, route->current);
		    route->current = attr;
		    rip_update_call_fn (rip, route->prefix, route->current, 
				        NULL);
		    if (route->active == imported) {
			if (route->active->pref >= route->current->pref) {
			    route->active = route->current;
			    route->flags |= RT_RIP_CHANGE;
			    rip->changed++;
			    return (1);
			}
		    }
		    else {
			route->active = route->current;
			if (imported && route->active->pref > imported->pref)
			    route->active = imported;
			route->flags |= RT_RIP_CHANGE;
			rip->changed++;
			return (1);
		    }
		return (0);
	    }
	    else {
		trace (TR_PACKET, rip->trace,
			"  x %p metric %d (>= existing %d)\n", route->prefix,
			attr->metric, route->current->metric);
	    	LL_Add (route->received, attr);
		return (0);
	    }
        }
    /* MUST NOT REACH HERE */
    assert (0);
    return (0);
}


int
rip_process_update (rip_t *rip, LINKED_LIST *ll_rip_ann_rt)
{
    rip_ann_rt_t *rip_ann_rt;
    int n = 0;

    LL_Iterate (ll_rip_ann_rt, rip_ann_rt) {
	n += rip_process_route (rip, rip_ann_rt->prefix, rip_ann_rt->attr);
    }
    if (n > 0) {
	assert (rip->changed);
        rip_set_flash_update (rip);
    }
    return (n);
}


/*
 * rip_update_route()
 * will be called from rib, that is, they are called from
 * other threads. Even though RIPng runs with a single thread,
 * locking on the route table and flash update flag have to be
 * protected by locking.
 *
 * -> changes to use the scheduler. So, I think locking is no need but... 
 */

static void
rip_import (rip_t * rip, prefix_t * prefix, generic_attr_t * new,
	    generic_attr_t * old, int pref)
{
    rip_attr_t *rip_attr, *attr;
    rip_route_t *route;
    time_t now;
    int changed = 0;

    /* this routine doesn't handle a rip route */
    assert (new == NULL || new->type != rip->proto);
    assert (old == NULL || old->type != rip->proto);

    time (&now);

    if (old) {

	if ((route = HASH_Lookup (rip->hash, prefix)) == NULL) {
	    trace (TR_WARN, rip->trace,
	           "delete %p nh %a proto %r (prefix not found)\n",
	           prefix, old->nexthop->prefix, old->type);
	    goto quit;
	}

	LL_Iterate (route->imported, attr) {
	    if (attr->type == old->type /* &&
	         (old->gateway == NULL || attr->gateway == old->gateway) */)
		break;
	}

	if (attr == NULL) {
	    trace (TR_WARN, rip->trace,
	           "delete %p nh %a proto %r (proto not found)\n",
	           prefix, old->nexthop->prefix, old->type);
	    goto quit;
	}

	trace (TR_TRACE, rip->trace, "delete %p nh %a proto %r\n",
	       prefix, old->nexthop->prefix, old->type);

	assert (LL_GetCount (route->imported) >= 1);

	if (route->active == attr) {

	    if (route->current == NULL) {
		if (LL_GetCount (route->imported) <= 1) {
		    attr->metric = RIP_METRIC_INFINITY;
		    attr->dtime = now;
		    route->flags |= RT_RIP_DELETE;
		}
		else {
		    LL_Remove (route->imported, attr);
		    route->active = LL_GetHead (route->imported);
		}
	    }
	    else {
		if (LL_GetCount (route->imported) <= 1) {
		    route->active = route->current;
		}
		else {
		    route->active = LL_GetHead (route->imported);
		    if (route->active == NULL || 
			    route->active->pref >= route->current->pref)
			route->active = route->current;
		}
		LL_Remove (route->imported, attr);
	    }
	    route->flags |= RT_RIP_CHANGE;
	    rip->changed++;
	    changed++;
	}
	else {
	    /* just remove it */
	    LL_Remove (route->imported, attr);
	}
    }

    if (new) {

#define RIP_IMPORTED_METRIC 1
	rip_attr = rip_new_attr (rip, RIP_IMPORTED_METRIC);
	rip_attr->type = new->type;
	rip_attr->nexthop = ref_nexthop (new->nexthop);
	rip_attr->gateway = new->gateway;
	rip_attr->pref = pref;
	rip_attr->tag = new->tag;

	if ((route = HASH_Lookup (rip->hash, prefix)) == NULL) {
	    /* new route */
	    route = rip_new_route (rip, prefix, rip_attr);
    	    trace (TR_TRACE, rip->trace,
	   	    "add %p nh %a proto %r (new prefix)\n",
	   	    prefix, new->nexthop->prefix, new->type);
	}
	else if (route->flags & RT_RIP_DELETE) {
	    assert (route->active->metric >= RIP_METRIC_INFINITY);

	    if (route->active == LL_GetHead (route->imported)) {
		assert (route->current == NULL);
		LL_Remove (route->imported, route->active);
	    }
	    else {
		assert (route->current);
		rip_del_attr (route->current);
		route->current = NULL;
	    }
	    LL_Add (route->imported, rip_attr);
	    route->active = rip_attr;
	    route->flags &= ~RT_RIP_DELETE;
	}
	else {
	    LL_Iterate (route->imported, attr) {
	        if (attr->type == new->type /* &&
	             (new->gateway == NULL || attr->gateway == new->gateway) */)
		    break;
	    }

	    if (attr != NULL) {
	        rip_attr_t *old_best = LL_GetHead (route->imported);
	        rip_attr_t *new_best;

		/* updating the existing one */
		LL_Remove (route->imported, attr);
	        LL_Add (route->imported, rip_attr);
	        trace (TR_TRACE, rip->trace, "update %p nh %a proto %r\n",
		       prefix, new->nexthop->prefix, new->type);
		new_best = LL_GetHead (route->imported);
		if (old_best != new_best) {
		   /* the best changed */
		    if (route->active == route->current) {
		        if (route->active->pref > new_best->pref) {
			    route->active = new_best;
	    		    route->flags |= RT_RIP_CHANGE;
			    rip->changed++;
			    changed++;
			}
		    }
		    else {
			assert (route->active == old_best);
		        route->active = new_best;
		        if (route->current &&
			        route->active->pref >= route->current->pref) {
			    route->active = route->current;
		        }
	    	        route->flags |= RT_RIP_CHANGE;
			rip->changed++;
                        changed++;
		    }
		}
	    }
	    else {
	        LL_Add (route->imported, rip_attr);
	        trace (TR_TRACE, rip->trace, "add %p nh %a proto %r\n",
		       prefix, new->nexthop->prefix, new->type);
	        assert (route->active);
		if (route->active == route->current) {
		    if (route->active->pref >= rip_attr->pref) {
		        assert (rip_attr == LL_GetHead (route->imported));
			route->active = rip_attr;
	    		route->flags |= RT_RIP_CHANGE;
			rip->changed++;
                        changed++;
		    }
		}
		else {
		    if (rip_attr == LL_GetHead (route->imported)) {
			route->active = rip_attr;
			if (route->current &&
				route->active->pref >= route->current->pref)
			    route->active = route->current;
	    		route->flags |= RT_RIP_CHANGE;
	    		rip->changed++;
                        changed++;
		    }
		}
	    }
	}
    }

    if (changed) {
	assert (rip->changed);
	rip_set_flash_update (rip);
    }
  quit:
    Deref_Prefix (prefix);
    if (new)
	Deref_Generic_Attr (new);
    if (old)
	Deref_Generic_Attr (old);
}


/* this is called from threads other than rip, so it must be shceduled */
void
rip_update_route (rip_t * rip, prefix_t * prefix, generic_attr_t * new,
		  generic_attr_t * old, int pref)
{
    /* in case the rib wants to delete them */
    Ref_Prefix (prefix);
    if (new)
	Ref_Generic_Attr (new);
    if (old)
	Ref_Generic_Attr (old);

    schedule_event2 ("rip_import",
		 rip->schedule, rip_import, 5, rip, prefix, new, old, pref);
}


/* 
 * change/set rip attributes.
 */
void
rip_set (rip_t *rip, va_list ap)
{
    enum RIP_ATTR attr;

    while ((attr = va_arg (ap, enum RIP_ATTR)) != 0) {

	switch (attr) {
/*
	case RIP_RT_UPDATE_FN:
	    rip->update_call_fn = va_arg (ap, int_fn_t);
	    break;
*/
	case RIP_TRACE_STRUCT:
	    rip->trace = va_arg (ap, trace_t *);
	    break;
	default:
	    assert (0);
	    break;
	}
    }
}


/* 
 * dump various rip stats to a socket
 * usually called by UII (user interactive interface 
 */
int
rip_show (rip_t *rip, uii_connection_t * uii)
{
    rip_interface_t *rip_interface;

    uii_add_bulk_output (uii, "Routing Protocol is \"%s\"\n",
		   proto2string (rip->proto));

    if (rip->sockfd < 0)
	uii_add_bulk_output (uii, "Not listening for announcements\n");
    else
	uii_add_bulk_output (uii, "Listening on port %d (socket %d)\n",
		       rip->port, rip->sockfd);

    if (rip->timer->time_next_fire > 0) {
        uii_add_bulk_output (uii,
      		   "Sending updates every %d seconds jitter [%d..%d], "
		   "next due in %d seconds\n", RIP_UPDATE_INTERVAL, 
		    rip->timer->time_jitter_low,
		    rip->timer->time_jitter_high,
		    rip->timer->time_next_fire - time (NULL));
        uii_add_bulk_output (uii, "Triggered update and split horizon "
		       "(no poisoned reverse) implemented\n");
        uii_add_bulk_output (uii,
	     "Invalid after %d, hold down %d, flushed after %d seconds\n",
	      RIP_TIMEOUT_INTERVAL, RIP_GARBAGE_INTERVAL, 
	      RIP_TIMEOUT_INTERVAL+RIP_GARBAGE_INTERVAL);

        uii_add_bulk_output (uii, "Interface enabled:");
        LL_Iterate (rip->ll_rip_interfaces, rip_interface) {
			uii_add_bulk_output (uii, " %s", 
			rip_interface->interface->name);
		}
        uii_add_bulk_output (uii, "\n");
        uii_add_bulk_output (uii, "Number of routes in routing table: %d\n", 
			     HASH_GetCount (rip->hash));
    }
    else {
	uii_add_bulk_output (uii, "Not sending announcements\n");
    }
    return (1);
}


static int
rip_route_compare (rip_route_t * a, rip_route_t * b)
{
    return (prefix_compare2 (a->prefix, b->prefix));
}


/*
 * dump routing table to socket. Usually called by user interactive interface
 */
int
rip_show_routing_table (rip_t *rip, uii_connection_t * uii, char *ifname)
{
    interface_t *interface = NULL;
    rip_route_t *route;
    time_t now;
    char stmp[MAXLINE];
    rip_route_t **array;
    int i, c, t;
    u_int nel;

    if (ifname) {
	if ((interface = find_interface_byname (ifname)) == NULL) {
	    /* can not call uii from rip thread */
/*
	    config_notice (TR_ERROR, uii,
	    		   "no such interface: %s\n", ifname);
*/
	    return (-1);
	}
    }

    if (rip->hash == NULL)
        return (0);

    time (&now);
    array = (rip_route_t **) HASH_ToArray (rip->hash, NULL, &nel);

    ARRAY_Sort (array, nel, (DATA_PTR)rip_route_compare);

    sprintf (stmp, "%-4s %-4s", "Cost", "Time");
    rib_show_route_head (uii, stmp);

    for (i = 0; i < nel; i++) {
	rip_attr_t *attr;
	route = array[i];

	LL_Iterate (route->received, attr) {

	    if (interface && attr->gateway->interface &&
		    interface != attr->gateway->interface)
		continue;

	    sprintf (stmp, "%4d %4ld", attr->metric, now - attr->utime);
	    rib_show_route_line (uii, ' ', ' ', attr->type,
				     attr->pref, now - attr->ctime,
				     route->prefix, attr->nexthop->prefix,
				     (attr->gateway)? attr->gateway->interface:
					NULL, stmp);
	}

	if ((attr = route->current)) {
	    if (interface == NULL || interface == attr->gateway->interface) {

	        c = (route->active == attr)? '>' : '*';
		t = now - attr->utime;
		if (BIT_TEST (route->flags, RT_RIP_DELETE)) {
		    c = 'D';
		    t = now - attr->dtime;
		}
	        sprintf (stmp, "%4d %4d", attr->metric, t);
	        rib_show_route_line (uii, c, ' ', attr->type,
				     attr->pref, now - attr->ctime,
				     route->prefix, attr->nexthop->prefix,
				     (attr->gateway)? attr->gateway->interface:
					NULL, stmp);
	    }
	}

	LL_Iterate (route->imported, attr) {

	    if (interface && attr->gateway->interface &&
		    interface != attr->gateway->interface)
		continue;

	    c = (route->active == attr)? '>' : ' ';
	    sprintf (stmp, "%4d ----", attr->metric);
	    if (BIT_TEST (route->flags, RT_RIP_DELETE)) {
		c = 'D';
	        sprintf (stmp, "%4d %4ld", attr->metric, now - attr->dtime);
	    }

	    rib_show_route_line (uii, c, ' ', attr->type,
				     attr->pref, now - attr->ctime,
				     route->prefix, attr->nexthop->prefix,
				     (attr->gateway)? attr->gateway->interface:
					NULL, stmp);
	}
    }
    Delete (array);
    return (1);
}


static void
rip_timer_update (rip_t * rip)
{
    trace (TR_TRACE, rip->trace, "timer (update) fired\n");
    if (rip->flash_update_waiting)
	rip->flash_update_waiting = 0;	/* clear flash update */
    rip_advertise_route (rip, TRUE);
}


static void
rip_flash_update (rip_t * rip)
{
    trace (TR_TRACE, rip->trace, "timer (flash update) fired\n");
    if (rip->flash_update_waiting) {
	rip->flash_update_waiting = 0;
        rip_advertise_route (rip, FALSE);
    }
}


/* run under rip thread */
/* run for all the interfaces. it is an easier way
   because MRT allows two ways to specify prefix and interface name */
void
rip_interface_recheck (rip_t * rip)
{
    prefix_t *prefix;
    char *name;
    interface_t *table[MAX_INTERFACES];
    LINKED_LIST *ll;
    int i;
    interface_t *interface;
    rip_interface_t *rip_interface;
    
    memset (table, 0, sizeof (table));
    LL_Iterate (rip->ll_networks, prefix) {
        if ((ll = find_network (prefix)) != NULL) {
	    LL_Iterate (ll, interface) {
		table[interface->index] = interface;
	    }
	    LL_Destroy (ll);
	}
    }
    LL_Iterate (rip->ll_networks2, name) {
	if ((ll = find_interface_byname_all (name)) != NULL) {
	    LL_Iterate (ll, interface) {
		table[interface->index] = interface;
	    }
	    LL_Destroy (ll);
	}
    }

    for (i = 0; i < sizeof (table)/sizeof (table[0]); i++) {
	interface = table[i];
	rip_interface = rip->rip_interfaces[i];
	if (interface == NULL) {
	    if (!BITX_TEST (&rip->interface_mask, i))
		continue;
	    assert (rip_interface);
	    assert (rip_interface->interface->index == i);
	    trace (TR_TRACE, rip->trace, "interface %s (off)\n",
		   rip_interface->interface->name);
	    if (rip->interface_fn)
                rip->interface_fn (rip_interface, OFF);
	    BGP4_BIT_RESET (rip_interface->interface->protocol_mask, 
			    rip->proto);
	    BITX_RESET (&rip->interface_mask, i);
	    LL_Remove (rip->ll_rip_interfaces, rip_interface);
	}
	else {
	    assert (interface->index == i);
	    if (BITX_TEST (&rip->interface_mask, i))
		continue;

	    if (rip->interface_fn)
                if (rip->interface_fn (rip_interface, ON) < 0)
		    continue;
	    trace (TR_TRACE, rip->trace, "interface %s (on)\n",
				       interface->name);
	    BITX_SET (&rip->interface_mask, i);
	    BGP4_BIT_SET (interface->protocol_mask, rip->proto);
	    LL_Add (rip->ll_rip_interfaces, rip_interface);
	}
    }
}


void
rip_distribute_list_recheck (rip_t *rip)
{
    rip_interface_t *rip_interface;
    dlist_t *dlist;

    /* check distribute-list */
    /* reset all first */
    LL_Iterate (rip->ll_rip_interfaces, rip_interface) {
	rip_interface->dlist_out = -1;
	rip_interface->dlist_in = -1;
    }

    /* find out distribute-list without interface */
    /* this is default */
    LL_Iterate (rip->ll_dlists, dlist) {
	if (dlist->interface)
	    continue;
        LL_Iterate (rip->ll_rip_interfaces, rip_interface) {
	    if (dlist->out)
		rip_interface->dlist_out = dlist->num;
	    else
		rip_interface->dlist_in = dlist->num;
	}
    }

    LL_Iterate (rip->ll_dlists, dlist) {
	if (dlist->interface == NULL)
	    continue;
	if (!BITX_TEST (&rip->interface_mask, dlist->interface->index))
	    continue;
	rip_interface = rip->rip_interfaces[dlist->interface->index];
	assert (rip_interface);
	if (dlist->out)
	    rip_interface->dlist_out = dlist->num;
	else
	    rip_interface->dlist_in = dlist->num;
	
    }
}


void
rip_start (rip_t *rip)
{
    interface_t *interface;

    /* copy all interfaces at this point, so all new interfaces created later
       by the kernel should be entered individually into ll_rip_interfaces 
       structure */
    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
	rip_interface_t *rip_interface = New (rip_interface_t);
	rip_interface->interface = interface;
        rip_interface->dlist_in = -1;
        rip_interface->dlist_out = -1;
        rip_interface->metric_in = 1;
        rip_interface->metric_out = 0;
        rip_interface->default_pref = -1;
        rip_interface->sockfd = -1;
	rip->rip_interfaces[interface->index] = rip_interface;
    }
    Timer_Turn_ON (rip->timer);
    Timer_Turn_ON (rip->age);
}


void
rip_stop (rip_t *rip)
{
    int i;
    int afi = AFI_IP;

    /* stop all interfaces */
    LL_Clear (rip->ll_networks);
    LL_Clear (rip->ll_networks2);
    rip_interface_recheck (rip);
    LL_Clear (rip->ll_dlists);
    rip_distribute_list_recheck (rip);
    memset (&rip->interface_mask, 0, sizeof (rip->interface_mask));

#ifdef HAVE_IPV6
    if (rip->proto == PROTO_RIPNG)
	afi = AFI_IP6;
#endif /* HAVE_IPV6 */

    for (i = PROTO_MIN; i <= PROTO_MAX; i++) {
        if (BGP4_BIT_TEST (rip->redistribute_mask, i)) {
            if (MRT->rib_redistribute_request)
                MRT->rib_redistribute_request (rip->proto, 0, i, 0, 
					       afi, SAFI_UNICAST);
        }   
    }       
    rip->redistribute_mask = 0;

    for (i = 0; i < MAX_INTERFACES; i++) {
        if (rip->rip_interfaces[i]) {
	    Delete (rip->rip_interfaces[i]);
	    rip->rip_interfaces[i] = NULL;
	}
    }

    if (rip->sockfd >= 0) {
	trace (TR_INFO, rip->trace, "Closing scoket %d\n", rip->sockfd);
	select_delete_fdx (rip->sockfd);
	rip->sockfd = -1;
    }

    clear_schedule (rip->schedule);
    Timer_Turn_OFF (rip->timer);
    Timer_Turn_OFF (rip->age);
    Timer_Turn_OFF (rip->flash);
}


/*
 * initialize rip common stuff
 */
void
rip_init (rip_t *rip)
{
    rip_route_t route;
    char *name = (rip->proto == PROTO_RIP)? "RIP": "RIPNG";

    rip->sockfd = -1;

    rip->hash = HASH_Create (RIP_TABLE_HASH_SIZE,
			     HASH_KeyOffset, 
			     HASH_Offset (&route, &route.prefix),
			     HASH_LookupFunction, ip_lookup_fn,
			     HASH_HashFunction, ip_hash_fn,
			     HASH_DestroyFunction, rip_delete_route,
			     NULL);

    rip->ll_networks = LL_Create (LL_DestroyFunction, Deref_Prefix, 0);
    rip->ll_networks2 = LL_Create (LL_DestroyFunction, free, 0);
    rip->ll_dlists = LL_Create (LL_DestroyFunction, free, 0);
    rip->ll_rip_interfaces = LL_Create (0);
    memset (&rip->interface_mask, 0, sizeof (rip->interface_mask));

    rip->schedule = New_Schedule (name, rip->trace);
    rip->timer = New_Timer2 ("RIP update timer", RIP_UPDATE_INTERVAL, 0,
			     rip->schedule, rip_timer_update, 1, rip);
    timer_set_jitter2 (rip->timer, -50, 50);
    rip->age = New_Timer2 ("RIP aging timer", RIP_TIMEOUT_INTERVAL, 
			   TIMER_ONE_SHOT, rip->schedule,
			   rip_timeout_routes, 1, rip);
    rip->flash = New_Timer2 ("RIP flash timer", 0, TIMER_ONE_SHOT,
			     rip->schedule, rip_flash_update, 1, rip);
    mrt_thread_create2 (name, rip->schedule, NULL, NULL);
}


void
rip_delete_rip_ann_rt (rip_ann_rt_t *rip_ann_rt)
{
    Deref_Prefix (rip_ann_rt->prefix);
    Delete (rip_ann_rt);
}


/* 
 * $Id: bgpconf.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>
#include <bgp.h>
#include <config_file.h>
#include <protoconf.h>


static void
restart_bgp_peer (bgp_peer_t *peer)
{
    if (peer->state == BGPSTATE_IDLE || peer->state == BGPSTATE_ACTIVE)
	return;
    bgp_sm_process_event (peer, BGPEVENT_STOP);
}


static void
get_config_aspath_filter (int num)
{
    char *cp = as_access_list_toa (num);
    if (cp) {
	config_add_output ("%s", cp);
	Delete (cp);
    }
}


static int
config_ip_as_filter (uii_connection_t * uii, int num, char *permit_or_deny,
		     char *re)
{
    int permit = 0;

    if (strcasecmp ("permit", permit_or_deny) == 0)
	permit = 1;

    if (num < 0 && num >= MAX_AS_ALIST) {
	config_notice (TR_ERROR, uii,
		   "invalid as-path access-list number (%d)\n", num);
	Delete (permit_or_deny);
	Delete (re);
	return (-1);
    }

    if (uii->negative) {
        if (remove_as_access_list (num, re, permit) > 0) {
	    if (count_as_access_list (num) <= 0) {
	        config_del_module (0, "as-path access-list", 
			           get_config_aspath_filter, (void *) num);
	    }
    	    Delete (permit_or_deny);
    	    Delete (re);
    	    return (1);
        }
        else {
            Delete (permit_or_deny);
            Delete (re);
            return (-1);
	}
    }

    if (add_as_access_list (num, re, permit) > 0) {
	if (count_as_access_list (num) == 1) {
	    config_add_module (0, "as-path access-list", 
			       get_config_aspath_filter, (void *) num);
	}
    }
    else {
        Delete (permit_or_deny);
        Delete (re);
        return (-1);
    }
    Delete (permit_or_deny);
    Delete (re);
    return (1);
}


static void 
get_community_list_config (int num)
{
    community_list_out (num, (void_fn_t) config_add_output);
}


static int
config_community_list (uii_connection_t * uii, int num,
		       char *permit_or_deny, char *string)
{
    int permit, n;
    u_long value;

    permit = (strcasecmp (permit_or_deny, "permit") == 0);
    Delete (permit_or_deny);

    if (num <= 0 && num >= MAX_CLIST) {
	config_notice (TR_ERROR, uii,
		       "CONFIG invalid community-list number %d\n", num);
	return (-1);
    }

    if (strcasecmp (string, "no-export") == 0)
	value = COMMUNITY_NO_EXPORT;
    else if (strcasecmp (string, "no-advertise") == 0)
	value = COMMUNITY_NO_ADVERTISE;
    else if (strcasecmp (string, "no-export-subconfed") == 0)
	value = COMMUNITY_NO_EXPORT_SUBCONFED;
    else if (strcasecmp (string, "all") == 0)
	value = 0; /* all */
    else {
	char *cp;
	value = strtoul10 (string, &cp);
	if (*cp != '\0') {
	    config_notice (TR_ERROR, uii,
		           "bad community %s\n", string);
	    Delete (string);
	    return (-1);
	}
    }
    Delete (string);

    if (uii->negative) {
        n = remove_community_list (num, permit, value);
	if (n == 0) {
            config_del_module (0, "community-list", get_community_list_config, 
			       (void *) num);
	}
    	return (1);
    }

    n = add_community_list (num, permit, value);
    if (n <= 0) {
	config_notice (TR_ERROR, uii,
		       "community list not added to %d\n", num);
	return (-1);
    }
    if (n > 0)
        config_add_module (0, "community-list", get_community_list_config, 
			   (void *) num);
    return (1);
}


static void
print_aggregate_address (prefix_t * prefix, u_long option, void *arg)
{
    config_add_output ("  aggregate-address %s%s%s\n",
		       prefix_toax (prefix),
		       BIT_TEST (option, BGP_AGGOPT_AS_SET) ? " as-set" : "",
	  BIT_TEST (option, BGP_AGGOPT_SUMMARY_ONLY) ? " summary-only" : "");
}


static void
get_config_bgp_peer (view_t *view, bgp_peer_t *peer)
{
    char name[MAXLINE];
    char stmp[64];
    bgp_filters_t *filters;

        pthread_mutex_lock (&peer->mutex_lock);
	strcpy (name, (peer->name)? peer->name: 
		prefix_toa (peer->peer_addr));

	if (peer->name) {
	    char option[MAXLINE], *cp = option;
	    *cp = '\0';
#ifdef notdef
	    if (peer->bind_addr) {
	        sprintf (cp, " src %s", prefix_toa (peer->bind_addr));
		cp += strlen (cp);
	    }
	    if (peer->bind_if) {
		sprintf (cp, " iface %s", peer->bind_if->name);
		cp += strlen (cp);
	    }
	    if (peer->peer_id) {
		sprintf (cp, " remote-id %s", 
			 inet_ntop (AF_INET, &peer->peer_id, stmp, 
				    sizeof (stemp)));
		cp += strlen (cp);
	    }
#endif
	    config_add_output ("  neighbor %s peer %a%s\n", 
		peer->name, peer->peer_addr, option);
	}

	if (peer->name == NULL || peer->peer_as >= 0)
	    config_add_output ("  neighbor %s remote-as %d\n", 
			       name, peer->peer_as);

	if (peer->description)
	    config_add_output ("  neighbor %s description %s\n", name,
			       peer->description);

#ifdef notdef
	if (peer->name == NULL) {
#endif
	    if (peer->peer_id)
	        config_add_output ("  neighbor %s remote-id %s\n", name, 
			           inet_ntop (AF_INET, &peer->peer_id, stmp, 
					      sizeof (stmp)));
	    if (peer->bind_addr) {
	        config_add_output ("  neighbor %s update-source %s\n", name,
	        		   prefix_toa (peer->bind_addr));
	    }
	    if (peer->bind_if) {
	        config_add_output ("  neighbor %s update-source %s\n", name,
	        		   peer->bind_if->name);
	    }
#ifdef notdef
	}
#endif
	filters = &peer->filters[view->viewno];
	if (filters->dlist_in >= 0)
	    config_add_output ("  neighbor %s distribute-list %d in\n",
			name, filters->dlist_in);
	if (filters->dlist_out >= 0)
	    config_add_output ("  neighbor %s distribute-list %d out\n",
		       name, filters->dlist_out);
	if (filters->flist_in >= 0)
	    config_add_output ("  neighbor %s filter-list %d in\n",
			name, filters->flist_in);
	if (filters->flist_out >= 0)
	    config_add_output ("  neighbor %s filter-list %d out\n",
		       name, filters->flist_out);
	if (filters->clist_in >= 0)
	    config_add_output ("  neighbor %s community-list %d in\n",
			name, filters->clist_in);
	if (filters->clist_out >= 0)
	    config_add_output ("  neighbor %s community-list %d out\n",
		       name, filters->clist_out);
	if (filters->route_map_in >= 0)
	    config_add_output ("  neighbor %s route-map %d in\n",
			name, filters->route_map_in);
	if (filters->route_map_out >= 0)
	    config_add_output ("  neighbor %s route-map %d out\n",
		       name, filters->route_map_out);

	if (peer->default_weight[view->viewno] >= 0)
	    config_add_output ("  neighbor %s weight %d\n",
		       name, peer->default_weight[view->viewno]);

	if (peer->maximum_prefix > 0)
	    config_add_output ("  neighbor %s maximum-prefix %d\n",
		       name, peer->maximum_prefix);

	if (BIT_TEST (peer->options, BGP_CONNECT_PASSIVE))
	    config_add_output ("  neighbor %s passive\n", name);
	if (BIT_TEST (peer->options, BGP_TRANSPARENT_AS))
	    config_add_output ("  neighbor %s transparent-as\n", name);
	if (BIT_TEST (peer->options, BGP_TRANSPARENT_NEXTHOP))
	    config_add_output ("  neighbor %s transparent-nexthop\n", name);
	if (BIT_TEST (peer->options, BGP_NEXTHOP_SELF))
	    config_add_output ("  neighbor %s next-hop-self\n", name);
	if (BIT_TEST (peer->options, BGP_NEXTHOP_PEER))
	    config_add_output ("  neighbor %s next-hop-peer\n", name);
	if (!BIT_TEST (peer->options, BGP_BGP4PLUS_AUTO)) {
	    if (BIT_TEST (peer->options, BGP_BGP4PLUS_00))
	        config_add_output ("  neighbor %s bgp4+ 0\n", name);
	    if (BIT_TEST (peer->options, BGP_BGP4PLUS_01))
	        config_add_output ("  neighbor %s bgp4+ 1\n", name);
	}
	if (BIT_TEST (peer->options, BGP_ROUTE_REFLECTOR_CLIENT))
	    config_add_output ("  neighbor %s route-reflector-client\n", name);
	if (BIT_TEST (peer->options, BGP_REMOVE_PRIVATE_AS))
	    config_add_output ("  neighbor %s remove-private-as\n", name);
	if (BIT_TEST (peer->options, BGP_PEER_CISCO))
	    config_add_output ("  neighbor %s cisco\n", name);
	if (BIT_TEST (peer->options, BGP_PEER_TEST))
	    config_add_output ("  neighbor %s test\n", name);

	if (peer->KeepAlive_Interval >= 0 && peer->HoldTime_Interval >= 0) {
	    config_add_output ("  neighbor %s timers %d %d\n",
		               name, peer->KeepAlive_Interval,
		               peer->HoldTime_Interval);
	}
	else {
	    if (peer->KeepAlive_Interval >= 0)
	        config_add_output ("  neighbor %s keepalive %d\n",
		                   name, peer->KeepAlive_Interval);
	    if (peer->HoldTime_Interval >= 0)
	        config_add_output ("  neighbor %s holdtime %d\n",
		                   name, peer->HoldTime_Interval);
	}
	if (peer->ConnectRetry_Interval >= 0)
	    config_add_output ("  neighbor %s connectretry %d\n",
		               name, peer->ConnectRetry_Interval);
	if (peer->Start_Interval >= 0)
	    config_add_output ("  neighbor %s starttime %d\n",
		               name, peer->Start_Interval);

	if (peer->aliases) {
	    prefix_t *prefix;
	    LL_Iterate (peer->aliases, prefix) {
	        config_add_output ("  neighbor %s alias %a\n", name, prefix);
	    }
	}
        pthread_mutex_unlock (&peer->mutex_lock);
}


static void
get_config_router_bgp (view_t *view)
{
    bgp_peer_t *peer;
    int i;
    prefix_t *prefix;
    char stmp[64], sview[64];
    u_long router_id;
    u_long cluster_id;

    strcpy (sview, "");
    router_id = view->local_bgp->this_id;
    /* there is no flags if or not it is explicitly defined */
    if (router_id) {
        sprintf (sview, " id %s", 
			inet_ntop (AF_INET, &router_id, stmp, sizeof stmp));
    }

    if (view->explicit) {
	sprintf (sview + strlen (sview), " view %d", view->viewno);
    }
    if (view->afi == AFI_IP && view->safi == SAFI_UNICAST)
        config_add_output ("router bgp %d%s\n", view->local_bgp->this_as, 
			   sview);
    else if (view->afi == AFI_IP && view->safi == SAFI_MULTICAST)
        config_add_output ("router bgp %d%s multicast\n", 
			   view->local_bgp->this_as, sview);
    else if (view->afi == AFI_IP6 && view->safi == SAFI_UNICAST)
        config_add_output ("router bgp %d%s ipv6\n", 
			   view->local_bgp->this_as, sview);
    else if (view->afi == AFI_IP6 && view->safi == SAFI_MULTICAST)
        config_add_output ("router bgp %d%s ipv6 multicast\n", 
			   view->local_bgp->this_as, sview);
    else
	assert (0);

    cluster_id = view->local_bgp->cluster_id;
    if (cluster_id != 0) {
        config_add_output ("  bgp cluster-id %s\n", 
			inet_ntop (AF_INET, &cluster_id, stmp, sizeof stmp));
    }

    /* I think this is thread-safe... we're just reading data */
    /* NO. someone may change the peer's list, and it may break here */

    view_open (view);
    LL_Iterate (view->ll_networks, prefix) {
	config_add_output ("  network %s\n", prefix_toax (prefix));
    }

    view_eval_aggregate (view, print_aggregate_address, NULL);

    for (i = PROTO_MIN; i <= PROTO_MAX; i++) {
        if (BGP4_BIT_TEST (view->redistribute_mask, i))
	    config_add_output ("  redistribute %s\n", proto2string (i));
    }
    view_close (view);

    pthread_mutex_lock (&view->local_bgp->peers_mutex_lock);
    /* we have to have a machanism like shcedule all and then wait all */
    /* waiting inside a lock will cause a deadlock when the same peer
       tries to get the lock in bgp_process_changes. get_config_bgp_peer
       scheduled can not go ahead unless the currect task finishes
       if they are in the same schedule queue. */
    LL_Iterate (view->local_bgp->ll_bgp_peers, peer) {
	/* if peer's being blocked on connect(), it doesn't run
	   so call it from this thread directly -- masaki */
	if (BITX_TEST (&peer->view_mask, view->viewno)) {
	    get_config_bgp_peer (view, peer);
/*
	    schedule_event_and_wait ("get_config_bgp_peer", peer->schedule,
				      get_config_bgp_peer, 2, view, peer);
*/
	}
    }
    pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
}


static int
config_router_bgp_int (uii_connection_t * uii, int as, u_long id, int viewno, 
		       int afi, int safi)
{
    int explicit = 0;
    int isfirst = 0;
    bgp_local_t *local_bgp;
    view_t *view = NULL;

    if (as < 0 || as > MAX_AS_NUMBER) {
	config_notice (TR_TRACE, uii,
	    "AS %d is out of bounds.  An AS number is only 16-bits\n", as);
	return (-1);
    }
    if (viewno >= 0)
	explicit++;

    LL_Iterate (BGP->ll_bgp_locals, local_bgp) {
	if (local_bgp->this_id != id)
	    continue;
	if (local_bgp->this_as != as)
	    continue;
	break;
    }

    if (uii->negative) {
        LINKED_LIST *ll_remove;
        bgp_peer_t *peer;
        prefix_t *network;
        int proto;

	if (local_bgp == NULL)
	    return (0);
        if (!BGP4_BIT_TEST (MRT->protocols, PROTO_BGP))
	    return (0);
	if (viewno >= 0) {
	    if (!BITX_TEST (&local_bgp->view_mask, viewno))
		return (0);
	    view = BGP->views[viewno];
	    assert (view);
	    assert (view->local_bgp == local_bgp);
	    if (afi > 0 && view->afi != afi)
		return (-1);
	    if (safi > 0 && view->safi != safi)
		return (-1);
	}
	else {
	    for (viewno = 0; viewno < MAX_BGP_VIEWS; viewno++) {
	        if (!BITX_TEST (&local_bgp->view_mask, viewno))
		    continue;
	        view = BGP->views[viewno];
	        assert (view);
	        assert (view->local_bgp == local_bgp);
		if (view->explicit)
		    continue;
		if (afi > 0 && afi != view->afi)
		    continue;
		if (safi > 0 && safi != view->safi)
		    continue;
		break;
	    }
	    if (viewno >= MAX_BGP_VIEWS)
		return (0);
	}

	assert (view);
 	assert (viewno == view->viewno);
	ll_remove = LL_Create (0);
        pthread_mutex_lock (&local_bgp->peers_mutex_lock);
        LL_Iterate (local_bgp->ll_bgp_peers, peer) {
	    if (BITX_TEST (&peer->view_mask, viewno)) {
	        BITX_RESET (&peer->view_mask, viewno);
		if (ifzero (&peer->view_mask, sizeof (peer->view_mask)))
		    LL_Add (ll_remove, peer);
	    }
	}
        pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
	LL_Iterate (ll_remove, peer) {
	    Destroy_BGP_Peer (peer, 1 /* fast */);
	}
        LL_Destroy (ll_remove);

 	view_open (view);
        LL_Iterate (view->ll_networks, network) {
	    if (MRT->rib_redistribute_network)
                MRT->rib_redistribute_network (PROTO_BGP, viewno, network, 
					       -1 /* XXX */, view->safi);
	}
	LL_Clear (view->ll_networks);

        for (proto = 0; proto <= PROTO_MAX; proto++) {
            if (!BGP4_BIT_TEST (view->redistribute_mask, proto))
		continue;
            if (MRT->rib_redistribute_request)
                MRT->rib_redistribute_request (PROTO_BGP, viewno, proto, 
					       -1 /* XXX */,
					       view->afi, view->safi);
            BGP4_BIT_RESET (view->redistribute_mask, proto);
 	}
    	view_close (view);

        config_del_module (CF_DELIM, "router bgp", get_config_router_bgp, 
			   view);
	if (viewno < BGP_VIEW_RESERVED) {
	    if (MRT->rib_flush_route) {
	        MRT->rib_flush_route (PROTO_BGP, view->afi, view->safi);
	    }
	    BGP->views[viewno] = New_View (view->trace, viewno, 
					   view->afi, view->safi);
	}
	else {
	    BGP->views[viewno] = NULL;
	    assert (BITX_TEST (&BGP->view_mask, viewno));
	    BITX_RESET (&BGP->view_mask, viewno);
	}
        Destroy_View (view);
	assert (BITX_TEST (&local_bgp->view_mask, viewno));
	BITX_RESET (&local_bgp->view_mask, viewno);
	if (!ifzero (&local_bgp->view_mask, sizeof (local_bgp->view_mask)))
	    return (1);
        remove_bgp_local (local_bgp);
        return (1);
    }

    if (local_bgp == NULL) {

	if (viewno < 0) {
	    /* no viewno specified */
	    /* assign from the start */
            for (viewno = 0; viewno < MAX_BGP_VIEWS; viewno++) {
	        if ((view = BGP->views[viewno]) == NULL)
	            break;
	        if (view->local_bgp == NULL &&
		    ((afi == 0 && view->afi == AFI_IP) || afi == view->afi) &&
		    ((safi == 0 && view->safi == SAFI_UNICAST) 
			|| safi == view->safi))
		    break;
	    }
            if (viewno >= MAX_BGP_VIEWS) {
	        config_notice (TR_ERROR, uii, "No more views available (%d)\n", 
			       MAX_BGP_VIEWS);
	        return (-1);
            }
	}
	else {
	    if (BGP->views[viewno] != NULL) {
	        config_notice (TR_ERROR, uii, "View %d has been assigned\n", 
			       viewno);
		return (-1);
	    }
	}
	/* create a new bgp router */
        local_bgp = init_bgp_local (as, id);
	isfirst++;
    }
    else {
	if (viewno < 0) {
	    int candidate = -1;
	    /* no viewno specified */
	    /* search from the start */
            for (viewno = 0; viewno < MAX_BGP_VIEWS; viewno++) {
	        view = BGP->views[viewno];
	        if (candidate < 0 && view == NULL)
		    candidate = viewno;
	        if (candidate < 0 && view->local_bgp == NULL &&
		    ((afi == 0 && view->afi == AFI_IP) || afi == view->afi) &&
		    ((safi == 0 && view->safi == SAFI_UNICAST) 
			|| safi == view->safi))
		    candidate = viewno;
	        if (!BITX_TEST (&local_bgp->view_mask, viewno))
	            continue;
	        assert (view->local_bgp == local_bgp);
		if (view->explicit)
		    continue;
		if (afi > 0 && afi != view->afi)
		    continue;
		if (safi > 0 && safi != view->safi)
		    continue;
		break;
	    }
            if (viewno >= MAX_BGP_VIEWS) {
		if (candidate < 0) {
	            config_notice (TR_ERROR, uii, 
				   "No more views available (%d)\n", 
			           MAX_BGP_VIEWS);
	            return (-1);
		}
		viewno = candidate;
		isfirst++;
	    }
	}
	else {
	    if (!BITX_TEST (&local_bgp->view_mask, viewno)) {
		if (BGP->views[viewno]) {
	    	    assert (BGP->views[viewno]->local_bgp != local_bgp);
	            config_notice (TR_ERROR, uii, 
			 "View %d has been defined for another router\n", 
			           viewno);
		    return (-1);
		}
		isfirst++;
	    }
	    else {
	        view = BGP->views[viewno];
	        assert (view);
	        if (afi > 0 && view->afi != afi) {
	            config_notice (TR_ERROR, uii, 
			 "View %d has been defined for another afi\n", 
			           viewno);
		    return (-1);
		}
	        if (safi > 0 && view->safi != safi) {
	            config_notice (TR_ERROR, uii, 
			 "View %d has been defined for another safi\n", 
			           viewno);
		    return (-1);
		}
	    }
	}
    }


    if (isfirst) {
	if ((view = BGP->views[viewno]) == NULL) {
	    view = New_View (BGP->trace, viewno, afi, safi);
	    view->explicit = explicit;
	    BGP->views[viewno] = view;
	    BITX_SET (&BGP->view_mask, viewno);
	}
	assert (BGP->views[viewno]->local_bgp == NULL);
	BGP->views[viewno]->local_bgp = local_bgp;
	BITX_SET (&local_bgp->view_mask, viewno);
        config_add_module (CF_DELIM, "router bgp", get_config_router_bgp, view);
    }

    CONFIG_MRTD->protocol = PROTO_BGP;
    uii->previous[++uii->prev_level] = uii->state;
    uii->state = UII_CONFIG_ROUTER_BGP;
    CONFIG_MRTD->viewno = viewno;
    return (1);
}


static void
copy_aggregate_address (prefix_t * prefix, u_long option, void *arg)
{
    view_add_aggregate (arg, prefix, option);
}


/* copy the view from view0 to view1 */
static int
config_router_bgp_copy_view (view_t *view0, view_t *view1)
{
    bgp_peer_t *peer;
    prefix_t *network;
    int proto;

    assert (view0);
    assert (view1);
    assert (view0->local_bgp);
    assert (view1->local_bgp == NULL || view0->local_bgp == view1->local_bgp);

    pthread_mutex_lock (&view0->local_bgp->peers_mutex_lock);
    LL_Iterate (view0->local_bgp->ll_bgp_peers, peer) {
	assert (BITX_TEST (&peer->view_mask, view0->viewno));
        BITX_SET (&peer->view_mask, view1->viewno);
    }
    pthread_mutex_unlock (&view0->local_bgp->peers_mutex_lock);

    view1->local_bgp = view0->local_bgp;
    assert (!BITX_TEST (&view0->local_bgp->view_mask, view1->viewno));
    BITX_SET (&view0->local_bgp->view_mask, view1->viewno);
    view_open (view0);
    view_open (view1);

     LL_Iterate (view0->ll_networks, network) {
	if (MRT->rib_redistribute_network) {
            MRT->rib_redistribute_network (PROTO_BGP, view1->viewno, 
					   network, 1, view1->safi);
	}
	LL_Add (view1->ll_networks, network);
    }

    for (proto = PROTO_MIN; proto <= PROTO_MAX; proto++) {
        if (!BGP4_BIT_TEST (view0->redistribute_mask, proto))
	    continue;
        if (MRT->rib_redistribute_request) {
            MRT->rib_redistribute_request (PROTO_BGP, view1->viewno, proto, 1,
					   view1->afi, view1->safi);
	}
        BGP4_BIT_SET (view1->redistribute_mask, proto);
    }
    view_eval_aggregate (view0, copy_aggregate_address, view1);
    view_close (view1);
    view_close (view0);

    config_add_module (CF_DELIM, "router bgp", get_config_router_bgp, 
		       view1);
    return (1);
}


static void
config_router_check_family (uii_connection_t *uii, prefix_t *prefix)
{
    view_t *view = BGP->views[CONFIG_MRTD->viewno];

    assert (prefix);
    if (view->afi != family2afi (prefix->family)) {
        config_notice (TR_WARN, uii, "Address family? %p\n", prefix);
    }
#if 1
#ifdef HAVE_IPV6
    /* only when adding */
    if (!uii->negative) {
	/* XXX to keep compatible. If trying to define an IPv6 peer,
	   this IPv4 view #0 will be automatically moved to IPv6 view #1 */
	/* only neighbor ... will trigger this conversion -- enough for now */
	if (CONFIG_MRTD->viewno == 0 && prefix->family == AF_INET6) {
	    if (BGP->views[1]->local_bgp == NULL) {
		int save = uii->negative;
		config_router_bgp_copy_view (BGP->views[0], BGP->views[1]);
		uii->negative = 1;
		/* delete view #0 */
		config_router_bgp_int (uii, BGP->views[0]->local_bgp->this_as, 
				       BGP->views[0]->local_bgp->this_id,
				       0 /* viewno */, BGP->views[0]->afi, 
				       BGP->views[0]->safi);
		uii->negative = save;
		/* switch to view #1 */
    	        CONFIG_MRTD->viewno = 1;
        	config_notice (TR_WARN, uii, "Convert view #0 to #1\n");
	    }
	}
    }
#endif /* HAVE_IPV6 */
#endif
}


static int
config_router_bgp_id_view (uii_connection_t * uii, int as, prefix_t *prefix,
			   int viewno, char *ipv6, char *multicast)
{
    u_long id = 0;
    int afi = AFI_IP;
    int safi = SAFI_UNICAST;

    if (prefix) {
        id = (u_long) prefix_tolong (prefix);
        Deref_Prefix (prefix);
    }
    if (ipv6) {
	afi = AFI_IP6;
	Delete (ipv6);
    }
    if (multicast) {
	safi = SAFI_MULTICAST;
	Delete (multicast);
    }
    return (config_router_bgp_int (uii, as, id, viewno, afi, safi));
}

static int
config_router_bgp (uii_connection_t * uii, int as, char *ipv6, char *multicast)
{
    return (config_router_bgp_id_view (uii, as, NULL, -1, ipv6, multicast));
}

static int
config_router_bgp_id (uii_connection_t * uii, int as, prefix_t *prefix,
		      char *ipv6, char *multicast)
{
    return (config_router_bgp_id_view (uii, as, prefix, -1, ipv6, multicast));
}

static int
config_router_bgp_view (uii_connection_t * uii, int as,
			int viewno, char *ipv6, char *multicast)
{
    return (config_router_bgp_id_view (uii, as, NULL, viewno, 
				       ipv6, multicast));
}


static int
config_router_bgp_bind_interface_only (uii_connection_t * uii)
{
  if (BGP->views[CONFIG_MRTD->viewno]->local_bgp->bind_interface_only) {
    config_notice (TR_TRACE, uii, "Interfaces are already bound.\n");
    return (1);
  }

  BGP->views[CONFIG_MRTD->viewno]->local_bgp->bind_interface_only = 1;
  config_notice (TR_TRACE, uii, "Interfaces are bound.\n");
  return (1);
}

static int
config_router_bgp_add_interface (uii_connection_t * uii, prefix_t *prefix)
{
  BGP->views[CONFIG_MRTD->viewno]->local_bgp->num_interfaces++;
  LL_Add (BGP->views[CONFIG_MRTD->viewno]->local_bgp->ll_interfaces, 
	  prefix);
  return (1);
}

static int
config_router_bgp_delete_interface (uii_connection_t * uii, prefix_t *prefix)
{
  prefix_t *p;
  p = LL_Find (BGP->views[CONFIG_MRTD->viewno]->local_bgp->ll_interfaces, 
	       prefix);
  if (p) {
    LL_Remove (BGP->views[CONFIG_MRTD->viewno]->local_bgp->ll_interfaces, p);
    Deref_Prefix (p);
    Deref_Prefix (prefix);
    return (1);
  }
  config_notice(TR_TRACE, uii, "Prefix not found.\n");
  Deref_Prefix (prefix);
  return (0);
}


/* config_router_neighbor_remoteas
 * neighbor %p remote-as %d
 */
static int
config_router_neighbor_remoteas (uii_connection_t * uii,
				 prefix_t * prefix, int as)
{
    bgp_peer_t *peer;
    view_t *view;
    int restart = 0;

    if (as < 0 || as > MAX_AS_NUMBER) {
	config_notice (TR_TRACE, uii,
	    "AS %d is out of bounds.  An AS number is only 16-bits\n", as);
	return (-1);
    }

    config_router_check_family (uii, prefix);
    view = BGP->views[CONFIG_MRTD->viewno];

    if (uii->negative) {
        pthread_mutex_lock (&view->local_bgp->peers_mutex_lock);
        if ((peer = Find_BGP_Peer_ByPrefix (view->local_bgp, prefix)) == NULL) {
	    config_notice (TR_ERROR, uii, "Peer does not exist\n");
	    Deref_Prefix (prefix);
            pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
	    return (-1);
        }
	/* to see if the peer is defined in this view */
    	if (!BITX_TEST (&peer->view_mask, view->viewno)) {
	    config_notice (TR_ERROR, uii, "Peer does not exist in this view\n");
	    Deref_Prefix (prefix);
            pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
	    return (-1);
	}

    	BITX_RESET (&peer->view_mask, view->viewno);
        pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
        Destroy_BGP_Peer (peer, 0);
        config_notice (TR_TRACE, uii, "Peer deleted\n");
        Deref_Prefix (prefix);
        return (1);
    }

    pthread_mutex_lock (&view->local_bgp->peers_mutex_lock);
    if ((peer = Find_BGP_Peer_ByPrefix (view->local_bgp, prefix)) == NULL) {
        /* I am only one except for automatic addition that adds a peer */
        peer = Add_BGP_Peer (view->local_bgp, NULL, prefix, as, 0, BGP->trace);
	if (peer == NULL)
	    return (-1);
    	BITX_SET (&peer->view_mask, view->viewno);
	if (BGPSIM_TRANSPARENT) {
	    /* BGPSIM should behave as transparent */
	    /*
            pthread_mutex_lock (&peer->mutex_lock);
	    BIT_SET (peer->options, BGP_TRANSPARENT_AS);
	    BIT_SET (peer->options, BGP_TRANSPARENT_NEXTHOP);
            pthread_mutex_unlock (&peer->mutex_lock);
	    */
	}
    }
    else {
	if (peer->peer_as != as) {
	    restart++;
	    config_notice (TR_TRACE, uii, "Peer AS is changing to %d\n", as);
	    if (peer->state == BGPSTATE_IDLE ||
	            peer->state == BGPSTATE_ACTIVE ||
	            peer->state == BGPSTATE_CONNECT) {
		/* should I once down the peer? */
		peer->peer_as = as;
        	BIT_RESET (peer->options, BGP_INTERNAL);
        	if (as == peer->local_bgp->this_as)
            	    BIT_SET (peer->options, BGP_INTERNAL);
		peer->gateway = NULL;
	    }
	    else
	        peer->new_as = as;
	}
        pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
	if (!BITX_TEST (&peer->view_mask, view->viewno)) {
	    /* incorporate into this view */
    	    BITX_SET (&peer->view_mask, view->viewno);
            bgp_re_evaluate_in (peer, view->viewno);
	}
	if (restart)
	    restart_bgp_peer (peer);
    	Deref_Prefix (prefix);
    	return (0);
    }
    pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);

    if (BIT_TEST (peer->options, BGP_INTERNAL)) {
	trace (TR_PARSE, BGP->trace, "neighbor %s AS%d (iBGP)\n",
	       prefix_toa (prefix), as);
    }
    else {
	trace (TR_PARSE, BGP->trace, "neighbor %s AS%d (eBGP)\n",
	       prefix_toa (prefix), as);
    }
    Deref_Prefix (prefix);
    start_bgp_peer (peer);
    return (1);
}


static int
config_router_neighbor_n_peer (uii_connection_t * uii, char *name,
			prefix_t * prefix, char *option)
{
    bgp_peer_t *peer;
    prefix_t *usrc = NULL;
    char ifname[MAXLINE];
    interface_t *interface = NULL;
    view_t *view;
    int restart = 0;

    assert (prefix);
    config_router_check_family (uii, prefix);
    view = BGP->views[CONFIG_MRTD->viewno];

    if (uii->negative) {
        pthread_mutex_lock (&view->local_bgp->peers_mutex_lock);
        if ((peer = Find_BGP_Peer_ByID (view->local_bgp, name)) == NULL) {
            pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
	    config_notice (TR_ERROR, uii, "Peer %s does not exist\n", name);
	    Delete (name);
	    return (-1);
        }
	/* to see if the peer is defined in this view */
    	if (!BITX_TEST (&peer->view_mask, view->viewno)) {
	    config_notice (TR_ERROR, uii, 
			   "Peer %s does not exist in this view\n", name);
	    Deref_Prefix (prefix);
            pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
	    return (-1);
	}

        pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
        Destroy_BGP_Peer (peer, 0);
        config_notice (TR_INFO, uii, "Peer %s deleted\n", name);
        Delete (name);
        return (1);
    }

    pthread_mutex_lock (&view->local_bgp->peers_mutex_lock);
#ifdef notdef
    /* resulting in peers with the same prefix */
    if ((peer = Find_BGP_Peer_ByPrefix (view->local_bgp, prefix)) != NULL) {
	config_notice (TR_ERROR, uii, "Peer %s is already defined\n",
			prefix_toa (prefix));
        pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
    	Delete (name);
    	Deref_Prefix (prefix);
    	Delete (option);
    	return (-1);
    }
#endif

    if ((peer = Find_BGP_Peer_ByID (view->local_bgp, name)) != NULL) {
	if (BITX_TEST (&peer->view_mask, view->viewno)) {
	    config_notice (TR_ERROR, uii, "Peer %s is already defined\n", name);
            pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
    	    Delete (name);
    	    Deref_Prefix (prefix);
    	    Delete (option);
    	    return (-1);
	}
    }

    strcpy (ifname, "");
    if (option) {
        if (parse_line (option, "src %M iface %s", &usrc, ifname) <= 0 &&
            parse_line (option, "iface %s src %M", ifname, &usrc) <= 0) {
            pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
    	    Delete (name);
    	    Deref_Prefix (prefix);
    	    Delete (option);
    	    return (-1);
	}
	Delete (option);
    }

    /* XXX usrc should be checked against interface addresses */

    if (ifname[0] && (interface = find_interface_byname (ifname)) == NULL) {
	config_notice (TR_ERROR, uii, "Interface %s is not found\n", ifname);
        pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
    	Delete (name);
    	Deref_Prefix (prefix);
    	if (usrc) Deref_Prefix (usrc);
    	return (-1);
    }

    if (peer) {
	if (prefix_compare2 (peer->peer_addr, prefix) != 0) {
	    /* changing the peer address */
	    Deref_Prefix (peer->peer_addr);
	    peer->peer_addr = Ref_Prefix (prefix);
	    restart++;
	}
    }
    else {
        /* I am only one except for automatic addition that adds a peer */
        peer = Add_BGP_Peer (view->local_bgp, name, prefix, 
			     -1 /* AS number XXX */, 0, BGP->trace);
	if (peer == NULL)
	    return (-1);
    }

    if (!BITX_TEST (&peer->view_mask, view->viewno)) {
        BITX_SET (&peer->view_mask, view->viewno);
	/* XXX */
	restart++;
    }

    if (usrc) {
	if (peer->bind_addr && prefix_compare2 (peer->bind_addr, usrc) != 0) {
	    Deref_Prefix (peer->bind_addr);
	    peer->bind_addr = Ref_Prefix (usrc);
	    restart++;
	}
    }
    if (interface) {
	if (peer->bind_if && peer->bind_if != interface) {
	    peer->bind_if = interface;
	    restart++;
	}
    }

	if (BGPSIM_TRANSPARENT) {
	    /* BGPSIM should behave as transparent */
	    /*
            pthread_mutex_lock (&peer->mutex_lock);
	    BIT_SET (peer->options, BGP_TRANSPARENT_AS);
	    BIT_SET (peer->options, BGP_TRANSPARENT_NEXTHOP);
            pthread_mutex_unlock (&peer->mutex_lock);
	    */
	}

    pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
    Delete (name);
    Deref_Prefix (prefix);
    if (usrc) Deref_Prefix (usrc);
    if (restart) {
	restart_bgp_peer (peer);
    }
    return (1);
}


static int
config_router_neighbor_test (uii_connection_t * uii, char *name)
{
    bgp_peer_t *peer;

	if ((peer = name2peer (uii, name)) == NULL) {
		config_notice (TR_ERROR, uii, "No peer %s\n", name);
		Delete (name);
		return (-1);
    }
    Delete (name);

	BIT_SET (peer->options, BGP_PEER_TEST);
    return (1);
}





static int
config_router_neighbor_n_remoteas (uii_connection_t * uii, char *name, int as)
{
    bgp_peer_t *peer;
    view_t *view = BGP->views[CONFIG_MRTD->viewno];
    int restart = -1;

    if (as < 0 || as > MAX_AS_NUMBER) {
	config_notice (TR_TRACE, uii,
	    "AS %d is out of bounds.  An AS number is only 16-bits\n", as);
	return (-1);
    }

    pthread_mutex_lock (&view->local_bgp->peers_mutex_lock);
    if ((peer = Find_BGP_Peer_ByID (view->local_bgp, name)) == NULL) {
        pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
	config_notice (TR_ERROR, uii, "Peer %s is not defined\n", name);
    	Delete (name);
    	return (-1);
    }

    if (!BITX_TEST (&peer->view_mask, view->viewno)) {
	config_notice (TR_ERROR, uii, "Peer %s is not defined in this view\n",
		       name);
        pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
    	Delete (name);
	return (-1);
    }
    pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);

    if (peer->peer_as < 0) {
	/* not yet set */
	peer->peer_as = as;
	restart = 0; /* start newly */
    }
    else if (peer->peer_as != as) {
	restart++;
	config_notice (TR_TRACE, uii, "Peer AS is changing to %d\n", as);
	if (peer->state == BGPSTATE_IDLE ||
	        peer->state == BGPSTATE_ACTIVE ||
	        peer->state == BGPSTATE_CONNECT) {
	    /* should I once down the peer? */
	    peer->peer_as = as;
	    peer->gateway = NULL;
	}
	else
	    peer->new_as = as;
    }

    if (restart >= 0) {
        if (as == peer->local_bgp->this_as) {
            BIT_SET (peer->options, BGP_INTERNAL);
	    trace (TR_PARSE, BGP->trace,
	           "neighbor %s AS%d as iBGP\n", name, as);
        }
        else {
            BIT_RESET (peer->options, BGP_INTERNAL);
	    trace (TR_PARSE, BGP->trace,
	           "neighbor %s AS%d as eBGP\n", name, as);
        }
    }
    Delete (name);
    if (restart > 0)
	restart_bgp_peer (peer);
    else if (restart == 0)
        start_bgp_peer (peer);
    return (1);
}


static int
config_router_neighbor_list (uii_connection_t *uii, char *name, int alist)
{
    bgp_peer_t *peer;
    view_t *view = BGP->views[CONFIG_MRTD->viewno];

    pthread_mutex_lock (&view->local_bgp->peers_mutex_lock);
    peer = Find_BGP_Peer_ByID (view->local_bgp, name);

    if (uii->negative) {
	if (peer == NULL || !BITX_TEST (&peer->view_mask, view->viewno)) {
    	    pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
	    config_notice (TR_ERROR, uii, "Peer %s is not defined\n", name);
    	    Delete (name);
    	    return (-1);
	}
        pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
	Destroy_BGP_Peer (peer, 0);
        Delete (name);
        return (1);
    }
    else {
	if (peer != NULL) {
	    if (BITX_TEST (&peer->view_mask, view->viewno)) {
    	        pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
	        config_notice (TR_ERROR, uii, 
			       "Peer %s is already defined in this view\n", 
			       name);
    	        Delete (name);
    	        return (-1);
	    }
	}
	else {
	    peer = Add_BGP_Peer (view->local_bgp, name, NULL, 0, 0, BGP->trace);
	    if (peer == NULL) {
    	        pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
    	        Delete (name);
	        return (-1);
	    }
	}
 	/* XXX */
	peer->neighbor_list = alist;
        BITX_SET (&peer->view_mask, view->viewno);
    }

    pthread_mutex_unlock (&view->local_bgp->peers_mutex_lock);
    Delete (name);
    return (1);
}


bgp_peer_t *
name2peer (uii_connection_t *uii, char *name)
{
    bgp_peer_t *peer;
    prefix_t *prefix;
    bgp_local_t *local_bgp = NULL;

    if (uii->state >= UII_CONFIG_ROUTER_BGP) {
        assert (CONFIG_MRTD->viewno >= 0);
        local_bgp = BGP->views[CONFIG_MRTD->viewno]->local_bgp;
	assert (local_bgp);
    }

    if (local_bgp)
	pthread_mutex_lock (&local_bgp->peers_mutex_lock);

    if ((prefix = ascii2prefix (0, name)) != NULL) {
        peer = Find_BGP_Peer_ByPrefix (local_bgp, prefix);
	Deref_Prefix (prefix);
    }
    else {
        peer = Find_BGP_Peer_ByID (local_bgp, name);
    }

    if (local_bgp)
        pthread_mutex_unlock (&local_bgp->peers_mutex_lock);

    if (peer == NULL || 
	    (local_bgp && !BITX_TEST (&peer->view_mask, CONFIG_MRTD->viewno)))
	return (NULL);
    return (peer);
}


static int
config_router_neighbor_update_source (uii_connection_t *uii, char *name, 
				      char *s)
{
    bgp_peer_t *peer;
    prefix_t *prefix;

    if ((peer = name2peer (uii, name)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", name);
	Delete (name);
    	Delete (s);
	return (-1);
    }
    Delete (name);

    pthread_mutex_lock (&peer->mutex_lock);
    if (uii->negative) {
        prefix = ascii2prefix (0, s);
    	Delete (s);
	if (prefix) {
	    if (peer->bind_addr && prefix_compare (prefix, peer->bind_addr)) {
	        Deref_Prefix (peer->bind_addr);
	        peer->bind_addr = NULL;
    		pthread_mutex_unlock (&peer->mutex_lock);
        	return (1);
	    }
	    Deref_Prefix (prefix);
	}
	else {
	    if (peer->bind_if && strcasecmp (peer->bind_if->name, s) == 0) {
		peer->bind_if = NULL;
    		pthread_mutex_unlock (&peer->mutex_lock);
        	return (1);
	    }
	}
    	pthread_mutex_unlock (&peer->mutex_lock);
        return (0);
    }
    else {
        prefix = ascii2prefix (0, s);
    	Delete (s);
	if (prefix) {
	    if (find_interface_local (prefix) == NULL) {
		config_notice (TR_ERROR, uii, 
			       "Address %s is not found\n", 
				prefix_toa (prefix));
    	        pthread_mutex_unlock (&peer->mutex_lock);
		return (-1);
	    }
	    if (peer->bind_addr) {
	        Deref_Prefix (peer->bind_addr);
	    }
	    peer->bind_addr = prefix;
    	    pthread_mutex_unlock (&peer->mutex_lock);
    	    return (1);
	}
	else {
	    interface_t *interface;

	    interface = find_interface_byname (s);
	    if (interface) {
	        peer->bind_if = interface;
    	        pthread_mutex_unlock (&peer->mutex_lock);
    	        return (1);
	    }
	    else {
		config_notice (TR_ERROR, uii, 
			       "Interface %s is not found\n", s);
    	        pthread_mutex_unlock (&peer->mutex_lock);
		return (-1);
	    }
	}
    }
    /* NOT REACHED */
}



static void
set_bgp_peer (bgp_peer_t *peer, int first, ...)
{
    va_list ap;
    enum BGP_PEER_ATTR attr;
    int re_eval = -1;
    int establish = -1;
    int viewno = -1;
    char str[MAXLINE];

    assert (peer);
    pthread_mutex_lock (&peer->mutex_lock);
    va_start (ap, first);
    for (attr = (enum BGP_PEER_ATTR) first; attr; 
				     attr = va_arg (ap, enum BGP_PEER_ATTR)) {
	switch (attr) {
	case BGP_PEER_DESCRIPTION:
	    if (peer->description)
		Delete (peer->description);
	    peer->description = va_arg (ap, char *); /* don't need to dup */
	    if (peer->description) {
#ifdef HAVE_IPV6
		if (peer->peer_addr && peer->peer_addr->family == AF_INET6)
		    sprintf (str, "BGP4+ %s", peer->description);
		else
#endif /* HAVE_IPV6 */
		sprintf (str, "BGP %s", peer->description);
	    }
	    else {
#ifdef HAVE_IPV6
		if (peer->peer_addr && peer->peer_addr->family == AF_INET6)
		    sprintf (str, "BGP4+ %s", peer->name?peer->name:
					prefix_toa (peer->peer_addr));
		else
#endif /* HAVE_IPV6 */
		sprintf (str, "BGP %s", peer->name?peer->name:
                                        prefix_toa (peer->peer_addr));
	    }
	    set_trace (peer->trace, TRACE_PREPEND_STRING, str, 0);
	    break;
	case BGP_PEER_WEIGHT:
    	    viewno = va_arg (ap, int);
    	    peer->default_weight[viewno] = va_arg (ap, int);
	    if (peer->state == BGPSTATE_ESTABLISHED)
		re_eval = 1;
	    break;
	case BGP_PEER_ALIAS_ADD:
    	    if (peer->aliases == NULL)
	        peer->aliases = LL_Create (0);
    	    LL_Add (peer->aliases, va_arg (ap, prefix_t *));
	    break;
	case BGP_PEER_ALIAS_DEL:
    	    if (peer->aliases == NULL || LL_GetCount (peer->aliases) <= 0)
	        break;
    	    LL_Remove (peer->aliases, va_arg (ap, prefix_t *));
	    break;
	case BGP_PEER_MAXPREF:
    	    peer->maximum_prefix = va_arg (ap, int);
	    break;
	case BGP_PEER_SETOPT:
            BIT_SET (peer->options, va_arg (ap, u_long));
	    break;
	case BGP_PEER_RESETOPT:
            BIT_RESET (peer->options, va_arg (ap, u_long));
	    break;
	case BGP_PEER_DLIST_IN:
    	    viewno = va_arg (ap, int);
    	    peer->filters[viewno].dlist_in = va_arg (ap, int);
	    if (peer->state == BGPSTATE_ESTABLISHED)
    		re_eval = 1;
	    break;
	case BGP_PEER_DLIST_OUT:
    	    viewno = va_arg (ap, int);
    	    peer->filters[viewno].dlist_out = va_arg (ap, int);
	    if (peer->state == BGPSTATE_ESTABLISHED)
		establish = 0;
	    break;
	case BGP_PEER_FLIST_IN:
    	    viewno = va_arg (ap, int);
    	    peer->filters[viewno].flist_in = va_arg (ap, int);
	    if (peer->state == BGPSTATE_ESTABLISHED)
    		re_eval = 1;
	    break;
	case BGP_PEER_FLIST_OUT:
    	    viewno = va_arg (ap, int);
    	    peer->filters[viewno].flist_out = va_arg (ap, int);
	    if (peer->state == BGPSTATE_ESTABLISHED)
		establish = 0;
	    break;
	case BGP_PEER_CLIST_IN:
    	    viewno = va_arg (ap, int);
    	    peer->filters[viewno].clist_in = va_arg (ap, int);
	    if (peer->state == BGPSTATE_ESTABLISHED)
    		re_eval = 1;
	    break;
	case BGP_PEER_CLIST_OUT:
    	    viewno = va_arg (ap, int);
    	    peer->filters[viewno].clist_out = va_arg (ap, int);
	    if (peer->state == BGPSTATE_ESTABLISHED)
		establish = 0;
	    break;
	case BGP_PEER_RTMAP_IN:
    	    viewno = va_arg (ap, int);
    	    peer->filters[viewno].route_map_in = va_arg (ap, int);
	    if (peer->state == BGPSTATE_ESTABLISHED)
    		re_eval = 1;
	    break;
	case BGP_PEER_RTMAP_OUT:
    	    viewno = va_arg (ap, int);
    	    peer->filters[viewno].route_map_out = va_arg (ap, int);
	    if (peer->state == BGPSTATE_ESTABLISHED)
		establish = 1;
	    break;
	case BGP_PEER_HOLDTIME:
            peer->HoldTime_Interval = va_arg (ap, int);
	    if (peer->HoldTime_Interval >= 0)
	        Timer_Set_Time (peer->timer_HoldTime, peer->HoldTime_Interval);
	    break;
	case BGP_PEER_KEEPALIVE:
            peer->KeepAlive_Interval = va_arg (ap, int);
	    if (peer->KeepAlive_Interval >= 0)
	        Timer_Set_Time (peer->timer_KeepAlive, 
				peer->KeepAlive_Interval);
	    break;
	case BGP_PEER_CONNECTRETRY:
            peer->ConnectRetry_Interval = va_arg (ap, int);
	    if (peer->ConnectRetry_Interval >= 0)
	        Timer_Set_Time (peer->timer_ConnectRetry, 
				peer->ConnectRetry_Interval);
	    break;
	case BGP_PEER_START:
            peer->Start_Interval = va_arg (ap, int);
	    if (peer->Start_Interval >= 0)
	        Timer_Set_Time (peer->timer_Start, 
				peer->Start_Interval);
	    break;
	default:
	    assert (0);
    	    break;
	}
    }
    va_end (ap);
    pthread_mutex_unlock (&peer->mutex_lock);
    if (re_eval >= 0)
        bgp_re_evaluate_in (peer, viewno);
    if (establish >= 0)
	bgp_establish_peer (peer, establish, viewno);
}


static int
config_router_neighbor_weight (uii_connection_t * uii,
			       char * name, int weight)
{
    bgp_peer_t *peer;

    if ((peer = name2peer (uii, name)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", name);
	Delete (name);
	return (-1);
    }
    Delete (name);

    if (uii->negative)
	weight = -1;

    schedule_event2 ("set_bgp_peer",
                     peer->schedule, (event_fn_t) set_bgp_peer, 5,
                     peer, BGP_PEER_WEIGHT, CONFIG_MRTD->viewno, weight, 0);

    return (1);
}


static int
config_router_neighbor_description (uii_connection_t * uii,
			            char * name, char *description)
{
    bgp_peer_t *peer;
    char *s;

    if ((peer = name2peer (uii, name)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", name);
	Delete (name);
	Delete (description);
	return (-1);
    }
    Delete (name);

    if (uii->negative)
	s = NULL;
    else {
	s = description;
    }

    schedule_event2 ("set_bgp_peer",
                     peer->schedule, (event_fn_t) set_bgp_peer, 4,
                     peer, BGP_PEER_DESCRIPTION, s, 0);

    return (1);
}


static int
config_router_neighbor_maximum_prefix (uii_connection_t * uii,
			                 char * name, int num)
{
    bgp_peer_t *peer;

    if ((peer = name2peer (uii, name)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", name);
	Delete (name);
	return (-1);
    }
    Delete (name);

    if (uii->negative)
	num = -1;

    schedule_event2 ("set_bgp_peer",
                     peer->schedule, (event_fn_t) set_bgp_peer, 4,
                     peer, BGP_PEER_MAXPREF, num, 0);

    return (1);
}


static int
config_router_neighbor_alias (uii_connection_t * uii, char *name,
			      prefix_t * prefix_alias)
{
    bgp_peer_t *peer;

    if ((peer = name2peer (uii, name)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", name);
	Delete (name);
	return (-1);
    }
    Delete (name);

    schedule_event2 ("set_bgp_peer", peer->schedule, 
		     (event_fn_t) set_bgp_peer, 4, peer, 
		     (uii->negative)? BGP_PEER_ALIAS_DEL: BGP_PEER_ALIAS_ADD, 
		     prefix_alias, 0);
    return (1);
}


static int
config_router_neighbor_option (uii_connection_t * uii, char *name,
			       char *option)
{
    bgp_peer_t *peer;
    u_long opt = 0;
    enum BGP_PEER_ATTR attr = BGP_PEER_SETOPT;

    if ((peer = name2peer (uii, name)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", name);
	Delete (name);
	Delete (option);
	return (-1);
    }
    Delete (name);

    if (uii->negative)
	attr = BGP_PEER_RESETOPT;

    if (strcasecmp (option, "transparent-as") == 0)
        opt = BGP_TRANSPARENT_AS;
    else if (strcasecmp (option, "transparent-nexthop") == 0)
        opt = BGP_TRANSPARENT_NEXTHOP;
    else if (strcasecmp (option, "passive") == 0)
        opt = BGP_CONNECT_PASSIVE;
    else if (strcasecmp (option, "next-hop-self") == 0)
        opt = BGP_NEXTHOP_SELF;
    else if (strcasecmp (option, "next-hop-peer") == 0)
        opt = BGP_NEXTHOP_PEER;
    else if (strcasecmp (option, "route-reflector-client") == 0)
        opt = BGP_ROUTE_REFLECTOR_CLIENT;
    else if (strcasecmp (option, "remove-private-as") == 0)
        opt = BGP_REMOVE_PRIVATE_AS;
    else if (strcasecmp (option, "cisco") == 0)
        opt = BGP_PEER_CISCO;
    else {
	assert (0);
    }

    schedule_event2 ("set_bgp_peer", peer->schedule, 
		     (event_fn_t) set_bgp_peer, 4, peer, attr, opt, 0);
    Delete (option);
    return (1);
}


static int
config_router_neighbor_list_in_out (uii_connection_t * uii, char *name, 
				      char *op, int num, char *in_or_out)
{
    bgp_peer_t *peer;
    enum BGP_PEER_ATTR attr = 0;

    if ((peer = name2peer (uii, name)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", name);
	Delete (name);
	Delete (op);
	Delete (in_or_out);
	return (-1);
    }
    Delete (name);

    if (uii->negative)
	num = -1;

    if (strcasecmp (op, "distribute-list") == 0) {
	if (strcasecmp (in_or_out, "in") == 0)
            attr = BGP_PEER_DLIST_IN;
	else
            attr = BGP_PEER_DLIST_OUT;
    }
    else if (strcasecmp (op, "filter-list") == 0) {
	if (strcasecmp (in_or_out, "in") == 0)
            attr = BGP_PEER_FLIST_IN;
	else
            attr = BGP_PEER_FLIST_OUT;
    }
    else if (strcasecmp (op, "community-list") == 0) {
	if (strcasecmp (in_or_out, "in") == 0)
            attr = BGP_PEER_CLIST_IN;
	else
            attr = BGP_PEER_CLIST_OUT;
    }
    else {
	assert (0);
    }
    schedule_event2 ("set_bgp_peer", peer->schedule, 
		     (event_fn_t) set_bgp_peer, 5, peer, 
		      attr, CONFIG_MRTD->viewno, num, 0);
    Delete (op);
    Delete (in_or_out);
    return (1);
}


static int
config_router_neighbor_routemap_in_out (uii_connection_t * uii,
				       char * name, int num, char *in_or_out)
{
    bgp_peer_t *peer;

    if ((peer = name2peer (uii, name)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", name);
	Delete (name);
	Delete (in_or_out);
	return (-1);
    }
    Delete (name);

    if (uii->negative)
	num = -1;

    schedule_event2 ("set_bgp_peer", peer->schedule, 
		     (event_fn_t) set_bgp_peer, 
		     5, peer, 
    		     (strcasecmp (in_or_out, "in") == 0)?
			  BGP_PEER_RTMAP_IN: BGP_PEER_RTMAP_OUT,
		     CONFIG_MRTD->viewno, num, 0);
    Delete (in_or_out);
    return (1);
}


static int
config_router_neighbor_routerid (uii_connection_t * uii,
				 char * name, prefix_t *prefix)
{
    bgp_peer_t *peer;
    u_long id = 0;

    if ((peer = name2peer (uii, name)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", name);
	Delete (name);
	Delete (prefix);
	return (-1);
    }
    Delete (name);

    if (prefix) {
	id = (u_long) prefix_tolong (prefix);
	Deref_Prefix (prefix);
    }
    /* XXX check? */
    if (uii->negative) {
	id = 0;
    }

    if (peer->peer_id != id) {
        /* just lazy XXXX */
        peer->peer_id = id;
	restart_bgp_peer (peer);
    }
    return (1);
}


#ifdef HAVE_IPV6
static int
config_router_neighbor_bgp4plus (uii_connection_t * uii,
				   char * name, char * version)
{
    bgp_peer_t *peer;
    /* u_long opt = BGP_BGP4PLUS_00; */
    /* enum BGP_PEER_ATTR cmd = BGP_PEER_SETOPT; */

    if ((peer = name2peer (uii, name)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", name);
	Delete (name);
        Delete (version);
	return (-1);
    }
    Delete (name);

/*
    if (uii->negative)
	cmd = BGP_PEER_RESETOPT;
*/

    BIT_RESET (peer->options, BGP_BGP4PLUS_01_RCVD);
    if (strcasecmp (version, "1") == 0 || strcasecmp (version, "new") == 0 ||
        strcasecmp (version, "rfc") == 0) {
	if (uii->negative) {
	    BIT_RESET (peer->options, BGP_BGP4PLUS_00);
	    BIT_RESET (peer->options, BGP_BGP4PLUS_01);
	    BIT_SET (peer->options, BGP_BGP4PLUS_DEFAULT);
	}
	else {
	    BIT_RESET (peer->options, BGP_BGP4PLUS_DEFAULT);
	    BIT_RESET (peer->options, BGP_BGP4PLUS_00);
	    BIT_SET (peer->options, BGP_BGP4PLUS_01);
	}
    }
    else if (strcasecmp (version, "auto") == 0) {
	BIT_RESET (peer->options, BGP_BGP4PLUS_00);
	BIT_RESET (peer->options, BGP_BGP4PLUS_01);
	BIT_SET (peer->options, BGP_BGP4PLUS_DEFAULT);
    }
    else {
	if (uii->negative) {
	    BIT_RESET (peer->options, BGP_BGP4PLUS_00);
	    BIT_RESET (peer->options, BGP_BGP4PLUS_01);
	    BIT_SET (peer->options, BGP_BGP4PLUS_DEFAULT);
	}
	else {
	    BIT_RESET (peer->options, BGP_BGP4PLUS_DEFAULT);
	    BIT_RESET (peer->options, BGP_BGP4PLUS_01);
	    BIT_SET (peer->options, BGP_BGP4PLUS_00);
	}
    }

/*
    XXX just lazy
    schedule_event2 ("set_bgp_peer", peer->schedule, 
		     (event_fn_t) set_bgp_peer, 4, peer, cmd, opt, 0);
*/

    Delete (version);
    return (1);
}
#endif /* HAVE_IPV6 */


static int
config_router_neighbor_time (uii_connection_t * uii,
			     char * name, char *timer, int num)
{
    bgp_peer_t *peer;
    enum BGP_PEER_ATTR cmd = 0;
    int num2;

    if ((peer = name2peer (uii, name)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", name);
	Delete (name);
	return (-1);
    }
    Delete (name);

    /* since the argument num may not be available on the stack */
    num2 = (uii->negative)? -1: num;

    if (strcasecmp (timer, "holdtime") == 0) {
	cmd = BGP_PEER_HOLDTIME;
    }
    else if (strcasecmp (timer, "keepalive") == 0) {
	cmd = BGP_PEER_KEEPALIVE;
    }
    else if (strcasecmp (timer, "connectretry") == 0) {
	cmd = BGP_PEER_CONNECTRETRY;
    }
    else if (strcasecmp (timer, "starttime") == 0) {
	cmd = BGP_PEER_START;
    }
    else {
	assert (0);
    }

    schedule_event2 ("set_bgp_peer", peer->schedule, 
		     (event_fn_t) set_bgp_peer, 4, peer, cmd, num2, 0);

    Delete (timer);
    return (1);
}


static int
config_router_neighbor_timers (uii_connection_t * uii, char *name,
			       int keepalive, int holdtime)
{
    bgp_peer_t *peer;

    if ((peer = name2peer (uii, name)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", name);
	Delete (name);
	return (-1);
    }
    Delete (name);

    if (uii->negative) {
	keepalive = -1;
	holdtime = -1;
    }

    schedule_event2 ("set_bgp_peer", peer->schedule, 
	(event_fn_t) set_bgp_peer, 4, peer, BGP_PEER_KEEPALIVE, keepalive, 0);
    schedule_event2 ("set_bgp_peer", peer->schedule, 
	(event_fn_t) set_bgp_peer, 4, peer, BGP_PEER_HOLDTIME, holdtime, 0);

    return (1);
}


static int
trace_bgp_neighbor (uii_connection_t * uii, char *name)
{
    bgp_peer_t *peer;

    if ((peer = name2peer (uii, name)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", name);
	Delete (name);
	return (-1);
    }
    Delete (name);

    if (uii->negative)
        set_trace (peer->trace, TRACE_DEL_FLAGS, TR_ALL, NULL);
    else
        set_trace (peer->trace, TRACE_ADD_FLAGS, TR_ALL, NULL);
    return (1);
}


static int
config_router_aggregate (uii_connection_t * uii, prefix_t * prefix, 
			 char *as_set, char *summary_only)
{
    u_long option = 0;
    view_t *view;

    config_router_check_family (uii, prefix);
    view = BGP->views[CONFIG_MRTD->viewno];

    if (uii->negative) {
        view_open (view);
        view_del_aggregate (view, prefix);
        view_close (view);
	return (1);
    }

    if (as_set) {
	BIT_SET (option, BGP_AGGOPT_AS_SET);
	Delete (as_set);
    }
    if (summary_only) {
	BIT_SET (option, BGP_AGGOPT_SUMMARY_ONLY);
	Delete (summary_only);
    }

    view_open (view);
    view_add_aggregate (view, prefix, option);
    config_notice (TR_TRACE, uii,
		   "CONFIG aggregate-address %p%s%s\n", prefix,
		   BIT_TEST (option, BGP_AGGOPT_AS_SET) ? " as-set" : "",
	 BIT_TEST (option, BGP_AGGOPT_SUMMARY_ONLY) ? " summary-only" : "");
    view_close (view);
    Deref_Prefix (prefix);
    return (1);
}


static int
config_dump_bgp_common (uii_connection_t * uii, char *filename,
			char *unit, time_t * time)
{
    if (unit[0] && isdigit (unit[0])) {
	int i;
	u_int u;
	u = atoi (unit);
	for (i = 0; i < sizeof (unit) && unit[i] && isdigit (unit[i]); i++);
	if (i < sizeof (unit) && isalpha (unit[i])) {
	    if (strncasecmp (unit + i, "m", 1) == 0)
		u *= 60;
	    else if (strncasecmp (unit + i, "h", 1) == 0)
		u *= (60 * 60);
	}
	*time = u;
    }
    return (1);
}


static char *
time_to_unit (time_t t)
{
    char *buff;

    THREAD_SPECIFIC_STORAGE (buff);
    if ((t % 3600) == 0)
	sprintf (buff, "%ldh", t / 3600);
    else if ((t % 60) == 0)
	sprintf (buff, "%ldm", t / 60);
    else
	sprintf (buff, "%ld", t);
    return (buff);

}

static void
get_config_dump_bgp_updates (u_long type_mask)
{
    char *type = "updates";

    if (type_mask == ~0)
	type = "all";
    config_add_output ("dump bgp %s %s %s\n", type, BGP->dump_update_form,
		       time_to_unit (BGP->dump_update_interval));
}


static void
get_config_dump_bgp_view (int id)
{
    config_add_output ("dump bgp view %d %s %s\n", id,
			   BGP->dump_route_form[id],
			   time_to_unit (BGP->dump_route_interval[id]));
}


int
config_dump_bgp_updates2 (uii_connection_t * uii, char *type, char *filename, 
			  char *unit, int add_config)
{
    time_t t = 0;
    u_long type_mask = 0;

    BGP4_BIT_SET (type_mask, BGP_UPDATE);
    if (strcasecmp (type, "all") == 0)
	type_mask = ~0;

    if (uii->negative) {
	set_BGP (BGP_DUMP_UPDATE_FORM, NULL, 0);
	config_del_module (0, "dump bgp", get_config_dump_bgp_updates,
			   (void *) type_mask);
	Delete (type);
	return (1);
    }
    if (config_dump_bgp_common (uii, filename, unit, &t) >= 0 && filename[0]) {
	set_BGP (BGP_DUMP_UPDATE_FORM, filename, t, type_mask, 0, 0);
	config_notice (TR_TRACE, uii,
		       "CONFIG dump bgp %s %s %d\n", type, filename, t);
	if (add_config)
	    config_add_module (0, "dump bgp", get_config_dump_bgp_updates, 
			       (void *) type_mask);
	Delete (type);
	Delete (filename);
	Delete (unit);
	return (1);
    }
    Delete (type);
    Delete (filename);
    Delete (unit);
    return (-1);
}


int
config_dump_bgp_updates (uii_connection_t * uii, char *type, char *filename,
			 char *unit)
{
    return config_dump_bgp_updates2(uii, type, filename, unit, TRUE);
}


static int
config_dump_bgp_view (uii_connection_t * uii,
		      int id, char *filename, char *unit)
{
    time_t t = 0;

    if (config_dump_bgp_common (uii, filename, unit, &t) >= 0 && filename[0]) {
        set_BGP (BGP_DUMP_ROUTE_FORM, id, filename, t, DUMP_ASCII, 0);
	config_notice (TR_TRACE, uii,
		       "CONFIG dump bgp view %d %s %d\n", id, filename, t);
	config_add_module (0, "dump bgp", get_config_dump_bgp_view, (void *)id);
	Delete (filename);
	Delete (unit);
	return (1);
    }
    Delete (filename);
    Delete (unit);
    return (-1);
}


static void
get_config_dump_f_bgp (u_long type_mask)
{
    char *type = "updates";

    if (type_mask == ~0)
	type = "all";
    config_add_output ("dump %s bgp %s %s %s\n", (
			BGP->dump_update_family == AF_INET6)?"ipv6":"ip",
			type, BGP->dump_update_form,
		        time_to_unit (BGP->dump_update_interval));
}


static int
config_dump_f_bgp_updates (uii_connection_t * uii, int family,
		     char *type, char *filename, char *unit)
{
    time_t t = 0;
    u_long type_mask = 0;

    BGP4_BIT_SET (type_mask, BGP_UPDATE);
    if (strcasecmp (type, "all") == 0)
	type_mask = ~0;

    if (uii->negative) {
	set_BGP (BGP_DUMP_UPDATE_FORM, NULL, 0);
	config_del_module (0, "dump f bgp", 
			   get_config_dump_f_bgp, (void *) type_mask);
	Delete (type);
	return (1);
    }

    if (config_dump_bgp_common (uii, filename, unit, &t) >= 0 && filename[0]) {
	set_BGP (BGP_DUMP_UPDATE_FORM, filename, t, type_mask, family, 0);
	config_add_module (0, "dump f bgp", 
			   get_config_dump_f_bgp, (void *) type_mask);
	Delete (type);
	Delete (filename);
	Delete (unit);
	return (1);
    }
    Delete (type);
    Delete (filename);
    Delete (unit);
    return (-1);
}


static int
config_dump_ip_bgp_updates (uii_connection_t * uii,
		    char *type, char *filename, char *unit)
{
    return (config_dump_f_bgp_updates (uii, AF_INET, type, filename, unit));
}


#ifdef HAVE_IPV6
static int
config_dump_ipv6_bgp_updates (uii_connection_t * uii,
		      char *type, char *filename, char *unit)
{
    return (config_dump_f_bgp_updates (uii, AF_INET6, type, filename, unit));
}
#endif /* HAVE_IPV6 */


static void
get_config_dump_f_bgp_routes (int id)
{
    config_add_output ("dump %s bgp routes %s %s\n", (id == 1)?"ipv6":"ip",
			   BGP->dump_route_form[id],
			   time_to_unit (BGP->dump_route_interval[id]));
}


static int
config_dump_f_bgp_routes (uii_connection_t * uii, int family,
	 	   	  char *filename, char *unit)
{
    int id = 0;
    time_t t = 0;

#ifdef HAVE_IPV6
    if (family == AF_INET6)
	id = 1;
#endif /* HAVE_IPV6 */

    if (uii->negative) {
        set_BGP (BGP_DUMP_ROUTE_FORM, id, NULL, 0);
	config_del_module (0, "dump bgp routes", get_config_dump_f_bgp_routes, 
			   (void *)id);
	return (1);
    }

    if (config_dump_bgp_common (uii, filename, unit, &t) >= 0 && filename[0]) {
        set_BGP (BGP_DUMP_ROUTE_FORM, id, filename, t, DUMP_ASCII, 0);
	config_notice (TR_TRACE, uii,
		       "CONFIG dump bgp view %d %s %d\n", id, filename, t);
	config_add_module (0, "dump bgp routes", get_config_dump_f_bgp_routes, 
			   (void *)id);
	Delete (filename);
	Delete (unit);
	return (1);
    }
    Delete (filename);
    Delete (unit);
    return (-1);
}


static int
config_dump_ip_bgp_routes (uii_connection_t * uii,
	 	   	   char *filename, char *unit)
{
    return (config_dump_f_bgp_routes (uii, AF_INET, filename, unit));
}


static int
dump_f_bgp_routes (uii_connection_t * uii, int family, char *filename)
{
    int viewno = 0;
    char *cp;
    char *name;

    if (family == AF_INET6)
	viewno = 1;

    if ((cp = strrchr (filename, '/')))
      cp = cp + 1;
    else
      cp = filename;

    if (UII->redirect == NULL) {
	uii_send_data (uii,
                   "No redirection allowed! Use redirect in configuration\n");
	Delete (filename);
	return (0);
    }

    name = NewArray (char, strlen (UII->redirect) + strlen (cp) + 1 + 1);
    sprintf (name, "%s/%s", UII->redirect, cp);
    if (dump_view_bgp_routes (viewno, name, DUMP_BINARY) >= 0) {
	uii_send_data (uii, "[%s]\n", name);
    }
    Delete (name);
    Delete(filename);
    return (1);
}


static int
dump_ip_bgp_routes (uii_connection_t * uii, char *filename)
{
    return (dump_f_bgp_routes (uii, AF_INET, filename));
}


#ifdef HAVE_IPV6
static int
dump_ipv6_bgp_routes (uii_connection_t * uii, char *filename)
{
    return (dump_f_bgp_routes (uii, AF_INET6, filename));
}
#endif /* HAVE_IPV6 */


#ifdef HAVE_IPV6
static int
config_dump_ipv6_bgp_routes (uii_connection_t * uii,
	 	   	   char *filename, char *unit)
{
    return (config_dump_f_bgp_routes (uii, AF_INET6, filename, unit));
}
#endif /* HAVE_IPV6 */


static void
get_config_dump_bgp_routes ()
{
  if (BGP->dump_route_form[0]) {
      if (BGP->dump_route_type[0] == DUMP_ASCII) 
        config_add_output ("dump bgp routes %s %s\n", BGP->dump_route_form[0],
		           time_to_unit (BGP->dump_route_interval[0]));
      else
        config_add_output ("dump-binary bgp routes %s %s\n", 
		           BGP->dump_route_form[0],
		           time_to_unit (BGP->dump_route_interval[0]));
  }
}


static int
_config_dump_bgp_routes (uii_connection_t * uii, char *filename, 
			 char *unit, int dump_type)
{
    time_t t = 0;

    if (uii->negative) {
	set_BGP (BGP_DUMP_ROUTE_FORM, 0, NULL, 0);
#ifdef HAVE_IPV6
	set_BGP (BGP_DUMP_ROUTE_FORM, 1, NULL, 0);
#endif /* HAVE_IPV6 */
	config_del_module (0, "bgp dump", get_config_dump_bgp_routes, NULL);
	return (1);
    }

    if (config_dump_bgp_common (uii, filename, unit, &t) >= 0 && filename[0]) {
	set_BGP (BGP_DUMP_ROUTE_FORM, 0, filename, t, dump_type, 0);
#ifdef HAVE_IPV6
	set_BGP (BGP_DUMP_ROUTE_FORM, 1, filename, t, dump_type, 0);
#endif /* HAVE_IPV6 */
	config_notice (TR_TRACE, uii,
		       "CONFIG dump bgp routes %s %d\n", filename, t);
	config_add_module (0, "bgp dump", get_config_dump_bgp_routes, NULL);
	Delete (filename);
	Delete (unit);
	return (1);
    }
    Delete (filename);
    Delete (unit);
    return (-1);
}


static int
config_dump_bgp_routes (uii_connection_t * uii, char *filename, char *unit) {
  
  if (uii->negative)
      return (_config_dump_bgp_routes (uii, NULL, NULL, DUMP_ASCII));
  else
      return (_config_dump_bgp_routes (uii, filename, unit, DUMP_ASCII));
}


static int
config_dump_bgp_routes_binary (uii_connection_t * uii, char *filename, 
			       char *unit) {
  if (uii->negative)
    return (_config_dump_bgp_routes (uii, NULL, NULL, DUMP_BINARY));
  else
    return (_config_dump_bgp_routes (uii, filename, unit, DUMP_BINARY));
}


static int
kill_peer (uii_connection_t * uii, char *whom)
{
    bgp_peer_t *peer;

    if (strcmp (whom, "*") == 0) {
	bgp_kill_all (NULL);
	Delete (whom);
	return (1);
    }
    if ((peer = name2peer (uii, whom)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", whom);
	Delete (whom);
	return (-1);
    }
    Delete (whom);
    bgp_stop_peer (peer);
    return (1);
}


static int
start_peer (uii_connection_t * uii, char *whom)
{
    bgp_peer_t *peer;

    if (strcmp (whom, "*") == 0) {
	bgp_start_all (NULL);
	Delete (whom);
	return (1);
    }
    if ((peer = name2peer (uii, whom)) == NULL) {
	config_notice (TR_ERROR, uii, "No peer %s\n", whom);
	Delete (whom);
	return (-1);
    }
    Delete (whom);
    bgp_start_peer (peer);
    return (1);
}


static int
config_router_bgp_network_prefix (uii_connection_t * uii, prefix_t *prefix)
{
    prefix_t *network;
    view_t *view;

    config_router_check_family (uii, prefix);
    view = BGP->views[CONFIG_MRTD->viewno];

    view_open (view);
    LL_Iterate (view->ll_networks, network) {
	if (prefix_compare (prefix, network))
	    break;
    }

    if (uii->negative) {
	if (network == NULL) {
            Deref_Prefix (prefix);
    	    view_close (view);
	    return (0);
	}
	if (MRT->rib_redistribute_network)
            MRT->rib_redistribute_network (CONFIG_MRTD->protocol, 
					   CONFIG_MRTD->viewno, prefix, 
					   0, view->safi);
        LL_Remove (view->ll_networks, network);
        Deref_Prefix (prefix);
    	view_close (view);
        return (1);
    }

    if (network != NULL) {
	Deref_Prefix (prefix);
    	view_close (view);
	return (0);
    }

    if (MRT->rib_redistribute_network)
        MRT->rib_redistribute_network (CONFIG_MRTD->protocol, 
				       CONFIG_MRTD->viewno, prefix, 1, 
				       view->safi);
    LL_Add (view->ll_networks, Ref_Prefix (prefix));
    Deref_Prefix (prefix);
    view_close (view);
    return (1);
}


/*
 * Redistribute a given protocol into another protocol 
 */
static int
config_router_bgp_redistribute (uii_connection_t * uii, char *proto_string)
{
    int proto;
    view_t *view = BGP->views[CONFIG_MRTD->viewno];

    if ((proto = string2proto (proto_string)) < 0) {
	Delete (proto_string);
	return (-1);
    }

    if (CONFIG_MRTD->protocol == proto) {
	config_notice (TR_ERROR, uii,
		 "%s redistribute %s -- the same protocols!\n",
		  proto2string (CONFIG_MRTD->protocol), proto2string (proto));
	Delete (proto_string);
	return (-1);
    }

    assert (view);
    view_open (view);
    if (uii->negative) {
	if (!BGP4_BIT_TEST (view->redistribute_mask, proto)) {
	    Delete (proto_string);
            view_close (view);
	    return (0);
	}
        BGP4_BIT_RESET (view->redistribute_mask, proto);
        if (MRT->rib_redistribute_request)
            MRT->rib_redistribute_request (CONFIG_MRTD->protocol, 
					   CONFIG_MRTD->viewno, proto, 0,
				           view->afi, view->safi);
        Delete (proto_string);
        view_close (view);
        return (1);
    }

    if (BGP4_BIT_TEST (view->redistribute_mask, proto)) {
	Delete (proto_string);
        view_close (view);
	return (0);
    }
    BGP4_BIT_SET (view->redistribute_mask, proto);
    if (MRT->rib_redistribute_request)
        MRT->rib_redistribute_request (CONFIG_MRTD->protocol, 
				       CONFIG_MRTD->viewno, proto, 1, 
				       view->afi, view->safi);
    Delete (proto_string);
    view_close (view);
    return (1);
}


static int 
show_bgp (uii_connection_t * uii)
{
    return (show_f_bgp_summary (uii, NULL, 0, FALSE));
}


static int 
show_bgp_summary (uii_connection_t * uii)
{
    return (show_f_bgp_summary (uii, NULL, 0, TRUE));
}

static int 
show_ip_bgp_summary (uii_connection_t * uii)
{
    return (show_f_bgp_summary (uii, NULL, AF_INET, TRUE));
}


static int 
show_ip_bgp_neighbors (uii_connection_t * uii)
{
    return (show_f_bgp_summary (uii, NULL, AF_INET, FALSE));
}


#ifdef HAVE_IPV6
static int 
show_ipv6_bgp_summary (uii_connection_t * uii)
{
    return (show_f_bgp_summary (uii, NULL, AF_INET6, TRUE));
}


static int 
show_ipv6_bgp_neighbors (uii_connection_t * uii)
{
    return (show_f_bgp_summary (uii, NULL, AF_INET6, FALSE));
}
#endif /* HAVE_IPV6 */


static int
show_bgp_neighbors_errors (uii_connection_t * uii, char *peer_or_star)
{
    return (show_f_bgp_neighbors_errors (uii, 0, peer_or_star));
}


static int
show_ip_bgp_neighbors_errors (uii_connection_t * uii, char *peer_or_star)
{
    return (show_f_bgp_neighbors_errors (uii, AF_INET, peer_or_star));
}


#ifdef HAVE_IPV6
static int
show_ipv6_bgp_neighbors_errors (uii_connection_t * uii, char *peer_or_star)
{
    return (show_f_bgp_neighbors_errors (uii, AF_INET6, peer_or_star));
}
#endif /* HAVE_IPV6 */


static int
show_bgp_neighbors_routes (uii_connection_t * uii, char *peer_or_star, 
			   char *in_out)
{
    return (show_f_bgp_neighbors_routes (uii, 0, -1, peer_or_star, in_out));
}


static int
show_ip_bgp_neighbors_routes (uii_connection_t * uii, char *peer_or_star,
			      char *in_out)
{
    return (show_f_bgp_neighbors_routes (uii, AF_INET, -1, peer_or_star, 
	    				 in_out));
}


#ifdef HAVE_IPV6
static int
show_ipv6_bgp_neighbors_routes (uii_connection_t * uii, char *peer_or_star,
				char *in_out)
{
    return (show_f_bgp_neighbors_routes (uii, AF_INET6, -1, peer_or_star,
					 in_out));
}
#endif /* HAVE_IPV6 */


static int 
show_f_bgp_rt_regexp (uii_connection_t * uii, int family, char *exp, 
		      char *filtered)
{
    return (show_f_bgp_rt_view_regexp (uii, family, -1, exp, filtered));
}


static int 
show_bgp_rt_regexp (uii_connection_t * uii, char *expr, char *filtered)
{
    return (show_f_bgp_rt_regexp (uii, 0, expr, filtered));
}


static int 
show_ip_bgp (uii_connection_t * uii, char *filtered)
{
    return (show_f_bgp_rt_regexp (uii, AF_INET, NULL, filtered));
}


static int 
show_ip_bgp_regexp (uii_connection_t * uii, char *exp, char *filtered)
{
    return (show_f_bgp_rt_regexp (uii, AF_INET, exp, filtered));
}


#ifdef HAVE_IPV6
static int 
show_ipv6_bgp (uii_connection_t * uii, char *filtered)
{
    return (show_f_bgp_rt_regexp (uii, AF_INET6, NULL, filtered));
}


static int 
show_ipv6_bgp_regexp (uii_connection_t * uii, char *exp, char *filtered)
{
    return (show_f_bgp_rt_regexp (uii, AF_INET6, exp, filtered));
}
#endif /* HAVE_IPV6 */


static int 
show_bgp_rt_view_regexp (uii_connection_t * uii, int viewno, char *expr,
			 char *filtered)
{
    return (show_f_bgp_rt_view_regexp (uii, 0, viewno, expr, filtered));
}


static int 
show_bgp_rt_view (uii_connection_t * uii, int viewno, char *filtered)
{
    return (show_f_bgp_rt_view_regexp (uii, 0, viewno, NULL, filtered));
}


/* show_bgp_routing table 
 * dump BGP routes to socket. usually called by UII
 */ 
static int
show_bgp_rt (uii_connection_t * uii, char *filtered)
{   
    return (show_f_bgp_rt_regexp (uii, 0, NULL, filtered));
}


static int
show_bgp_rt_prefix (uii_connection_t * uii, prefix_t *prefix, char *options,
		    char *filtered)
{
    return (show_bgp_rt_view_prefix (uii, -1, prefix, options,
				     filtered));
}


static int
show_bgp_rt_as (uii_connection_t * uii, int as, char *filtered)
{
    int viewno;

    for (viewno = 0; viewno < MAX_BGP_VIEWS; viewno++) {
        if (BGP->views[viewno] == NULL)
            continue;
        if (BGP->views[viewno]->local_bgp &&
                BGP->views[viewno]->local_bgp->this_as == as)
            show_bgp_rt_view (uii, viewno, filtered);
    }
    return (1);
}


static int 
trace_ip_bgp (uii_connection_t * uii)
{
    return (trace_f_bgp (uii, AF_INET));
}


#ifdef HAVE_IPV6
static int 
trace_ipv6_bgp (uii_connection_t * uii)
{
    return (trace_f_bgp (uii, AF_INET6));
}
#endif /* HAVE_IPV6 */


static int
load_bgp_routes (uii_connection_t * uii, char *filename)
{
    int count;
    count = load_f_bgp_routes (filename, 0);
    if (count < 0)
	user_notice (TR_ERROR, UII->trace, uii, "load from %s failed\n",
		     filename);
    else
	uii_send_data (uii, "load %d routes from %s\n", count, filename);
    Delete (filename);
    return (count);
}

static int
load_ip_bgp_routes (uii_connection_t * uii, char *filename)
{
    int count;
    count = load_f_bgp_routes (filename, AF_INET);
    if (count < 0)
	user_notice (TR_ERROR, UII->trace, uii, "load from %s failed\n",
		     filename);
    else
	uii_send_data (uii, "load %d routes from %s\n", count, filename);
    Delete (filename);
    return (count);
}


#ifdef HAVE_IPV6
static int
load_ipv6_bgp_routes (uii_connection_t * uii, char *filename)
{
    int count;
    count = load_f_bgp_routes (filename, AF_INET6);
    if (count < 0)
	user_notice (TR_ERROR, UII->trace, uii, "load from %s failed\n",
		     filename);
    else
	uii_send_data (uii, "load %d routes from %s\n", count, filename);
    Delete (filename);
    return (count);
}
#endif /* HAVE_IPV6 */


/*
 * router id %a 
 */
int
config_bgp_router_id (uii_connection_t * uii, prefix_t *prefix)
{
    if (uii->negative) {
        BGP->views[CONFIG_MRTD->viewno]->local_bgp->this_id = 0;
	return (1);
    }
    BGP->views[CONFIG_MRTD->viewno]->local_bgp->this_id = 
	(u_long) prefix_tolong (prefix);
    trace (TR_TRACE, MRT->trace, "router-id %s\n", prefix_toa (prefix));
    Deref_Prefix (prefix);
    return (1);
}


static int
config_bgp_cluster_id (uii_connection_t * uii, prefix_t *prefix)
{
    if (uii->negative) {
        BGP->views[CONFIG_MRTD->viewno]->local_bgp->cluster_id = 0;
	return (1);
    }
    BGP->views[CONFIG_MRTD->viewno]->local_bgp->cluster_id = 
        (u_long) prefix_tolong (prefix);
    trace (TR_TRACE, MRT->trace, "cluster-id %s\n", prefix_toa (prefix));
    Deref_Prefix (prefix);
    return (1);
}

/*
   This business of include_dump_commands is a kludge for Data Distiller.
   --mukesh
*/

void
config_bgp_init (void)
{
	config_bgp_init2 (TRUE);
}

void
config_bgp_init2 (int include_dump_commands)
{
    set_uii (UII, UII_PROMPT, UII_CONFIG_ROUTER_BGP, "Router BGP> ", 0);

    uii_add_command2 (UII_NORMAL, 0, "show ip bgp summary", 
		      show_ip_bgp_summary, 
		      "Show BGP peers and their status");
    uii_add_command2 (UII_NORMAL, 0, "show ip bgp neighbors", 
		      show_ip_bgp_neighbors,
		      "Show BGP peers and their status");
    uii_add_command2 (UII_NORMAL, 0, "show ip bgp [filtered|null]", 
		      show_ip_bgp, "Show BGP routing table");
    uii_add_command2 (UII_NORMAL, 0, "show ip bgp routes [filtered|null]", 
		      show_ip_bgp, "Show BGP routing table");
    uii_add_command2 (UII_NORMAL, 0, "show ip bgp regexp %S [filtered|null]",
		      show_ip_bgp_regexp,
		      "Show BGP routes matching the regular expression");
    uii_add_command2 (UII_NORMAL, 0, "show ip bgp %m %S [filtered|null]",
		      show_bgp_rt_prefix,
		      "Show BGP routes matching the expression");
    uii_add_command2 (UII_NORMAL, 0, 
		      "show ip bgp neighbors (%M|%n|*) errors",
		      show_ip_bgp_neighbors_errors,
		      "Show BGP recent errors [with the peer]");
    uii_add_command2 (UII_NORMAL, 0, 
		      "show ip bgp neighbors (%M|%n|*) routes [in|null]",
		      show_ip_bgp_neighbors_routes,
		      "Show BGP routes sent/received to/from the peer");
    uii_add_command2 (UII_ENABLE, 0, 
		      "clear ip bgp (%M|%n|*)", kill_peer,
		      "Close BGP peering session");
    uii_add_command2 (UII_CONFIG, 0,
		      "ip as-path access-list %d (permit|deny) %S",
		      config_ip_as_filter, "Defines AS path filter");
    uii_add_command2 (UII_CONFIG, 0,
		      "no ip as-path access-list %d (permit|deny) %S",
		      config_ip_as_filter, "Deletes AS path filter");
    uii_add_command2 (UII_CONFIG, 0,
                      "ip community-list %d (permit|deny) %s",
                      config_community_list, "Add community list");
    uii_add_command2 (UII_CONFIG, 0,
                      "no ip community-list %d (permit|deny) %s",
                      config_community_list, "Delete community list");

    uii_add_command2 (UII_ENABLE, 0, 
		      "trace ip bgp neighbor (%M|%n)", 
		      trace_bgp_neighbor,
		      "Enable trace bgp neighbor");
    uii_add_command2 (UII_ENABLE, 0, 
		      "no trace ip bgp neighbor (%M|%n)", 
		      trace_bgp_neighbor, "Disable trace bgp neighbor");
    uii_add_command2 (UII_ENABLE, 0, "trace ip bgp", 
		      trace_ip_bgp, "BGP information");
    uii_add_command2 (UII_ENABLE, 0, "no trace ip bgp", 
		      trace_ip_bgp, "BGP information");
    uii_add_command2 (UII_ENABLE, 0, "dump ip bgp routes %s",
		      dump_ip_bgp_routes, "Dumps BGP routing table");
    uii_add_command2 (UII_ENABLE, 0, "load ip bgp routes %s",
		      load_ip_bgp_routes, "Loads BGP routing table");
    uii_add_command2 (UII_ENABLE, 0, "load bgp routes %s",
		      load_bgp_routes, "Loads BGP routing table");

    uii_add_command2 (UII_CONFIG, 0, "dump ip bgp routes %s %s",
		      config_dump_ip_bgp_routes, "Dumps BGP routing table");
    uii_add_command2 (UII_CONFIG, 0, "no dump ip bgp routes",
		      config_dump_ip_bgp_routes, 
		      "Stops dumping BGP routing table");
    uii_add_command2 (UII_CONFIG, 0, 
		      "dump ip bgp (updates|all) %s %s",
		      config_dump_ip_bgp_updates, 
		      "Dumps BGP updates and state changes");
    uii_add_command2 (UII_CONFIG, 0, 
		      "no dump ip bgp (updates|all) %s %s",
		      config_dump_ip_bgp_updates, 
		      "Stops dumping BGP updates and state changes");

#ifdef HAVE_IPV6
    uii_add_command2 (UII_NORMAL, 0, "show ipv6 bgp summary", 
		      show_ipv6_bgp_summary, 
		      "Show IPv6 BGP peers and their status");
    uii_add_command2 (UII_NORMAL, 0, "show ipv6 bgp neighbors", 
		      show_ipv6_bgp_neighbors,
		      "Show IPv6 BGP peers and their status");
    uii_add_command2 (UII_NORMAL, 0, "show ipv6 bgp [filtered|null]", 
		      show_ipv6_bgp, "Show IPv6 BGP routing table");
    uii_add_command2 (UII_NORMAL, 0, "show ipv6 bgp routes [filtered|null]", 
		      show_ipv6_bgp, "Show BGP routing table");
    uii_add_command2 (UII_NORMAL, 0, "show ipv6 bgp regexp %S [filtered|null]",
		      show_ipv6_bgp_regexp,
		      "Show IPv6 BGP routes matching the regular expression");
    uii_add_command2 (UII_NORMAL, 0, "show ipv6 bgp %P %S [filtered|null]",
		      show_bgp_rt_prefix,
		      "Show IPv6 BGP routes matching the expression");
    uii_add_command2 (UII_NORMAL, 0, 
		      "show ipv6 bgp neighbors (%A|%n|*) errors",
		      show_ipv6_bgp_neighbors_errors,
		      "Show IPv6 BGP recent errors [with the peer]");
    uii_add_command2 (UII_NORMAL, 0, 
		      "show ipv6 bgp neighbors (%A|%n|*) routes [in|null]",
		      show_ipv6_bgp_neighbors_routes,
		      "Show BGP routes sent/received to/from the peer");
    uii_add_command2 (UII_ENABLE, 0, 
		      "clear ipv6 bgp (%A|%n|*)", kill_peer,
		      "Close IPv6 BGP peering session");
    uii_add_command2 (UII_CONFIG, 0,
		      "ipv6 as-path access-list %d (permit|deny) %S",
		      config_ip_as_filter, "Defines AS path filter");
    uii_add_command2 (UII_CONFIG, 0,
		      "no ipv6 as-path access-list %d (permit|deny) %S",
		      config_ip_as_filter, "Deletes AS path filter");

    uii_add_command2 (UII_ENABLE, 0, 
		      "trace ipv6 bgp neighbor (%A|%n)", 
		      trace_bgp_neighbor,
		      "Enable trace IPv6 BGP neighbor");
    uii_add_command2 (UII_ENABLE, 0, 
		      "no trace ipv6 bgp neighbor (%A|%n)", 
		      trace_bgp_neighbor, 
		      "Disable trace IPv6 BGP neighbor");

    uii_add_command2 (UII_ENABLE, 0, "trace ipv6 bgp", 
		      trace_ipv6_bgp, "Traces IPv6 BGP information");
    uii_add_command2 (UII_ENABLE, 0, "no trace ipv6 bgp", 
		      trace_ipv6_bgp, "Untraces IPv6 BGP information");
    uii_add_command2 (UII_ENABLE, 0, "dump ipv6 bgp routes %s",
		      dump_ipv6_bgp_routes, 
		      "Dumps IPv6 BGP routing table");
    uii_add_command2 (UII_ENABLE, 0, "load ipv6 bgp routes %s",
		      load_ipv6_bgp_routes, 
		      "Loads IPv6 BGP routing table");

    uii_add_command2 (UII_CONFIG, 0, "dump ipv6 bgp routes %s %s",
		      config_dump_ipv6_bgp_routes, 
		      "Dumps IPv6 BGP routing table");
    uii_add_command2 (UII_CONFIG, 0, "no dump ipv6 bgp routes",
		      config_dump_ipv6_bgp_routes, 
		      "Stops dumping IPv6 BGP routing table");
    uii_add_command2 (UII_CONFIG, 0, 
		      "dump ipv6 bgp (updates|all) %s %s",
		      config_dump_ipv6_bgp_updates,
		      "Dumps IPv6 BGP updates and state changes");
    uii_add_command2 (UII_CONFIG, 0, 
		      "no dump ipv6 bgp (updates|all) %s %s",
		      config_dump_ipv6_bgp_updates, 
		      "Stops dumping IPv6 BGP updates and state changes");
#endif /* HAVE_IPV6 */

    uii_add_command2 (UII_NORMAL, 0, "show bgp", show_bgp,
		      "Show BGP peers and their status");
    uii_add_command2 (UII_NORMAL, 0, "show bgp summary", show_bgp_summary,
		      "Show BGP peers and their status");
    uii_add_command2 (UII_NORMAL, 0, "show bgp local", show_bgp_local,
		      "Show locally configured ASes");
    uii_add_command2 (UII_NORMAL, 0, "show bgp neighbors", show_bgp,
		      "Show BGP peers and their status");
    uii_add_command2 (UII_NORMAL, COMMAND_NODISPLAY, 
		      "show view %d [filtered|null]", show_bgp_rt_view,
		      "Show the BGP routing table for the view");
    uii_add_command2 (UII_NORMAL, COMMAND_NODISPLAY, 
		      "show bgp view %d [filtered|null]", 
		      show_bgp_rt_view,
		      "Show the BGP routing table for the view");
    uii_add_command2 (UII_NORMAL, COMMAND_NODISPLAY, "show bgp views", 
		      show_bgp_views, "Show the BGP routing views info");
    uii_add_command2 (UII_NORMAL, 0, "show bgp routes [filtered|null]",
		      show_bgp_rt, "Show BGP routing table");

    uii_add_command2 (UII_NORMAL, 0, "show bgp as %d routes [filtered|null]",
		      show_bgp_rt_as, "Show BGP routing table");
    uii_add_command2 (UII_NORMAL, 0, "show bgp view %d routes [filtered|null]",
		      show_bgp_rt_view, "Show BGP routing table");
    uii_add_command2 (UII_NORMAL, 0, 
		      "show bgp view %d regexp %S [filtered|null]",
		      show_bgp_rt_view_regexp,
		      "Show BGP routes matching the regular expression");
	/* XXX I know this doesn't work */
    uii_add_command2 (UII_NORMAL, 0, "show bgp view %d %m %S [filtered|null]",
		      show_bgp_rt_view_prefix,
		      "Show BGP routes matching the expression");
    uii_add_command2 (UII_NORMAL, 0, "show bgp regexp %S [filtered|null]",
		      show_bgp_rt_regexp,
		      "Show BGP routes matching the regular expression");
    uii_add_command2 (UII_NORMAL, 0, "show bgp %m %S [filtered|null]",
		      show_bgp_rt_prefix,
		      "Show BGP routes matching the expression");
    uii_add_command2 (UII_NORMAL, 0, 
		      "show bgp neighbors (%M|%n|*) errors",
		      show_bgp_neighbors_errors,
		      "Show BGP recent errors [with the peer]");
    uii_add_command2 (UII_NORMAL, 0, 
		      "show bgp neighbors (%M|%n|*) routes [in|null]",
		      show_bgp_neighbors_routes,
		      "Show BGP routes sent/received to/from the peer");

    uii_add_command2 (UII_ENABLE, 0, 
		      "clear bgp (%M|%n|*)", kill_peer,
		      "Close BGP peering session");
    uii_add_command2 (UII_ENABLE, 0, 
		      "start bgp (%M|%n|*)", start_peer,
		      "Kick BGP peering session");

    uii_add_command2 (UII_CONFIG, 0, 
		      "router bgp %d [ipv6|null] [multicast|null]",
		      config_router_bgp,
		      "Enables BGP routing protocol with AS number");
    uii_add_command2 (UII_CONFIG, 0, 
		      "router bgp %d id %a [ipv6|null] [multicast|null]",
		      config_router_bgp_id,
		      "Enables BGP routing protocol with AS and router-id");
    uii_add_command2 (UII_CONFIG, 0, 
		      "router bgp %d view %d [ipv6|null] [multicast|null]",
		      config_router_bgp_view,
		      "Enables BGP routing protocol with AS number and view");
    uii_add_command2 (UII_CONFIG, 0, 
	"router bgp %d id %a view %d [ipv6|null] [multicast|null]",
		      config_router_bgp_id_view,
		  "Enables BGP routing protocol with AS, router-id, and view");

    uii_add_command2 (UII_CONFIG, 0, 
		      "no router bgp %d [ipv6|null] [multicast|null]",
		      config_router_bgp,
		      "Disables BGP routing protocol with AS number");
    uii_add_command2 (UII_CONFIG, 0, 
		  "no router bgp %d id %a [ipv6|null] [multicast|null]",
		      config_router_bgp_id,
		      "Disables BGP routing protocol with AS and router-id");
    uii_add_command2 (UII_CONFIG, 0, 
		      "no router bgp %d view %d [ipv6|null] [multicast|null]",
		      config_router_bgp_view,
		      "Disables BGP routing protocol with AS number and view");
    uii_add_command2 (UII_CONFIG, 0, 
	"no router bgp %d id %a view %d [ipv6|null] [multicast|null]",
		      config_router_bgp_id_view,
		"Disables BGP routing protocol with AS, router-id, and view");

    uii_add_command2 (UII_CONFIG, 0, "bgp router-id %a",
		      config_bgp_router_id, "Set default BGP router-id");
    uii_add_command2 (UII_CONFIG, 0, "no bgp router-id",
		      config_bgp_router_id, "Unset default BGP router-id");
    uii_add_command2 (UII_CONFIG, 0, "bgp cluster-id %a",
		      config_bgp_cluster_id, "Set default BGP cluster-id");
    uii_add_command2 (UII_CONFIG, 0, "no bgp cluster-id",
		      config_bgp_cluster_id, "Unset default BGP cluster-id");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, COMMAND_NODISPLAY, "router_id %a",
                      config_bgp_router_id, "Set router id"); 

    uii_add_command2 (UII_CONFIG, 0,
                      "as-path access-list %d (permit|deny) %S",
                      config_ip_as_filter, "Defines AS path filter");
    uii_add_command2 (UII_CONFIG, 0,
                      "no as-path access-list %d (permit|deny) %S",
                      config_ip_as_filter, "Undefines AS path filter");
    uii_add_command2 (UII_CONFIG, 0,
                      "community-list %d (permit|deny) %s",
                      config_community_list, "Add community list");
    uii_add_command2 (UII_CONFIG, 0,
                      "no community-list %d (permit|deny) %s",
                      config_community_list, "Delete community list");

    uii_add_command2 (UII_ENABLE, 0, 
		      "trace bgp neighbor (%M|%n)", trace_bgp_neighbor,
		      "Enable trace bgp neighbor");
    uii_add_command2 (UII_ENABLE, 0, 
		      "no trace bgp neighbor (%M|%n)", 
		      trace_bgp_neighbor, "Disable trace bgp neighbor");
    uii_add_command2 (UII_ENABLE, COMMAND_NODISPLAY, 
		      "trace bgp view (*|inet|inet6|%d)", 
		      trace_bgp_view, "Enable trace bgp view");
    uii_add_command2 (UII_ENABLE, COMMAND_NODISPLAY, 
		      "no trace bgp view (*|inet|inet6|%d)", 
		      no_trace_bgp_view, "Disable trace bgp view");

    uii_add_command2 (UII_ENABLE, 0, "trace bgp", trace_bgp,
		      "Enable trace BGP");
    uii_add_command2 (UII_ENABLE, 0, "no trace bgp", trace_bgp,
		      "Disable trace BGP");

	if (include_dump_commands) {
    	uii_add_command2 (UII_CONFIG, 0, 
		"dump bgp view %dview_number %sFilename %sInterval(e.g._1m)",
		 config_dump_bgp_view, "Dumps BGP routing table for the view");
    	uii_add_command2 (UII_CONFIG, 0, "dump bgp routes %s %s",
		    	  config_dump_bgp_routes, "Dumps BGP routing table");
    	uii_add_command2 (UII_CONFIG, 0, "no dump bgp routes",
		    	  config_dump_bgp_routes, 
		    	  "Stops dumping BGP routing table");
    	uii_add_command2 (UII_CONFIG, 0, 
		    	  "dump-binary bgp routes %sFilename %sInterval",
		    	  config_dump_bgp_routes_binary, 
		    	  "Dumps Binary BGP routing table");
    	uii_add_command2 (UII_CONFIG, 0, 
		    	  "no dump-binary bgp routes",
		    	  config_dump_bgp_routes_binary, 
		    	  "Stops dumping Binary BGP routing table");
    	uii_add_command2 (UII_CONFIG, 0, 
	    	  "dump bgp (updates|all) %sFilename %sInterval(e.g._1m)",
		    	  config_dump_bgp_updates, 
		    	  "Dumps BGP updates and state changes");
    	uii_add_command2 (UII_CONFIG, 0, 
		    	  "no dump bgp (updates|all)",
		    	  config_dump_bgp_updates, 
		    	  "Stops dumping BGP updates and state changes");
	}
	
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0, "add interface %m",
		      config_router_bgp_add_interface,
		      "Adds a useable interface to the active bgp config");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0, "delete interface %m",
		      config_router_bgp_delete_interface,
		      "Removes an interface to the active bgp config");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0, "bind interface only",
		      config_router_bgp_bind_interface_only,
		      "Allows connectons only over bound interfaces");

    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0, "network %m",
		      config_router_bgp_network_prefix, 
		      "Originates routes in BGP");

    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
	"redistribute (static|ospf|rip|ripng|direct|connected|kernel)",
		      config_router_bgp_redistribute,
		      "Redistribute route from the protocol");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
	"no redistribute (static|ospf|rip|ripng|direct|connected|kernel)",
		      config_router_bgp_redistribute,
		      "Not redistribute route from the protocol");

    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "neighbor %M remote-as %d",
		   config_router_neighbor_remoteas, "Adds an BGP neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "no neighbor %M remote-as %d",
	     config_router_neighbor_remoteas, "Deletes an BGP neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "neighbor (%M|%n) description %s",
		       config_router_neighbor_description, 
		      "Describes BGP neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "no neighbor (%M|%n) description",
	     	      config_router_neighbor_description, 
		      "Undescribe BGP neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "neighbor (%M|%n) update-source (%M|%n)",
		   config_router_neighbor_update_source, 
		   "Specify the source address");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "no neighbor (%M|%n) update-source (%M|%n)",
		   config_router_neighbor_update_source, 
		   "Unspecify the source address");

    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "neighbor (%M|%n) weight %d", 
		       config_router_neighbor_weight,
		      "Sets a weight for the neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "no neighbor (%M|%n) weight %d", 
		       config_router_neighbor_weight,
		      "Resets a weight for the neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "neighbor (%M|%n) maximum-prefix %d", 
		       config_router_neighbor_maximum_prefix,
		      "Sets max number of prefixes for the neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "no neighbor (%M|%n) maximum-prefix %d", 
		       config_router_neighbor_maximum_prefix,
		      "Resets max number of prefixes for the neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "neighbor (%M|%n) alias %M",
		      config_router_neighbor_alias, 
		      "Accept from another address");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "no neighbor (%M|%n) alias %M",
		      config_router_neighbor_alias, 
		      "No accept from another address");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
	"neighbor (%M|%n) "
	"(transparent-as|transparent-nexthop|passive|next-hop-self|"
	"route-reflector-client|remove-private-as|next-hop-peer|cisco)",
		      config_router_neighbor_option,
		      "Sets an option for the neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
	"no neighbor (%M|%n) "
	"(transparent-as|transparent-nexthop|passive|next-hop-self|"
	"route-reflector-client|remove-private-as|next-hop-peer|cisco)",
		      config_router_neighbor_option,
		      "Resets an option for the neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
    		      "neighbor (%M|%n) "
		      "(distribute-list|filter-list|community-list) "
		      "%d (in|out)",
		      config_router_neighbor_list_in_out,
		      "Applies the filter for incoming or outgoing");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
 		      "no neighbor (%M|%n) "
		      "(distribute-list|filter-list|community-list) "
		      "%d (in|out)",
		      config_router_neighbor_list_in_out,
		      "Removes the filter for incoming or outgoing");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "neighbor (%M|%n) route-map %d (in|out)",
		      config_router_neighbor_routemap_in_out,
		      "Applies the route map for incoming or outgoing");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "no neighbor (%M|%n) route-map %d (in|out)",
		      config_router_neighbor_routemap_in_out,
		      "Removes the route map for incoming or outgoing");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "neighbor (%M|%n) remote-id %a",
		       config_router_neighbor_routerid, 
		      "Sets router-id to the neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "no neighbor (%M|%n) remote-id %a",
		       config_router_neighbor_routerid, 
		      "Resets router-id from the neighbor");
#ifdef HAVE_IPV6
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "neighbor (%M|%n) bgp4+ (0|1|old|new|rfc|auto)",
		      config_router_neighbor_bgp4plus,
		      "Specifies BGP4+ packet format");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "no neighbor (%M|%n) bgp4+ (0|1|old|new|rfc|auto)",
		      config_router_neighbor_bgp4plus,
		      "Unspecifies BGP4+ packet format");
#endif /* HAVE_IPV6 */
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
	"neighbor (%M|%n) (holdtime|keepalive|connectretry|starttime) %d",
		      config_router_neighbor_time,
		      "Sets timer for neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
	"no neighbor (%M|%n) (holdtime|keepalive|connectretry|starttime)",
		      config_router_neighbor_time,
		      "Resets timer for neighbor to the default");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
	"neighbor (%M|%n) timers %dkeepalive %dholdtime",
		      config_router_neighbor_timers,
		      "Sets keepalive and holdtime for neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
	"no neighbor (%M|%n) timers %dkeepalive %dholdtime",
		      config_router_neighbor_timers,
		  "Resets keepalive and holdtime for neighbor to the default");

    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "neighbor %n peer %M %S",
		   config_router_neighbor_n_peer, "Adds an BGP neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "no neighbor %n peer",
	     config_router_neighbor_n_peer, "Deletes an BGP neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "neighbor %n remote-as %d",
		       config_router_neighbor_n_remoteas, 
		      "Sets AS number to the neighbor");

	 uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "neighbor (%M|%n) test",
			   config_router_neighbor_test, 
			   "Configure a test neighbor (skip policy/announcements)");


    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "neighbor %n neighbor-list %d",
		       config_router_neighbor_list, 
		      "Allows anonymous neighbor peers");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "no neighbor %n neighbor-list",
		       config_router_neighbor_list, 
		      "Deletes anonymous neighbor peers");

    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0, 
		      "neighbor (%M|%n) trace", trace_bgp_neighbor,
		      "Enable trace bgp neighbor");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0, 
		      "no neighbor (%M|%n) trace",
		      trace_bgp_neighbor, "Disable trace bgp neighbor");

    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		      "aggregate-address %m [as-set|null] [summary-only|null]",
		       config_router_aggregate,
		      "Creates an aggregate entry to prefix");
    uii_add_command2 (UII_CONFIG_ROUTER_BGP, 0,
		  "no aggregate-address %m [as-set|null] [summary-only|null]", 
		       config_router_aggregate,
		      "Deletes an aggregate entry to prefix");
}

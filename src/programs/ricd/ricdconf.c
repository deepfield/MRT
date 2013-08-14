/*
 * $Id: ricdconf.c,v 1.1.1.1 2000/08/14 18:46:14 labovit Exp $
 */

#include "ricd.h"
#include "config_file.h"


static int hqlip_register_area_center (hqlip_t *hqlip, my_area_t *my_area, 
					int pri);
static int
hqlip_register_area_addr (uii_connection_t *uii, my_area_t *my_area, int on);

config_ricd_t *CONFIG_RICD;

/*
 * turn on/off the interface
 */
static void
ricd_activate_interface (ricd_t *ricd, hqlip_config_network_t *network, 
			 int on, my_area_t *my_area)
{
    schedule_event2 ("hqlip_activate_interface",
                     ricd->hqlip->schedule, 
		     (event_fn_t) hqlip_activate_interface,
                     4, ricd->hqlip, network, on, my_area);
    schedule_event2 ("srsvp_activate_interface",
                     ricd->srsvp->schedule, 
		     (event_fn_t) srsvp_activate_interface,
                     4, ricd->srsvp, network->interface, network->prefix, on);
}


my_area_t *
my_area_new (hqlip_t *hqlip, char *name, area_t *area)
{
    my_area_t *my_area;
    char strbuf[64];

    my_area = New (my_area_t);
    my_area->name = strdup (name);
    my_area->area = area;
    area->my_area = my_area;
    if (area->level < HQLIP_AREA_LEVEL_INTERNET) {
        my_area->parent = hqlip->root;
        LL_Add2 (hqlip->root->ll_children, my_area);
    }
    my_area->ll_neighbors = LL_Create (0);
    my_area->ll_children = LL_Create (0);
    my_area->ll_prefixes = LL_Create (0);
    my_area->ll_spath_link_qoses = LL_Create (0);
    my_area->ll_spath_area_centers = LL_Create (0);
    my_area->ll_spath_area_addrs = LL_Create (0);
    my_area->ll_spath_area_qoses = LL_Create (0);
    my_area->trace = trace_copy (hqlip->trace);
    sprintf (strbuf, "area %s (%d:%s)", name, my_area->area->level, 
		prefix_toa (my_area->area->id));
    set_trace (my_area->trace, TRACE_PREPEND_STRING, strbuf, 0);
/*
    my_area->schedule = New_Schedule (name, hqlip->trace);
    mrt_thread_create2 (name, my_area->schedule, NULL, NULL);
*/

    return (my_area);
}


static int
config_ric_network_if_qos_prefix (uii_connection_t *uii, char *name,
			char *if_qos_name, char *link_qos_name,
			prefix_t *prefix)
{
    hqlip_t *hqlip = CONFIG_RICD->ricd->hqlip;
    hqlip_config_network_t *network;
    config_if_qos_t *config_if_qos = NULL;
    config_link_qos_t *config_link_qos = NULL;
    area_t *area0, *area1;
    my_area_t *my_area0, *my_area1;

    LL_Iterate (hqlip->ll_networks, network) {
        if (strcasecmp (name, network->interface->name) == 0) { 
	    break;
        }
    }

    if (uii->negative) {
	if (network != NULL) {
	    if (!BIT_TEST (network->flags, HQLIP_NETWORK_DELETED)) {
    	        ricd_activate_interface (CONFIG_RICD->ricd, network, 0, NULL);
	        network->flags |= HQLIP_NETWORK_DELETED;
		network->config_area0->flags |= HQLIP_AREA_DELETED;
		network->config_area1->flags |= HQLIP_AREA_DELETED;
		if (network->config_area0->my_area->center)
		    hqlip_register_area_center (hqlip, 
			    network->config_area0->my_area, -1);
		if (network->config_area1->my_area->center)
		    hqlip_register_area_center (hqlip, 
			    network->config_area1->my_area, -1);
		if (hqlip_register_area_addr (uii, 
			network->config_area0->my_area, 0) < 0) {
		    Delete (name);
		    return (-1);
		}
		if (hqlip_register_area_addr (uii, 
			network->config_area1->my_area, 0) < 0) {
		    Delete (name);
		    return (-1);
		}
	    }
	}
        Delete (name);
	return (0);
    }

    if (if_qos_name) {
        LL_Iterate (CONFIG_RICD->ll_config_if_qoses, config_if_qos) {
	    if (strcasecmp (config_if_qos->name, if_qos_name) == 0)
	        break;
        }
        if (config_if_qos == NULL) {
	    config_notice (TR_ERROR, uii, "no such if-qos: %s\n", if_qos_name);
	    Delete (name);
	    Delete (if_qos_name);
	    Delete (link_qos_name);
	    Deref_Prefix (prefix);
	    return (-1);
	}
    }
    
    LL_Iterate (CONFIG_RICD->ll_config_link_qoses, config_link_qos) {
	if (strcasecmp (config_link_qos->name, link_qos_name) == 0)
	    break;
    }
    if (config_link_qos == NULL) {
	config_notice (TR_ERROR, uii, "no such link-qos: %s\n", link_qos_name);
	Delete (name);
	Delete (if_qos_name);
	Delete (link_qos_name);
	Deref_Prefix (prefix);
	return (-1);
    }
    
    if (network == NULL) {
	interface_t *interface;
	config_area_t *config_area;
	prefix_t *prefix0, *prefix1;
	int plen = 32;
	spath_area_center_t *spath_area_center;

	interface = find_interface_byname (name);
	if (interface == NULL) {
	    config_notice (TR_ERROR, uii, "no such interface: %s\n", name);
	    Delete (name);
	    Delete (if_qos_name);
	    Delete (link_qos_name);
	    Deref_Prefix (prefix);
	    return (-1);
	}
        if (!BIT_TEST (interface->flags, IFF_MULTICAST)) {
	    config_notice (TR_ERROR, uii, "no multicast available on %s\n", 
			   name);
	    Delete (name);
	    Delete (if_qos_name);
	    Delete (link_qos_name);
	    Deref_Prefix (prefix);
	    return (-1);
	}
	if (prefix && !is_prefix_local_on (prefix, interface)) {
	    config_notice (TR_ERROR, uii, "no such prefix on %s\n", 
			   name);
	    Delete (name);
	    Delete (if_qos_name);
	    Delete (link_qos_name);
	    Deref_Prefix (prefix);
	    return (-1);
	}

	network = New (hqlip_config_network_t);
	network->interface = interface;
	network->config_if_qos = config_if_qos;
	network->config_link_qos = config_link_qos;
	network->prefix = Ref_Prefix (prefix);
	network->keep_alive_interval = -1;
	network->metric = -1;
	LL_Add2 (hqlip->ll_networks, network);

 	if (prefix == NULL) {
#ifdef HAVE_IPV6
	    if (hqlip->family == AF_INET6)
	        prefix = Ref_Prefix (interface->primary6->prefix);
	    else
#endif /* HAVE_IPV6 */
	    prefix = Ref_Prefix (interface->primary->prefix);
	}
#ifdef HAVE_IPV6
	if (prefix->family == AF_INET6)
	    plen = 128;
#endif /* HAVE_IPV6 */
	prefix0 = New_Prefix (prefix->family, prefix_tochar (prefix), plen);
	netmasking (prefix0->family, prefix_tochar (prefix0), prefix0->bitlen);
	area0 = add_area (0, prefix0);
	my_area0 = my_area_new (hqlip, name, area0);
	LL_Add2 (my_area0->ll_prefixes, prefix0);

	/* register myself as a center */
        spath_area_center = New (spath_area_center_t);
        spath_area_center->area = area0;
        spath_area_center->pri = 0;
        /* spath_area_center->router_id = hqlip->router_id; */
        time (&spath_area_center->tstamp);
        LL_Add2 (my_area0->ll_spath_area_centers, spath_area_center);
	my_area0->winner = spath_area_center;

	config_area = New (config_area_t);
	config_area->name = strdup (name);
	config_area->my_area = my_area0;
        LL_Add2 (hqlip->ll_areas, config_area);
	network->config_area0 = config_area;

	prefix1 = New_Prefix (prefix->family, prefix_tochar (prefix), 
			      prefix->bitlen);
	netmasking (prefix1->family, prefix_tochar (prefix1), prefix1->bitlen);
	area1 = add_area (1, prefix1);
	my_area1 = my_area_new (hqlip, name, area1);
	my_area0->parent = my_area1;
	LL_Add2 (my_area1->ll_children, my_area0);
	LL_Remove (hqlip->root->ll_children, my_area0);
	LL_Add2 (my_area1->ll_prefixes, prefix1);
	config_area = New (config_area_t);
	config_area->name = strdup (name);
	config_area->my_area = my_area1;
        LL_Add2 (hqlip->ll_areas, config_area);
	network->config_area1 = config_area;

    	ricd_activate_interface (CONFIG_RICD->ricd, network, 1, my_area0);
	/* here to avoid reconnection */
	if (hqlip_register_area_addr (uii, my_area0, 1) < 0) {
    	    Delete (name);
    	    Delete (if_qos_name);
    	    Delete (link_qos_name);
    	    Deref_Prefix (prefix);
	    return (-1);
	}
	if (hqlip_register_area_addr (uii, my_area1, 1) < 0) {
    	    Delete (name);
    	    Delete (if_qos_name);
    	    Delete (link_qos_name);
    	    Deref_Prefix (prefix);
	    return (-1);
	}
/*
	hqlip_register_area_center (hqlip, my_area0, 0);
	hqlip_register_area_center (hqlip, my_area1, 0);
*/
    }
    else {
	if (BIT_TEST (network->flags, HQLIP_NETWORK_DELETED)) {
	    network->config_area0->flags &= ~HQLIP_AREA_DELETED;
	    network->config_area1->flags &= ~HQLIP_AREA_DELETED;
	    network->flags &= ~HQLIP_NETWORK_DELETED;
	if (hqlip_register_area_addr (uii, network->config_area0->my_area, 
				      1) < 0)
	    return (-1);
	if (hqlip_register_area_addr (uii, network->config_area1->my_area, 
				      1) < 0) {
    	    Delete (name);
    	    Delete (if_qos_name);
    	    Delete (link_qos_name);
    	    Deref_Prefix (prefix);
	    return (-1);
	}
/*
	    hqlip_register_area_center (hqlip, 
		network->config_area0->my_area, 0);
	    hqlip_register_area_center (hqlip, 
		network->config_area0->my_area, 0);
*/
	}
	network->config_if_qos = config_if_qos;
	network->config_link_qos = config_link_qos;
    	ricd_activate_interface (CONFIG_RICD->ricd, network, 
					2, NULL);
    }
    Delete (name);
    Delete (if_qos_name);
    Delete (link_qos_name);
    Deref_Prefix (prefix);
    return (1);
}


static int
config_ric_network_qos_prefix (uii_connection_t *uii, char *name,
			       char *link_qos_name, prefix_t *prefix)
{
    return (config_ric_network_if_qos_prefix (uii, name, NULL, link_qos_name,
					      prefix));
}


static int
config_ric_network_if_qos (uii_connection_t *uii, char *name,
			   char *if_qos_name, char *link_qos_name)
{
    return (config_ric_network_if_qos_prefix (uii, name, if_qos_name, 
					      link_qos_name, NULL));
}


static int
config_ric_network_qos (uii_connection_t *uii, char *name,
			char *link_qos_name)
{
    return (config_ric_network_if_qos_prefix (uii, name, NULL, 
					      link_qos_name, NULL));
}


static int
config_ric_network_keep_alive (uii_connection_t *uii, char *name,
			       int keep_alive)
{
    hqlip_t *hqlip = CONFIG_RICD->ricd->hqlip;
    hqlip_config_network_t *network;
    int changed = 0;

    LL_Iterate (hqlip->ll_networks, network) {
        if (strcasecmp (name, network->interface->name) == 0) { 
	    break;
        }
    }
    if (network == NULL || BIT_TEST (network->flags, HQLIP_NETWORK_DELETED)) {
	config_notice (TR_ERROR, uii, "no such network: %s\n", name);
	Delete (name);
	return (-1);
    }

    if (uii->negative) {
	if (network == NULL || 
		BIT_TEST (network->flags, HQLIP_NETWORK_DELETED) ||
		network->keep_alive_interval < 0) {
	    Delete (name);
	    return (0);
	}
	network->keep_alive_interval = -1;
	changed++;
    }
    else {
        if (network == NULL || 
		BIT_TEST (network->flags, HQLIP_NETWORK_DELETED)) {
	    config_notice (TR_ERROR, uii, "no such network: %s\n", name);
	    Delete (name);
	    return (-1);
        }
	if (network->keep_alive_interval != keep_alive) {
	    network->keep_alive_interval = keep_alive;
	    changed++;
	}
    }
    if (changed)
    	ricd_activate_interface (CONFIG_RICD->ricd, network, 2, NULL);
    Delete (name);
    return (1);
}


static int
config_ric_network_metric (uii_connection_t *uii, char *name,
			   int metric)
{
    hqlip_t *hqlip = CONFIG_RICD->ricd->hqlip;
    hqlip_config_network_t *network;
    int changed = 0;

    LL_Iterate (hqlip->ll_networks, network) {
        if (strcasecmp (name, network->interface->name) == 0) { 
	    break;
        }
    }

    if (uii->negative) {
	if (network == NULL || 
		BIT_TEST (network->flags, HQLIP_NETWORK_DELETED) || 
		network->metric < 0) {
	    Delete (name);
	    return (0);
	}
	network->metric = -1;
	changed++;
    }
    else {
        if (network == NULL || 
		BIT_TEST (network->flags, HQLIP_NETWORK_DELETED)) {
	    config_notice (TR_ERROR, uii, "no such network: %s\n", name);
	    Delete (name);
	    return (-1);
        }
	if (network->metric != metric) {
	    network->metric = metric;
	    changed++;
	}
    }
    if (changed)
    	ricd_activate_interface (CONFIG_RICD->ricd, network, 2, NULL);
    Delete (name);
    return (1);
}


static int
hqlip_register_area_center (hqlip_t *hqlip, my_area_t *my_area, int pri)
{
    spath_area_center_t *spath_area_center;

    /* register/unregister myself upto/from the parent */
    if (pri < 0) {
	LL_Iterate (my_area->parent->ll_spath_area_centers,
		    spath_area_center) {
	    /* learned from the neighbor may be deleted */
	    if (BIT_TEST (spath_area_center->flags, AREA_CENTER_DELETED))
		continue;
	    if (spath_area_center->area == my_area->area &&
	        spath_area_center->neighbor == NULL /* &&
	        spath_area_center->router_id == hqlip->router_id*/) {
	        BIT_SET (spath_area_center->flags, AREA_CENTER_DELETED);
		/* XXX it's gone. need to flood the info, though */
	    	trace (TR_TRACE, my_area->trace, 
			"area %s withdrawn from center candidate in %s\n",
			my_area->name, my_area->parent->name);
			/* XXX check the current center */
		hqlip_update_area_center (hqlip, my_area->parent, 
					  spath_area_center);
		break;
	    }
	}
    }
    else {
	if (my_area->center == NULL) {
            spath_area_center = New (spath_area_center_t);
            spath_area_center->area = my_area->area;
            spath_area_center->pri = pri;
            /* spath_area_center->router_id = hqlip->router_id; */
            time (&spath_area_center->tstamp);
	    BIT_SET (spath_area_center->flags, AREA_CENTER_CHANGED);
	    my_area->center = spath_area_center;
	    /* XXX assuming configration doesn't change while running */
	}
	else if (my_area->center->pri != pri) {
	    my_area->center->pri = pri;
	    BIT_SET (my_area->center->flags, AREA_CENTER_CHANGED);
	}
	assert (my_area->parent);
        LL_Iterate (my_area->parent->ll_spath_area_centers, spath_area_center) {
	    if (BIT_TEST (spath_area_center->flags, AREA_CENTER_DELETED))
		continue;
	    if (spath_area_center->pri == my_area->center->pri &&
	        spath_area_center->neighbor == NULL /*&&
	        spath_area_center->router_id == my_area->center->router_id*/) {
		trace (TR_WARN, my_area->trace, 
			"area %s can't regiester as a center in %s "
			"due to the same priority %d with area %d:%a\n",
			my_area->name, my_area->parent->name,
			spath_area_center->pri,
			spath_area_center->area->level,
			spath_area_center->area->id);
		return (-1);
	    }
	}
        LL_Iterate (my_area->parent->ll_spath_area_centers, spath_area_center) {
	    if (spath_area_center->area == my_area->center->area &&
	            spath_area_center->neighbor == NULL)
		break;
	}
	if (spath_area_center) {
	    BIT_RESET (spath_area_center->flags, AREA_CENTER_DELETED);
	    if (my_area->center->pri != spath_area_center->pri) {
	        spath_area_center->pri = my_area->center->pri;
	        BIT_SET (spath_area_center->flags, AREA_CENTER_CHANGED);
	        hqlip_update_area_center (hqlip, my_area->parent, 
					  spath_area_center);
	    }
	}
	else {
            spath_area_center = New (spath_area_center_t);
            spath_area_center->area = my_area->center->area;
            spath_area_center->pri = my_area->center->pri;
            /* spath_area_center->router_id = hqlip->router_id; */
            spath_area_center->tstamp = my_area->center->tstamp;
	    BIT_SET (spath_area_center->flags, AREA_CENTER_CHANGED);
            LL_Add2 (my_area->parent->ll_spath_area_centers, 
		     spath_area_center);
	    trace (TR_TRACE, my_area->trace, 
		    "area %s registered to center candidate in %s\n",
		    my_area->name, my_area->parent->name);
	    hqlip_update_area_center (hqlip, my_area->parent, 
				      spath_area_center);
	}
    }
    return (1);
}


static int
config_ric_network_center (uii_connection_t *uii, char *name,
			   int pri, int pps, int level)
{
    hqlip_t *hqlip = CONFIG_RICD->ricd->hqlip;
    hqlip_config_network_t *network;
    config_area_t *config_area = NULL;

    if (level < 0 || level > 1) {
	config_notice (TR_ERROR, uii, "level must be 0 or 1\n");
	Delete (name);
	return (-1);
    }

    LL_Iterate (hqlip->ll_networks, network) {
        if (strcasecmp (name, network->interface->name) == 0) { 
	    break;
        }
    }

    if (network) {
	if (level == 0)
	    config_area = network->config_area0;
        else
	    config_area = network->config_area1;
    }

    if (uii->negative) {
	if (network == NULL || 
		BIT_TEST (network->flags, HQLIP_NETWORK_DELETED) || 
		config_area->my_area->center == NULL) {
	    Delete (name);
	    return (0);
	}
	if (hqlip_register_area_center (hqlip, config_area->my_area, -1) < 0) {
	    Delete (name);
	    return (-1);
	 }
	Delete (config_area->my_area->center);
	config_area->my_area->center = NULL;
    }
    else {
        if (network == NULL || 
		BIT_TEST (network->flags, HQLIP_NETWORK_DELETED)) {
	    config_notice (TR_ERROR, uii, "no such network: %s\n", name);
	    Delete (name);
	    return (-1);
        }
	config_area->my_area->pps = pps;
	if (config_area->my_area->center != NULL) {
	    Delete (config_area->my_area->center);
	    config_area->my_area->center = NULL;
	}
	if (hqlip_register_area_center (hqlip, config_area->my_area, pri) < 0) {
	    Delete (name);
	    return (-1);
	}
    }
    Delete (name);
    return (1);
}


static void
get_config_router_ric (ricd_t *ricd)
{
    hqlip_config_network_t *network;
    config_area_t *config_area;
    config_aggregate_t *aggregate;

#ifdef HAVE_IPV6
    if (ricd->family == AF_INET6) {
        config_add_output ("router ric ipv6\n");
    }
    else
#endif /* HAVE_IPV6 */
    config_add_output ("router ric\n");

    LL_Iterate (ricd->hqlip->ll_networks, network) {
	char strbuf[MAXLINE] = "";
	if (network->config_if_qos || network->config_link_qos)
	    sprintf (strbuf + strlen (strbuf), " %s", "qos");
	if (network->config_if_qos)
	    sprintf (strbuf + strlen (strbuf), " %s", 
			network->config_if_qos->name);
	if (network->config_link_qos)
	    sprintf (strbuf + strlen (strbuf), " %s", 
			network->config_link_qos->name);
	if (network->prefix)
            config_add_output ("  network %s%s prefix %p\n", 
			   network->interface->name, strbuf, network->prefix);
	else
            config_add_output ("  network %s%s\n", 
			   network->interface->name, strbuf);
	if (network->keep_alive_interval >= 0)
            config_add_output ("  network %s keep-alive %d\n", 
			        network->interface->name,
				network->keep_alive_interval);
	if (network->metric >= 0)
            config_add_output ("  network %s metric %d\n", 
			       network->interface->name,
			       network->metric);
	if (network->config_area0->my_area->center)
            config_add_output ("  network %s center %d %d level 0\n", 
			       network->interface->name,
			       network->config_area0->my_area->center->pri, 
			       network->config_area0->my_area->pps);
	if (network->config_area1->my_area->center)
            config_add_output ("  network %s center %d %d level 1\n",
			       network->interface->name,
			       network->config_area1->my_area->center->pri, 
			       network->config_area1->my_area->pps);
    }

    LL_Iterate (ricd->hqlip->ll_areas, config_area) {
	if (config_area->my_area->area->level <= 1)
	    continue;
	if (config_area->my_area->area->level >= HQLIP_AREA_LEVEL_INTERNET)
	    continue;
	if (config_area->my_area->area->id)
            config_add_output ("  area %s level %d id %a\n", 
			   config_area->name, 
			   config_area->my_area->area->level,
			   config_area->my_area->area->id);
	else
            config_add_output ("  area %s level %d\n", 
			   config_area->name, 
			   config_area->my_area->area->level);
	if (config_area->ll_aggregates) {
	    LL_Iterate (config_area->ll_aggregates, aggregate) {
	        if (aggregate->name)
            	    config_add_output ("  area %s aggregate %s masklen %d\n", 
			   config_area->name, aggregate->name,
			   aggregate->prefix->bitlen);
		else
            	    config_add_output ("  area %s aggregate %p\n", 
			   config_area->name, aggregate->prefix);
	    }
	}
	if (config_area->my_area->center) {
            config_add_output ("  area %s center %d %d\n", 
				config_area->name,
				config_area->my_area->center->pri, 
				config_area->my_area->pps);
	}
    }
}


static int
config_router_ric (uii_connection_t *uii, char *ipv6)
{
    ricd_t *ricd = RICD;

#ifndef HAVE_IPV6
    if (ipv6) {
	config_notice (TR_ERROR, uii, "NO IPV6 support available\n");
	Delete (ipv6);
	return (-1);
    }
#endif /* HAVE_IPV6 */
    if (ipv6) {
	ricd = RICD6;
	Delete (ipv6);
    }
    if (uii->negative) {
        hqlip_config_network_t *network;

        if (ricd == NULL || !ricd->running)
            return (0);    
        ricd->running = 0;
        config_del_module (CF_DELIM, "router ric", get_config_router_ric,
                           ricd);

	LL_Iterate (ricd->hqlip->ll_networks, network) {
    	    ricd_activate_interface (CONFIG_RICD->ricd, network, 0, NULL);
	    LL_Remove (ricd->hqlip->ll_networks, network);
	    Delete (network);
	}

	CONFIG_RICD->ricd = NULL;
        return (1);
    }
    ricd->running++;
    uii->previous[++uii->prev_level] = uii->state;
    uii->state = UII_CONFIG_ROUTER_RIC;
    config_add_module (CF_DELIM, "router ric", get_config_router_ric, ricd);
    CONFIG_RICD->ricd = ricd;
    return (1);
}


static void
get_config_if_qos (config_if_qos_t *config_if_qos)
{
    config_add_output ("if-qos %s %d %d %d %d\n", config_if_qos->name,
		        config_if_qos->if_qos->pps,
    			config_if_qos->if_qos->qos_pps,
    			config_if_qos->if_qos->ann_pps,
    			config_if_qos->if_qos->dly);
}


static int
config_x_if_qos (uii_connection_t *uii, char *name, int pps, int qos_pps,
	      int ann_pps, int dly)
{
    config_if_qos_t *config_if_qos;

    LL_Iterate (CONFIG_RICD->ll_config_if_qoses, config_if_qos) {
	if (strcasecmp (config_if_qos->name, name) == 0)
	    break;
    }
    if (uii->negative) {
	Delete (name);
	if (config_if_qos == NULL)
	    return (0);
	config_if_qos->flags |= CONFIG_QOS_DELETED;
        config_del_module (0, "if-qos", get_config_if_qos, config_if_qos);
	return (1);
    }

    if (config_if_qos == NULL) {
	config_if_qos = New (config_if_qos_t);
	config_if_qos->name = strdup (name);
	config_if_qos->flags = 0;
	config_if_qos->if_qos = New (if_qos_t);
	LL_Add2 (CONFIG_RICD->ll_config_if_qoses, config_if_qos);
    }
    config_if_qos->if_qos->pps = pps;
    config_if_qos->if_qos->qos_pps = qos_pps;
    config_if_qos->if_qos->ann_pps = ann_pps;
    config_if_qos->if_qos->dly = dly;
    config_if_qos->flags &= ~CONFIG_QOS_DELETED;
    config_add_module (0, "if-qos", get_config_if_qos, config_if_qos);
    Delete (name);
    return (1);
}


static void
get_config_link_qos (config_link_qos_t *config_link_qos)
{
    if (config_link_qos->link_qos->flag)
        config_add_output ("link-qos %s %u %u %u %u\n", 
			config_link_qos->name,
		        config_link_qos->link_qos->pri,
    			config_link_qos->link_qos->pps,
    			config_link_qos->link_qos->dly,
    			config_link_qos->link_qos->loh);
    else
        config_add_output ("link-qos %s %u %u %u\n", 
			config_link_qos->name,
		        config_link_qos->link_qos->pri,
    			config_link_qos->link_qos->pps,
    			config_link_qos->link_qos->dly);
}


static int
config_x_link_qos (uii_connection_t *uii, char *name, int pri, int pps, 
		 int dly, int loh)
{
    config_link_qos_t *config_link_qos;

    LL_Iterate (CONFIG_RICD->ll_config_link_qoses, config_link_qos) {
	if (strcasecmp (config_link_qos->name, name) == 0)
	    break;
    }
    if (uii->negative) {
	Delete (name);
	if (config_link_qos == NULL)
	    return (0);
	config_link_qos->flags |= CONFIG_QOS_DELETED;
        config_del_module (0, "link-qos", get_config_link_qos, config_link_qos);
	return (1);
    }

    if (config_link_qos == NULL) {
	config_link_qos = New (config_link_qos_t);
	config_link_qos->name = strdup (name);
	config_link_qos->flags = 0;
	config_link_qos->link_qos = New (link_qos_t);
	LL_Add2 (CONFIG_RICD->ll_config_link_qoses, config_link_qos);
    }
    config_link_qos->link_qos->pri = pri;
    config_link_qos->link_qos->pps = pps;
    config_link_qos->link_qos->dly = dly;
    config_link_qos->link_qos->loh = (loh >= 0)? loh: 0;
    config_link_qos->link_qos->flag = (loh >= 0);
    config_link_qos->flags &= ~CONFIG_QOS_DELETED;
    config_add_module (0, "link-qos", get_config_link_qos, config_link_qos);
    Delete (name);
    return (1);
}


static void
get_config_area_qos (config_area_qos_t *config_area_qos)
{
    config_add_output ("area-qos %s %u %u %u %u\n", 
			config_area_qos->name,
		        config_area_qos->area_qos->pri,
    			config_area_qos->area_qos->ctu,
    			config_area_qos->area_qos->bfee,
    			config_area_qos->area_qos->pfee);
}


static int
config_x_area_qos (uii_connection_t *uii, char *name, 
		 int pri, int ctu, int bfee, int pfee)
{
    config_area_qos_t *config_area_qos;

    LL_Iterate (CONFIG_RICD->ll_config_area_qoses, config_area_qos) {
	if (strcasecmp (config_area_qos->name, name) == 0)
	    break;
    }
    if (uii->negative) {
	Delete (name);
	if (config_area_qos == NULL)
	    return (0);
	config_area_qos->flags |= CONFIG_QOS_DELETED;
        config_del_module (0, "area-qos", get_config_area_qos, config_area_qos);
	return (1);
    }

    if (config_area_qos == NULL) {
	config_area_qos = New (config_area_qos_t);
	config_area_qos->name = strdup (name);
	config_area_qos->flags = 0;
	config_area_qos->area_qos = New (area_qos_t);
	LL_Add2 (CONFIG_RICD->ll_config_area_qoses, config_area_qos);
    }
    config_area_qos->area_qos->pri = pri;
    config_area_qos->area_qos->ctu = ctu;
    config_area_qos->area_qos->bfee = bfee;
    config_area_qos->area_qos->pfee = pfee;
    config_area_qos->flags &= ~CONFIG_QOS_DELETED;
    config_add_module (0, "area-qos", get_config_area_qos, config_area_qos);
    Delete (name);
    return (1);
}


static void
get_config_req_qos (config_req_qos_t *config_req_qos)
{
    config_add_output ("req-qos %s %u %u %u %u %u %u %u %u\n", 
			config_req_qos->name,
		        config_req_qos->req_qos->pri,
		        config_req_qos->req_qos->mtu,
    			config_req_qos->req_qos->pps,
    			config_req_qos->req_qos->sec,
    			config_req_qos->req_qos->cd,
    			config_req_qos->req_qos->cf,
    			config_req_qos->req_qos->rdly,
    			config_req_qos->req_qos->rfee);
}


static int
config_x_req_qos (uii_connection_t *uii, char *name, int pri,
		int mtu, int pps, int sec, int cd, int cf, int rdly, int rfee)
{
    config_req_qos_t *config_req_qos;

    LL_Iterate (CONFIG_RICD->ll_config_req_qoses, config_req_qos) {
	if (strcasecmp (config_req_qos->name, name) == 0)
	    break;
    }
    if (uii->negative) {
	Delete (name);
	if (config_req_qos == NULL)
	    return (0);
	config_req_qos->flags |= CONFIG_QOS_DELETED;
        config_del_module (0, "req-qos", get_config_req_qos, config_req_qos);
	return (1);
    }

    if (config_req_qos == NULL) {
	config_req_qos = New (config_req_qos_t);
	config_req_qos->name = strdup (name);
	config_req_qos->flags = 0;
	config_req_qos->req_qos = New (req_qos_t);
	LL_Add2 (CONFIG_RICD->ll_config_req_qoses, config_req_qos);
    }
    config_req_qos->req_qos->pri = pri;
    config_req_qos->req_qos->mtu = mtu;
    config_req_qos->req_qos->pps = pps;
    config_req_qos->req_qos->sec = sec;
    config_req_qos->req_qos->cd = cd;
    config_req_qos->req_qos->cf = cf;
    config_req_qos->req_qos->rdly = rdly;
    config_req_qos->req_qos->rfee = rfee;
    config_req_qos->flags &= ~CONFIG_QOS_DELETED;
    config_add_module (0, "req-qos", get_config_req_qos, config_req_qos);
    Delete (name);
    return (1);
}


static int
config_ric_area_level_id (uii_connection_t *uii, char *name, int level,
			  prefix_t *id)
{
    hqlip_t *hqlip = CONFIG_RICD->ricd->hqlip;
    config_area_t *config_area;

    if (level < 2 || level > HQLIP_AREA_LEVEL_INTERNET) {
	config_notice (TR_ERROR, uii, "area must be >=2 && < %d\n",
			HQLIP_AREA_LEVEL_INTERNET);
	Delete (name);
	Deref_Prefix (id);
	return (-1);
    }

    LL_Iterate (hqlip->ll_areas, config_area) {
        if (strcasecmp (name, config_area->name) == 0) { 
	    break;
        }
    }

    if (uii->negative) {
	if (config_area != NULL) {
	    if (!BIT_TEST (config_area->flags, HQLIP_AREA_DELETED)) {
	        config_area->flags |= HQLIP_AREA_DELETED;
	    }
	}
	Delete (name);
	return (0);
    }

    if (config_area == NULL) {
	config_area = New (config_area_t);
	config_area->name = strdup (name);
	config_area->flags = 0;
	config_area->my_area = my_area_new (hqlip, name, add_area (level, id));
        LL_Add2 (hqlip->ll_areas, config_area);
    }
    else {
	config_area->flags &= ~HQLIP_AREA_DELETED;
	config_area->my_area->flags &= ~HQLIP_MY_AREA_DELETED;
    }
    if (config_area->my_area->area->level != level ||
	!address_equal (config_area->my_area->area->id, id)) {
	config_area->my_area->area = add_area (level, id);
	/* I don't know if it works */
    }

    Deref_Prefix (id);
    Delete (name);
    return (1);
}

static int
config_ric_area_level (uii_connection_t *uii, char *name, int level)
{
    return (config_ric_area_level_id (uii, name, level, NULL));
}


static LINKED_LIST *
find_sub_areas (hqlip_t *hqlip, my_area_t *my_area, prefix_t *prefix, 
		LINKED_LIST *ll)
{
    config_area_t *config_area;
    prefix_t *b;

    LL_Iterate (hqlip->ll_areas, config_area) {
	if (config_area->my_area->area->level == my_area->area->level)
	    continue;
	if (config_area->my_area->area->level >= my_area->area->level)
	    continue;

	/* XXX stack up the lowest to top only */
	if (config_area->my_area->parent != my_area 
		&& config_area->my_area->parent != hqlip->root)
	    continue;

	if (config_area->my_area->ll_prefixes == NULL ||
		LL_GetCount (config_area->my_area->ll_prefixes) <= 0)
	    continue;
	LL_Iterate (config_area->my_area->ll_prefixes, b) {
	    if (a_include_b (prefix, b)) {
		if (ll == NULL) {
		    LL_Add2 (ll, config_area->my_area);
		    trace (TR_TRACE, hqlip->trace, "sub-area found: %s\n",
			   config_area->my_area->name);
		}
		else {
		    /* to avoid duplicates */
		    my_area_t *a;
		    LL_Iterate (ll, a) {
			if (a == config_area->my_area)
			    break;
		    }
		    if (a == NULL) {
			LL_Add2 (ll, config_area->my_area);
		        trace (TR_TRACE, hqlip->trace, "sub-area found: %s\n",
			       config_area->my_area->name);
		    }
		}
	    }
	}
    }
    return (ll);
}



static int
hqlip_config_re_eval_areas (uii_connection_t *uii, config_area_t *config_area)
{
    prefix_t *prefix;
    LINKED_LIST *ll = LL_Create (0);
    my_area_t *my_area, *child;
    hqlip_t *hqlip = CONFIG_RICD->ricd->hqlip;
    config_aggregate_t *aggregate;

    LL_ClearFn (config_area->my_area->ll_prefixes, 
		(LL_DestroyProc) Deref_Prefix);
    LL_Iterate (config_area->ll_aggregates, aggregate) {
	/* since aggregate may have duplicated prefixes */
	LL_Iterate (config_area->my_area->ll_prefixes, prefix) {
	    if (prefix_equal (aggregate->prefix, prefix))
		break;
	}
	if (prefix == NULL)
            LL_Add2 (config_area->my_area->ll_prefixes, 
		     Ref_Prefix (aggregate->prefix));
    }
    assert (config_area->my_area->ll_prefixes);

    LL_Iterate (config_area->my_area->ll_prefixes, prefix) {
	find_sub_areas (hqlip, config_area->my_area, prefix, ll);
    }
    /* check for delete */
    LL_Iterate (config_area->my_area->ll_children, child) {
        LL_Iterate (ll, my_area) {
	    if (my_area == child)
		break;
	}
	if (my_area == NULL) {
	    my_area_t *prev;
	    config_notice (TR_INFO, uii, "area %s parent changed %s -> %s\n",
			child->name, config_area->my_area->name, 
			hqlip->root->name);
	    assert (child->parent == config_area->my_area);

	    if (child->center)
	        hqlip_register_area_center (hqlip, child, -1);
            if (hqlip_register_area_addr (uii, child, 0) < 0) {
    		LL_Destroy (ll);
		return (-1);
	    }

	    prev = LL_GetPrev (config_area->my_area->ll_children, child);
	    LL_Remove (child->parent->ll_children, child);
	    child->parent = hqlip->root;
	    LL_Add2 (hqlip->root->ll_children, child);
	    /* XXX should search for a new parent */
	    child = prev;
	}
    }

    /* check for add */
    LL_Iterate (ll, my_area) {
	LL_Iterate (config_area->my_area->ll_children, child) {
	    if (child == my_area)
		break;
	}
	if (child == NULL) {
	    assert (my_area->parent != config_area->my_area);
	    config_notice (TR_INFO, uii, "area %s parent changed %s -> %s\n",
			    my_area->name, my_area->parent->name,
			    config_area->my_area->name);
	    if (my_area->center)
	        hqlip_register_area_center (hqlip, my_area, -1);
            if (hqlip_register_area_addr (uii, my_area, 0) < 0) {
    		LL_Destroy (ll);
		return (-1);
	    }
	    LL_Remove (my_area->parent->ll_children, my_area);
	    my_area->parent = config_area->my_area;
	    LL_Add (my_area->parent->ll_children, my_area);
	    if (my_area->center)
	        hqlip_register_area_center (hqlip, my_area, 
			/* no change */ my_area->center->pri);
            if (hqlip_register_area_addr (uii, my_area, 1) < 0) {
    		LL_Destroy (ll);
		return (-1);
	    }
        }   
    }
    LL_Destroy (ll);
    return (1);
}


/* area address info into config_area's parent ll_spath_area_addrs */
static int
hqlip_register_area_addr (uii_connection_t *uii, my_area_t *my_area, int on)
{
    spath_area_addr_t *spath_area_addr;
    prefix_t *pp, *prefix;

    LL_Iterate (my_area->parent->ll_spath_area_addrs, spath_area_addr) {

	if (spath_area_addr->area != my_area->area)
	    continue;

	LL_Iterate (my_area->ll_prefixes, prefix) {
	    prefix_t *pp2;

            if (on) {
	        LL_Iterate (my_area->parent->ll_prefixes, pp2) {
		    if (a_include_b (pp2, prefix))
		        break;
	        }
	        if (pp2 == NULL) {
		    config_notice (TR_ERROR, uii, 
		        "%p in area %s can not be included in area %s\n", 
		        prefix, my_area->name, my_area->parent->name);
		    return (-1);
	        }
	    }

	    LL_Iterate (spath_area_addr->ll_prefixes, pp) {
		if (prefix_equal (pp, prefix)) {
		    break;
		}
	    }

            if (on) {
		if (!pp) {
		    LL_Add (spath_area_addr->ll_prefixes, Ref_Prefix (prefix));
		    spath_area_addr->flags |= AREA_ADDR_CHANGED;
	    	    trace (TR_TRACE, my_area->trace, 
			"inject area-addr %p in %s\n", prefix,
			my_area->parent->name);
		}
	    }
	    else {
		if (pp) {
		    LL_Remove (spath_area_addr->ll_prefixes, pp);
	    	    trace (TR_TRACE, my_area->trace, 
			"removed area-addr %p in %s\n", prefix,
			my_area->parent->name);
		    Deref_Prefix (pp);
		    spath_area_addr->flags |= AREA_ADDR_CHANGED;
		    if (LL_GetCount (spath_area_addr->ll_prefixes) <= 0) {
			spath_area_addr->flags |= AREA_ADDR_DELETED;
			LL_Destroy (spath_area_addr->ll_prefixes);
			spath_area_addr->ll_prefixes = NULL;
			/* we broke the linked list, so have to return */
			LL_Remove (my_area->parent->ll_spath_area_addrs,
				   spath_area_addr);
			Delete (spath_area_addr);
			return (1);
		    }
		}
		else {
	    	    trace (TR_TRACE, my_area->trace, 
			"no area-addr %p in %s\n", prefix,
			my_area->parent->name);
		    /* continue */
		}
	    }
	}
	break;
    }

    if (spath_area_addr == NULL) {
	if (on) {
	    spath_area_addr = New (spath_area_addr_t);
	    spath_area_addr->area = my_area->area;
	    spath_area_addr->ll_prefixes = LL_Create (0);
	    spath_area_addr->flags |= AREA_ADDR_CHANGED;
	    LL_Add (my_area->parent->ll_spath_area_addrs, spath_area_addr);
	    LL_Iterate (my_area->ll_prefixes, prefix) {
	        trace (TR_TRACE, my_area->trace, 
		       "inject area-addr %p in %s (1st time)\n", prefix,
		        my_area->parent->name);
	        LL_Add2 (spath_area_addr->ll_prefixes, Ref_Prefix (prefix));
	    }
	}
	else {
	   trace (TR_TRACE, my_area->trace, 
		  "no area %s in %s\n", my_area->name, my_area->parent->name);
	   return (0);
	}
    }
    return (1);
}


static int
config_ric_area_aggregate_prefix (uii_connection_t *uii, char *name, 
				  prefix_t *prefix)
{
    hqlip_t *hqlip = CONFIG_RICD->ricd->hqlip;
    config_area_t *config_area;
    config_aggregate_t *aggregate;

    LL_Iterate (hqlip->ll_areas, config_area) {
        if (strcasecmp (name, config_area->name) == 0) { 
	    break;
        }
    }

    if (uii->negative) {
	if (config_area != NULL || 
	    	!BIT_TEST (config_area->flags, HQLIP_AREA_DELETED)) {
	    if (config_area->ll_aggregates) {
		LL_Iterate (config_area->ll_aggregates, aggregate) {
		    if (aggregate->name)
			continue;
		    if (prefix_equal (aggregate->prefix, prefix))
			break;
		}
		if (aggregate) {
		    LL_Remove (config_area->ll_aggregates, aggregate);
		    assert (aggregate->name == NULL);
		    Deref_Prefix (aggregate->prefix);
		    Delete (aggregate);
		    hqlip_config_re_eval_areas (uii, config_area);
		    hqlip_register_area_addr (uii, config_area->my_area, 0);
		}
	    }
	}
	Delete (name);
	Deref_Prefix (prefix);
	return (0);
    }

    if (config_area == NULL) {
	config_notice (TR_ERROR, uii, "no such area: %s\n", name);
	Delete (name);
	Deref_Prefix (prefix);
	return (-1);
    }
    if (config_area->ll_aggregates == NULL)
	config_area->ll_aggregates = LL_Create (0);
    LL_Iterate (config_area->ll_aggregates, aggregate) {
	if (aggregate->name)
	    continue;
	if (prefix_equal (aggregate->prefix, prefix))
	    break;
    }
    if (aggregate == NULL) {
	aggregate = New (config_aggregate_t);
	aggregate->name = NULL;
	aggregate->prefix = Ref_Prefix (prefix);
	LL_Add2 (config_area->ll_aggregates, aggregate);
        hqlip_config_re_eval_areas (uii, config_area);
	hqlip_register_area_addr (uii, config_area->my_area, 1);
    }

    Delete (name);
    Deref_Prefix (prefix);
    return (1);
}


static int
config_ric_area_aggregate_len (uii_connection_t *uii, char *name, 
			       char *area_name, int masklen)
{
    hqlip_t *hqlip = CONFIG_RICD->ricd->hqlip;
    config_area_t *config_area;
    config_aggregate_t *aggregate;

    LL_Iterate (hqlip->ll_areas, config_area) {
        if (strcasecmp (name, config_area->name) == 0) { 
	    break;
        }
    }

    if (uii->negative) {
	if (config_area != NULL || 
	    	!BIT_TEST (config_area->flags, HQLIP_AREA_DELETED)) {
	    if (config_area->ll_aggregates) {
		LL_Iterate (config_area->ll_aggregates, aggregate) {
		    if (aggregate->name == NULL)
			continue;
		    if (strcasecmp (aggregate->name, area_name) == 0)
			break;
		}
		if (aggregate) {
		    LL_Remove (config_area->ll_aggregates, aggregate);
		    Delete (aggregate->name);
		    Deref_Prefix (aggregate->prefix);
		    Delete (aggregate);
    		    hqlip_config_re_eval_areas (uii, config_area);
		    hqlip_register_area_addr (uii, config_area->my_area, 0);
		}
	    }
	}
	Delete (name);
	Delete (area_name);
	return (0);
    }

    if (config_area == NULL) {
	config_notice (TR_ERROR, uii, "no such area: %s\n", name);
	Delete (name);
	Delete (area_name);
	return (-1);
    }
    if (config_area->ll_aggregates == NULL)
	config_area->ll_aggregates = LL_Create (0);
    LL_Iterate (config_area->ll_aggregates, aggregate) {
	if (aggregate->name == NULL)
	    continue;
	if (strcasecmp (aggregate->name, area_name) == 0)
	    break;
    }
    if (aggregate == NULL) {
	hqlip_config_network_t *network;
	prefix_t *prefix;
        LL_Iterate (hqlip->ll_networks, network) {
            if (strcasecmp (area_name, network->interface->name) == 0)
	        break;
        }
        if (network == NULL) {
	    config_notice (TR_ERROR, uii, "no such network: %s\n", area_name);
	    Delete (name);
	    Delete (area_name);
	    return (-1);
        }
	prefix = LL_GetHead (network->config_area1->my_area->ll_prefixes);
	assert (prefix);
	aggregate = New (config_aggregate_t);
	aggregate->name = strdup (area_name);
	prefix = New_Prefix (prefix->family, prefix_tochar (prefix), masklen);
	if (prefix->bitlen < masklen) {
	    config_notice (TR_WARN, uii, "masklen %d is longer than %p\n", 
			   masklen, prefix->bitlen);
	}
	netmasking (prefix->family, prefix_tochar (prefix), masklen);
	aggregate->prefix = Ref_Prefix (prefix);
	LL_Add2 (config_area->ll_aggregates, aggregate);
    	hqlip_config_re_eval_areas (uii, config_area);
	hqlip_register_area_addr (uii, config_area->my_area, 1);
    }

    Delete (name);
    Delete (area_name);
    return (1);
}


static int
config_ric_area_center (uii_connection_t *uii, char *name, int pri, int pps)
{
    hqlip_t *hqlip = CONFIG_RICD->ricd->hqlip;
    config_area_t *config_area;

    LL_Iterate (hqlip->ll_areas, config_area) {
        if (strcasecmp (name, config_area->name) == 0) { 
	    break;
        }
    }

    if (uii->negative) {
	if (config_area != NULL || 
	    	!BIT_TEST (config_area->flags, HQLIP_AREA_DELETED)) {
	    if (config_area->my_area->center) {
	        hqlip_register_area_center (hqlip, config_area->my_area, -1);
		Delete (config_area->my_area->center);
		config_area->my_area->center = NULL;
	    }
	}
	Delete (name);
	return (0);
    }

    if (config_area == NULL) {
	config_notice (TR_ERROR, uii, "no such area: %s\n", name);
	Delete (name);
	return (-1);
    }
    if (config_area->my_area->center) {
	Delete (config_area->my_area->center);
	config_area->my_area->center = NULL;
    }
    config_area->my_area->pps = pps;
    if (hqlip_register_area_center (hqlip, config_area->my_area, pri) < 0) {
        Delete (name);
	return (-1);
    }

    Delete (name);
    return (1);
}


static void
get_config_rvp (ricd_rvp_t *rvp)
{
    config_add_output ("rvp %p %a\n", rvp->prefix, rvp->address);
}


static int
config_rvp (uii_connection_t *uii, prefix_t *prefix, prefix_t *address)
{
    ricd_rvp_t *rvp;

    LL_Iterate (CONFIG_RICD->ll_rvps, rvp) {
	if (prefix_equal (rvp->prefix, prefix) &&
	    prefix_equal (rvp->address, address))
	    break;
    }
    if (uii->negative) {
	if (rvp) {
	    config_del_module (0, "rvp", get_config_rvp, rvp);
	    LL_Remove (CONFIG_RICD->ll_rvps, rvp);
	    Deref_Prefix (rvp->prefix);
	    Deref_Prefix (rvp->address);
	}
	Deref_Prefix (prefix);
	Deref_Prefix (address);
	return (0);
    }

    if (rvp == NULL) {
	rvp = New (ricd_rvp_t);
	LL_Add2 (CONFIG_RICD->ll_rvps, rvp);
        config_add_module (0, "rvp", get_config_rvp, rvp);
    }
    else {
	Deref_Prefix (rvp->prefix);
	Deref_Prefix (rvp->address);
    }
    rvp->prefix = prefix;
    rvp->address = address;
    return (1);
}


prefix_t *
ricd_get_rvp (prefix_t *prefix)
{
    ricd_rvp_t *rvp;

    /* XXX multiple rvps */
    LL_Iterate (CONFIG_RICD->ll_rvps, rvp) {
	if (a_include_b (rvp->prefix, prefix))
	    return (rvp->address);
    }
    return (NULL);
}


void
ricd_init_config (void)
{
    assert (CONFIG_RICD == NULL);
    CONFIG_RICD = New (config_ricd_t);
    CONFIG_RICD->ricd = NULL;
    CONFIG_RICD->ll_config_if_qoses = LL_Create (0);
    CONFIG_RICD->ll_config_link_qoses = LL_Create (0);
    CONFIG_RICD->ll_config_area_qoses = LL_Create (0);
    CONFIG_RICD->ll_config_req_qoses = LL_Create (0);
    CONFIG_RICD->ll_rvps = LL_Create (0);

    set_uii (UII, UII_PROMPT, UII_CONFIG_ROUTER_RIC, "Router RIC> ", 0);

    uii_add_command2 (UII_NORMAL, 0, 
    		     "show (ip|ipv6) srsvp neighbor [%s|null]", 
    		     srsvp_show_neighbors, "Shows SRSVP neighbors");

    uii_add_command2 (UII_NORMAL, 0, 
    		     "show (ip|ipv6) flows", 
    		     srsvp_show_flows, "Shows SRSVP flows");
    uii_add_command2 (UII_NORMAL, 0, 
    		     "flow (send|recv) %adest port %d (udp|tcp) %sreq-qos",
    		     srsvp_flow_request_by_user, 
		     "Requests creation of flow to SRSVP");
    uii_add_command2 (UII_NORMAL, 0, 
    		     "ip flow (send|recv) %Adest port %d (udp|tcp) %sreq-qos",
    		     srsvp_flow_request_by_user, 
		     "Requests creation of flow to SRSVP");
    uii_add_command2 (UII_NORMAL, 0, 
    		 "ipv6 flow (send|recv) %Mdest port %d (udp|tcp) %sreq-qos",
    		     srsvp_flow_request_by_user, 
		     "Requests creation of flow to SRSVP");
    uii_add_command2 (UII_NORMAL, 0, "clear (ip|ipv6) flow %d",
    		      srsvp_no_flow_request_by_user, 
		      "Destroys flow of SRSVP");

    uii_add_command2 (UII_NORMAL, 0, 
    		     "show (ip|ipv6) hqlip neighbor [%s|null]", 
    		     hqlip_show_neighbors, "Shows HQLIP neighbors");

    uii_add_command2 (UII_NORMAL, 0, "show (ip|ipv6) hqlip areas", 
    		     hqlip_show_areas, "Shows HQLIP areas");

    uii_add_command2 (UII_NORMAL, 0, "show (ip|ipv6) hqlip path %p %p", 
		      hqlip_show_path, "Calculates HQLIP path");

    uii_add_command2 (UII_CONFIG, 0, 
    		"if-qos %sname %dif-pps %dqos-pps %dann-pps %dqueue-delay",
                      config_x_if_qos, "Define interface qos");
    uii_add_command2 (UII_CONFIG, 0, "no if-qos %sname",
                      config_x_if_qos, "Undefine interface qos");
    uii_add_command2 (UII_CONFIG, 0, 
    		      "link-qos %sname %dpri %dpps %ddly [%dloh|nil]",
                      config_x_link_qos, "Define link qos");
    uii_add_command2 (UII_CONFIG, 0, "no link-qos %sname",
                      config_x_link_qos, "Undefine link qos");
    uii_add_command2 (UII_CONFIG, 0, 
    		      "area-qos %sname %dpri %dctu %dbfee %dpfee",
                      config_x_area_qos, "Define area qos");
    uii_add_command2 (UII_CONFIG, 0, "no area-qos %sname",
                      config_x_area_qos, "Undefine area qos");
    uii_add_command2 (UII_CONFIG, 0, 
    	"req-qos %sname %dpri %dmtu %dpps %dsec %dcd %dcf %drdly %drfee",
                      config_x_req_qos, "Define req qos");
    uii_add_command2 (UII_CONFIG, 0, "no req-qos %sname",
                      config_x_area_qos, "Undefine req qos");
    uii_add_command2 (UII_CONFIG, 0, "rvp %p %a",
                      config_rvp, "Define rvp");
    uii_add_command2 (UII_CONFIG, 0, "no rvp %p %a",
                      config_rvp, "Undefine rvp");

    uii_add_command2 (UII_CONFIG, 0, "router ric [ipv6|null]",
                      config_router_ric,
    		      "Enables RIC routing protocols (HQLIP/SRSVP)");
    uii_add_command2 (UII_CONFIG, 0, "no router ric [ipv6|null]",
                      config_router_ric,
    		      "Disables RIC routing protocols (HQLIP/SRSVP)");

    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "network %nif-name qos %slink-qos",
                      config_ric_network_qos,
                      "Turns ON RIC routing on the interface with qos");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                  "network %nif-name qos %slink-qos prefix %p",
                      config_ric_network_qos_prefix,
          "Turns ON RIC routing on the interface with qos with the prefix");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "network %nif-name qos %sif-qos %slink-qos",
                      config_ric_network_if_qos,
                      "Turns ON RIC routing on the interface with qos");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                  "network %nif-name qos %sif-qos %slink-qos prefix %p",
                      config_ric_network_if_qos_prefix,
          "Turns ON RIC routing on the interface with qos with the prefix");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "no network %nif-name",
                      config_ric_network_qos,
                      "Turns OFF RIC routing on the interface");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "network %nif-name keep-alive %d",
                      config_ric_network_keep_alive,
                      "Set keep-alive interval");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "no network %nif-name keep-alive",
                      config_ric_network_keep_alive,
                      "Reset keep-alive interval");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "network %nif-name metric %d",
                      config_ric_network_metric, "Set metric");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "no network %nif-name metric",
                      config_ric_network_metric, "Reset metric");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "network %n center %dpri %dpps level %d",
                      config_ric_network_center, "Define center");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "no network %n center",
                      config_ric_network_center, "Undefine center");

#ifdef notdef
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "area %n level %d",
                      config_ric_area_level, "Define area");
#endif
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "area %n level %d id %M",
                      config_ric_area_level_id, "Define area with id");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "no area %n level %d",
                      config_ric_area_level, "Undefine area");

    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "area %n aggregate %m",
                      config_ric_area_aggregate_prefix, "Include sub-area");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "no area %n aggregate %m",
                      config_ric_area_aggregate_prefix, "Exclude sub-area");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "area %n aggregate %n masklen %d",
                       config_ric_area_aggregate_len, "Include sub-area");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "no area %n aggregate %n",
                      config_ric_area_aggregate_len, "Exclude sub-area");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "area %n center %dpri %dpps",
                      config_ric_area_center, "Define center");
    uii_add_command2 (UII_CONFIG_ROUTER_RIC, 0,
                      "no area %n center",
                      config_ric_area_center, "Undefine center");

{
    prefix_t *prefix;
    config_area_t *config_area;
    char *name = "Internet";
    my_area_t *my_area;

    prefix = ascii2prefix (AF_INET, "0.0.0.0/0");
    my_area = my_area_new (RICD->hqlip, name,
				add_area (HQLIP_AREA_LEVEL_INTERNET, prefix));
    LL_Add2 (my_area->ll_prefixes, Ref_Prefix (prefix));
    config_area = New (config_area_t);
    config_area->name = strdup (name);
    config_area->my_area = my_area;
    LL_Add2 (RICD->hqlip->ll_areas, config_area);
    RICD->hqlip->root = my_area;
    Deref_Prefix (prefix);

#ifdef HAVE_IPV6
    prefix = ascii2prefix (AF_INET6, "::/0");
    my_area = my_area_new (RICD6->hqlip, name,
				add_area (HQLIP_AREA_LEVEL_INTERNET, prefix));
    LL_Add2 (my_area->ll_prefixes, Ref_Prefix (prefix));
    config_area = New (config_area_t);
    config_area->name = strdup (name);
    config_area->my_area = my_area;
    LL_Add2 (RICD6->hqlip->ll_areas, config_area);
    RICD6->hqlip->root = my_area;
    Deref_Prefix (prefix);
#endif /* HAVE_IPV6 */
}
}


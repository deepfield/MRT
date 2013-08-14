/* 
 * $Id: commconf.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <ctype.h>
#include <mrt.h>
#include <rip.h>
#include <config_file.h>
#include <protoconf.h>
#ifdef NT
#include <ws2tcpip.h>
#endif /* NT */
config_mrtd_t *CONFIG_MRTD;
int BGPSIM_TRANSPARENT = 0; /* should be zero */


static void
get_config_ip_route (static_route_t * static_route)
{
    char options[MAXLINE], *cp = options;
    char *cmd = "route";

    if (static_route->safi == SAFI_MULTICAST)
	cmd = "mroute";

    strcpy (cp, "");
    if (static_route->nexthop) {
	sprintf (cp, " %s", prefix_toa (static_route->nexthop));
	cp += strlen (cp);
    }
    if (static_route->pref >= 0) {
	sprintf (cp, " %d", static_route->pref);
	cp += strlen (cp);
    }
    if (static_route->interface) {
	sprintf (cp, " %s", static_route->interface->name);
	cp += strlen (cp);
    }
    config_add_output ("%s %p %s\n", cmd, static_route->prefix, options);
}


/* 
 * config a static ip route
 */
static int
config_ip_route (uii_connection_t * uii, char *cmd, prefix_t * prefix,
		 prefix_t * nexthop, char * name, int pref)
{
    static_route_t *static_route;
    interface_t *interface = NULL;
    interface_t *interface2;
    int safi = SAFI_UNICAST;
    HASH_TABLE *hash_table = CONFIG_MRTD->static_routes;
    pthread_mutex_t *mutex_lock_p = &CONFIG_MRTD->static_routes_lock;
    generic_attr_t *attr;
    prefix_t *nexthop2;
    u_long flags = 0;

    if (strcasecmp (cmd, "mroute") == 0) {
		safi = SAFI_MULTICAST;
		hash_table = CONFIG_MRTD->static_mroutes;
        mutex_lock_p = &CONFIG_MRTD->static_mroutes_lock;
    }

    if (name) {
	interface = find_interface_byname (name);
	if (interface == NULL) {
    	    config_notice (TR_ERROR, uii, "interface %s not found\n", name);
	    Deref_Prefix (prefix);
	    Deref_Prefix (nexthop);
            if (name) Delete (name);
	    Delete (cmd);
	    return (-1);
	}
    }

    if ((nexthop == NULL || prefix_is_unspecified (nexthop)) 
	    && interface == NULL) {
        config_notice (TR_ERROR, uii,
                   "null nexthop requires an interface name\n");
        Deref_Prefix (prefix);
        Deref_Prefix (nexthop); 
        if (name) Delete (name);
	Delete (cmd);
        return (-1); 
    }
#ifdef HAVE_IPV6
    else if (nexthop != NULL && prefix_is_linklocal (nexthop)
	     && interface == NULL) {
        config_notice (TR_ERROR, uii,
		   "link_local nexthop requires an interface name\n");
	Deref_Prefix (prefix);
        Deref_Prefix (nexthop);
        if (name) Delete (name);
	Delete (cmd);
	return (-1);
    }
#endif /* HAVE_IPV6 */

    pthread_mutex_lock (mutex_lock_p);
    static_route = HASH_Lookup (hash_table, prefix);

    if (uii->negative) {

        if (static_route == NULL) {
    	    pthread_mutex_unlock (mutex_lock_p);
	    Deref_Prefix (prefix);
	    Delete (cmd);
	    return (0);
        }

        if (MRT->rib_update_route) {
            MRT->rib_update_route (prefix, NULL, static_route->attr, 0, 0, 
				   safi);
            /* XXX error handling ? */
	}

        config_del_module (0, cmd, get_config_ip_route, static_route);
        config_notice (TR_PARSE, uii,
		       "CONFIG static %s %p via %a being deleted\n", cmd,
		       static_route->prefix,
		       static_route->attr->nexthop->prefix);
        HASH_Remove (hash_table, static_route);
    	pthread_mutex_unlock (mutex_lock_p);
        if (name) Delete (name);
		Deref_Prefix (prefix);
        Deref_Prefix (nexthop);
		Delete (cmd);
        return (1);
    }

    if (nexthop != NULL) {
	nexthop2 = Ref_Prefix (nexthop);
    }
    else {
#ifdef HAVE_IPV6
        if (prefix->family == AF_INET6)
	    nexthop2 = ascii2prefix (AF_INET6, "::/128");
	else
#endif /* HAVE_IPV6 */
	nexthop2 = ascii2prefix (AF_INET, "0.0.0.0/32");
    }

    /* make sure that searched interface will be given to nexthops */
    /* static_route holds one supplied by user */
    interface2 = interface;
    if (interface2 == NULL) {
	assert (nexthop);
	interface2 = find_interface (nexthop);
	if (interface2 == NULL || !BIT_TEST (interface2->flags, IFF_UP))
	    interface2 = find_interface_local (nexthop);
    }
	
    attr = New_Generic_Attr (PROTO_STATIC);
    attr->nexthop = add_nexthop (nexthop2, interface2);
    attr->gateway = add_gateway (nexthop2, 0, interface2);
    Deref_Prefix (nexthop2);

    if (MRT->rib_update_route) {
	if (nexthop_available (attr->nexthop)) {
            MRT->rib_update_route (prefix, attr, NULL,
			    (pref >= 0)? pref: STATIC_PREF, 0, safi);
	    BIT_SET (flags, STATIC_ROUTE_UP);
	}
	else {
            MRT->rib_update_route (prefix, NULL, attr, 0, 0, safi);
	}
    }

    /* XXX error handling ? */

    if (static_route) {
        Deref_Prefix (static_route->prefix);
        static_route->prefix = Ref_Prefix (prefix);
        Deref_Prefix (static_route->nexthop);
        static_route->nexthop = Ref_Prefix (nexthop);
        static_route->interface = interface;
        static_route->pref = pref;
        static_route->flags = flags;
        Deref_Generic_Attr (static_route->attr);
        static_route->attr = attr;
        assert (static_route->safi == safi);
    }
    else {
        static_route = New (static_route_t);
        static_route->prefix = Ref_Prefix (prefix);
        static_route->nexthop = Ref_Prefix (nexthop);
        static_route->interface = interface;
        static_route->pref = pref;
        static_route->safi = safi;
        static_route->attr = attr;
        static_route->flags = flags;
	HASH_Insert (hash_table, static_route);
        config_add_module (0, cmd, get_config_ip_route, static_route);
    }
    pthread_mutex_unlock (mutex_lock_p);

    if (name)
        config_notice (TR_PARSE, uii,
		   "static %s %p via %a pref %d on %s\n", cmd,
		   prefix, attr->nexthop->prefix, 
		   (pref >= 0) ? pref : STATIC_PREF, name);
    else
        config_notice (TR_PARSE, uii,
		   "static %s %p via %a pref %d\n", cmd,
		   prefix, attr->nexthop->prefix, 
		   (pref >= 0) ? pref : STATIC_PREF);
    if (name) Delete (name);
    Delete (cmd);
    Deref_Prefix (prefix);
    Deref_Prefix (nexthop);
    return (1);
}


static void
re_evaluate_static_routes (HASH_TABLE *hash_table, 
			   int cmd, interface_t *interface, ll_addr_t *if_addr)
{
    static_route_t *static_route;

    if (hash_table == NULL) {
        pthread_mutex_lock (&CONFIG_MRTD->static_routes_lock);
        re_evaluate_static_routes (CONFIG_MRTD->static_routes, cmd, interface,
				   if_addr);
        pthread_mutex_unlock (&CONFIG_MRTD->static_routes_lock);
	pthread_mutex_lock (&CONFIG_MRTD->static_mroutes_lock);
        re_evaluate_static_routes (CONFIG_MRTD->static_mroutes, cmd, interface,
				   if_addr);
        pthread_mutex_unlock (&CONFIG_MRTD->static_mroutes_lock);
	return;
    }

    HASH_Iterate (hash_table, static_route) {

	if (static_route->interface == interface) {
	    int avail = nexthop_available (static_route->attr->nexthop);
	    if (!BIT_TEST (static_route->flags, STATIC_ROUTE_UP) && avail) {
            	MRT->rib_update_route (static_route->prefix, 
				        static_route->attr, NULL,
			    	       (static_route->pref >= 0)? 
					    static_route->pref: 
					    STATIC_PREF, 
					0, static_route->safi);
		BIT_SET (static_route->flags, STATIC_ROUTE_UP);
	    }
	    if (BIT_TEST (static_route->flags, STATIC_ROUTE_UP) && !avail) {
            	MRT->rib_update_route (static_route->prefix, 
					NULL, static_route->attr,
					0, 0, static_route->safi);
		BIT_RESET (static_route->flags, STATIC_ROUTE_UP);
	    }
	}
	else if (static_route->interface == NULL) {
	    interface_t *interface2 = NULL;

	    /* looking for interface in case not supplied */

    	    assert (!prefix_is_linklocal (static_route->nexthop));
    	    assert (!prefix_is_unspecified (static_route->nexthop));

	    interface2 = find_interface (static_route->nexthop);
	    if (interface2 == NULL || !BIT_TEST (interface2->flags, IFF_UP)) {
	        interface2 = find_interface_local (static_route->nexthop);
	    }

	    if (interface2 == NULL || !BIT_TEST (interface2->flags, IFF_UP)) {
		/* give up */
		if (BIT_TEST (static_route->flags, STATIC_ROUTE_UP)) {
            	    MRT->rib_update_route (static_route->prefix, 
					   NULL, static_route->attr,
					   0, 0, static_route->safi);
		    BIT_RESET (static_route->flags, STATIC_ROUTE_UP);
		}
	    }
	    else if (!BIT_TEST (static_route->flags, STATIC_ROUTE_UP) ||
	            (interface2 != static_route->attr->nexthop->interface)) {
	        generic_attr_t *attr = static_route->attr;
	        /* change */
	        deref_nexthop (attr->nexthop);
	        attr->nexthop = add_nexthop (static_route->nexthop, 
					     interface2);
    	        attr->gateway = add_gateway (static_route->nexthop, 0, 
					     interface2);
		/* this will update (overwrite) */
                MRT->rib_update_route (static_route->prefix, attr, NULL,
                	        (static_route->pref >= 0)? 
				        static_route->pref: STATIC_PREF, 
			        0, static_route->safi);
		BIT_SET (static_route->flags, STATIC_ROUTE_UP);
	    }
	}
    }
}


static void
interface_call_fn (int cmd, interface_t *interface, ll_addr_t *if_addr)
{
    if (MRT->rib_update_route == NULL)
	return;
    re_evaluate_static_routes (NULL, cmd, interface, if_addr);
}


static void
static_delete_route (static_route_t *static_route)
{
    Deref_Prefix (static_route->prefix);
    Deref_Prefix (static_route->nexthop);
    Deref_Generic_Attr (static_route->attr);
    Delete (static_route);
}


/*
 * start interface configuration 
 */
void
get_config_interface (interface_t * interface)
{
    int proto;

#ifdef HAVE_MROUTING
    if (interface->index < 0) {
        config_add_output ("interface tunnel %d\n", -interface->index);
        if (interface->tunnel_source)
            config_add_output ("  tunnel source %a\n", 
			       interface->tunnel_source);
        if (interface->tunnel_destination)
            config_add_output ("  tunnel destination %a\n",
                               interface->tunnel_destination);
    }
    else
#endif /* HAVE_MROUTING */
        config_add_output ("interface %s\n", interface->name);
    for (proto = PROTO_MIN; proto <= PROTO_MAX; proto++) {
        if (BGP4_BIT_TEST (interface->protocol_mask, proto)) {
	    if (proto == PROTO_DVMRP)
    	        config_add_output ("  ip dvmrp\n");
	    if (proto == PROTO_PIM)
    	        config_add_output ("  ip pim dense-mode\n");
	    else if (proto == PROTO_PIMV6)
    	        config_add_output ("  ipv6 pim dense-mode\n");
	}
    }
}


static int
config_interface (uii_connection_t * uii, char *name)
{
    interface_t *interface, *ip;

    if ((interface = find_interface_byname (name)) == NULL) {
	config_notice (TR_ERROR, uii,
		       "INTERFACE %s not found\n", name);
	Delete (name);
	return (-1);
    }
    config_notice (TR_TRACE, uii, "INTERFACE %s\n", name);
    CONFIG_MRTD->interface = interface;
    uii->previous[++uii->prev_level] = uii->state;
    uii->state = UII_CONFIG_INTERFACE;
    Delete (name);

    LL_Iterate (CONFIG_MRTD->ll_interfaces, (char *) ip) {
	if (ip == interface)
	    return (0);
    }

    LL_Add (CONFIG_MRTD->ll_interfaces, interface);
    /* this is a memory to avoid duplication of config_add_module */
    config_add_module (CF_DELIM, "interface", get_config_interface, interface);
    return (1);
}


static void
get_config_interface_gateway (prefix_t * prefix)
{
    config_add_output ("  gateway %s\n", prefix_toa (prefix));
}


static int
config_interface_gateway (uii_connection_t * uii, prefix_t * prefix)
{
    config_notice (TR_TRACE, uii,
		   "gateway %s\n", prefix_toa (prefix));
    add_gateway (prefix, 0, CONFIG_MRTD->interface);
    config_add_module (0, "gateway", get_config_interface_gateway, prefix);
    return (1);
}


/* XXX obsolete */
static int
config_router_id (uii_connection_t * uii, prefix_t *prefix)
{
    MRT->default_id = prefix_tolong (prefix);
    return (1);
}


static void
get_config_gateway (gateway_t *gateway)
{
    config_add_output ("gateway %s on %s\n", prefix_toa (gateway->prefix),
		       gateway->interface->name);
}


static int
config_gateway (uii_connection_t * uii, prefix_t *prefix, char *name)
{
    interface_t *interface;
    gateway_t *gateway;

    interface = find_interface_byname (name);
    if (interface == NULL) {
        config_notice (TR_ERROR, uii,
		       "interface %s not found\n", name);
	Delete (name);
	return (-1);
    }
    config_notice (TR_TRACE, uii, "gateway %s on %s\n", prefix_toa (prefix),
		   interface->name);
    gateway = add_gateway (prefix, 0, interface);
    config_add_module (0, "gateway", get_config_gateway, gateway);
    Delete (name);
    Deref_Prefix (prefix);
    return (1);
}


#ifdef notdef
int
config_router_network_weight (uii_connection_t * uii, char *name_or_prefix,
			      int weight)
{
    prefix_t *prefix;
    char name[MAXLINE];
    interface_t *interface;
    LINKED_LIST *ll;

    if (CONFIG_MRTD->protocol != PROTO_RIP && 
	CONFIG_MRTD->protocol != PROTO_RIPNG &&
	CONFIG_MRTD->protocol != PROTO_BGP) {
	Delete (name_or_prefix);
	return (-1);
    }

    if (parse_line (name_or_prefix, "%m", &prefix) >= 1) {

	Delete (name_or_prefix);

	if (CONFIG_MRTD->protocol == PROTO_BGP)
	    LL_Add (BGP->ll_networks, Ref_Prefix (prefix));
	if (CONFIG_MRTD->protocol == PROTO_RIP)
	    LL_Add (RIP->ll_networks, Ref_Prefix (prefix));
#ifdef HAVE_IPV6
	if (CONFIG_MRTD->protocol == PROTO_RIPNG)
	    LL_Add (RIPNG->ll_networks, Ref_Prefix (prefix));
#endif /* HAVE_IPV6 */
	if (CONFIG_MRTD->protocol == PROTO_BGP) {
	    Deref_Prefix (prefix);
	    return (1);
	}

	if ((ll = find_network (prefix)) != NULL) {
	    LL_Iterate (ll, interface) {
		switch (CONFIG_MRTD->protocol) {
		case PROTO_RIP:
		    if (BITX_TEST (&RIP->interface_mask, interface->index))
			break;
		    BITX_SET (&RIP->interface, interface->index);
		    interface->default_pref = weight;
		    config_notice (TR_TRACE, uii,
				   "CONFIG RIP on interface %s weight %d\n",
				   interface->name, weight);
		    break;
#ifdef HAVE_IPV6
		case PROTO_RIPNG:
		    if (BITX_TEST (&RIPNG->interface_mask, interface->index))
			break;
		    if (!BIT_TEST (interface->flags, IFF_MULTICAST) &&
			BIT_TEST (interface->flags, IFF_POINTOPOINT) &&
			(interface->link_local == NULL ||
			 interface->link_local->broadcast == NULL)) {
			config_notice (TR_ERROR, uii,
				     "RIPNG on interface %s ignored "
			    "due to no multicast or link-local dest addr\n",
				       interface->name);
			break;
		    }
		    BITX_SET (&RIPNG->interface, interface->index);
		    interface->default_pref = weight;
		    config_notice (TR_TRACE, uii,
				 "CONFIG RIPNG on interface %s weight %d\n",
				   interface->name, weight);
		    break;
#endif /* HAVE_IPV6 */
		default:
		    assert (0);
		    break;
		}
	    }
	    LL_Destroy (ll);
	    Deref_Prefix (prefix);
	    return (1);
	}
	/* else {
	    Deref_Prefix (prefix);
	    return (-1);
	} */
    }
    else if (parse_line (name_or_prefix, "%s", name) >= 1) {

	Delete (name_or_prefix);
/*
 * This part must be the last otherwise some ipv6 address will be mistook 
 */
	if ((interface = find_interface_byname (name)) == NULL) {
	    config_notice (TR_ERROR, uii,
		   "could not find interface %s\n", name);
	    return (-1);
	}

	if (CONFIG_MRTD->protocol == PROTO_RIP) {
	    BITX_SET (&RIP->interface, interface->index);
	    interface->default_pref = weight;
	    config_notice (TR_TRACE, uii,
			   "CONFIG RIP on interface %s\n", interface->name);
	    LL_Add (RIP->ll_networks, Ref_Prefix (interface->primary->prefix));
	    return (1);
	}
#ifdef HAVE_IPV6
	else if (CONFIG_MRTD->protocol == PROTO_RIPNG) {
	    if (!BITX_TEST (&RIPNG->interface, interface->index)) {
		if (!BIT_TEST (interface->flags, IFF_MULTICAST) &&
		    BIT_TEST (interface->flags, IFF_POINTOPOINT) &&
		    (interface->link_local == NULL ||
		     interface->link_local->broadcast == NULL)) {
		    config_notice (TR_ERROR, uii,
				   "RIPNG on interface %s ignored "
			    "due to no multicast or link-local dest addr\n",
				   interface->name);
		}
		else {
	    	    BITX_SET (&RIPNG->interface_mask, interface->index);
		    interface->default_pref = weight;
		    config_notice (TR_TRACE, uii,
				   "CONFIG RIPNG on interface %s\n",
				   interface->name);
	            LL_Add (RIPNG->ll_networks, Ref_Prefix (interface->primary6->prefix));
		}
	    }
	    return (1);
	}
#endif /* HAVE_IPV6 */
	else if (CONFIG_MRTD->protocol == PROTO_BGP) {
	    /* not supported */
	    return (-1);
	}
	else {
	    /* should not happen */
	    assert (0);
	}
    }
    else {
	Delete (name_or_prefix);
	return (-1);
    }
    assert (0);
    /* NOT REACHED */
    return (-1); /* shut up the compiler */
}
#endif


static int
config_mrt_reboot (uii_connection_t *uii)
{
#if defined (__linux__) && defined (HAVE_LIBPTHREAD) && 0
    /* I couldn't figure out how I can do this */
    config_notice (TR_ERROR, uii,
        "This command is unavailable on Linux with Pthread\n");
    return (0);
#else
    uii_send_data (uii, "Are you sure (yes/no)? ");
    if (uii_yes_no (uii)) {
        uii_send_data (uii, "Reboot requested\n");
        mrt_set_force_exit (MRT_FORCE_REBOOT);
    }
    return (1);
#endif
}


int
init_mrtd_config (trace_t * trace)
{
    static_route_t static_route;

    CONFIG_MRTD = New (config_mrtd_t);
    CONFIG_MRTD->interface = NULL;
    CONFIG_MRTD->ll_interfaces = LL_Create (0);
#define STATIC_TABLE_HASH_SIZE 123
    CONFIG_MRTD->static_routes = HASH_Create (STATIC_TABLE_HASH_SIZE,
                             HASH_KeyOffset,
                             HASH_Offset (&static_route, &static_route.prefix),
                             HASH_LookupFunction, ip_lookup_fn,
                             HASH_HashFunction, ip_hash_fn,
                             HASH_DestroyFunction, static_delete_route,
                             NULL);
    CONFIG_MRTD->static_mroutes = HASH_Create (STATIC_TABLE_HASH_SIZE,
                             HASH_KeyOffset,
                             HASH_Offset (&static_route, &static_route.prefix),
                             HASH_LookupFunction, ip_lookup_fn,
                             HASH_HashFunction, ip_hash_fn,
                             HASH_DestroyFunction, static_delete_route,
                             NULL);
    pthread_mutex_init (&CONFIG_MRTD->static_routes_lock, NULL);
    pthread_mutex_init (&CONFIG_MRTD->static_mroutes_lock, NULL);

    /* this will be set depending on password in conf file */
#if 0
    UII->initial_state = 0;	/* password required */
#endif

    set_uii (UII, UII_PROMPT, UII_UNPREV, "Password: ", 0);
    set_uii (UII, UII_PROMPT, UII_NORMAL, "MRTd> ", 0);
    set_uii (UII, UII_PROMPT, UII_ENABLE, "MRTd# ", 0);
    set_uii (UII, UII_PROMPT, UII_CONFIG, "Config> ", 0);
    set_uii (UII, UII_PROMPT, UII_CONFIG_INTERFACE, "Interface> ", 0);
    set_uii (UII, UII_PROMPT, UII_CONFIG_LINE, "Line> ", 0);

    /* Interactive commands */

    uii_add_command2 (UII_NORMAL, COMMAND_NODISPLAY, "show ip", 
		      show_ip_routes,
		      "Show the central routing table");
    uii_add_command2 (UII_NORMAL, 0, "show ip (routes|mroutes)", 
		      show_ip_routes,
		      "Show the central routing table");
    uii_add_command2 (UII_NORMAL, COMMAND_NODISPLAY, 
		     "show rib (routes|mroutes)", 
		      show_ip_routes, "Show the central routing table");
    uii_add_command2 (UII_NORMAL, COMMAND_NODISPLAY, "show rib", 
		      show_rib_status,
		      "Show the central routing status");

    uii_add_command2 (UII_NORMAL, 0, "show interfaces",
		      show_interfaces, "Show all interfaces available");

    uii_add_command2 (UII_ENABLE, 0, "reboot", config_mrt_reboot,
		      "Reboot MRTd");

#ifdef HAVE_IPV6
    uii_add_command2 (UII_NORMAL, 0, 
		      "show ipv6 (routes|mroutes)", show_ipv6_routes,
		      "Show the central routing status");
    uii_add_command2 (UII_NORMAL, COMMAND_NODISPLAY, "show rib6", 
		      show_rib_status,
		      "Show the central routing status");
    uii_add_command2 (UII_NORMAL, COMMAND_NODISPLAY, "show ipv6", 
		      show_ipv6_routes,
		      "Show the central routing status");
    uii_add_command2 (UII_NORMAL, COMMAND_NODISPLAY, 
		      "show rib6 (routes|mroutes)", 
		      show_ipv6_routes, "Show the central routing status");
#endif /* HAVE_IPV6 */

    uii_add_command2 (UII_CONFIG, 0, 
		      "(route|mroute) %m [%M|null] [%n|null] [%d|nil]",
		      config_ip_route, "Add a static route");
    uii_add_command2 (UII_CONFIG, 0, 
		      "ip (route|mroute) %m [%M|null] [%n|null] [%d|nil]",
		      config_ip_route, "Add a static route");
    uii_add_command2 (UII_CONFIG, 0, 
		       "no (route|mroute) %m [%M|null] [%n|null]",
		      config_ip_route, "Delete static route");
    uii_add_command2 (UII_CONFIG, 0, 
		      "no ip (route|mroute) %m [%M|null] [%n|null]",
		      config_ip_route, "Delete static route");
#ifdef HAVE_IPV6
    uii_add_command2 (UII_CONFIG, 0, 
		     "ipv6 (route|mroute) %P [%A|null] [%n|null] [%d|nil]",
		      config_ip_route, "Add a static route");
    uii_add_command2 (UII_CONFIG, 0, 
		      "no ipv6 (route|mroute) %P [%A|null] [%n|null] [%d|nil]",
		      config_ip_route, "Delete static route");
#endif /* HAVE_IPV6 */

    uii_add_command2 (UII_CONFIG, 0, "interface %s",
		      config_interface, "Define interface");
    uii_add_command2 (UII_CONFIG_INTERFACE, 0, "gateway %M",
		      config_interface_gateway, 
		      "Define gateways on the interface");

#ifndef HAVE_IPV6
    uii_add_command2 (UII_ENABLE, 0, "trace rib (*|inet)", 
		      trace_rib, "Enable trace rib");

    uii_add_command2 (UII_ENABLE, 0, "no trace rib (*|inet)", 
		      no_trace_rib, "Disable trace rib");
#else
    uii_add_command2 (UII_ENABLE, 0, "trace rib (*|inet|inet6)", 
		      trace_rib, "Enable trace rib");
    uii_add_command2 (UII_ENABLE, 0, "no trace rib (*|inet|inet6)", 
		      no_trace_rib, "Disable trace rib");
#endif /* HAVE_IPV6 */
    uii_add_command2 (UII_ENABLE, 0, "trace ip rib", 
		      trace_ip_rib, "Enable trace rib");
    uii_add_command2 (UII_ENABLE, 0, "no trace ip rib", 
		      trace_ip_rib, "Disable trace rib");
#ifdef HAVE_IPV6
    uii_add_command2 (UII_ENABLE, 0, "trace ipv6 rib", 
		      trace_ipv6_rib, "Enable trace rib");
    uii_add_command2 (UII_ENABLE, 0, "no trace ipv6 rib", 
		      trace_ipv6_rib, "Disable trace rib");
#endif /* HAVE_IPV6 */

    uii_add_command2 (UII_CONFIG, COMMAND_NODISPLAY, "router_id %a",
	    	      config_router_id, "Set router id");

    uii_add_command2 (UII_CONFIG, 0, "gateway %M on %n",
	    	      config_gateway, "Define gateway on interface");

    LL_Add (INTERFACE_MASTER->ll_call_fns, interface_call_fn);
    return (1);
}


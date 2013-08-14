/* 
 * $Id: rtmapconf.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <ctype.h>
#include <mrt.h>
#include <config_file.h>
#include <protoconf.h>


static void
get_config_route_map (int num)
{
    route_map_out (num, (void_fn_t) config_add_output);
}


static int
config_route_map (uii_connection_t * uii, int num, int precedence)
{
    int n;

    if (num < 0 || num >= MAX_ROUTE_MAP) {
	config_notice (TR_ERROR, uii,
	       "wrong route-map number %d (should be 0 <= x < %d)\n",
	       num, MAX_ROUTE_MAP);
	return (-1);
    }
    if (uii->negative) {
        if (del_route_map (num, precedence) <= 0)
            config_del_module (CF_DELIM, "route-map", get_config_route_map, 
		               (void *) num);
	return (1);
    }
    n = get_route_map_num (num);
    CONFIG_MRTD->route_map = add_route_map (num, precedence, 0);
    uii->previous[++uii->prev_level] = uii->state;
    uii->state = UII_CONFIG_ROUTE_MAP;
    if (n < 1 && get_route_map_num (num) == 1)
        config_add_module (CF_DELIM, "route-map", get_config_route_map, 
		           (void *) num);
    return (1);
}


static int
config_route_map_match_address (uii_connection_t * uii, int num)
{
    assert (CONFIG_MRTD->route_map);
    assert (CONFIG_MRTD->route_map->attr);
    if (uii->negative) {
	CONFIG_MRTD->route_map->alist = -1;
        return (1);
    }
    CONFIG_MRTD->route_map->alist = num;
    return (1);
}


static int
config_route_map_match_aspath (uii_connection_t * uii, int num)
{
    assert (CONFIG_MRTD->route_map);
    assert (CONFIG_MRTD->route_map->attr);
    if (uii->negative) {
	CONFIG_MRTD->route_map->flist = -1;
        return (1);
    }
    CONFIG_MRTD->route_map->flist = num;
    return (1);
}


static int
config_route_map_match_community (uii_connection_t * uii, int num)
{
    assert (CONFIG_MRTD->route_map);
    assert (CONFIG_MRTD->route_map->attr);
    if (uii->negative) {
	CONFIG_MRTD->route_map->clist = -1;
        return (1);
    }
    CONFIG_MRTD->route_map->clist = num;
    return (1);
}


static int
config_route_map_origin (uii_connection_t * uii, char *str)
{
    int origin, as = 0;

    if (parse_line (str, "igp") >= 1) {
	origin = 0;
    }
    else if (parse_line (str, "egp %d", &as) >= 1) {
	/* as is just for cisco-like syntax */
	origin = 1;
    }
    else if (parse_line (str, "incomplete") >= 1) {
	origin = 2;
    }
    else {
	Delete (str);
	return (-1);
    }

    assert (CONFIG_MRTD->route_map);
    assert (CONFIG_MRTD->route_map->attr);
    if (uii->negative) {
        if (BGP4_BIT_TEST (CONFIG_MRTD->route_map->attr->attribs, 
			   PA4_TYPE_ORIGIN)) {
            BGP4_BIT_RESET (CONFIG_MRTD->route_map->attr->attribs, PA4_TYPE_ORIGIN);
            return (1);
	}
        return (0);
    }
    CONFIG_MRTD->route_map->attr->origin = origin;
    BGP4_BIT_SET (CONFIG_MRTD->route_map->attr->attribs, PA4_TYPE_ORIGIN);
    Delete (str);
    return (1);
}


static int
config_route_map_weight (uii_connection_t * uii, int weight)
{
    assert (CONFIG_MRTD->route_map);
    assert (CONFIG_MRTD->route_map->attr);
    /* XXX
       CONFIG_MRTD->route_map->attr->pref = weight; */
    return (1);
}


static int
config_route_map_nexthop (uii_connection_t * uii, prefix_t * prefix)
{
    nexthop_t *nexthop;

    assert (CONFIG_MRTD->route_map);
    assert (CONFIG_MRTD->route_map->attr);

    if (uii->negative) {
	int ok = 0;
	if (BGP4_BIT_TEST (CONFIG_MRTD->route_map->attr->attribs, 
                           PA4_TYPE_NEXTHOP)) {
	    deref_nexthop (CONFIG_MRTD->route_map->attr->nexthop);
	    CONFIG_MRTD->route_map->attr->nexthop = NULL;
	    BGP4_BIT_RESET (CONFIG_MRTD->route_map->attr->attribs, 
			    PA4_TYPE_NEXTHOP);
	    ok++;
	}
#ifdef HAVE_IPV6
	if (CONFIG_MRTD->route_map->attr->link_local) {
	    deref_nexthop (CONFIG_MRTD->route_map->attr->link_local);
	    CONFIG_MRTD->route_map->attr->link_local = NULL;
	    ok++;
	}
	if (CONFIG_MRTD->route_map->attr->nexthop4) {
	    deref_nexthop (CONFIG_MRTD->route_map->attr->nexthop4);
	    CONFIG_MRTD->route_map->attr->nexthop4 = NULL;
	    ok++;
	}
#endif /* HAVE_IPV6 */
	return (1);
    }

    nexthop = add_nexthop (prefix, NULL);
    Deref_Prefix (prefix);
    assert (nexthop);

    if (nexthop->prefix->family == AF_INET) {
	if (BGP4_BIT_TEST (CONFIG_MRTD->route_map->attr->attribs,
			   PA4_TYPE_NEXTHOP)) {
#ifdef HAVE_IPV6
	    if (CONFIG_MRTD->route_map->attr->nexthop->prefix->family 
		    == AF_INET6) {
		if (CONFIG_MRTD->route_map->attr->nexthop4)
		    deref_nexthop (CONFIG_MRTD->route_map->attr->nexthop4);
		CONFIG_MRTD->route_map->attr->nexthop4 = nexthop;
	    }
	    else
#endif /* HAVE_IPV6 */
	    {
		deref_nexthop (CONFIG_MRTD->route_map->attr->nexthop);
		CONFIG_MRTD->route_map->attr->nexthop = nexthop;
	    }
	}
	else {
	    CONFIG_MRTD->route_map->attr->nexthop = nexthop;
	}
	BGP4_BIT_SET (CONFIG_MRTD->route_map->attr->attribs, PA4_TYPE_NEXTHOP);
	return (1);
    }
#ifdef HAVE_IPV6
    else {
	assert (CONFIG_MRTD->route_map);
	assert (CONFIG_MRTD->route_map->attr);

	if (IN6_IS_ADDR_LINKLOCAL (prefix_toaddr6 (nexthop->prefix))) {
	    if (!BGP4_BIT_TEST (CONFIG_MRTD->route_map->attr->attribs, 
			PA4_TYPE_NEXTHOP))
		CONFIG_MRTD->route_map->attr->nexthop = ref_nexthop (nexthop);
	    if (CONFIG_MRTD->route_map->attr->link_local)
		deref_nexthop (CONFIG_MRTD->route_map->attr->link_local);
	    CONFIG_MRTD->route_map->attr->link_local = nexthop;
	}
	else {
	    if (BGP4_BIT_TEST (CONFIG_MRTD->route_map->attr->attribs,
			       PA4_TYPE_NEXTHOP)) {
		if (CONFIG_MRTD->route_map->attr->nexthop->prefix->family 
			== AF_INET) {
		    if (CONFIG_MRTD->route_map->attr->nexthop4)
			deref_nexthop (CONFIG_MRTD->route_map->attr->nexthop4);
		    CONFIG_MRTD->route_map->attr->nexthop4 =
			CONFIG_MRTD->route_map->attr->nexthop; /* save */
		}
		else
		    deref_nexthop (CONFIG_MRTD->route_map->attr->nexthop);
		CONFIG_MRTD->route_map->attr->nexthop = nexthop;
	    }
	    else
		CONFIG_MRTD->route_map->attr->nexthop = nexthop;
	}
	BGP4_BIT_SET (CONFIG_MRTD->route_map->attr->attribs, PA4_TYPE_NEXTHOP);
	return (1);
    }
#else
    deref_nexthop (nexthop);
    return (-1);
#endif /* HAVE_IPV6 */
}


static int
config_route_map_metric (uii_connection_t * uii, int metric)
{
    assert (CONFIG_MRTD->route_map);
    assert (CONFIG_MRTD->route_map->attr);
    if (uii->negative) {
        if (BGP4_BIT_TEST (CONFIG_MRTD->route_map->attr->attribs, 
			   PA4_TYPE_METRIC)) {
            CONFIG_MRTD->route_map->attr->multiexit = 0;
            BGP4_BIT_RESET (CONFIG_MRTD->route_map->attr->attribs, PA4_TYPE_METRIC);
	    return (1);
	}
	return (0);
    }
    CONFIG_MRTD->route_map->attr->multiexit = metric;
    BGP4_BIT_SET (CONFIG_MRTD->route_map->attr->attribs, PA4_TYPE_METRIC);
    return (1);
}


static int
config_route_map_localpref (uii_connection_t * uii, int localpref)
{
    assert (CONFIG_MRTD->route_map);
    assert (CONFIG_MRTD->route_map->attr);
    if (uii->negative) {
        if (BGP4_BIT_RESET (CONFIG_MRTD->route_map->attr->attribs, 
			    PA4_TYPE_LOCALPREF)) {
            CONFIG_MRTD->route_map->attr->local_pref = 0;
            BGP4_BIT_RESET (CONFIG_MRTD->route_map->attr->attribs, 
			    PA4_TYPE_LOCALPREF);
	    return (1);
	}
	return (0);
    }
    CONFIG_MRTD->route_map->attr->local_pref = localpref;
    BGP4_BIT_SET (CONFIG_MRTD->route_map->attr->attribs, PA4_TYPE_LOCALPREF);
    return (1);
}


static int
config_route_map_community (uii_connection_t * uii, char *string, int opt_num,
			    char *additive)
{
    u_long value;
    char *cp;

    if (uii->negative) {
        if (BGP4_BIT_TEST (CONFIG_MRTD->route_map->attr->attribs, 
			    PA4_TYPE_COMMUNITY)) {
	    Delete_community (CONFIG_MRTD->route_map->attr->community);
	    CONFIG_MRTD->route_map->attr->community = NULL;
            BGP4_BIT_RESET (CONFIG_MRTD->route_map->attr->attribs, 
			    PA4_TYPE_COMMUNITY);
            return (1);
	}
        return (0);
    }

    if (opt_num > 0) {
        /* delete this before fogret */
	Delete (additive);
    }
    if (strcasecmp (string, "no-export") == 0)
	value = COMMUNITY_NO_EXPORT;
    else if (strcasecmp (string, "no-advertise") == 0)
	value = COMMUNITY_NO_ADVERTISE;
    else if (strcasecmp (string, "no-export-subconfed") == 0)
	value = COMMUNITY_NO_EXPORT_SUBCONFED;
    else {
	value = strtoul10 (string, &cp);
	if (*cp != '\0') {
	    config_notice (TR_ERROR, uii,
		           "route-map bad community %s\n", string);
	    Delete (string);
	    return (-1);
	}
    }
    Delete (string);

    assert (CONFIG_MRTD->route_map);
    assert (CONFIG_MRTD->route_map->attr);

    if (!BGP4_BIT_TEST (CONFIG_MRTD->route_map->attr->attribs, 
			PA4_TYPE_COMMUNITY)) {
	CONFIG_MRTD->route_map->attr->community =
	    New_community (1, (u_char *) & value, 0);
    }
    else {
	if (opt_num > 0) {	/* additive */
	    CONFIG_MRTD->route_map->attr->community->len++;
	    CONFIG_MRTD->route_map->attr->community->value =
		(u_long *) ReallocateArray (
			      CONFIG_MRTD->route_map->attr->community->value,
					       u_long,
			       CONFIG_MRTD->route_map->attr->community->len);
	    CONFIG_MRTD->route_map->attr->community->value
		[CONFIG_MRTD->route_map->attr->community->len - 1] = value;
	}
	else {
	    Delete_community (CONFIG_MRTD->route_map->attr->community);
	    CONFIG_MRTD->route_map->attr->community =
		New_community (1, (u_char *) & value, 0);
	}
    }
    BGP4_BIT_SET (CONFIG_MRTD->route_map->attr->attribs, PA4_TYPE_COMMUNITY);
    return (1);
}


static int
config_route_map_aspath (uii_connection_t * uii, char *arg)
{
    char *aspath = arg;

    assert (CONFIG_MRTD->route_map);
    assert (CONFIG_MRTD->route_map->attr);

    if (uii->negative) {
        if (BGP4_BIT_TEST (CONFIG_MRTD->route_map->attr->attribs, 
			   PA4_TYPE_ASPATH)) {
	    Delete_ASPATH (CONFIG_MRTD->route_map->attr->aspath);
            CONFIG_MRTD->route_map->attr->aspath = NULL;
            BGP4_BIT_RESET (CONFIG_MRTD->route_map->attr->attribs, 
			   PA4_TYPE_ASPATH);
	    return (1);
	}
	return (0);
    }

    if (strncasecmp (aspath, "prepend ", 8) == 0) {
	aspath += 8;
	BIT_SET (CONFIG_MRTD->route_map->flag, ROUTE_MAP_ASPATH_PREPEND);
    }
    if (BGP4_BIT_TEST (CONFIG_MRTD->route_map->attr->attribs, 
			   PA4_TYPE_ASPATH))
	Delete_ASPATH (CONFIG_MRTD->route_map->attr->aspath);
    if ((CONFIG_MRTD->route_map->attr->aspath = 
		aspth_from_string (aspath)) == NULL) {
	config_notice (TR_ERROR, uii,
		       "route-map bad aspath %s\n", aspath);
        Delete (arg);
        return (-1);
    }
    CONFIG_MRTD->route_map->attr->home_AS = 
	bgp_get_home_AS (CONFIG_MRTD->route_map->attr->aspath);
    BGP4_BIT_SET (CONFIG_MRTD->route_map->attr->attribs, PA4_TYPE_ASPATH);
    Delete (arg);
    return (1);
}


static int
config_route_map_atomic (uii_connection_t * uii)
{
    /* Atomic Aggregate */
    assert (CONFIG_MRTD->route_map);
    assert (CONFIG_MRTD->route_map->attr);
    if (uii->negative) {
        if (BGP4_BIT_TEST (CONFIG_MRTD->route_map->attr->attribs, 
		        PA4_TYPE_ATOMICAGG)) {
            BGP4_BIT_RESET (CONFIG_MRTD->route_map->attr->attribs, 
		            PA4_TYPE_ATOMICAGG);
            return (1);
	}
	return (0);
    }
    BGP4_BIT_SET (CONFIG_MRTD->route_map->attr->attribs, PA4_TYPE_ATOMICAGG);
    return (1);
}


static int
config_route_map_aggregator (uii_connection_t * uii, int as, prefix_t * prefix)
{
    assert (CONFIG_MRTD->route_map);
    assert (CONFIG_MRTD->route_map->attr);
    if (uii->negative) {
        if (BGP4_BIT_TEST (CONFIG_MRTD->route_map->attr->attribs, 
		           PA4_TYPE_AGGREGATOR)) {
            Deref_Prefix (CONFIG_MRTD->route_map->attr->aggregator.prefix);
    	    CONFIG_MRTD->route_map->attr->aggregator.as = 0;
    	    CONFIG_MRTD->route_map->attr->aggregator.prefix = NULL;
    	    BGP4_BIT_SET (CONFIG_MRTD->route_map->attr->attribs, 
			  PA4_TYPE_AGGREGATOR);
	    return (1);
	}
	return (0);
    }
    if (BGP4_BIT_TEST (CONFIG_MRTD->route_map->attr->attribs, 
		    PA4_TYPE_AGGREGATOR))
        Deref_Prefix (CONFIG_MRTD->route_map->attr->aggregator.prefix);
    CONFIG_MRTD->route_map->attr->aggregator.as = as;
    CONFIG_MRTD->route_map->attr->aggregator.prefix = prefix;
    BGP4_BIT_SET (CONFIG_MRTD->route_map->attr->attribs, PA4_TYPE_AGGREGATOR);
    return (1);
}


static int
config_route_map_dpa (uii_connection_t * uii, int as, int value)
{
    /* set dpa */
    assert (CONFIG_MRTD->route_map);
    assert (CONFIG_MRTD->route_map->attr);
    if (uii->negative) {
	if (BGP4_BIT_SET (CONFIG_MRTD->route_map->attr->attribs, 
			  PA4_TYPE_DPA)) {
    	    CONFIG_MRTD->route_map->attr->dpa.as = 0;
    	    CONFIG_MRTD->route_map->attr->dpa.value = 0;
    	    BGP4_BIT_RESET (CONFIG_MRTD->route_map->attr->attribs, 
			    PA4_TYPE_DPA);
	    return (1);
	}
	return (0);
    }
    CONFIG_MRTD->route_map->attr->dpa.as = as;
    CONFIG_MRTD->route_map->attr->dpa.value = value;
    BGP4_BIT_SET (CONFIG_MRTD->route_map->attr->attribs, PA4_TYPE_DPA);
    return (1);
}


void
config_rtmap_init (void)
{
    set_uii (UII, UII_PROMPT, UII_CONFIG_ROUTE_MAP, "Route Map> ", 0);

    uii_add_command2 (UII_CONFIG, 0, "route-map %d [%d|nil]", 
		      config_route_map, "Defines route map");
    uii_add_command2 (UII_CONFIG, 0, "no route-map %d [%d|nil]", 
		      config_route_map, "Deletes route map");

    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "match ip address %d",
		      config_route_map_match_address, 
		      "Matches the ip address");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "no match ip address",
		      config_route_map_match_address, 
		      "Removes the ip address match");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "match as-path %d",
		      config_route_map_match_aspath, 
		      "Matches the as-path");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "no match as-path",
		      config_route_map_match_aspath, 
		      "Removes the as-path match");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "match community %d",
		      config_route_map_match_community, 
		      "Matches the community");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "no match community",
		      config_route_map_match_community, 
		      "Removes the community match");

    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, 
		      "set origin (igp|egp|incomplete)",
		      config_route_map_origin, "Sets origin");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, 
		      "set origin (egp) %d", /* for cisco compatibility */
		      config_route_map_origin, "Sets origin");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "no set origin",
		      config_route_map_origin, "Resets origin");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "set as-path %S",
		      config_route_map_aspath, "Sets aspath");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "no set as-path",
		      config_route_map_aspath, "Resets aspath");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "set next-hop %M",
		      config_route_map_nexthop, "Sets nexthop");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "no set next-hop",
		      config_route_map_nexthop, "Resets nexthop");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "set metric %d",
		      config_route_map_metric, "Sets mertic");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "no set metric",
		      config_route_map_metric, "Resets mertic");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "set weight %d",
		      config_route_map_weight, "Sets weight");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "no set weight",
		      config_route_map_weight, "Resets weight");
/* for aompatibility */
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "set aspath %S",
		      config_route_map_aspath, "Sets aspath");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "no set aspath",
		      config_route_map_aspath, "Resets aspath");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "set nexthop %M",
		      config_route_map_nexthop, "Sets nexthop");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "no set nexthop",
		      config_route_map_nexthop, "Resets nexthop");

    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, 
		      "set community %s [additive]",
		      config_route_map_community, "Sets community");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, 
		      "no set community",
		      config_route_map_community, "Resets community");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "set dpa as %d %d",
		      config_route_map_dpa, "Sets dpa");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, "no set dpa",
		      config_route_map_dpa, "Resets dpa");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0,
		      "set atomic-aggregate", config_route_map_atomic,
		      "Sets atomic-aggregate");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0,
		      "no set atomic-aggregate", config_route_map_atomic,
		      "Resets atomic-aggregate");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, 
		      "set aggregator as %d %M",
		      config_route_map_aggregator, "Sets aggregator");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0, 
		      "no set aggregator",
		      config_route_map_aggregator, "Resets aggregator");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0,
		      "set local-preference %d",
		      config_route_map_localpref, "Sets local preference");
    uii_add_command2 (UII_CONFIG_ROUTE_MAP, 0,
		      "no set local-preference",
		      config_route_map_localpref, "Resets local preference");
}

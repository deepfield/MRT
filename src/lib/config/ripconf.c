/* 
 * $Id: ripconf.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>
#include <rip.h>
#include <config_file.h>
#include <protoconf.h>

/* Comments...
 * Config can work from a file or from user configuration via a
 * socket.
 */


static int
config_distribute_list (uii_connection_t * uii,
			int num, char *in_or_out, int opt_num, char *name)
{
    interface_t *interface;
    dlist_t *dlist;
    rip_t *rip = RIP;
    int out = 0;

#ifdef HAVE_IPV6
    if (CONFIG_MRTD->protocol == PROTO_RIPNG)
	rip = RIPNG;
#endif /* HAVE_IPV6 */

    if (num < 0 || num >= MAX_ALIST) {
	config_notice (TR_ERROR, uii,
		       "wrong access-list number %d (should be 0 <= x < %d)\n",
		       num, MAX_ALIST);
	Delete (in_or_out);
	if (opt_num > 0)
	    Delete (name);
	return (-1);
    }

    if (opt_num <= 0)
	name = "";
    config_notice (TR_PARSE, uii,
		 "CONFIG distribute-list %d %s %s\n", num, in_or_out, name);
    out = (strcasecmp (in_or_out, "out") == 0);
    Delete (in_or_out);

    if (opt_num > 0) {
	if ((interface = find_interface_byname (name)) == NULL) {
	    config_notice (TR_ERROR, uii,
			   "unkown interface %s\n", name);
	    Delete (name);
	    return (-1);
	}
	LL_Iterate (rip->ll_dlists, dlist) {
	    if (dlist->interface == interface && dlist->out == out) {
		break;
	    }
	}
	if (uii->negative) {
	    if (dlist) {
	        LL_Remove (rip->ll_dlists, dlist);
		rip_distribute_list_recheck (rip);
	    }
	}
	else {
	    if (dlist == NULL) {
	        dlist = New (dlist_t);
	        LL_Add (rip->ll_dlists, dlist);
	    }
	    dlist->num = num;
	    dlist->out = out;
	    dlist->interface = interface;
	    rip_distribute_list_recheck (rip);
	}
	Delete (name);
    }
    else {
	LL_Iterate (rip->ll_dlists, dlist) {
	    if (dlist->interface == NULL && dlist->out == out) {
		break;
	    }
	}
	if (uii->negative) {
	    if (dlist) {
	        LL_Remove (rip->ll_dlists, dlist);
		rip_distribute_list_recheck (rip);
	    }
	}
	else {
	    if (dlist == NULL) {
	        dlist = New (dlist_t);
		LL_Add (rip->ll_dlists, dlist);
	    }
	    dlist->num = num;
	    dlist->out = out;
	    dlist->interface = NULL;
	    rip_distribute_list_recheck (rip);
	}
    }
    return (1);
}


static void
get_config_rt_rip (rip_t *rip)
{
    int i;
    prefix_t *prefix;
    char *name;
    dlist_t *dlist;
    int default_port = RIP_DEFAULT_PORT;

#ifdef HAVE_IPV6
    if (rip->proto == PROTO_RIPNG)
        default_port = RIPNG_DEFAULT_PORT;
#endif /* HAVE_IPV6 */
    if (rip->port != default_port)
        config_add_output ("router %s %d\n", 
	    proto2string (rip->proto), rip->port);
    else
        config_add_output ("router %s\n", proto2string (rip->proto));

    if (rip->alist >= 0)
        config_add_output ("  accept-update-from %d\n", rip->alist);

    LL_Iterate (rip->ll_networks, prefix) {
	config_add_output ("  network %s\n", prefix_toax (prefix));
    }

    LL_Iterate (rip->ll_networks2, name) {
	config_add_output ("  network %s\n", name);
    }

    LL_Iterate (rip->ll_dlists, dlist) {
        config_add_output ("  distribute-list %d %s %s\n",
                           dlist->num, (dlist->out)?"out":"in",
                           dlist->interface ? dlist->interface->name : "");
    }

    for (i = 0; i <= PROTO_MAX; i++) {
        if (BGP4_BIT_TEST (rip->redistribute_mask, i))
	    config_add_output ("  redistribute %s\n", proto2string (i));
    }
}


static void
get_config_router_rip (rip_t *rip)
{
    schedule_event_and_wait ("get_config_rt_rip", rip->schedule,
                             get_config_rt_rip, 1, rip);
}


#ifdef HAVE_IPV6
/*
 * start RIPNG protocol configuration 
 */
static int
config_router_ripng_port (uii_connection_t * uii, int port)
{
    if (uii->negative) {
        if (!BGP4_BIT_TEST (MRT->protocols, PROTO_RIPNG))
	    return (0);
        BGP4_BIT_RESET (MRT->protocols, PROTO_RIPNG);
        config_del_module (CF_DELIM, "router ripng", get_config_router_rip, 
			   RIPNG);
        ripng_stop ();
        return (1);
    }
    CONFIG_MRTD->protocol = PROTO_RIPNG;
    uii->previous[++uii->prev_level] = uii->state;
    uii->state = UII_CONFIG_ROUTER_RIPNG;
    if (BGP4_BIT_TEST (MRT->protocols, PROTO_RIPNG))
	return (0);

    BGP4_BIT_SET (MRT->protocols, PROTO_RIPNG);
    config_add_module (CF_DELIM, "router ripng", get_config_router_rip, RIPNG);
    ripng_start (port);
    return (1);
}


static int
config_router_ripng (uii_connection_t * uii)
{
    return (config_router_ripng_port (uii, RIPNG_DEFAULT_PORT));
}
#endif /* HAVE_IPV6 */


/*
 * start RIP protocol configuration 
 */
static int
config_router_rip_port (uii_connection_t * uii, int port)
{
    if (uii->negative) {
        if (!BGP4_BIT_TEST (MRT->protocols, PROTO_RIP))
	    return (0);
        BGP4_BIT_RESET (MRT->protocols, PROTO_RIP);
        config_del_module (CF_DELIM, "router rip", get_config_router_rip, 
			   RIP);
        rip2_stop ();
        return (1);
    }
    CONFIG_MRTD->protocol = PROTO_RIP;
    uii->previous[++uii->prev_level] = uii->state;
    uii->state = UII_CONFIG_ROUTER_RIP;
    if (BGP4_BIT_TEST (MRT->protocols, PROTO_RIP))
	return (0);

    BGP4_BIT_SET (MRT->protocols, PROTO_RIP);
    config_add_module (CF_DELIM, "router rip", get_config_router_rip, RIP);
    rip2_start (port);
    return (1);
}


static int
config_router_rip (uii_connection_t * uii)
{
    return (config_router_rip_port (uii, RIP_DEFAULT_PORT));
}


static int
config_router_rip_network_prefix (uii_connection_t * uii, prefix_t *prefix)
{
    rip_t *rip = RIP;
    prefix_t *network;

    assert (CONFIG_MRTD->protocol == PROTO_RIP ||
	CONFIG_MRTD->protocol == PROTO_RIPNG);

#ifdef HAVE_IPV6
    if (CONFIG_MRTD->protocol == PROTO_RIPNG)
	rip = RIPNG;
#endif /* HAVE_IPV6 */

    LL_Iterate (rip->ll_networks, network) {
        if (prefix_compare (prefix, network)) { 
	    break;
        }
    }

    if (uii->negative) {
	 if (network == NULL) {
	    Deref_Prefix (prefix);
	    return (0);
	}

	if (MRT->rib_redistribute_network)
            MRT->rib_redistribute_network (rip->proto, 0, prefix, 0, 0);

        LL_Remove (rip->ll_networks, network);
        rip_interface_recheck (rip);
    }
    else {
        if (network) {
	    Deref_Prefix (prefix);
	    return (0);
	}

	if (MRT->rib_redistribute_network)
            MRT->rib_redistribute_network (rip->proto, 0, prefix, 1, 0);

        LL_Add (rip->ll_networks, Ref_Prefix (prefix));
        rip_interface_recheck (rip);
    }

    Deref_Prefix (prefix);
    return (1);
}


static int
config_router_rip_network_interface (uii_connection_t * uii, char *name)
{
    rip_t *rip = RIP;
    char *net2;

    assert (CONFIG_MRTD->protocol == PROTO_RIP ||
	CONFIG_MRTD->protocol == PROTO_RIPNG);

#ifdef HAVE_IPV6
    if (CONFIG_MRTD->protocol == PROTO_RIPNG)
	rip = RIPNG;
#endif /* HAVE_IPV6 */

	/* check already enabled/exists */
    LL_Iterate (rip->ll_networks2, net2) {
        if (strcasecmp (name, net2) == 0) { 
	    break;
        }
    }

    if (uii->negative) {
		if (net2 != NULL) {
			LL_Remove (rip->ll_networks2, net2);
			Delete (net2);
    	    rip_interface_recheck (rip);
		}
        Delete (name);
    }
    else {
		if (net2 == NULL) {
			LL_Add (rip->ll_networks2, name);
    			rip_interface_recheck (rip);
		}
		else {
            Delete (name);
		}
    }

    return (1);
}


/*
 * Redistribute a given protocol into another protocol 
 */
static int
config_router_rip_redistribute (uii_connection_t * uii, char *proto_string)
{
    rip_t *rip = RIP;
    int proto;
    int afi = AFI_IP;
    int safi = SAFI_UNICAST;

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

#ifdef HAVE_IPV6
    if (CONFIG_MRTD->protocol == PROTO_RIPNG) {
	rip = RIPNG;
        afi = AFI_IP6;
    }
#endif /* HAVE_IPV6 */

    if (uii->negative) {
        if (!BGP4_BIT_TEST (rip->redistribute_mask, proto)) {
	    Delete (proto_string);
	    return (0);
	}
        BGP4_BIT_RESET (rip->redistribute_mask, proto);
	if (MRT->rib_redistribute_request)
	    MRT->rib_redistribute_request (rip->proto, 0, proto, 0, afi, safi);
        Delete (proto_string);
        return (1);
    }

    if (BGP4_BIT_TEST (rip->redistribute_mask, proto)) {
	Delete (proto_string);
	return (0);
    }
    BGP4_BIT_SET (rip->redistribute_mask, proto);
    if (MRT->rib_redistribute_request)
	MRT->rib_redistribute_request (rip->proto, 0, proto, 1, afi, safi);
    Delete (proto_string);
    return (1);
}


static int
config_router_rip_accept_update_from (uii_connection_t * uii, int num)
{
    rip_t *rip = RIP;

    assert (CONFIG_MRTD->protocol == PROTO_RIP ||
	CONFIG_MRTD->protocol == PROTO_RIPNG);

#ifdef HAVE_IPV6
    if (CONFIG_MRTD->protocol == PROTO_RIPNG)
	rip = RIPNG;
#endif /* HAVE_IPV6 */

    if (uii->negative) {
	rip->alist = -1;
	return (0);
    }
    rip->alist = num;
    return (1);
}


void
config_rip_init (void)
{
    set_uii (UII, UII_PROMPT, UII_CONFIG_ROUTER_RIP, "Router RIP> ", 0);
#ifdef HAVE_IPV6
    set_uii (UII, UII_PROMPT, UII_CONFIG_ROUTER_RIPNG, "Router RIPng> ", 0);
#endif /* HAVE_IPV6 */

    /* Interactive commands */
    uii_add_command_schedule (UII_NORMAL, 0, "show rip", rip2_show,
		      "Show RIP status", RIP->schedule);
    uii_add_command_schedule (UII_NORMAL, 0, "show rip routes [%n]",
		      rip2_show_routing_table, "Show RIP routing table",
		      RIP->schedule);
    uii_add_command_schedule (UII_NORMAL, 0, "show ip rip", 
		      rip2_show, "Show RIP status", RIP->schedule);
    uii_add_command_schedule (UII_NORMAL, 0, 
		      "show ip rip routes [%n]",
		      rip2_show_routing_table, "Show RIP routing table",
		      RIP->schedule);

#ifdef HAVE_IPV6
    uii_add_command_schedule (UII_NORMAL, 0, "show ripng", 
		      ripng_show,
		      "Show RIPng Status", RIPNG->schedule);
    uii_add_command_schedule (UII_NORMAL, 0, "show ipv6 ripng", 
		      ripng_show,
		      "Show RIPng Status", RIPNG->schedule);
    uii_add_command_schedule (UII_NORMAL, 0, 
		      "show ripng routes [%n]",
		      ripng_show_routing_table,
		      "Show RIPng routing table", RIPNG->schedule);
    uii_add_command_schedule (UII_NORMAL, 0, 
		      "show ipv6 ripng routes [%n]", ripng_show_routing_table,
		      "Show RIPng routing table", RIPNG->schedule);
#endif /* HAVE_IPV6 */

    /* Config mode */
    uii_add_command_schedule (UII_CONFIG, 0, "router rip",
		      config_router_rip, "Enables RIP routing protocol",
		      RIP->schedule);
    uii_add_command_schedule (UII_CONFIG, 0, "no router rip",
		      config_router_rip, "Disables RIP routing protocol",
		      RIP->schedule);
    uii_add_command_schedule (UII_CONFIG, 0, "router rip %d",
		      config_router_rip_port, 
		      "Enables RIP routing protocol with port number",
		      RIP->schedule);

#ifdef HAVE_IPV6
    uii_add_command_schedule (UII_CONFIG, 0, "router ripng",
		      config_router_ripng, "Enables RIPng routing protocol",
		      RIPNG->schedule);
    uii_add_command_schedule (UII_CONFIG, 0, "no router ripng",
		      config_router_ripng, "Disable RIPng routing protocol",
		      RIPNG->schedule);
    uii_add_command_schedule (UII_CONFIG, 0, "router ripng %d",
		      config_router_ripng_port, 
		      "Enables RIPng routing protocol with port number",
		      RIPNG->schedule);
#endif /* HAVE_IPV6 */

    uii_add_command_schedule (UII_CONFIG_ROUTER_RIP, 0, 
		      "network %p",
		      config_router_rip_network_prefix, 
		      "Turns ON RIP routing for the network",
		      RIP->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIP, 0, 
		      "network %n",
		      config_router_rip_network_interface, 
		      "Turns ON RIP routing on the interface",
		      RIP->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIP, 0, 
		      "no network %p",
		      config_router_rip_network_prefix, 
		      "Turns OFF RIP routing for the network",
		      RIP->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIP, 0, 
		      "no network %n",
		      config_router_rip_network_interface, 
		      "Turns OFF RIP routing on the interface",
		      RIP->schedule);

    /* shared by RIP and RIPNG */
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIP, 0, 
		      "accept-update-from %d",
		      config_router_rip_accept_update_from, 
		      "Accepts updates only from as specified",
		      RIP->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIP, 0, 
		      "no accept-update-from",
		      config_router_rip_accept_update_from, 
		      "Accepts all updates",
		      RIP->schedule);

#ifdef HAVE_IPV6
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIPNG, 0, 
		      "network %P",
		      config_router_rip_network_prefix, 
		      "Turns ON RIPng routing for the network",
		      RIPNG->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIPNG, 0, 
		      "network %n",
		      config_router_rip_network_interface, 
		      "Turns ON RIPng routing on the interface",
		      RIPNG->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIPNG, 0, 
		      "no network %P",
		      config_router_rip_network_prefix, 
		      "Turns OFF RIPng routing for the network",
		      RIPNG->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIPNG, 0, 
		      "no network %n",
		      config_router_rip_network_interface, 
		      "Turns OFF RIPng routing on the interface",
		      RIPNG->schedule);
#endif /* HAVE_IPV6 */

    uii_add_command_schedule (UII_CONFIG_ROUTER_RIP, 0,
	"redistribute (static|ospf|bgp|direct|connected|kernel)",
		      config_router_rip_redistribute,
		      "Redistributes route from the protocol",
		      RIP->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIP, 0,
	"no redistribute (static|ospf|bgp|direct|connected|kernel)",
		      config_router_rip_redistribute,
		      "Not redistribute route from the protocol",
		      RIP->schedule);

#ifdef HAVE_IPV6
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIPNG, 0,
	"redistribute (static|ospf|bgp|direct|connected|kernel)",
		      config_router_rip_redistribute,
		      "Redistributes route from the protocol",
		      RIPNG->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIPNG, 0,
	"no redistribute (static|ospf|bgp|direct|connected|kernel)",
		      config_router_rip_redistribute,
		      "Not redistribute route from the protocol",
		      RIPNG->schedule);
#endif /* HAVE_IPV6 */

    uii_add_command_schedule (UII_CONFIG_ROUTER_RIP, 0,
		      "distribute-list %d (in|out) [%s]",
		      config_distribute_list,
		      "Applies access list to route [on interface]",
		      RIP->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIP, 0,
		      "no distribute-list %d (in|out) [%s]",
		      config_distribute_list,
		      "Deletes access list to route [on interface]",
		      RIP->schedule);

#ifdef HAVE_IPV6
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIPNG, 0,
		      "distribute-list %d (in|out) [%s]",
		      config_distribute_list,
		      "Applies access list to route [on interface]",
		      RIPNG->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_RIPNG, 0,
		      "no distribute-list %d (in|out) [%s]",
		      config_distribute_list,
		      "Deletes access list to route [on interface]",
		      RIPNG->schedule);
#endif /* HAVE_IPV6 */
}

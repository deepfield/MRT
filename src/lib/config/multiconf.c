/* 
 * $Id: multiconf.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>

#ifdef HAVE_IGMP
#include <config_file.h>
#include <protoconf.h>
#include <igmp.h>
#include <pim.h>
#include <dvmrp.h>


#ifdef HAVE_MROUTING
static int
config_interface_tunnel_source (uii_connection_t * uii, prefix_t *prefix)
{
    if (!BIT_TEST (CONFIG_MRTD->interface->flags, IFF_VIF_TUNNEL)) {
	config_notice (TR_ERROR, uii, "%s is not a tunnel interface\n", 
			CONFIG_MRTD->interface->name);
	Deref_Prefix (prefix);
	return (-1);
    }
    if (CONFIG_MRTD->interface->tunnel_source != NULL)
	Deref_Prefix (CONFIG_MRTD->interface->tunnel_source);
    CONFIG_MRTD->interface->tunnel_source = prefix;
    return (1);
}


static int
config_interface_tunnel_destination (uii_connection_t * uii, prefix_t *prefix)
{
    if (!BIT_TEST (CONFIG_MRTD->interface->flags, IFF_VIF_TUNNEL)) {
	config_notice (TR_ERROR, uii, "%s is not a tunnel interface\n", 
			CONFIG_MRTD->interface->name);
	Deref_Prefix (prefix);
	return (-1);
    }
        
    if (CONFIG_MRTD->interface->tunnel_destination != NULL)
	Deref_Prefix (CONFIG_MRTD->interface->tunnel_destination);
    CONFIG_MRTD->interface->tunnel_destination = prefix;
    return (1);
}

static int
config_interface_tunnel (uii_connection_t * uii, int n)
{
    interface_t *interface;

    LL_Iterate (CONFIG_MRTD->ll_interfaces, interface) {
	if (interface->vif_index == n)
	    break;
    }

    if (uii->negative) {
	if (interface) {
	    LL_Remove (CONFIG_MRTD->ll_interfaces, interface);
            config_del_module (CF_DELIM, "interface tunnel", 
		               get_config_interface, interface);
            return (1);
	}
	return (0);
    }

    if (interface == NULL) {
	char name[16];
	int i;

	/* assign an index backward from the end to the tunnel if */
	for (i = MAX_INTERFACES - 1; i > 0; i--) {
	    if (INTERFACE_MASTER->index2if[i] == NULL)
		break;
	}
	if (i <= 0) {
	    config_notice (TR_ERROR, uii, "too many tunnel interfaces\n");
	    return (-1);
	}
	sprintf (name, "tunnel%d", n);
	interface = new_interface (name, IFF_VIF_TUNNEL, 0, i);
    }

    LL_Add (CONFIG_MRTD->ll_interfaces, interface);
    /* this is a memory to avoid duplication of config_add_module */
    config_add_module (CF_DELIM, "interface tunnel", 
		       get_config_interface, interface);

    uii->previous[++uii->prev_level] = uii->state;
    uii->state = UII_CONFIG_INTERFACE;

    CONFIG_MRTD->interface = interface;

    return (1);
}


static int
config_show_ip_mroute (uii_connection_t *uii, int optnum, char *ifname)
{
    if (optnum > 0) {
        int ret;
        ret = show_cache_entries (uii, AF_INET, ifname);
	Delete (ifname);
	return (ret);
    }
    return (show_cache_entries (uii, AF_INET, NULL));
}

#endif /* HAVE_MROUTING */


#if defined(HAVE_MROUTING) || defined(HAVE_MROUTING6)
static int
config_interface_mc_ttl_threashold (uii_connection_t * uii, int ttl)
{
    CONFIG_MRTD->interface->threshold = ttl;
    return (1);
}


static int
config_interface_mc_rate_limit (uii_connection_t * uii, int rate)
{
    CONFIG_MRTD->interface->rate_limit = rate;
    return (1);
}
#endif /* HAVE_MROUTING || HAVE_MROUTING6 */


static void
get_config_ip_multicast_routing (void)
{
    config_add_output ("ip multicast-routing\n");
}


static int
config_ip_multicast_routing (uii_connection_t * uii)
{
    if (uii->negative) {
        config_del_module (0, "ip multicast-routing", 
		           get_config_ip_multicast_routing, NULL);
        return (1);
    }
    config_add_module (0, "ip multicast-routing", 
		       get_config_ip_multicast_routing, NULL);
    return (1);
}


#ifdef HAVE_IPV6
static void
get_config_ipv6_multicast_routing (void)
{
    config_add_output ("ipv6 multicast-routing\n");
}


static int
config_ipv6_multicast_routing (uii_connection_t * uii)
{
    if (uii->negative) {
        config_del_module (0, "ipv6 multicast-routing", 
		           get_config_ipv6_multicast_routing, NULL);
        return (1);
    }
    config_add_module (0, "ipv6 multicast-routing", 
		       get_config_ipv6_multicast_routing, NULL);
    return (1);
}
#endif /* HAVE_IPV6 */


#ifdef HAVE_MROUTING6
static int
config_show_ipv6_mroute (uii_connection_t *uii, int optnum, char *ifname)
{
    if (optnum > 0) {
        int ret;
        ret = show_cache_entries (uii, AF_INET6, ifname);
	Delete (ifname);
	return (ret);
    }
    return (show_cache_entries (uii, AF_INET6, NULL));
}
#endif /* HAVE_MROUTING6 */


void
config_multicast_init (void)
{
#ifdef HAVE_MROUTING
    uii_add_command_schedule (UII_NORMAL, COMMAND_NORM, 
			"show ip mroute [%n]",
		      config_show_ip_mroute, 
		      "Show IP multicast routing table", IGMP->schedule);
    uii_add_command_schedule (UII_NORMAL, COMMAND_NORM, 
			"show ip mcache [%n]",
		      config_show_ip_mroute, 
		      "Show IP multicast routing table", IGMP->schedule);

    uii_add_command2 (UII_CONFIG, COMMAND_NORM, "interface tunnel %d",
		      config_interface_tunnel, 
		      "Configure tunnel interface");
    uii_add_command2 (UII_CONFIG, COMMAND_NORM, "no interface tunnel %d",
		      config_interface_tunnel, 
		      "Delete tunnel interface");
    uii_add_command2 (UII_CONFIG_INTERFACE, COMMAND_NORM, 
		      "tunnel source %m",
		      config_interface_tunnel_source, 
		      "Sets source address of the interface");
    uii_add_command2 (UII_CONFIG_INTERFACE, COMMAND_NORM, 
		      "tunnel destination %m",
		      config_interface_tunnel_destination, 
		      "Sets destination address of the interface");
#endif /* HAVE_MROUTING */

#if defined(HAVE_MROUTING) || defined(HAVE_MROUTING6)
    uii_add_command2 (UII_CONFIG_INTERFACE, COMMAND_NORM, 
		      "ip multicast ttl-threshold %d",
		      config_interface_mc_ttl_threashold, 
		      "Configure the TTL threshold");
    uii_add_command2 (UII_CONFIG_INTERFACE, COMMAND_NORM, 
		      "ip multicast rate-limit %d",
		      config_interface_mc_rate_limit, 
		      "Configure the rate limit in kbps");
#endif /* HAVE_MROUTING || HAVE_MROUTING6 */

    uii_add_command_schedule (UII_NORMAL, COMMAND_NORM, "show ip igmp groups",
		      igmp_show_group, "Show IP igmp group membership table",
		      IGMP->schedule);

    /* Config mode */
    uii_add_command2 (UII_CONFIG, COMMAND_NORM, "ip multicast-routing",
		      config_ip_multicast_routing, 
		      "Enables IP multicast routing protocol");
    uii_add_command2 (UII_CONFIG, COMMAND_NORM, 
		      "no ip multicast-routing",
		      config_ip_multicast_routing, 
		      "Disables IP multicast routing protocol");

#ifdef HAVE_IPV6
    uii_add_command_schedule (UII_NORMAL, COMMAND_NORM, "show ipv6 igmp groups",
		      igmp6_show_group, "Show IPV6 igmp group membership table",
		      IGMPv6->schedule);

    uii_add_command2 (UII_CONFIG, COMMAND_NORM, 
		      "ipv6 multicast-routing",
		      config_ipv6_multicast_routing, 
		      "Enables IPv6 multicast routing protocol");
    uii_add_command2 (UII_CONFIG, COMMAND_NORM, 
		      "no ipv6 multicast-routing",
		      config_ipv6_multicast_routing, 
		      "Disables IPv6 multicast routing protocol");
#endif /* HAVE_IPV6 */

#ifdef HAVE_MROUTING6
    uii_add_command_schedule (UII_NORMAL, COMMAND_NORM, "show ipv6 mroute [%n]",
		      config_show_ipv6_mroute, 
		      "Show IPV6 multicast routing table", IGMPv6->schedule);
    uii_add_command_schedule (UII_NORMAL, COMMAND_NORM, "show ipv6 mcache [%n]",
		      config_show_ipv6_mroute, 
		      "Show IPV6 multicast routing table", IGMPv6->schedule);

#endif /* HAVE_MROUTING6 */
}
#endif /* IGMP */

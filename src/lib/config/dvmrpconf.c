/* 
 * $Id: dvmrpconf.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>

#ifdef HAVE_MROUTING
#include <config_file.h>
#include <protoconf.h>
#include <igmp.h>
#include <dvmrp.h>


static int
config_dvmrp_distribute_list (uii_connection_t * uii,
			int num, char *in_or_out, int opt_num, char *name)
{
    interface_t *interface;
    dlist_t *dlist;
    int out = 0;

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
    out = (strcasecmp (in_or_out, "out") == 0);
    Delete (in_or_out);

    if (opt_num > 0) {
	if ((interface = find_interface_byname (name)) == NULL) {
	    config_notice (TR_ERROR, uii,
			   "unkown interface %s\n", name);
	    Delete (name);
	    return (-1);
	}
	LL_Iterate (DVMRP->ll_dlists, dlist) {
	    if (dlist->interface == interface && dlist->out == out) {
		break;
	    }
	}
	if (uii->negative) {
	    if (dlist) {
	        LL_Remove (DVMRP->ll_dlists, dlist);
		dvmrp_distribute_list_recheck ();
	    }
	}
	else {
	    if (dlist == NULL) {
	        dlist = New (dlist_t);
	        LL_Add (DVMRP->ll_dlists, dlist);
	    }
	    dlist->num = num;
	    dlist->out = out;
	    dlist->interface = interface;
	    dvmrp_distribute_list_recheck ();
	}
	Delete (name);
    }
    else {
	LL_Iterate (DVMRP->ll_dlists, dlist) {
	    if (dlist->interface == NULL && dlist->out == out) {
		break;
	    }
	}
	if (uii->negative) {
	    if (dlist) {
	        LL_Remove (DVMRP->ll_dlists, dlist);
		dvmrp_distribute_list_recheck ();
	    }
	}
	else {
	    if (dlist == NULL) {
	        dlist = New (dlist_t);
		LL_Add (DVMRP->ll_dlists, dlist);
	    }
	    dlist->num = num;
	    dlist->out = out;
	    dlist->interface = NULL;
	    dvmrp_distribute_list_recheck ();
	}
    }
    return (1);
}


static void
get_config_rt_dvmrp (void)
{
    prefix_t *prefix;
    char *name;
    dlist_t *dlist;

    config_add_output ("router %s\n", proto2string (DVMRP->proto));

    LL_Iterate (DVMRP->ll_networks, prefix) {
	config_add_output ("  network %a\n", prefix);
    }

    LL_Iterate (DVMRP->ll_networks2, name) {
	config_add_output ("  network %s\n", name);
    }

    LL_Iterate (DVMRP->ll_leafs, name) {
	config_add_output ("  force-leaf %s\n", name);
    }

    LL_Iterate (DVMRP->ll_dlists, dlist) {
        config_add_output ("  distribute-list %d %s %s\n",
                           dlist->num, (dlist->out)?"out":"in",
                           dlist->interface ? dlist->interface->name : "");
    }
}


static void
get_config_router_dvmrp (void)
{
    schedule_event_and_wait ("get_config_rt_dvmrp", DVMRP->schedule,
                             get_config_rt_dvmrp, 0);
}


/*
 * start DVMRP protocol configuration 
 */
static int
config_router_dvmrp (uii_connection_t * uii)
{
    if (uii->negative) {
        if (!BGP4_BIT_TEST (MRT->protocols, PROTO_DVMRP))
	    return (0);
        BGP4_BIT_RESET (MRT->protocols, PROTO_DVMRP);
        config_del_module (CF_DELIM, "router dvmrp", get_config_router_dvmrp, 
			   NULL);
        dvmrp_stop ();
        return (1);
    }
    CONFIG_MRTD->protocol = PROTO_DVMRP;
    uii->previous[++uii->prev_level] = uii->state;
    uii->state = UII_CONFIG_ROUTER_DVMRP;
    if (BGP4_BIT_TEST (MRT->protocols, PROTO_DVMRP))
	return (0);

    BGP4_BIT_SET (MRT->protocols, PROTO_DVMRP);
    config_add_module (CF_DELIM, "router dvmrp", get_config_router_dvmrp, NULL);
    dvmrp_start ();
    return (1);
}


static int
config_router_dvmrp_network_prefix (uii_connection_t * uii, prefix_t *prefix)
{
    prefix_t *network;

    LL_Iterate (DVMRP->ll_networks, network) {
        if (prefix_compare (prefix, network)) { 
	    break;
        }
    }

    if (uii->negative) {
	 if (network == NULL) {
	    Deref_Prefix (prefix);
	    return (0);
	}

        LL_Remove (DVMRP->ll_networks, network);
	Deref_Prefix (network);
        dvmrp_interface_recheck ();
    }
    else {
        if (network) {
	    Deref_Prefix (prefix);
	    return (0);
	}

        LL_Add (DVMRP->ll_networks, Ref_Prefix (prefix));
        dvmrp_interface_recheck ();
    }

    Deref_Prefix (prefix);
    return (1);
}


static int
config_router_dvmrp_network_interface (uii_connection_t * uii, char *name)
{
    char *net2;

    LL_Iterate (DVMRP->ll_networks2, net2) {
        if (strcasecmp (name, net2) == 0) { 
	    break;
        }
    }

    if (uii->negative) {
	if (net2 != NULL) {
	    LL_Remove (DVMRP->ll_networks2, net2);
	    Delete (net2);
    	    dvmrp_interface_recheck ();
	}
        Delete (name);
    }
    else {
	if (net2 == NULL) {
	    LL_Add (DVMRP->ll_networks2, name);
    	    dvmrp_interface_recheck ();
	}
	else {
            Delete (name);
	}
    }

    return (1);
}


static int
config_router_dvmrp_force_leaf (uii_connection_t * uii, char *name)
{
    char *net2;

    LL_Iterate (DVMRP->ll_leafs, net2) {
        if (strcasecmp (name, net2) == 0) { 
	    break;
        }
    }

    if (uii->negative) {
	if (net2 != NULL) {
	    LL_Remove (DVMRP->ll_leafs, net2);
	    Delete (net2);
    	    dvmrp_interface_recheck ();
	}
        Delete (name);
    }
    else {
	if (net2 == NULL) {
	    LL_Add (DVMRP->ll_leafs, name);
    	    dvmrp_interface_recheck ();
	}
	else {
            Delete (name);
	}
    }

    return (1);
}


void
config_dvmrp_init (void)
{
    set_uii (UII, UII_PROMPT, UII_CONFIG_ROUTER_DVMRP, "Router DVMRP> ", 0);

    uii_add_command_schedule (UII_NORMAL, 0, "show ip dvmrp route [%n]", 
		      dvmrp_show_routing_table, "Show DVMRP routing table", 
		      DVMRP->schedule);

    uii_add_command_schedule (UII_NORMAL, 0, "show ip dvmrp neighbor [%n]", 
		      dvmrp_show_neighbors, "Show DVMRP neighbor table", 
		      DVMRP->schedule);

    uii_add_command_schedule (UII_CONFIG, 0, "router dvmrp",
		      config_router_dvmrp, 
		      "Enables DVMRP routing protocol", DVMRP->schedule);
    uii_add_command_schedule (UII_CONFIG, 0, "no router dvmrp",
		      config_router_dvmrp,
		      "Disables DVMRP routing protocol", DVMRP->schedule);

    uii_add_command_schedule (UII_CONFIG_ROUTER_DVMRP, 0,
                      "force-leaf %n",
                      config_router_dvmrp_force_leaf,
                      "Force the interface as leaf",
                      DVMRP->schedule);

    uii_add_command_schedule (UII_CONFIG_ROUTER_DVMRP, 0,
                      "network %p",
                      config_router_dvmrp_network_prefix,
                      "Turns ON DVMRP routing for the network",
                      DVMRP->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_DVMRP, 0,
                      "network %n",
                      config_router_dvmrp_network_interface,
                      "Turns ON DVMRP routing on the interface",
                      DVMRP->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_DVMRP, 0,
                      "no network %p",
                      config_router_dvmrp_network_prefix,
                      "Turns OFF DVMRP routing for the network",
                      DVMRP->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_DVMRP, 0,
                      "no network %n",
                      config_router_dvmrp_network_interface,
                      "Turns OFF DVMRP routing on the interface",
                      DVMRP->schedule);

    uii_add_command_schedule (UII_CONFIG_ROUTER_DVMRP, 0,
                      "distribute-list %d (in|out) [%s]",
                      config_dvmrp_distribute_list,
                      "Applies access list to route [on interface]",
                      DVMRP->schedule);
    uii_add_command_schedule (UII_CONFIG_ROUTER_DVMRP, 0,
                      "no distribute-list %d (in|out) [%s]",
                      config_dvmrp_distribute_list,
                      "Deletes access list to route [on interface]",
                      DVMRP->schedule);
}
#endif /* HAVE_MROUTING */

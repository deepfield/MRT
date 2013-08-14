/* 
 * $Id: pimconf.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>

#if defined(HAVE_MROUTING) || defined(HAVE_MROUTING6)
#include <config_file.h>
#include <protoconf.h>
#include <igmp.h>
#include <pim.h>
#include <dvmrp.h>


#ifdef HAVE_MROUTING
#ifdef notdef
static int
config_interface_ip_dvmrp (uii_connection_t *uii)
{
    if (uii->negative) {
        if (!BGP4_BIT_TEST (CONFIG_MRTD->interface->protocol_mask, PROTO_DVMRP))
	    return (0);
        BGP4_BIT_RESET (CONFIG_MRTD->interface->protocol_mask, PROTO_DVMRP);
        dvmrp_interface (CONFIG_MRTD->interface, OFF);
	return (1);
    }
    if (BGP4_BIT_TEST (CONFIG_MRTD->interface->protocol_mask, PROTO_PIM)) {
	config_notice (TR_ERROR, uii, "%s is already configured for PIM\n", 
		       CONFIG_MRTD->interface->name);
	return (-1);
    }
    if (BGP4_BIT_TEST (CONFIG_MRTD->interface->protocol_mask, PROTO_DVMRP))
	return (0);
    BGP4_BIT_SET (CONFIG_MRTD->interface->protocol_mask, PROTO_DVMRP);
    dvmrp_interface (CONFIG_MRTD->interface, ON);
    return (1);
}
#endif


static int
config_interface_ip_pim (uii_connection_t *uii, char *mode)
{
    Delete (mode); /* XXX */

    if (uii->negative) {
        if (!BGP4_BIT_TEST (CONFIG_MRTD->interface->protocol_mask, PROTO_PIM))
	    return (0);
        BGP4_BIT_RESET (CONFIG_MRTD->interface->protocol_mask, PROTO_PIM);
        pim_activate_interface (PROTO_PIM, CONFIG_MRTD->interface, OFF);
	return (1);
    }
    if (BGP4_BIT_TEST (CONFIG_MRTD->interface->protocol_mask, PROTO_DVMRP)) {
	config_notice (TR_ERROR, uii, "%s is already configured for DVMRP\n", 
		       CONFIG_MRTD->interface->name);
	return (-1);
    }
    if (BGP4_BIT_TEST (CONFIG_MRTD->interface->protocol_mask, PROTO_PIM))
	return (0);
    BGP4_BIT_SET (CONFIG_MRTD->interface->protocol_mask, PROTO_PIM);
    pim_activate_interface (PROTO_PIM, CONFIG_MRTD->interface, ON);
    return (1);
}


static int show_ip_pim (uii_connection_t *uii) { return (1); }

static int
show_ip_pim_neighbors (uii_connection_t *uii)
{
    return (pim_show_neighbors (uii, PROTO_PIM));
}
#endif /* HAVE_MROUTING */


#ifdef HAVE_MROUTING6
static int
config_interface_ipv6_pim (uii_connection_t *uii, char *mode)
{
    Delete (mode); /* XXX */

    if (uii->negative) {
        if (!BGP4_BIT_TEST (CONFIG_MRTD->interface->protocol_mask, PROTO_PIMV6))
	    return (0);
        BGP4_BIT_RESET (CONFIG_MRTD->interface->protocol_mask, PROTO_PIMV6);
        pim_activate_interface (PROTO_PIMV6, CONFIG_MRTD->interface, 0);
	return (1);
    }
    if (BGP4_BIT_TEST (CONFIG_MRTD->interface->protocol_mask, PROTO_PIMV6))
	return (0);
    BGP4_BIT_SET (CONFIG_MRTD->interface->protocol_mask, PROTO_PIMV6);
    pim_activate_interface (PROTO_PIMV6, CONFIG_MRTD->interface, 1);
    return (1);
}

static int show_ipv6_pim (uii_connection_t *uii) { return (1); }

static int
show_ipv6_pim_neighbors (uii_connection_t *uii)
{
    return (pim_show_neighbors (uii, PROTO_PIMV6));
}
#endif /* HAVE_MROUTING6 */


void
config_pim_init (void)
{
    /* Interactive commands */
#ifdef HAVE_MROUTING
    uii_add_command_schedule (UII_NORMAL, COMMAND_NORM, "show ip pim", 
		      show_ip_pim, "Show PIM status", PIM->schedule);
    uii_add_command_schedule (UII_NORMAL, COMMAND_NORM, 
		      "show ip pim neighbors", show_ip_pim_neighbors, 
		      "Show PIM neighbors", PIM->schedule);
#ifdef notdef
    uii_add_command_schedule (UII_CONFIG_INTERFACE, COMMAND_NORM, 
		      "ip dvmrp",
		      config_interface_ip_dvmrp, 
		      "Turns ON DVMRP routing for the interface",
		      DVMRP->schedule);
    uii_add_command_schedule (UII_CONFIG_INTERFACE, COMMAND_NORM, 
		      "no ip dvmrp", 
		      config_interface_ip_dvmrp, 
		      "Turns OFF DVMRP routing for the interface",
		      DVMRP->schedule);
#endif
    uii_add_command_schedule (UII_CONFIG_INTERFACE, COMMAND_NORM, 
		      "ip pim (dense-mode|sparse-mode)",
		      config_interface_ip_pim, 
		      "Turns ON PIM routing for the interface",
		      PIM->schedule);
    uii_add_command_schedule (UII_CONFIG_INTERFACE, COMMAND_NORM, 
		      "no ip pim (dense-mode|sparse-mode)", 
		      config_interface_ip_pim, 
		      "Turns OFF PIM routing for the interface",
		      PIM->schedule);

#endif /* HAVE_MROUTING */

#ifdef HAVE_MROUTING6
    uii_add_command_schedule (UII_NORMAL, COMMAND_NORM, "show ipv6 pim", 
		      show_ipv6_pim, "Show PIMv6 Status", PIMv6->schedule);
    uii_add_command_schedule (UII_NORMAL, COMMAND_NORM, 
		      "show ipv6 pim neighbors", show_ipv6_pim_neighbors, 
		      "Show PIMv6 neighbors", PIMv6->schedule);

    uii_add_command_schedule (UII_CONFIG_INTERFACE, COMMAND_NORM, 
		      "ipv6 pim (dense-mode|sparse-mode)", 
		      config_interface_ipv6_pim, 
		      "Turns ON PIMv6 routing for the interface",
		      PIMv6->schedule);
    uii_add_command_schedule (UII_CONFIG_INTERFACE, COMMAND_NORM, 
		      "no ipv6 pim (dense-mode|sparse-mode)",
		      config_interface_ipv6_pim, 
		      "Turns OFF PIMv6 routing for the interface",
		      PIMv6->schedule);
#endif /* HAVE_MROUTING6 */
}
#endif /* HAVE_MROUTING || HAVE_MROUTING6 */

/*
 * $Id: mroute.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>
#if defined(HAVE_MROUTING) || defined (HAVE_MROUTING6)
#include <sys/ioctl.h>
#include <api6.h>
#include <igmp.h>
#include <net/route.h>
#undef MRT_VERSION 
#ifdef linux
#include <linux/mroute.h>
#else
/*#include <netinet/ip_mroute.h>*/
#endif /* linux */
#ifdef WIDE_IPV6
#ifdef __FreeBSD__
#include <net/if_var.h>
#else
#include <net/if.h>
#endif /* __FreeBSD__ */
#include <netinet6/in6_var.h>
#include <netinet6/ip6_mroute.h>
#endif /* WIDE_IPV6 */

static int initialized = 0;
static int version = -1;

#ifdef HAVE_MROUTING
int
mc_mrtinit (void)
{
    int ret = -1;
    int yes = 1;

    if (initialized++)
	return (0);

    if ((ret = setsockopt (IGMP->sockfd, IPPROTO_IP, MRT_INIT, (char *) &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, IGMP->trace, "setsockopt MRT_INIT (%d): %s\n",
	       yes, strerror (errno));
    }
    return (ret);
}


int
mc_mrtversion (void)
{
    int ret = -1;
    int verlen = sizeof (version);
   
    if (version > 0)
	return (version);
#ifdef MRT_VERSION
    if ((ret = getsockopt (IGMP->sockfd, IPPROTO_IP, MRT_VERSION, 
		           (char *) &version, &verlen)) < 0) {
	trace (TR_ERROR, IGMP->trace, "getsockopt MRT_VERSION: %s\n",
	       strerror (errno));
    }
#endif /* MRT_VERSION */
    if (ret >= 0)
	return (version);
    return (ret);
}


int
mc_mrtdone (void)
{
    int ret = -1;

    if (--initialized > 0)
	return (0);
    if ((ret = setsockopt (IGMP->sockfd, IPPROTO_IP, MRT_DONE, (char *) NULL,
		    0)) < 0) {
	trace (TR_ERROR, IGMP->trace, "setsockopt MRT_DONE: %s\n",
	       strerror (errno));
    }
    return (ret);
}


/* not thread-safe but ok */
int
mc_add_vif (interface_t *interface)
{
    int vifi;
    struct vifctl vifc;
    int ret = -1;

    if (interface->vif_index >= 0) {
	assert (INTERFACE_MASTER->vindex2if[interface->vif_index]);
	return (0);
    }

    /* skip zero (may be used in the feature for special purpose */
    for (vifi = 1; vifi < INTERFACE_MASTER->num_vif; vifi++) {
	if (INTERFACE_MASTER->vindex2if[vifi] == NULL)
	    break;
    }

    vifc.vifc_vifi = vifi;
    vifc.vifc_flags = 0; /* interface->mflags */
    if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL)) {
        vifc.vifc_flags |= VIFF_TUNNEL;
        vifc.vifc_lcl_addr.s_addr = prefix_tolong (interface->tunnel_source);
        vifc.vifc_rmt_addr.s_addr = 
	    prefix_tolong (interface->tunnel_destination);
    }
    else {
        vifc.vifc_lcl_addr.s_addr = prefix_tolong (interface->primary->prefix);
    }
    vifc.vifc_threshold = interface->threshold; 
    vifc.vifc_rate_limit = interface->rate_limit;

    /* this enables ALLMULTI on the interface to receive all multicast packets 
       so that it is required even for a normal interface  */
    if ((ret = setsockopt (IGMP->sockfd, IPPROTO_IP, MRT_ADD_VIF, 
			   (char *) &vifc, sizeof (vifc))) < 0) {
	trace (TR_ERROR, IGMP->trace, "setsockopt MRT_ADD_VIF (%d): %s\n",
	       vifi, strerror (errno));
    }
    else {
	assert (interface->vif_index < 0);
	interface->vif_index = vifi;
	assert (INTERFACE_MASTER->vindex2if[vifi] == NULL);
	INTERFACE_MASTER->vindex2if[vifi] = interface;
	if (INTERFACE_MASTER->num_vif < ++vifi)
	    INTERFACE_MASTER->num_vif = vifi;
    }
    
    return (ret);
}


int
mc_del_vif (interface_t *interface)
{
    int vifi;
    struct vifctl vifc;
    int ret = -1;

    assert (interface->vif_index >= 0);
    assert (INTERFACE_MASTER->vindex2if[interface->vif_index]);
	return (0);

    vifc.vifc_vifi = interface->vif_index;
    vifc.vifc_flags = 0; /* interface->mflags */
    if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL)) {
        vifc.vifc_flags |= VIFF_TUNNEL;
        vifc.vifc_lcl_addr.s_addr = prefix_tolong (interface->tunnel_source);
        vifc.vifc_rmt_addr.s_addr = 
	    prefix_tolong (interface->tunnel_destination);
    }
    else {
        vifc.vifc_lcl_addr.s_addr = prefix_tolong (interface->primary->prefix);
    }

    if ((ret = setsockopt (IGMP->sockfd, IPPROTO_IP, MRT_DEL_VIF, 
			   (char *) &vifc, sizeof (vifc))) < 0) {
	trace (TR_ERROR, IGMP->trace, "setsockopt MRT_DEL_VIF (%d): %s\n",
	       vifc.vifc_vifi, strerror (errno));
    }
    INTERFACE_MASTER->vindex2if[vifc.vifc_vifi] = NULL;
    interface->vif_index = -1;
    for (vifi = INTERFACE_MASTER->num_vif; vifi > 0; vifi--)
        if (INTERFACE_MASTER->vindex2if[vifi - 1] != NULL)
	    break;
    INTERFACE_MASTER->num_vif = vifi;
    return (ret);
}


int
mc_add_mfc (prefix_t *group, prefix_t *origin, interface_t *parent, 
	    interface_bitset_t *children)
{
    int ret = -1;
    struct mfcctl mfcctl;
    int i;

    memset (&mfcctl, 0, sizeof (mfcctl));
    mfcctl.mfcc_mcastgrp.s_addr = prefix_tolong (group);
    mfcctl.mfcc_origin.s_addr = prefix_tolong (origin);
    mfcctl.mfcc_parent = (parent)?parent->vif_index:-1;
    for (i = 0; i < MAX_INTERFACES; i++) {
	if (BITX_TEST (children, i)) {
	    int vindex;
	    assert (INTERFACE_MASTER->index2if[i]);
	    assert (INTERFACE_MASTER->index2if[i]->vif_index >= 0);
	    vindex = INTERFACE_MASTER->index2if[i]->vif_index;
	    assert (sizeof (mfcctl.mfcc_ttls) / sizeof (mfcctl.mfcc_ttls[0]) > vindex);
            mfcctl.mfcc_ttls[vindex] = INTERFACE_MASTER->index2if[i]->threshold;
	}
    }

    if ((ret = setsockopt (IGMP->sockfd, IPPROTO_IP, MRT_ADD_MFC, 
			  (char *) &mfcctl, sizeof (mfcctl))) < 0) {
	trace (TR_ERROR, IGMP->trace, 
	       "setsockopt MRT_ADD_MFC (group %a origin %a): %m\n",
	       group, origin);
    }
    return (ret);
}


int
mc_del_mfc (prefix_t *group, prefix_t *origin)
{
    int ret = -1;
    struct mfcctl mfcctl;

    mfcctl.mfcc_mcastgrp.s_addr = prefix_tolong (group);
    mfcctl.mfcc_origin.s_addr = prefix_tolong (origin);

    if ((ret = setsockopt (IGMP->sockfd, IPPROTO_IP, MRT_DEL_MFC, 
			  (char *) &mfcctl, sizeof (mfcctl))) < 0) {
	trace (TR_ERROR, IGMP->trace, 
	       "setsockopt MRT_DEL_MFC (group %s origin %s): %s\n",
	       prefix_toa (group), prefix_toa (origin), strerror (errno));
    }
    return (ret);
}


int
mc_req_mfc (prefix_t *group, prefix_t *origin)
{
    int ret = -1;
    struct sioc_sg_req sg_req;

    sg_req.src.s_addr = prefix_tolong (origin);
    sg_req.grp.s_addr = prefix_tolong (group);

    if ((ret = ioctl (IGMP->sockfd, SIOCGETSGCNT, (char *) &sg_req)) < 0) {
	trace (TR_ERROR, IGMP->trace, 
	       "ioctl SIOCGETSGCNT (group %a origin %a): %m\n",
	       group, origin);
    }
    else {
#ifdef DVMRP_INIT
        ret = sg_req.count;
#else
        ret = sg_req.pktcnt;
#endif /* DVMRP_INIT */
    }
    return (ret);
}


int
mc_assert (int yes)
{
    int ret = -1;

#ifdef MRT_ASSERT
    if ((ret = setsockopt (IGMP->sockfd, IPPROTO_IP, MRT_ASSERT, 
			  (char *) &yes, sizeof (yes))) < 0) {
	trace (TR_ERROR, IGMP->trace, 
	       "setsockopt MRT_ASSERT (%d): %s\n", yes, strerror (errno));
    }
#endif /* MRT_ASSERT */
    return (ret);
}
#endif /* HAVE_MROUTING */


#ifdef HAVE_MROUTING6
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif /* HAVE_SYS_SYSCTL_H */

static int initialized6 = 0;
static prefix_t *anyaddr6 = NULL;

int
mc6_mrtinit (void)
{
    int ret = -1;
    int one = 1;

    if (initialized6++)
	return (0);

    if (anyaddr6 == NULL)
	anyaddr6 = ascii2prefix (AF_INET6, "::/0");

#ifdef INRIA_IPV6
    /* This lets all multicast-capable interfaces go to allmulti mode */
    /* there is no way to enable it per interface */
#ifdef HAVE_SYSCTLBYNAME
    if ((ret = sysctlbyname ("net.inet6.ipv6.mforwarding", 
		       NULL, NULL, &one, sizeof (one))) < 0) {
	trace (TR_ERROR, IGMPv6->trace, 
	       "sysctl (net.inet6.ipv6.mforwarding) = %d: %s\n", 
		one, strerror (errno));
    }
#else
#ifdef HAVE_SYSCTL
{
#include <netinet/in6_var.h>
    int mib[] = {CTL_NET, PF_INET6, IPPROTO_IP, IP6CTL_MFORWARDING};
	/* I don't know but the third level must be IPPROTO_IP (0) */

    if ((ret = sysctl (mib, sizeof(mib)/sizeof(mib[0]), 
		       NULL, NULL, &one, sizeof (one))) < 0) {
        trace (TR_ERROR, IGMPv6->trace, "sysctl: %m\n");
    }
}
#endif /* HAVE_SYSCTL */
#endif /* HAVE_SYSCTLBYNAME */
#endif /* INRIA_IPV6 */
#ifdef WIDE_IPV6
    if ((ret = setsockopt (IGMPv6->sockfd, IPPROTO_IPV6, MRT6_INIT, 
			   (char *) &one, sizeof (one))) < 0) {
	trace (TR_ERROR, IGMPv6->trace, "setsockopt MRT6_INIT (%d): %s\n",
	       one, strerror (errno));
    }
    if (ret >= 0) {
        if ((ret = setsockopt (IGMPv6->sockfd, IPPROTO_IPV6, MRT6_PIM, 
			   (char *) &one, sizeof (one))) < 0) {
	    trace (TR_ERROR, IGMPv6->trace, "setsockopt MRT6_PIM (%d): %s\n",
	           one, strerror (errno));
	}
    }
#endif /* WIDE_IPV6 */
    return (ret);
}


int
mc6_add_vif (interface_t *interface)
{
    int ret = -1;
#ifdef WIDE_IPV6
    vifi_t vifi = interface->index; /* XXX index == vif_index in IPv6 */
    struct mif6ctl mifc;

    memset (&mifc, 0, sizeof (mifc));
    mifc.mif6c_mifi = vifi;
    mifc.mif6c_pifi = vifi;
    mifc.mif6c_flags = 0;

    /* this enables ALLMULTI on the interface to receive all multicast packets 
       so that it is required even for a normal interface  */
    if ((ret = setsockopt (IGMPv6->sockfd, IPPROTO_IPV6, MRT6_ADD_MIF, 
			   (char *) &mifc, sizeof (mifc))) < 0) {
	trace (TR_ERROR, IGMPv6->trace, "setsockopt MRT6_ADD_MIF (%d): %s\n",
	       vifi, strerror (errno));
    }
#endif /* WIDE_IPV6 */
#ifdef INRIA_IPV6
    ret = 0; /* it is not required */
#endif /* INRIA_IPV6 */
    return (ret);
}


int
mc6_del_vif (interface_t *interface)
{
    int ret = -1;
#ifdef WIDE_IPV6
    vifi_t vifi = interface->index;

    if ((ret = setsockopt (IGMPv6->sockfd, IPPROTO_IPV6, MRT6_DEL_MIF, 
			   (char *) &vifi, sizeof (vifi))) < 0) {
	trace (TR_ERROR, IGMPv6->trace, "setsockopt MRT6_DEL_MIF (%d): %s\n",
	       vifi, strerror (errno));
    }
#endif /* WIDE_IPV6 */
#ifdef INRIA_IPV6
    ret = 0; /* it is not required */
#endif /* INRIA_IPV6 */
    return (ret);
}


int
mc6_add_mfc (prefix_t *group, prefix_t *source, interface_t *parent, 
	     interface_bitset_t *children)
{
    int ret = -1;
#ifdef WIDE_IPV6
    struct mf6cctl mfc;
    int i;

    memset (&mfc, 0, sizeof (mfc));
    memcpy (&mfc.mf6cc_origin.sin6_addr, prefix_tochar (source), 16);
    memcpy (&mfc.mf6cc_mcastgrp.sin6_addr, prefix_tochar (group), 16);
    mfc.mf6cc_parent = parent->index; /* XXX vif? */
    IF_ZERO (&mfc.mf6cc_ifset);
    for (i = 0; i < MAX_INTERFACES; i++) {
	if (BITX_TEST (children, i))
	    IF_SET (i, &mfc.mf6cc_ifset);
    }
    if ((ret = setsockopt (IGMPv6->sockfd, IPPROTO_IPV6, MRT6_ADD_MFC, 
		           (char *) &mfc, sizeof (mfc))) < 0) {
	trace (TR_ERROR, IGMPv6->trace, 
	       "MRT6_ADD_MFC source %a group %a (%m)\n", source, group);
    }
#endif /* WIDE_IPV6 */
#ifdef INRIA_IPV6
    ret = mc6_kernel_update_cache (RTM_CHANGE, group, source, 
				   parent, children);
#endif /* INRIA_IPV6 */
    return (ret);
}


int
mc6_del_mfc (prefix_t *group, prefix_t *source)
{
    int ret = -1;
#ifdef WIDE_IPV6
    struct mf6cctl mfc;

    memset (&mfc, 0, sizeof (mfc));
    memcpy (&mfc.mf6cc_origin.sin6_addr, prefix_tochar (source), 16);
    memcpy (&mfc.mf6cc_mcastgrp.sin6_addr, prefix_tochar (group), 16);
    if ((ret = setsockopt (IGMPv6->sockfd, IPPROTO_IPV6, MRT6_DEL_MFC, 
		       (char *) &mfc, sizeof (mfc))) < 0) {
	trace (TR_ERROR, IGMPv6->trace, 
	       "MRT6_DEL_MFC source %a group %a (%m)\n", source, group);
    }
#endif /* WIDE_IPV6 */
#ifdef INRIA_IPV6
    ret = mc6_kernel_update_cache (RTM_DELETE, group, source, NULL, NULL);
#endif /* INRIA_IPV6 */
    return (ret);
}


int
mc6_req_mfc (prefix_t *group, prefix_t *source)
{
    int ret = -1;
#ifdef WIDE_IPV6
    struct sioc_sg_req6 sgreq;

    memset (&sgreq, 0, sizeof (sgreq));
    memcpy (&sgreq.src.sin6_addr, prefix_tochar (source), 16);
    memcpy (&sgreq.grp.sin6_addr, prefix_tochar (group), 16);
    if ((ret = ioctl (IGMPv6->sockfd, SIOCGETSGCNT_IN6,
		       (char *) &sgreq)) < 0) {
	trace (TR_ERROR, MRT->trace, 
	       "SIOCGETSGCNT_IN6 source %a group %a (%m)\n", source, group);
    }
    else {
	ret = sgreq.pktcnt; /* or sgreq.bytecnt */
	assert (ret >= 0);
    }
#endif /* WIDE_IPV6 */
#ifdef INRIA_IPV6
    mc6_kernel_update_cache (RTM_GET, group, source, NULL, NULL);
    ret = -1; /* XXX */
#endif /* INRIA_IPV6 */
    return (ret);
}


int
mc6_mrtdone (void)
{
    int ret = -1;
    int zero = 0;

    if (--initialized6 > 0)
	return (0);

#ifdef INRIA_IPV6
#ifdef HAVE_SYSCTLBYNAME
    if ((ret = sysctlbyname ("net.inet6.ipv6.mforwarding", 
		       NULL, NULL, &zero, sizeof (zero))) < 0) {
	trace (TR_ERROR, IGMPv6->trace, 
	       "sysctl (net.inet6.ipv6.mforwarding) = %d: %s\n", 
		zero, strerror (errno));
    }
#else
#ifdef HAVE_SYSCTL
{
/*#include <netinet/in6_var.h>*/
	/* I don't know but the third level must be IPPROTO_IP (0) */
    int mib[] = {CTL_NET, PF_INET6, IPPROTO_IP, IP6CTL_MFORWARDING};

    if ((ret = sysctl (mib, sizeof(mib)/sizeof(mib[0]), 
		       NULL, NULL, &zero, sizeof (zero))) < 0) {
        trace (TR_ERROR, IGMPv6->trace, "sysctl: %m\n");
        return (-1);
    }
}
#endif /* HAVE_SYSCTL */
#endif /* HAVE_SYSCTLBYNAME */
#endif /* INRIA_IPV6 */
#ifdef WIDE_IPV6
    if ((ret = setsockopt (IGMPv6->sockfd, IPPROTO_IPV6, MRT6_PIM, 
			   (char *) &zero, sizeof (zero))) < 0) {
	trace (TR_ERROR, IGMPv6->trace, "setsockopt MRT6_PIM (%d): %s\n",
	       zero, strerror (errno));
    }
    if ((ret = setsockopt (IGMPv6->sockfd, IPPROTO_IPV6, MRT6_DONE, 
			   (char *) NULL, 0)) < 0) {
	trace (TR_ERROR, IGMPv6->trace, "setsockopt MRT6_DONE: %s\n",
	       strerror (errno));
    }
#endif /* WIDE_IPV6 */
    return (ret);
}
#endif /* HAVE_MROUTING6 */

#endif /* HAVE_MROUTING || HAVE_MROUTING6 */

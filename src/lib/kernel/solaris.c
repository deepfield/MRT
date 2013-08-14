/*
 * $Id: solaris.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <fcntl.h>
#include <stropts.h>
#include <ctype.h>

#include <sys/stream.h>
#include <sys/tihdr.h>
#include <sys/tiuser.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/route.h>
#include <inet/common.h>
#include <inet/mib2.h>
#include <inet/ip.h>

#include <mrt.h>
#include <interface.h>

extern int getpagesize (void);

static int sockfd = -1;
#ifdef HAVE_IPV6
static int sockfd6 = -1;
#endif /* HAVE_IPV6 */

/* get interface configuration */
static interface_t *
ifstatus (char *name)
{
    struct ifreq ifr;
    int s;
    int index = 0;
    u_long flags, mtu;
    char *cp;
    interface_t *interface;

    safestrncpy (ifr.ifr_name, name, sizeof (ifr.ifr_name));

    if ((cp = strrchr (ifr.ifr_name, ':')))
	*cp = '\0';		/* Remove the :n extension from the name */

    if ((cp = strrchr (ifr.ifr_name, '#')))
	*cp = '\0';		/* Remove the # extension from the name */

    if ((interface = find_interface_byname (ifr.ifr_name)))
	return (interface);

    if ((s = sockfd) < 0)
	return (NULL);

    if (ioctl (s, SIOCGIFFLAGS, (caddr_t) & ifr) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "SIOCGIFFLAGS for %s (%s)\n",
	       name, strerror (errno));
	return (NULL);
    }
    assert (sizeof (ifr.ifr_flags) == 2);
    flags = ifr.ifr_flags & 0x0000ffff;		/* short */

    if (ioctl (s, SIOCGIFMTU, (caddr_t) & ifr) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "SIOGSIFMTU for %s (%s)\n", name, strerror (errno));
	return (NULL);
    }

    if (strncmp (ifr.ifr_name, "ip", 2) == 0 && isdigit (ifr.ifr_name[2]))
	flags |= IFF_TUNNEL;
#define ifr_mtu ifr_metric
    mtu = ifr.ifr_mtu;
    name = ifr.ifr_name;

#ifdef HAVE_IPV6
    /* I need to check if this works on Solaris 2.7 w/o IPv6 */
#ifdef SIOCGIFINDEX
    if (ioctl (s, SIOCGIFINDEX, (caddr_t) & ifr) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "SIOCGIFINDEX for %s (%s)\n", name, strerror (errno));
	return (NULL);
    }
    index = ifr.ifr_index;
    trace (TR_TRACE, INTERFACE_MASTER->trace,
	   "SIOCGIFINDEX returns %d for %s\n", index, name);
#endif /* SIOCGIFINDEX */
#endif /* HAVE_IPV6 */

    interface = new_interface (name, flags, mtu, index);
    return (interface);
}


/* get interface configuration for IPv4 */
static void
ifstatus_v4 (interface_t * interface, char *name)
{
    struct ifreq ifr;
    struct sockaddr_in addr, mask, dest;
    int s;
    u_long flags;

    if ((s = sockfd) < 0)
	return;

    safestrncpy (ifr.ifr_name, name, sizeof (ifr.ifr_name));
    flags = interface->flags;

    if (ioctl (s, SIOCGIFADDR, (caddr_t) & ifr) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "SIOCGIFADDR for %s (%s)\n",
	       name, strerror (errno));
	return;
    }
    memcpy (&addr, &ifr.ifr_addr, sizeof (addr));

    if (addr.sin_family != AF_INET || addr.sin_addr.s_addr == INADDR_ANY) {
#if 0
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "SIOCGIFADDR returns strange address (family=%d)\n",
	       addr.sin_family);
#endif
	return;
    }

    if (ioctl (s, SIOCGIFNETMASK, (caddr_t) & ifr) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "SIOCGIFNETMASK for %s (%s)\n",
	       name, strerror (errno));
	/* sometimes, no netmask */
	memset (&ifr.ifr_addr, -1, sizeof (ifr.ifr_addr));
    }
    memcpy (&mask, &ifr.ifr_addr, sizeof (mask));

    if (BIT_TEST (flags, IFF_POINTOPOINT)) {
	if (ioctl (s, SIOCGIFDSTADDR, (caddr_t) & ifr) < 0) {
	    trace (TR_ERROR, INTERFACE_MASTER->trace,
		   "SIOCGIFDSTADDR for %s (%s)\n",
		   name, strerror (errno));
	    /* sometimes, no destination address */
	    memset (&ifr.ifr_addr, 0, sizeof (ifr.ifr_addr));
	}
    }
    else if (BIT_TEST (flags, IFF_BROADCAST)) {
	if (ioctl (s, SIOCGIFBRDADDR, (caddr_t) & ifr) < 0) {
	    trace (TR_ERROR, INTERFACE_MASTER->trace,
		   "SIOCGIFBRDADDR for %s (%s)\n",
		   name, strerror (errno));
	    /* sometimes, no broadcast address ??? */
	    memset (&ifr.ifr_addr, 0, sizeof (ifr.ifr_addr));
	}
    }
    memcpy (&dest, &ifr.ifr_addr, sizeof (dest));

    add_addr_to_interface (interface, AF_INET,
			   &addr.sin_addr.s_addr,
			   mask2len (&mask.sin_addr.s_addr, 4),
			   &dest.sin_addr.s_addr);
}


#ifdef HAVE_IPV6
#ifdef SIOCGLIFADDR
/* get interface configuration for IPv6 */
static void
ifstatus_v6 (interface_t * interface, char *name)
{
    struct lifreq lifr;
    struct sockaddr_in6 *sin6;
    struct in6_addr addr;
    struct in6_addr temp, *dest = NULL;
    u_long flags, mask;
    int s;

    if ((s = sockfd6) < 0)
	return;

    safestrncpy (lifr.lifr_name, name, sizeof (lifr.lifr_name));
    flags = interface->flags;

    if (ioctl (s, SIOCGLIFADDR, &lifr) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "SIOCGLIFADDR for %s (%m)\n", name);
	return;
    }
    if (lifr.lifr_addr.ss_family != AF_INET6)
	return;
    sin6 = (struct sockaddr_in6 *) &lifr.lifr_addr;
    memcpy (&addr, &sin6->sin6_addr, sizeof (addr));
    mask = lifr.lifr_addrlen;

    if (BIT_TEST (flags, IFF_POINTOPOINT)) {
	if (ioctl (s, SIOCGLIFBRDADDR, &lifr) >= 0) {
    	    sin6 = (struct sockaddr_in6 *) &lifr.lifr_dstaddr;
	    memcpy (&temp, &sin6->sin6_addr, sizeof (temp));
	    dest = &temp;
	}
	else {
	    trace (TR_ERROR, INTERFACE_MASTER->trace,
		   "No destination? for %s\n", name);
	}
    }

    add_addr_to_interface (interface, AF_INET6,
			   (char *) &addr, mask, (char *) dest);
}
#else

/* get interface configuration for IPv6 */
static void
ifstatus_v6 (interface_t * interface, char *name)
{
    struct in6_addr addr, sin_zero;
    struct in6_addr sin, *dest = NULL;
    struct v6addrreq v6addrreq;
    struct v6maskreq v6maskreq;
    u_long flags, mask;
    int s;

    if ((s = sockfd6) < 0)
	return;

    flags = interface->flags;
    memcpy (v6addrreq.v6ar_name, name, sizeof (v6addrreq.v6ar_name));

    if (ioctl (s, SIOCGIFV6ADDR, (caddr_t) & v6addrreq) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "SIOCGIFV6ADDR for %s (%s)\n",
	       name, strerror (errno));
	return;
    }
    memcpy (&addr, &v6addrreq.v6ar_addr, sizeof (addr));

    /* not really an IPv6 address/interface */
    memset (&sin_zero, 0, sizeof (sin_zero));
    if (!memcmp (&addr, &sin_zero, sizeof (sin_zero))) {
#if 0
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "Interface %s doesn't have IPv6 address\n", name);
#endif
	return;
    }

    memcpy (v6maskreq.v6mr_name, name, sizeof (v6maskreq.v6mr_name));
    if (ioctl (s, SIOCGIFV6MASK, (caddr_t) & v6maskreq) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "SIOCGIFV6MASK for %s (%s)\n",
	       name, strerror (errno));
	return;
    }
    mask = v6maskreq.v6mr_mask;

    if (BIT_TEST (flags, IFF_POINTOPOINT)) {
	if (ioctl (s, SIOCGIFV6DST, (caddr_t) & v6addrreq) >= 0) {
	    dest = &sin;
	    memcpy (dest, &v6addrreq.v6ar_addr, sizeof (*dest));
	}
	else {
	    trace (TR_ERROR, INTERFACE_MASTER->trace,
		   "No destination? for %s\n", name);
	}
    }

    add_addr_to_interface (interface, AF_INET6,
			   (char *) &addr, mask, (char *) dest);
}

#endif /* SIOCGLIFADDR */
#endif /* HAVE_IPV6 */


static int
read_interface4 (void)
{
    struct ifconf ifc;
    struct ifreq *ifptr, *end;
    int num;
    char *name, *buffer;
    interface_t *interface;

    if ((sockfd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "socket for AF_INET (%s)\n", strerror (errno));
	return (-1);
    }

    if (ioctl (sockfd, SIOCGIFNUM, (char *) &num) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace, "SIOCGIFNUM (%m)\n");
	return (-1);
    }

    trace (TR_INFO, INTERFACE_MASTER->trace, "SIOCGIFNUM returns %d\n", num);

    buffer = (char *) NewArray (struct ifreq, num);
    ifc.ifc_len = num * sizeof (struct ifreq);
    ifc.ifc_buf = buffer;

    if (ioctl (sockfd, SIOCGIFCONF, (char *) &ifc) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace, "SIOCGIFCONF (%m)\n");
	return (-1);
    }

    end = (struct ifreq *) (ifc.ifc_buf + ifc.ifc_len);
    for (ifptr = ifc.ifc_req; ifptr < end; ifptr++) {
	interface = ifstatus (ifptr->ifr_name);
	if (interface == NULL)
	    continue;
	ifstatus_v4 (interface, ifptr->ifr_name);
    }
    Delete (buffer);
    return (1);
}


#ifdef HAVE_IPV6
#ifdef SIOCGLIFNUM
static int
read_interface6 (void)
{
    struct lifnum  lifn;
    struct lifconf lifc;
    struct lifreq *ifptr, *end;
    interface_t *interface;
    caddr_t buffer;

    if ((sockfd6 = socket (AF_INET6, SOCK_DGRAM, 0)) < 0) {
	trace (TR_WARN, INTERFACE_MASTER->trace,
	       "socket for AF_INET6 (%m), IPv4 only\n");
	return (-1);
    }

    lifn.lifn_family = AF_INET6;
    lifn.lifn_flags = 0;
    if (ioctl (sockfd6, SIOCGLIFNUM, &lifn) < 0) {
        trace (TR_ERROR, INTERFACE_MASTER->trace, "SIOCGLIFNUM (%m)\n");
        return (-1);
    }
    trace (TR_INFO, INTERFACE_MASTER->trace, 
	   "SIOCGLIFNUM for IPv6 returns %d\n", lifn.lifn_count);
    buffer = (caddr_t) NewArray (struct lifreq, lifn.lifn_count);
    lifc.lifc_family = AF_INET6;
    lifc.lifc_flags = 0;
    lifc.lifc_len = lifn.lifn_count * sizeof (struct lifreq);
    lifc.lifc_buf = buffer;

    if (ioctl (sockfd6, SIOCGLIFCONF, (char *) &lifc) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "SIOCGLIFCONF (%m)\n");
	Delete (buffer);
	return (-1);
    }

    end = lifc.lifc_req + lifn.lifn_count;

    for (ifptr = lifc.lifc_req; ifptr < end; ifptr++) {
	interface = ifstatus (ifptr->lifr_name);
	if (interface == NULL)
	    continue;
	ifstatus_v6 (interface, ifptr->lifr_name);
    }
    Delete (buffer);
    return (1);
}
#else
static int
read_interface6 (void)
{
    struct ifconf ifc;
    struct v6conf *ifptr, *end;
    int num;
    char *name, *buffer;
    interface_t *interface;

    if ((sockfd6 = socket (AF_INET6, SOCK_DGRAM, 0)) < 0) {
	trace (TR_WARN, INTERFACE_MASTER->trace,
	       "socket for AF_INET6 (%m), IPv4 only\n");
	return (-1);
    }

    if (ioctl (sockfd, SIOCGIFNUM, (char *) &num) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace, "SIOCGIFNUM (%m)\n");
	return (-1);
    }

    trace (TR_INFO, INTERFACE_MASTER->trace, "SIOCGIFNUM returns %d\n", num);

    buffer = (char *) NewArray (struct v6conf, num);
    ifc.ifc_len = num * sizeof (struct v6conf);
    ifc.ifc_buf = buffer;

    if (ioctl (sockfd6, SIOCGIFV6CONF, (char *) &ifc) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace, "SIOCGIFV6CONF (%m)\n");
	Delete (buffer);
	return (-1);
    }

    end = (struct v6conf *) (ifc.ifc_buf + ifc.ifc_len);

    for (ifptr = (struct v6conf *) ifc.ifc_req; ifptr < end; ifptr++) {
	interface = ifstatus (ifptr->v6cf_name);
	if (interface == NULL)
	    continue;
	ifstatus_v6 (interface, ifptr->v6cf_name);
    }
    Delete (buffer);
    return (1);
}
#endif /* SIOCGLIFNUM */
#endif /* HAVE_IPV6 */


int
read_interfaces (void)
{
    if (read_interface4 () < 0)
	return (-1);
#ifdef HAVE_IPV6
    read_interface6 ();
    /* don't care */
#endif /* HAVE_IPV6 */
    return (1);
}


#ifndef __EXTENSIONS__
int
sys_kernel_update_route (prefix_t * dest, prefix_t * next_hop,
		         prefix_t * old_hop, int index, int oldindex)
{
    int s;
    struct rtentry rt;
    struct sockaddr_in *dst = (struct sockaddr_in *) &rt.rt_dst;
    struct sockaddr_in *gateway = (struct sockaddr_in *) &rt.rt_gateway;
#ifdef HAVE_IPV6
    struct v6rtreq rt6;
#endif /* HAVE_IPV6 */
    int op;

    if (next_hop && old_hop) {
	sys_kernel_update_route (dest, NULL, old_hop, 0, oldindex);
	return (sys_kernel_update_route (dest, next_hop, NULL, index, 0));
    }

    if (dest->family == AF_INET) {

	if ((s = sockfd) < 0)
	    return (-1);

        if (next_hop) {
	    op = SIOCADDRT;
        }
        else if (old_hop) {
	    next_hop = old_hop;
	    index = oldindex;
	    op = SIOCDELRT;
        }

	memset (&rt, 0, sizeof (rt));

	dst->sin_family = AF_INET;
	memcpy (&dst->sin_addr, prefix_tochar (dest), sizeof (dst->sin_addr));

	gateway->sin_family = AF_INET;
	memcpy (&gateway->sin_addr, prefix_tochar (next_hop),
		sizeof (gateway->sin_addr));

	if (dest->bitlen == 32)
	    rt.rt_flags |= RTF_HOST;

	rt.rt_flags |= RTF_UP;
	if (gateway->sin_addr.s_addr != INADDR_ANY &&
	    gateway->sin_addr.s_addr != htonl (INADDR_LOOPBACK)) {
	    rt.rt_flags |= RTF_GATEWAY;
	}
#ifdef notdef
	if (cmd == KERNEL_ROUTE_ADD) {
	    /* I'm not sure this does work -- masaki */
	    interface = find_interface_byindex (index);
	    inf.if_name = interface->name;
	    rt.rt_ifp = &inf;
	}
#endif

	if (ioctl (s, op, &rt) < 0) {
	    trace (TR_ERROR, MRT->trace, "%s (%s)\n",
		   (op == SIOCADDRT) ? "SIOCADDRT" : "SIOCDELRT",
		   strerror (errno));
	    return (-1);
	}

    }
#ifdef HAVE_IPV6
    else if (dest->family == AF_INET6) {

	if ((s = sockfd6) < 0)
	    return (-1);

        if (next_hop) {
	    op = SIOCADDV6RT;
        }
        else if (old_hop) {
	    next_hop = old_hop;
	    index = oldindex;
	    op = SIOCDELV6RT;
        }
	memset (&rt6, 0, sizeof (rt6));

	memcpy (&rt6.v6rt_dst, prefix_tochar (dest), sizeof (rt6.v6rt_dst));
	memcpy (&rt6.v6rt_gw, prefix_tochar (next_hop), sizeof (rt6.v6rt_gw));
	rt6.v6rt_mask = dest->bitlen;
	/* Solaris IPv6 seems to require this */
	netmasking (dest->family, &rt6.v6rt_dst, dest->bitlen);

	if (dest->bitlen == 128)
	    rt6.v6rt_flags |= RTF_HOST;

	rt6.v6rt_flags |= RTF_UP;
	if (!ipv6_any_addr (&rt6.v6rt_gw)) {
	    rt6.v6rt_flags |= RTF_GATEWAY;
	}

	if (op == SIOCADDV6RT) {
	    interface_t *interface;
	    /* I'm not sure this does work -- masaki */
	    interface = find_interface_byindex (index);
	    assert (interface);
	    safestrncpy (rt6.v6rt_ifname, interface->name,
		         sizeof (rt6.v6rt_ifname));
#ifndef SIOCGLIFCONF
	    /* XXX dirty way! */
	    if (strchr (rt6.v6rt_ifname, '#') == NULL) {
		strcat (rt6.v6rt_ifname, "#v6");
	    }
#endif /* SIOCGLIFCONF */
	}

	if (ioctl (s, op, &rt6) < 0) {
	    trace (TR_ERROR, MRT->trace, "%s (%s)\n",
		   (op == SIOCADDV6RT) ? "SIOCADDV6RT" : "SIOCDELV6RT",
		   strerror (errno));
	    return (-1);
	}
    }
#endif /* HAVE_IPV6 */
    else {
	assert (0);		/* not a family we know about */
    }

    return (1);
}
#else /* __EXTENSIONS__ */


struct m_rtmsg {
    struct rt_msghdr m_rtm;
    char m_space[512];
};

static int route_sockfd2 = -1;

static int sys_kernel_rt_msg (u_char *buf, int bufsize);

static int
sa_len (sockunion_t *u)
{
    if (u->sa.sa_family == AF_INET) {
	return (sizeof (u->sin));
    }
#ifdef HAVE_IPV6
    else if (u->sa.sa_family == AF_INET6) {
	return (sizeof (u->sin6));
    }
#endif /* HAVE_IPV6 */
    else if (u->sa.sa_family == AF_LINK) {
	return (sizeof (u->sdl));
    }
    return (0);
}


/* 
 */
int 
sys_kernel_update_route (prefix_t * dest, prefix_t * nexthop, 
			 prefix_t * oldhop, int index, int oldindex)
{
    int rlen;
    struct m_rtmsg m_rtmsg;
    char *cp = m_rtmsg.m_space;
    sockunion_t so_dst, so_gate, so_mask, so_genmask, so_ifa, so_ifp;

    int flags, rtm_addrs;
    static int seq = 0;
    struct rt_metrics rt_metrics;
    register int l;
#ifdef notdef
    interface_t *interface;
#endif
    int len = dest->bitlen;

    if (route_sockfd2 < 0)
	return (-1);

    bzero ((char *) &m_rtmsg, sizeof (m_rtmsg));
    bzero ((char *) &rt_metrics, sizeof (rt_metrics));
    bzero (&so_dst, sizeof (so_dst));
    bzero (&so_gate, sizeof (so_gate));
    bzero (&so_mask, sizeof (so_mask));
    bzero (&so_genmask, sizeof (so_genmask));
    bzero (&so_ifp, sizeof (so_ifp));
    bzero (&so_ifa, sizeof (so_ifa));

    if (nexthop && oldhop == NULL) {
	m_rtmsg.m_rtm.rtm_type = RTM_ADD;
    }
    else if (nexthop == NULL && oldhop) {
	nexthop = oldhop;
	index = oldindex;
	m_rtmsg.m_rtm.rtm_type = RTM_DELETE;
    }
    else if (nexthop && oldhop) {
        /* probably, ADD works like CHANGE */
	/* there is no way to specify index of route to be removed */
	/* m_rtmsg.m_rtm.rtm_type = RTM_ADD; */
	m_rtmsg.m_rtm.rtm_type = RTM_CHANGE;
    }

    if (dest->family == AF_INET) {
	so_dst.sin.sin_addr.s_addr = prefix_tolong (dest);
	/* so_dst.sin.sin_len = sizeof (struct sockaddr_in); */
	so_dst.sin.sin_family = AF_INET;
    	netmasking (AF_INET, (char *)&so_dst.sin.sin_addr, len);

	so_gate.sin.sin_addr.s_addr = prefix_tolong (nexthop);
	/* so_gate.sin.sin_len = sizeof (struct sockaddr_in); */
	so_gate.sin.sin_family = AF_INET;

	/* so_mask.sin.sin_len = sizeof (struct sockaddr_in); */
        so_mask.sin.sin_family = AF_UNSPEC;
        so_mask.sin.sin_family = AF_INET;
	len2mask (len, (char *) &so_mask.sin.sin_addr, 4);

	rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;

	if (index > 0) {
	    so_ifp.sdl.sdl_index = index;
	    /* so_ifp.sdl.sdl_len = sizeof (struct sockaddr_dl); */
	    so_ifp.sdl.sdl_family = AF_LINK;
	    rtm_addrs |= RTA_IFP;
	}


    }
#ifdef HAVE_IPV6
    else if (dest->family == AF_INET6) {
	memcpy (&so_dst.sin6.sin6_addr, prefix_tochar (dest), 16);
	/* so_dst.sin6.sin6_len = sizeof (struct sockaddr_in6); */
	so_dst.sin6.sin6_family = AF_INET6;
    	netmasking (AF_INET6, (char *)&so_dst.sin6.sin6_addr, len);

        memcpy (&so_gate.sin6.sin6_addr, prefix_tochar (nexthop), 16);
	/* so_gate.sin6.sin6_len = sizeof (struct sockaddr_in6); */
	so_gate.sin6.sin6_family = AF_INET6;

	/* so_mask.sin6.sin6_len = sizeof (struct sockaddr_in6); */
        so_mask.sin6.sin6_family = AF_UNSPEC;
        so_mask.sin6.sin6_family = AF_INET6;
	len2mask (len, (char *) &so_mask.sin6.sin6_addr, 16);

	rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;

	if (index > 0) {
	     so_ifp.sdl.sdl_index = index;
	     /* so_ifp.sdl.sdl_len = sizeof (struct sockaddr_dl); */
	     so_ifp.sdl.sdl_family = AF_LINK;
	     rtm_addrs |= RTA_IFP;
	}

#ifdef __KAME__
	/* KAME IPV6 still requires an index here */
	if (IN6_IS_ADDR_LINKLOCAL (&so_gate.sin6.sin6_addr)) {
       	    so_gate.sin6.sin6_addr.s6_addr8[2] = index >> 8;;
       	    so_gate.sin6.sin6_addr.s6_addr8[3] = index;
	}
#endif /* __KAME__ */
#ifdef notdef
	interface = find_interface_byindex (index);

	assert (interface->primary6);
	memcpy (&so_ifa.sin6.sin6_addr,
		prefix_tochar (
			BIT_TEST (interface->flags, IFF_POINTOPOINT)?
			    interface->primary6->broadcast:
			interface->primary6->prefix), 16);
	/* so_ifa.sin6.sin6_len = sizeof (struct sockaddr_in6); */
	so_ifa.sin6.sin6_family = AF_INET6;
#endif

    }
#endif /* HAVE_IPV6 */
    else			/* unknown family */
	return (-1);

    flags = RTF_UP;
    if (dest->family == AF_INET) {
#ifdef notdef
	/* this doesn't work when removing it */
	if (len == 32)
	    flags |= RTF_HOST;
#endif
	if (so_gate.sin.sin_addr.s_addr != INADDR_ANY)
	    flags |= RTF_GATEWAY;
#ifdef RTF_REJECT
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK htonl(0x7f000001)
#endif /* INADDR_LOOPBACK */
	if (so_gate.sin.sin_addr.s_addr == INADDR_LOOPBACK)
	    flags |= RTF_REJECT;
#endif /* RTF_REJECT */
    }
#ifdef HAVE_IPV6
    else if (dest->family == AF_INET6) {
#ifdef notdef
	if (len == 128)
	    flags |= RTF_HOST;
#endif
	if (!IN6_IS_ADDR_UNSPECIFIED (&so_gate.sin6.sin6_addr))
	    flags |= RTF_GATEWAY;
#ifdef RTF_REJECT
	if (IN6_IS_ADDR_LOOPBACK (&so_gate.sin6.sin6_addr))
	    flags |= RTF_REJECT;
#endif /* RTF_REJECT */
    }
#endif /* HAVE_IPV6 */

#define ROUNDUP(x) (x)
#define NEXTADDRP(w, u) \
	if (rtm_addrs & (w)) {\
	    l = ROUNDUP(sa_len (&(u))); bcopy((char *)&(u), cp, l); cp += l;\
	}

    m_rtmsg.m_rtm.rtm_flags = flags;
    m_rtmsg.m_rtm.rtm_version = RTM_VERSION;
    m_rtmsg.m_rtm.rtm_seq = ++seq;
    m_rtmsg.m_rtm.rtm_addrs = rtm_addrs;
    m_rtmsg.m_rtm.rtm_rmx = rt_metrics;
    /*m_rtmsg.m_rtm.rtm_inits = 0; */

    NEXTADDRP (RTA_DST, so_dst);
    NEXTADDRP (RTA_GATEWAY, so_gate);
    NEXTADDRP (RTA_NETMASK, so_mask);
    NEXTADDRP (RTA_GENMASK, so_genmask);
    NEXTADDRP (RTA_IFP, so_ifp);
    NEXTADDRP (RTA_IFA, so_ifa);

    m_rtmsg.m_rtm.rtm_msglen = l = cp - (char *) &m_rtmsg;

again:
    if ((rlen = write (route_sockfd2, (char *) &m_rtmsg, l)) < 0) {
	/* I don't know why the kernel distinguishes 
		host and prefixlen = 32 (ipv6) or 128 (ipv6) */
	if (m_rtmsg.m_rtm.rtm_type == RTM_DELETE && (
    		(dest->family == AF_INET && len == 32 && 
		 !BIT_TEST (m_rtmsg.m_rtm.rtm_flags, RTF_HOST))
#ifdef HAVE_IPV6
    	     || (dest->family == AF_INET6 && len == 128 && 
		 !BIT_TEST (m_rtmsg.m_rtm.rtm_flags, RTF_HOST))
#endif /* HAVE_IPV6*/
	     )) {
	    trace (TR_WARN, MRT->trace, 
		   "route socket dst %p nh %a (%m), trying with RTF_HOST\n", 
	            dest, nexthop);
    	    m_rtmsg.m_rtm.rtm_flags |= RTF_HOST;
	    goto again;
	}
	if (m_rtmsg.m_rtm.rtm_type == RTM_CHANGE) {
	    int r = 0;
	    trace (TR_WARN, MRT->trace, 
		   "route socket dst %p nh %a (%m), trying delete/add\n", 
	            dest, nexthop);
	    r = sys_kernel_update_route (dest, NULL, oldhop, 0, oldindex);
	    r = sys_kernel_update_route (dest, nexthop, NULL, index, 0);
	    return (r);
	}
	if (errno == EEXIST) {
	    return (1);
	}			/* route already exists */
	trace (TR_ERROR, MRT->trace, "route socket dst %p nh %a (%m)\n", 
	       dest, nexthop);
	return (-1);
    }
    return (1);
}


#define NEXTADDRR(w, u) \
   if (rtm_addrs & (w)) {  \
           l = ROUNDUP(sa_len ((sockunion_t *)(cp))); \
           bcopy(cp, (char *)&(u), l); cp += l; \
   }


static int
sys_kernel_rt_msg (u_char *buf, int bufsize)
{

    sockunion_t so_dst, so_gate, so_mask, so_genmask, so_brd, so_ifa, so_ifp;
    u_char *next, *lim;
    struct rt_msghdr *rtm;

    lim = buf + bufsize;
    for (next = buf; next < lim; next += rtm->rtm_msglen) {

        int family = 0, masklen = 0, l, index = 0;
        u_char *dest, *nexthop, *mask;
	u_char *addr = NULL, *broadcast = NULL;
	u_char *cp;
	u_long rtm_addrs;

	rtm = (struct rt_msghdr *) next;

	if (rtm->rtm_version != RTM_VERSION) {
	    trace (TR_ERROR, MRT->trace,
		   "rtm_version mismatch: %d should be %d\n",
		   rtm->rtm_version, RTM_VERSION);
	}

	if (rtm->rtm_type == RTM_IFINFO) {
	    struct if_msghdr *ifm = (struct if_msghdr *) rtm;
            struct sockaddr_dl *sdl;
	    char name[IFNAMSIZ];

            cp = (u_char *)(ifm + 1);
	    rtm_addrs = ifm->ifm_addrs;

            if (ifm->ifm_addrs != RTA_IFP) {
                /* status change */
                if (ifm->ifm_addrs == 0 && ifm->ifm_index > 0) {
                    new_interface (NULL, ifm->ifm_flags & 0xffff,
                                 ifm->ifm_data.ifi_mtu, ifm->ifm_index);
                }
                continue;
	    }
            sdl = (struct sockaddr_dl *) cp;
            if (sdl->sdl_family != AF_LINK) {
                trace (TR_ERROR, INTERFACE_MASTER->trace,
		       "bad sdl family %d\n", sdl->sdl_family);
                continue;
	    }
	    memcpy (name, sdl->sdl_data, sdl->sdl_nlen);
	    name[sdl->sdl_nlen] = '\0';
            if (sdl->sdl_nlen >= IFNAMSIZ) {
                trace (TR_ERROR, INTERFACE_MASTER->trace,
		       "too long name %d\n", sdl->sdl_nlen);
                continue;
            }
	    if (ifm->ifm_index <= 0)
		ifm->ifm_index = sdl->sdl_index;

	    new_interface (name, ifm->ifm_flags & 0xffff, 
				 ifm->ifm_data.ifi_mtu, ifm->ifm_index);
	}
	else if (rtm->rtm_type == RTM_NEWADDR ||
	         rtm->rtm_type == RTM_DELADDR) {
	    struct ifa_msghdr *ifam = (struct ifa_msghdr *) rtm;
	    interface_t *interface;

	    cp = (u_char *) ifam + sizeof (*ifam);
	    rtm_addrs = ifam->ifam_addrs;

	    NEXTADDRR (RTA_DST, so_dst);
	    NEXTADDRR (RTA_GATEWAY, so_gate);
	    NEXTADDRR (RTA_NETMASK, so_mask);
	    NEXTADDRR (RTA_IFP, so_ifp);
	    NEXTADDRR (RTA_IFA, so_ifa);
	    NEXTADDRR (RTA_BRD, so_brd);

	    if (ifam->ifam_index <= 0) {
	        if (BIT_TEST (rtm_addrs, RTA_IFP)) {
                    struct sockaddr_dl *sdl;
                    sdl = (struct sockaddr_dl *) &so_ifp;
                    if (sdl->sdl_family == AF_LINK)
			ifam->ifam_index = sdl->sdl_index;
		}
	    }

	    if ((interface = find_interface_byindex (ifam->ifam_index)) == NULL)
	        continue;

	    if (BIT_TEST (ifam->ifam_addrs, RTA_BRD)) {
		broadcast = sockunion2char (&so_brd);
	    }
	    if (BIT_TEST (ifam->ifam_addrs, RTA_IFA)) {
		family = so_ifa.sa.sa_family;
		addr = sockunion2char (&so_ifa);
#ifdef __KAME__
		/* KAME IPV6 still has an index here */
		if (family == AF_INET6 && 
			IN6_IS_ADDR_LINKLOCAL ((struct in6_addr *)addr)) {
            	    addr[2] = 0;
            	    addr[3] = 0;
		}
#endif /* __KAME__ */
		if (BIT_TEST (ifam->ifam_addrs, RTA_NETMASK)) {
		    so_mask.sa.sa_family = so_ifa.sa.sa_family;
		    masklen = mask2len (sockunion2char (&so_mask),
					(family == AF_INET) ? 4 :
#ifdef HAVE_IPV6
					(family == AF_INET6) ? 16 :
#endif /* HAVE_IPV6 */
					0);
		}
		if (addr) {
		    update_addr_of_interface (
		   	(rtm->rtm_type == RTM_NEWADDR)? 'A': 'D',
				interface, family, addr, masklen,
				(broadcast) ? broadcast : NULL);
		}
	    }
	}
	else if (rtm->rtm_type == RTM_GET || rtm->rtm_type == RTM_ADD ||
		rtm->rtm_type == RTM_DELETE || rtm->rtm_type == RTM_CHANGE) {
	    int proto = PROTO_KERNEL;
#if 0
	    printf ("rtm->rtm_flags=%x rtm->rtm_addrs=%x\n", 
		rtm->rtm_flags, rtm->rtm_addrs);
#endif
	    if (rtm->rtm_type == RTM_CHANGE) {
	        trace (TR_TRACE, MRT->trace, "RTM_CHANGE not yet supported\n");
		rtm->rtm_type = RTM_ADD; /* XXX */
	    }
	    if (rtm->rtm_errno != 0)
		continue;

	    /* REJECT and BLACKHOLE are not handled yet */
	    if (rtm->rtm_flags &
		    ~(RTF_UP|RTF_GATEWAY|RTF_HOST|RTF_STATIC
			|RTF_CLONING /* direct if */
			|RTF_XRESOLVE /* direct if for IPv6 */
			|RTF_DONE /* on injection */
#ifdef RTF_PRCLONING
			|RTF_PRCLONING /* usual route has this */
#endif /* RTF_PRCLONING */
#ifdef RTF_LOCAL /* OpenBSD does not have RTF_LOCAL */
			|RTF_LOCAL /* loopback route has this */

#endif /* RTF_LOCAL */
			|RTF_REJECT|RTF_BLACKHOLE))
		continue;
/* RTM_DELETE doesn't have RTF_UP */
/*
	    if (!BIT_TEST (rtm->rtm_flags, RTF_UP))
		continue;
*/
	    /* currently I don't want to loop back my request */
	    if (MRT->pid == rtm->rtm_pid)
	        continue;

	    if (!BIT_TEST (rtm->rtm_flags, RTF_GATEWAY))
		/* connected route is added by interface */
		proto = PROTO_CONNECTED;
	    if (BIT_TEST (rtm->rtm_flags, RTF_STATIC))
		proto = PROTO_STATIC;

	    index = rtm->rtm_index;
	    cp = (u_char *) rtm + sizeof (*rtm);
	    rtm_addrs = rtm->rtm_addrs;

	    NEXTADDRR (RTA_DST, so_dst);
	    NEXTADDRR (RTA_GATEWAY, so_gate);
	    NEXTADDRR (RTA_NETMASK, so_mask);
	    NEXTADDRR (RTA_GENMASK, so_genmask);
	    NEXTADDRR (RTA_IFP, so_ifp);
	    NEXTADDRR (RTA_IFA, so_ifa);

	    if (index <= 0) {
	        if (BIT_TEST (rtm_addrs, RTA_IFP)) {
                    struct sockaddr_dl *sdl;
                    sdl = (struct sockaddr_dl *) &so_ifp;
                    if (sdl->sdl_family == AF_LINK)
			index = sdl->sdl_index;
		}
	    }

	    family = so_dst.sa.sa_family;
	    dest = sockunion2char (&so_dst);
	    nexthop = sockunion2char (&so_gate);
	    so_mask.sa.sa_family = family; /* required by sockunion2char */
	    mask = sockunion2char (&so_mask);

	    if (family != AF_INET
#ifdef HAVE_IPV6
		&& family != AF_INET6
#endif /* HAVE_IPV6 */
		)
		continue;

	    if (BIT_TEST (rtm->rtm_flags, RTF_HOST)) {
		masklen = (family == AF_INET) ? 32 : 128;
	    }
	    else {
		/* I don't know the reason, 
		   but it's needed for getting rid of strange subnetmask */
		if (family == AF_INET && *(u_long *) dest == *(u_long *) mask) {
		    /* so_mask.sa.sa_len = 0; */
		}

		if (!BIT_TEST (rtm->rtm_addrs, RTA_NETMASK) /* || 
			so_mask.sa.sa_len <= 2 */) {
		    /* not specific netmask */
		    if (family == AF_INET) {
			/* natural mask */
			if (*(u_long *) dest == INADDR_ANY)
			    masklen = 0;
			else
			    masklen = (dest[0] < 128) ? 8 :
				(dest[0] < 192) ? 16 :
				(dest[0] < 224) ? 24 : 32;
		    }
		    else {
			masklen = 0;
		    }
		}
		else {
		    char tmp[16];
		    memset (tmp, 0, sizeof (tmp));
		    memcpy (tmp, sockunion2char (&so_mask), sa_len (&so_mask) -
			    (sockunion2char (&so_mask) - (u_char *) &so_mask));
		    masklen = mask2len (tmp, (family == AF_INET) ? 4 : 16);
		}
	    }

	    if (so_gate.sa.sa_family == AF_LINK) {
		/* forget the physical if info  */
		memset (nexthop, 0, (family == AF_INET)? 4: 16);
	        so_gate.sa.sa_family = family;
	    }
	    if (so_gate.sa.sa_family != family)
		continue;

#ifdef __KAME__
	    /* KAME IPV6 still has an index here */
	    if (family == AF_INET6 && 
		    IN6_IS_ADDR_LINKLOCAL ((struct in6_addr *)nexthop)) {
       	        nexthop[2] = 0;
       	        nexthop[3] = 0;
	    }
#endif /* __KAME__ */

	    update_kernel_route ((rtm->rtm_type == RTM_DELETE)? 'D': 'A',
				 family, dest, nexthop, masklen, index, proto);
	}
    }
    return (0);
}


static void 
kernel_rtmsg_rcv (int sockfd)
{
    int n;
    char msgbuf[4096]; /* I don't know how much is enough */

    if ((n = read (sockfd, msgbuf, sizeof (msgbuf))) > 0) {
        sys_kernel_rt_msg (msgbuf, n);
    }
    else {
	trace (TR_ERROR, MRT->trace, "read on routing socket %d (%m)\n", 
	      sockfd);
    }
    select_enable_fd (sockfd);
}

#endif /* __EXTENSIONS__ */


#define DEV_IP "/dev/ip"
static int route_sockfd = -1;

int
kernel_init (void)
{
    if ((route_sockfd = open (DEV_IP, O_RDWR, 0)) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "open for %s (%s)\n", DEV_IP, strerror (errno));
	return (-1);
    }
#ifdef __EXTENSIONS__
    if ((route_sockfd2 = socket (PF_ROUTE, SOCK_RAW, 0)) < 0) {
        trace (TR_ERROR, MRT->trace, "PF_ROUTE socket (%m)\n");
        return (-1);
    }
    select_add_fd_event ("kernel_rtmsg_rcv", route_sockfd2, SELECT_READ, TRUE,
                          NULL, kernel_rtmsg_rcv, 1, route_sockfd2);
#endif /* __EXTENSIONS__ */
    return (0);
}


#ifdef IRE_DEFAULT		/* This means Solaris 5.6 */
/* I'm not sure if they are compatible, though -- masaki */
#define IRE_GATEWAY IRE_DEFAULT
#define IRE_NET IRE_PREFIX
#define IRE_ROUTE IRE_CACHE
#define IRE_SUBNET IRE_IF_NORESOLVER
#define IRE_RESOLVER IRE_IF_RESOLVER
#define IRE_ROUTE_ASSOC IRE_HOST
#define IRE_ROUTE_REDIRECT IRE_HOST_REDIRECT
#endif /* IRE_DEFAULT */

static int
kernel_read_rt_table_v4 (void)
{
    int sd, flags;
    struct strbuf strbuf;
    struct T_optmgmt_req *tor;
    struct T_optmgmt_ack *toa;
    struct T_error_ack *tea;
    struct opthdr *req;
    int rc = -1;
    char *cp;

    if ((sd = route_sockfd) < 0)
	return (-1);

    strbuf.maxlen = getpagesize ();
    strbuf.buf = (char *) malloc (strbuf.maxlen);
    if (strbuf.buf == NULL) {
	goto finish;
    }
    tor = (struct T_optmgmt_req *) strbuf.buf;
    toa = (struct T_optmgmt_ack *) strbuf.buf;
    tea = (struct T_error_ack *) strbuf.buf;

    tor->PRIM_type = T_OPTMGMT_REQ;
    tor->OPT_offset = sizeof (struct T_optmgmt_req);
    tor->OPT_length = sizeof (struct opthdr);
#ifndef MI_T_CURRENT
/* I don't know what this means -- masaki */
#define MI_T_CURRENT    0x100
#endif /* MI_T_CURRENT */
    tor->MGMT_flags = MI_T_CURRENT;

    req = (struct opthdr *) (tor + 1);
    req->level = MIB2_IP;
    req->name = 0;
    req->len = 0;

    strbuf.len = tor->OPT_length + tor->OPT_offset;
    flags = 0;
    rc = putmsg (sd, &strbuf, (struct strbuf *) 0, flags);
    if (rc < 0)
	goto finish;

    req = (struct opthdr *) (toa + 1);

    for (;;) {
	flags = 0;
	rc = getmsg (sd, &strbuf, (struct strbuf *) 0, &flags);
	if (rc < 0)
	    goto finish;	/* this is EOD msg */
	if (rc == 0
	    && strbuf.len >= sizeof (struct T_optmgmt_ack)
	    && toa->PRIM_type == T_OPTMGMT_ACK
	    && toa->MGMT_flags == T_SUCCESS
	    && req->len == 0) {
	    rc = 1;
	    goto finish;	/* this is EOD msg */
	}
	if (strbuf.len >= sizeof (struct T_error_ack)
	    && tea->PRIM_type == T_ERROR_ACK) {
	    rc = -1;
	    goto finish;
	}
	if (rc != MOREDATA
	    || strbuf.len < sizeof (struct T_optmgmt_ack)
	    || toa->PRIM_type != T_OPTMGMT_ACK
	    || toa->MGMT_flags != T_SUCCESS) {
	    rc = -1;
	    goto finish;
	}
	if (req->level != MIB2_IP || req->name != MIB2_IP_21) {
	    do {
		rc = getmsg (sd, (struct strbuf *) 0, &strbuf, &flags);
	    } while (rc == MOREDATA);
	    continue;
	}
	strbuf.maxlen = (getpagesize () / sizeof (mib2_ipRouteEntry_t)) *
	    sizeof (mib2_ipRouteEntry_t);
	strbuf.len = 0;
	flags = 0;
	do {
	    rc = getmsg (sd, (struct strbuf *) 0, &strbuf, &flags);
	    if (rc < 0)
		goto finish;
	    if (rc == 0 || rc == MOREDATA) {
		mib2_ipRouteEntry_t *rp = (mib2_ipRouteEntry_t *) strbuf.buf;
		mib2_ipRouteEntry_t *lp =
		(mib2_ipRouteEntry_t *) (strbuf.buf + strbuf.len);

		do {
    		    interface_t *interface = NULL;
		    int proto = PROTO_KERNEL;
#ifdef notdef
fprintf(stderr, "re_ire_type=%x\n", rp->ipRouteInfo.re_ire_type);
fprintf(stderr, "dest=0x%x\n", rp->ipRouteDest);
fprintf(stderr, "nexthop=0x%x\n", rp->ipRouteNextHop);
fprintf(stderr, "mask=%d\n", mask2len (&rp->ipRouteMask, 4));
#endif
		    if (BIT_TEST (rp->ipRouteInfo.re_ire_type, 
			    IRE_BROADCAST|IRE_ROUTE_REDIRECT
			    |IRE_LOCAL|IRE_ROUTE /* I'm not sure */
			    /*|IRE_INTERFACE|IRE_LOOPBACK*/)) {
			continue;
/* loopback route is differnt from one by interface */
		    }
#ifdef notdef
		    /* net or host routes */
		    if (!BIT_TEST (rp->ipRouteInfo.re_ire_type,
				   IRE_NET | IRE_ROUTE_ASSOC)) {
			continue;
		    }
#endif /* notdef */
		    /* On Solaris, even an interface route have an next hop */
		    if (rp->ipRouteNextHop == INADDR_ANY)
			continue;

		    if (rp->ipRouteIfIndex.o_length > 0) {
		        /* XXX dirty way! */
		        if ((cp = strrchr (rp->ipRouteIfIndex.o_bytes, ':'))) {
			    *cp = '\0';
		        }
		        interface = find_interface_byname (
					       rp->ipRouteIfIndex.o_bytes);
		    }
		    if (interface == NULL) {
			prefix_t *prefix;
			prefix = New_Prefix (AF_INET, &rp->ipRouteNextHop, 32);
			interface = find_interface (prefix);
			Deref_Prefix (prefix);
		    }
		    if (interface == NULL) {
			char tmp4[64], tmp5[64];
			trace (TR_ERROR, INTERFACE_MASTER->trace,
	       		       "interface unknown %s gw %s on %s type %x\n", 
				inet_ntop (AF_INET, &rp->ipRouteDest, 
					   tmp4, sizeof (tmp4)),
				mask2len (&rp->ipRouteMask, 4),
				inet_ntop (AF_INET, &rp->ipRouteNextHop, 
					   tmp5, sizeof (tmp5)),
				(rp->ipRouteIfIndex.o_length > 0)?
				    rp->ipRouteIfIndex.o_bytes:"?",
				rp->ipRouteInfo.re_ire_type);
			continue;
		    }
		    /* to do the same thing with other platforms,
		       clear the next hop in case of interface routes */
		    if (!BIT_TEST (rp->ipRouteInfo.re_ire_type, IRE_GATEWAY) &&
		       (BIT_TEST (rp->ipRouteInfo.re_ire_type, IRE_RESOLVER) ||
		        BIT_TEST (rp->ipRouteInfo.re_ire_type, IRE_LOOPBACK))) {
			rp->ipRouteNextHop = INADDR_ANY;
			proto = PROTO_CONNECTED;
		    }
		    update_kernel_route ('A', AF_INET, &rp->ipRouteDest,
				      &rp->ipRouteNextHop,
				      mask2len (&rp->ipRouteMask, 4), 
				      interface->index, proto);
		} while (++rp < lp);
	    }
	} while (rc == MOREDATA);
	rc = 1;
    }
  finish:
    if (strbuf.buf)
	free (strbuf.buf);
    return (rc);
}


#ifdef HAVE_IPV6
#ifdef SIOCGLIFCONF
#define MIB2_IP_23 MIB2_IP6_ROUTE
#define mib2_ip6RouteEntry_t mib2_ipv6RouteEntry_t
#define ip6RouteInfo ipv6RouteInfo
#define ip6RouteNextHop ipv6RouteNextHop
#define ip6RouteDest ipv6RouteDest
#define ip6RouteIfIndex ipv6RouteIfIndex
#endif /* SIOCGLIFCONF */
static int
kernel_read_rt_table_v6 (void)
{
    int sd, flags;
    struct strbuf strbuf;
    struct T_optmgmt_req *tor;
    struct T_optmgmt_ack *toa;
    struct T_error_ack *tea;
    struct opthdr *req;
    int rc = -1;
    interface_t *interface = NULL;
    char *cp;

    if ((sd = route_sockfd) < 0)
	return (-1);

    strbuf.maxlen = getpagesize ();
    strbuf.buf = (char *) malloc (strbuf.maxlen);
    if (strbuf.buf == NULL) {
	goto finish;
    }
    tor = (struct T_optmgmt_req *) strbuf.buf;
    toa = (struct T_optmgmt_ack *) strbuf.buf;
    tea = (struct T_error_ack *) strbuf.buf;

    tor->PRIM_type = T_OPTMGMT_REQ;
    tor->OPT_offset = sizeof (struct T_optmgmt_req);
    tor->OPT_length = sizeof (struct opthdr);
    tor->MGMT_flags = MI_T_CURRENT;

    req = (struct opthdr *) (tor + 1);
    req->level = MIB2_IP6;
    req->name = 0;
    req->len = 0;

    strbuf.len = tor->OPT_length + tor->OPT_offset;
    flags = 0;
    rc = putmsg (sd, &strbuf, (struct strbuf *) 0, flags);
    if (rc < 0)
	goto finish;

    req = (struct opthdr *) (toa + 1);

    for (;;) {
	flags = 0;
	rc = getmsg (sd, &strbuf, (struct strbuf *) 0, &flags);
	if (rc < 0)
	    goto finish;	/* this is EOD msg */
	if (rc == 0
	    && strbuf.len >= sizeof (struct T_optmgmt_ack)
	    && toa->PRIM_type == T_OPTMGMT_ACK
	    && toa->MGMT_flags == T_SUCCESS
	    && req->len == 0) {
	    rc = 1;
	    goto finish;	/* this is EOD msg */
	}
	if (strbuf.len >= sizeof (struct T_error_ack)
	    && tea->PRIM_type == T_ERROR_ACK) {
	    rc = -1;
	    goto finish;
	}
	if (rc != MOREDATA
	    || strbuf.len < sizeof (struct T_optmgmt_ack)
	    || toa->PRIM_type != T_OPTMGMT_ACK
	    || toa->MGMT_flags != T_SUCCESS) {
	    rc = -1;
	    goto finish;
	}
	if (req->level != MIB2_IP6 || req->name != MIB2_IP_23) {
	    do {
		rc = getmsg (sd, (struct strbuf *) 0, &strbuf, &flags);
	    } while (rc == MOREDATA);
	    continue;
	}
	strbuf.maxlen = (getpagesize () / sizeof (mib2_ip6RouteEntry_t)) *
	    sizeof (mib2_ip6RouteEntry_t);
	strbuf.len = 0;
	flags = 0;
	do {
	    rc = getmsg (sd, (struct strbuf *) 0, &strbuf, &flags);
	    if (rc < 0)
		goto finish;
	    if (rc == 0 || rc == MOREDATA) {
		mib2_ip6RouteEntry_t *rp = (mib2_ip6RouteEntry_t *) strbuf.buf;
		mib2_ip6RouteEntry_t *lp =
		(mib2_ip6RouteEntry_t *) (strbuf.buf + strbuf.len);
		do {
		    int proto = PROTO_KERNEL;
	    	    int masklen = 0;

		    if (BIT_TEST (rp->ip6RouteInfo.re_ire_type, 
			    IRE_BROADCAST|IRE_ROUTE_REDIRECT
			    |IRE_LOCAL|IRE_ROUTE /* I'm not sure */
			    /* |IRE_INTERFACE|IRE_LOOPBACK */)) {
			continue;
		    }
#ifdef notdef
fprintf(stderr, "re_ire_type=%x\n", rp->ip6RouteInfo.re_ire_type);
		    /* net or host routes */
		    if (!BIT_TEST (rp->ip6RouteInfo.re_ire_type,
				   IRE_NET | IRE_ROUTE_ASSOC)) {
			continue;
		    }
#endif
		    if (IN6_IS_ADDR_UNSPECIFIED (&rp->ip6RouteNextHop))
			continue;

#ifdef SIOCGLIFCONF
		    masklen = rp->ipv6RoutePfxLength;
#else
		    masklen = mask2len ((char *) &rp->ip6RouteMask, 16);
#endif /* SIOCGLIFCONF */

		    /* There are strange ::/0 routes for resolving ll addrs */
		    if (IN6_IS_ADDR_UNSPECIFIED (&rp->ip6RouteDest) &&
			    masklen == 0)
			continue;

		    if (rp->ip6RouteIfIndex.o_length > 0) {
		        /* XXX dirty way! */
		        if ((cp = strrchr (rp->ip6RouteIfIndex.o_bytes, ':'))) {
			    *cp = '\0';
		        }
		        if ((cp = strrchr (rp->ip6RouteIfIndex.o_bytes, '#'))) {
			    *cp = '\0';
		        }
		        interface = find_interface_byname (
					       rp->ip6RouteIfIndex.o_bytes);
		    }
		    if (interface == NULL) {
			prefix_t *prefix;
			prefix = New_Prefix (AF_INET6, &rp->ip6RouteNextHop, 
					     128);
			interface = find_interface (prefix);
			Deref_Prefix (prefix);
		    }
		    if (interface == NULL) {
			char tmp4[64], tmp5[64];
			trace (TR_ERROR, INTERFACE_MASTER->trace,
	       		       "interface unknown %s gw %s on %s type %x\n", 
			       	inet_ntop (AF_INET6, &rp->ip6RouteDest, 
					  tmp4, sizeof (tmp4)),
				masklen,
				inet_ntop (AF_INET6, &rp->ip6RouteNextHop, 
					  tmp5, sizeof (tmp5)),
					  (rp->ip6RouteIfIndex.o_length > 0)?
					      rp->ip6RouteIfIndex.o_bytes:"?",
				rp->ip6RouteInfo.re_ire_type);
			continue;
		    }
		    if (BIT_TEST (rp->ip6RouteInfo.re_ire_type, IRE_RESOLVER) ||
		        BIT_TEST (rp->ip6RouteInfo.re_ire_type, IRE_LOOPBACK)) {
			memset (&rp->ip6RouteNextHop, 0, 16);
			proto = PROTO_CONNECTED;
		    }

		    update_kernel_route ('A', AF_INET6, &rp->ip6RouteDest,
				      &rp->ip6RouteNextHop, masklen,
				      interface->index, proto);
		} while (++rp < lp);
	    }
	} while (rc == MOREDATA);
    }
  finish:
    if (strbuf.buf)
	free (strbuf.buf);
    return (rc);
}
#endif /* HAVE_IPV6 */


int
sys_kernel_read_rt_table (void)
{
    kernel_read_rt_table_v4 ();
#ifdef HAVE_IPV6
    kernel_read_rt_table_v6 ();
#endif /* HAVE_IPV6 */
    return (1);
}

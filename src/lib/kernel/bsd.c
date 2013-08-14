/*
 * $Id: bsd.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include "mrt.h"
#include "igmp.h"

#include <sys/sysctl.h>
/* #include <net/if_dl.h> */
#include <net/route.h>

struct sockaddr_dl *index2dl[MAX_INTERFACES];

static int sys_kernel_rt_msg (u_char *buf, int bufsize);

int 
read_interfaces (void)
{
    size_t needed;
    u_char *buf;

#define ROUNDUP(a) \
   ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

    int mib[] =
    {CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST, 0};

    if (sysctl (mib, 6, NULL, &needed, NULL, 0) < 0) {
	trace (TR_FATAL, INTERFACE_MASTER->trace, "sysctl: %m\n");
	return (-1);
    }
    needed = ROUNDUP (needed);
    buf = NewArray (u_char, needed);
    if (sysctl (mib, 6, buf, &needed, NULL, 0) < 0) {
	trace (TR_FATAL, INTERFACE_MASTER->trace, "sysctl: %m\n");
	return (-1);
    }

    sys_kernel_rt_msg (buf, needed);
    Delete (buf);
    return (1);
}


struct m_rtmsg {
    struct rt_msghdr m_rtm;
    char m_space[1024]; /* XXX */
};


static void kernel_rtmsg_rcv (int sockfd);
static int route_sockfd = -1;

int
kernel_init (void)
{
    if ((route_sockfd = socket (PF_ROUTE, SOCK_RAW, 0)) < 0) {
        trace (TR_ERROR, MRT->trace, "PF_ROUTE socket (%m)\n");
        return (-1);
    }   
    select_add_fd_event ("kernel_rtmsg_rcv", route_sockfd, SELECT_READ, TRUE, 
			  NULL, kernel_rtmsg_rcv, 1, route_sockfd);
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

    if (route_sockfd < 0)
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

    rtm_addrs = 0;
    flags = RTF_UP;

    if (dest->family == AF_INET) {
	so_dst.sin.sin_addr.s_addr = prefix_tolong (dest);
	so_dst.sin.sin_len = sizeof (struct sockaddr_in);
	so_dst.sin.sin_family = AF_INET;
    	netmasking (AF_INET, (char *)&so_dst.sin.sin_addr, len);
        rtm_addrs |= RTA_DST;
#ifdef notdef
	/* this doesn't work when removing it */
	if (len == 32)
	    flags |= RTF_HOST;
#endif

        if (nexthop && !prefix_is_unspecified (nexthop)) {
	    so_gate.sin.sin_addr.s_addr = prefix_tolong (nexthop);
	    so_gate.sin.sin_len = sizeof (struct sockaddr_in);
	    so_gate.sin.sin_family = AF_INET;
	    rtm_addrs |= RTA_GATEWAY;
	    flags |= RTF_GATEWAY;
	}
	/* this works at least with FreeBSD 3.X */
	else if (index > 0 && index < MAX_INTERFACES && index2dl[index]) {
	    so_gate.sdl = *index2dl[index];
	    rtm_addrs |= RTA_GATEWAY;
	    /* XXX should this have GATEWAY? */
	    flags |= RTF_GATEWAY;
        }

	so_mask.sin.sin_len = sizeof (struct sockaddr_in);
        /* so_mask.sin.sin_family = AF_UNSPEC; */
        so_mask.sin.sin_family = AF_INET;
	len2mask (len, (char *) &so_mask.sin.sin_addr, 4);
	rtm_addrs |= RTA_NETMASK;
    }
#ifdef HAVE_IPV6
    else if (dest->family == AF_INET6) {
	memcpy (&so_dst.sin6.sin6_addr, prefix_tochar (dest), 16);
	so_dst.sin6.sin6_len = sizeof (struct sockaddr_in6);
	so_dst.sin6.sin6_family = AF_INET6;
    	netmasking (AF_INET6, (char *)&so_dst.sin6.sin6_addr, len);
        rtm_addrs |= RTA_DST;
#ifdef notdef
	if (len == 128)
	    flags |= RTF_HOST;
#endif

        if (nexthop && !prefix_is_unspecified (nexthop)) {
            memcpy (&so_gate.sin6.sin6_addr, prefix_tochar (nexthop), 16);
	    so_gate.sin6.sin6_len = sizeof (struct sockaddr_in6);
	    so_gate.sin6.sin6_family = AF_INET6;
	    rtm_addrs |= RTA_GATEWAY;
	    flags |= RTF_GATEWAY;
#ifdef __KAME__
	    /* KAME IPV6 still requires an index here */
	    if (IN6_IS_ADDR_LINKLOCAL (&so_gate.sin6.sin6_addr)) {
       	        so_gate.sin6.sin6_addr.s6_addr[2] = index >> 8;;
       	        so_gate.sin6.sin6_addr.s6_addr[3] = index;
	    }
#endif /* __KAME__ */
	}

	so_mask.sin6.sin6_len = sizeof (struct sockaddr_in6);
        /* so_mask.sin6.sin6_family = AF_UNSPEC; */
        so_mask.sin6.sin6_family = AF_INET6;
	len2mask (len, (char *) &so_mask.sin6.sin6_addr, 16);
	rtm_addrs |= RTA_NETMASK;

#ifdef notdef
	interface = find_interface_byindex (index);

	assert (interface->primary6);
	memcpy (&so_ifa.sin6.sin6_addr,
		prefix_tochar (
			BIT_TEST (interface->flags, IFF_POINTOPOINT)?
			    interface->primary6->broadcast:
			interface->primary6->prefix), 16);
	so_ifa.sin6.sin6_len = sizeof (struct sockaddr_in6);
	so_ifa.sin6.sin6_family = AF_INET6;
#endif

    }
#endif /* HAVE_IPV6 */
    else			/* unknown family */
	return (-1);

#ifdef RTF_REJECT
    if (nexthop && prefix_is_loopback (nexthop))
	flags |= RTF_REJECT;
#endif /* RTF_REJECT */

    if (index > 0 && index < MAX_INTERFACES && index2dl[index]) {
	so_ifp.sdl = *index2dl[index];
	rtm_addrs |= RTA_IFP;
    }

#define NEXTADDRP(w, u) \
	if (rtm_addrs & (w)) {\
	    int l; \
	    l = ROUNDUP(u.sa.sa_len); bcopy((char *)&(u), cp, l); cp += l;\
	}

    m_rtmsg.m_rtm.rtm_flags = flags;
    m_rtmsg.m_rtm.rtm_version = RTM_VERSION;
    m_rtmsg.m_rtm.rtm_seq = ++seq;
    m_rtmsg.m_rtm.rtm_addrs = rtm_addrs;
    m_rtmsg.m_rtm.rtm_rmx = rt_metrics;
#ifdef INRIA_IPV6
    /* the latest INRIA requires index in rtm_index */
    m_rtmsg.m_rtm.rtm_index = index;
#endif /* INRIA_IPV6 */
    /*m_rtmsg.m_rtm.rtm_inits = 0; */

    NEXTADDRP (RTA_DST, so_dst);
    NEXTADDRP (RTA_GATEWAY, so_gate);
    NEXTADDRP (RTA_NETMASK, so_mask);
    NEXTADDRP (RTA_GENMASK, so_genmask);
    NEXTADDRP (RTA_IFP, so_ifp);
    NEXTADDRP (RTA_IFA, so_ifa);

    m_rtmsg.m_rtm.rtm_msglen = l = cp - (char *) &m_rtmsg;

again:
    if ((rlen = write (route_sockfd, (char *) &m_rtmsg, l)) < 0) {
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
	/* route already exists -- ok */
	trace ((errno == EEXIST || errno == ESRCH)? TR_TRACE: TR_ERROR, 
		MRT->trace, "route socket dst %p nh %a (%m)\n", 
	        dest, nexthop);
	return (-1);
    }
    return (1);
}


#ifdef HAVE_IPV6
int 
mc6_kernel_update_cache (int type, prefix_t *group, prefix_t *source, 
			 interface_t *parent, interface_bitset_t *children)
{
    int ret = -1;
#ifdef RTA_DOWNSTREAM
    u_char *cp;
    struct rt_msghdr *rtm;
    sockunion_t so_dst, so_src, so_ifp, *so_inds = NULL;
    struct ds_in6addr *dsa;
    int rtm_addrs = 0;
    static int seq = 0;
    int size = 0;

    if (route_sockfd < 0)
	return (-1);

    memset (&so_dst, 0, sizeof (so_dst));
    memset (&so_src, 0, sizeof (so_src));
    memset (&so_ifp, 0, sizeof (so_ifp));

    assert (type == RTM_ADD || type == RTM_CHANGE || type == RTM_DELETE ||
	    type == RTM_GET);

    if (type == RTM_ADD || type == RTM_CHANGE) {
	int i, count;
	assert (children != NULL);
	count = how_many_bits (children);
	if (count > 0) {
	    size = 4 /* XXX */ + count * sizeof (*dsa);
	    so_inds = alloca (size);
	    memset (so_inds, 0, size);
	    so_inds->inds.sin_len = size;
	    so_inds->inds.sin_family = AF_INET6;
	    so_inds->inds.sin_num = count;
	    dsa = (struct ds_in6addr *)so_inds->inds.sin_data;
	    /* why do we have to use ip addresses instead of indeces? */
	    for (i = 0; i < MAX_INTERFACES; i++) {
	        if (BITX_TEST (children, i)) {
		    interface_t *interface = INTERFACE_MASTER->index2if[i];
		    void *addr = prefix_tochar (interface->primary6->prefix);
		    assert (interface != NULL && interface->primary6 != NULL);
		    /* This is masaki's extension to CAIRN kernel */
		    if (BIT_TEST (interface->flags, IFF_POINTOPOINT) &&
			    interface->primary6->broadcast) {
			addr = prefix_tochar (interface->primary6->broadcast);
		    }
		    memcpy (&dsa->sin6_addr, addr, 16);
		    dsa->hoplimit = interface->threshold;
		    dsa->flags = 0;
		    dsa++;
	        }
	    }
	    rtm_addrs |= RTA_DOWNSTREAM;
	}
    }

    size = size + sizeof (*rtm) +
	sizeof (so_dst) + sizeof (so_src) + sizeof (so_ifp);

    assert (group->family == AF_INET6);
    assert (source->family == AF_INET6);

    memcpy (&so_dst.sin6.sin6_addr, prefix_tochar (group), 16);
    so_dst.sin6.sin6_len = sizeof (struct sockaddr_in6);
    so_dst.sin6.sin6_family = AF_INET6;
    rtm_addrs |= RTA_DST;

    memcpy (&so_src.sin6.sin6_addr, prefix_tochar (source), 16);
    so_src.sin6.sin6_len = sizeof (struct sockaddr_in6);
    so_src.sin6.sin6_family = AF_INET6;
    rtm_addrs |= RTA_AUTHOR;

	if (parent != NULL && parent->primary6 != NULL) {
            memcpy (&so_ifp.sin6.sin6_addr, 
		    prefix_tochar (parent->primary6->prefix), 16);
    	    so_ifp.sin6.sin6_len = sizeof (struct sockaddr_in6);
            so_ifp.sin6.sin6_family = AF_INET6;
	    rtm_addrs |= RTA_IFP;
	}

    rtm = (struct rt_msghdr *) alloca (size);
    memset (rtm, 0, size);
    rtm->rtm_type = type;
    rtm->rtm_flags = RTF_UP | RTF_MULTICAST | RTF_HOST;
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_seq = ++seq;
    rtm->rtm_addrs = rtm_addrs;
    cp = (u_char *)(rtm + 1);

    NEXTADDRP (RTA_DST, so_dst);
    NEXTADDRP (RTA_IFP, so_ifp);
    NEXTADDRP (RTA_AUTHOR, so_src);
    NEXTADDRP (RTA_DOWNSTREAM, (*so_inds));

    rtm->rtm_msglen = cp - (u_char *)rtm;

    if ((ret = write (route_sockfd, (char *) rtm, rtm->rtm_msglen)) < 0) {
	trace (TR_ERROR, MRT->trace, "route socket source %a group %a (%m)\n", 
	       source, group);
    }
#endif /* RTA_DOWNSTREAM */
    return (ret);
}
#endif /* HAVE_IPV6 */


#define NEXTADDRR(w, u) \
   if (rtm_addrs & (w)) {  \
	   int l; \
           l = ROUNDUP(((struct sockaddr *)cp)->sa_len); \
           bcopy(cp, (char *)&(u), l); cp += l; \
   }


static int
sys_kernel_rt_msg (u_char *buf, int bufsize)
{

    sockunion_t so_dst, so_gate, so_mask, so_genmask, so_brd, 
		    so_ifa, so_ifp, so_src;
    u_char *next, *lim;
    struct rt_msghdr *rtm;

    lim = buf + bufsize;
    for (next = buf; next < lim; next += rtm->rtm_msglen) {

        int family = 0, masklen = 0, index = 0;
        u_char *dest, *nexthop, *mask;
	u_char *addr = NULL, *broadcast = NULL, *src = NULL;
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
	    if (sdl->sdl_index > 0 && sdl->sdl_index < MAX_INTERFACES) {
		index2dl[sdl->sdl_index] = New (struct sockaddr_dl);
		memcpy (index2dl[sdl->sdl_index], sdl, sizeof (*sdl));
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
                    if (sdl->sdl_family == AF_LINK) {
			ifam->ifam_index = sdl->sdl_index;
		    }
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
		    if (rtm->rtm_type == RTM_DELADDR) {
		    	update_addr_of_interface ('D',
				interface, family, addr, masklen,
				(broadcast) ? broadcast : NULL);
		    }
#if 1
		    else
#endif
		    if (route_sockfd >= 0) {

		    /* I need to test if_flags since RTM_IFINFO is not issued
		       on FreeBSD for some interface when adding an address */

		        struct ifreq ifr;
  		        char tmpx[MAXLINE];
		        u_long flags;

		        strncpy (ifr.ifr_name, interface->name, 
			         sizeof (ifr.ifr_name));
  		        if (ioctl (route_sockfd, SIOCGIFFLAGS, &ifr) < 0) {
			    trace (TR_WARN, MRT->trace, 
				   "SIOCGIFFLAGS: %s (%m)\n",
			           interface->name);
		        } else if ((interface->flags & IFF_UP) != 
    			                (ifr.ifr_flags & IFF_UP)) {
			    flags = ((interface->flags & ~IFF_UP) |
				     (ifr.ifr_flags & IFF_UP));
	    	            new_interface (NULL, flags & 0xffff, 
				     interface->mtu, interface->index);
		        }
		    }
		    if (rtm->rtm_type == RTM_NEWADDR) {
		    	update_addr_of_interface ('A',
				interface, family, addr, masklen,
				(broadcast) ? broadcast : NULL);
		    }
		}
	    }
	}
#ifdef RTA_DOWNSTREAM
	else if (rtm->rtm_type == RTM_GET && 
		 BIT_TEST (rtm->rtm_flags, RTF_MULTICAST)) {

	    cp = (u_char *) (rtm + 1);
	    rtm_addrs = rtm->rtm_addrs;

	    NEXTADDRR (RTA_DST, so_dst);
	    NEXTADDRR (RTA_IFP, so_ifp);
	    NEXTADDRR (RTA_AUTHOR, so_src);

	    family = so_dst.sa.sa_family;
	    dest = sockunion2char (&so_dst);
	    src = sockunion2char (&so_src);
	    if (family != AF_INET6)
		continue;

	    if (MRT->pid == rtm->rtm_pid) {
	        kernel_mfc_request (MRTMSG_USAGE, family, dest, src, 
				    rtm->rtm_use);
	    }
	    else if (so_ifp.sdl.sdl_family == AF_LINK) {
	        kernel_mfc_request (MRTMSG_CACHE, family, dest, src, 
				    so_ifp.sdl.sdl_index);
	    }
	}
#endif /* RTA_DOWNSTREAM */
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
                    if (sdl->sdl_family == AF_LINK) {
			index = sdl->sdl_index;
		    }
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
		if (family == AF_INET && *(u_long *) dest == *(u_long *) mask)
		    so_mask.sa.sa_len = 0;

		if (!BIT_TEST (rtm->rtm_addrs, RTA_NETMASK) || 
			so_mask.sa.sa_len <= 2) {
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
		    memcpy (tmp, sockunion2char (&so_mask), so_mask.sa.sa_len -
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
#ifdef RTA_DOWNSTREAM
	else if (rtm->rtm_type == RTM_RESOLVE) {
	    int type = MRTMSG_NOCACHE;
#if 0
	    printf ("rtm->rtm_flags=%x rtm->rtm_addrs=%x\n", 
		rtm->rtm_flags, rtm->rtm_addrs);
#endif
	    if (rtm->rtm_flags & ~(RTF_DONE|RTF_MULTICAST|RTF_XRESOLVE))
		continue;

	    if (!BIT_TEST (rtm->rtm_flags, RTF_MULTICAST))
		continue;

	    if (/* rtm->rtm_errno && */ rtm->rtm_errno != EADDRNOTAVAIL
	        	   && rtm->rtm_errno != EADDRINUSE)
		continue;
	    if (rtm->rtm_errno == EADDRINUSE)
		type = MRTMSG_WRONGIF;

	    index = rtm->rtm_index;
	    cp = (u_char *) (rtm + 1);
	    rtm_addrs = rtm->rtm_addrs;

	    NEXTADDRR (RTA_DST, so_dst);
	    NEXTADDRR (RTA_IFP, so_ifp);
	    NEXTADDRR (RTA_AUTHOR, so_src);

	    if (index <= 0) {
	        if (BIT_TEST (rtm_addrs, RTA_IFP)) {
                    struct sockaddr_dl *sdl;
                    sdl = (struct sockaddr_dl *) &so_ifp;
                    if (sdl->sdl_family == AF_LINK) {
			index = sdl->sdl_index;
		    }
		}
	    }

	    assert (BIT_TEST (rtm_addrs, RTA_DST));
	    assert (BIT_TEST (rtm_addrs, RTA_IFP));
	    assert (BIT_TEST (rtm_addrs, RTA_AUTHOR));
	    family = so_dst.sa.sa_family;
	    dest = sockunion2char (&so_dst);
	    src = sockunion2char (&so_src);

	    if (family != AF_INET && family != AF_INET6)
		continue;

	    kernel_mfc_request (type, family, dest, src, index);
	}
#endif /* RTA_DOWNSTREAM */
    }
    return (0);
}


int
sys_kernel_read_rt_table (void)
{
    size_t needed;
    int mib[] =
    {CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0};
    u_char *buf;

    if (sysctl (mib, 6, NULL, &needed, NULL, 0) < 0) {
	trace (TR_ERROR, MRT->trace, "sysctl: %m\n");
	return (-1);
    }
    buf = NewArray (u_char, needed);
    if (sysctl (mib, 6, buf, &needed, NULL, 0) < 0) {
	trace (TR_ERROR, MRT->trace, "sysctl: %m\n");
	return (-1);
    }

    sys_kernel_rt_msg (buf, needed);
    Delete (buf);
    return (1);
}


#ifdef HAVE_IPV6
int
mc6_kernel_read_rt_table (void)
{
#ifdef RTA_DOWNSTREAM
    size_t needed;
    int mib[] = {CTL_NET, PF_ROUTE, 0, AF_INET6, NET_RT_DUMP, RTF_MULTICAST};
    u_char *buf;

    if (sysctl (mib, 6, NULL, &needed, NULL, 0) < 0) {
	trace (TR_ERROR, MRT->trace, "sysctl: %m\n");
	return (-1);
    }
    buf = NewArray (u_char, needed);
    if (sysctl (mib, 6, buf, &needed, NULL, 0) < 0) {
	trace (TR_ERROR, MRT->trace, "sysctl: %m\n");
	return (-1);
    }

    sys_kernel_rt_msg (buf, needed);
    Delete (buf);
#endif /* RTA_DOWNSTREAM */
    return (1);
}
#endif /* HAVE_IPV6 */


static void 
kernel_rtmsg_rcv (int sockfd)
{
    int n;
    u_char msgbuf[4096]; /* I don't know how much is enough */

    if ((n = read (sockfd, msgbuf, sizeof (msgbuf))) > 0) {
        sys_kernel_rt_msg (msgbuf, n);
    }
    else {
	trace (TR_ERROR, MRT->trace, "read on routing socket %d (%m)\n", 
	      sockfd);
    }
    select_enable_fd (sockfd);
}

/*
 *     $Id: linux.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 *
 *     Pedro gave me many suggestions about how to code on Linux
 *     Alexey gave me many suggestions about how to code on Linux 2.1.x
 */

#include <mrt.h>
#include <api6.h>

#include <fcntl.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#ifdef HAVE_IPV6
#include <netinet/icmp6.h>
#endif /* HAVE_IPV6 */

#ifdef __GLIBC__
#include <asm/types.h>
#include <linux/types.h>
/* people say this include caused trouble */
/* #include <linux/socket.h> */
#include <asm/posix_types.h>
/*#include <iovec.h>*/
#include <sys/uio.h>

/* from linux/socket.h */
#define MSG_TRUNC       0x20

#ifdef HAVE_IPV6
/* from linux/ipv6_route.h */
#define RTF_CACHE       0x01000000      /* cache entry                  */
#define RTF_FLOW        0x02000000      /* flow significant route       */
#define RTF_POLICY      0x04000000      /* policy route                 */

#if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
/* OK. net/route.h has the definitions */
#else /* GLIBC 2.1 */
/* I don't know why redhat conflicts definitions in net/route.h and
   netinet/ipv6_route.h */
struct in6_rtmsg {
        struct in6_addr         rtmsg_dst;
        struct in6_addr         rtmsg_src;
        struct in6_addr         rtmsg_gateway;
        __u32                   rtmsg_type;
        __u16                   rtmsg_dst_len;
        __u16                   rtmsg_src_len;
        __u32                   rtmsg_metric;
        unsigned long           rtmsg_info;
        __u32                   rtmsg_flags;
        int                     rtmsg_ifindex;
};
#endif /* GLIB 2.1 */
#endif /* HAVE_IPV6 */
#else  /* __GLIBC__ */
#ifdef HAVE_IPV6
#include <netinet/ipv6_route.h>
#endif /* HAVE_IPV6 inside #else __GLIBC__ */
#endif /* __GLIBC__ */

#include <netinet/ip.h>
#include <linux/if_tunnel.h>
#include <linux/autoconf.h>
/* #undef CONFIG_RTNETLINK */
#ifdef CONFIG_RTNETLINK
#include <linux/version.h>
#include <linux/rtnetlink.h>

/*
 * I learned how to use netlink from Alexey Kuznetsov's code "ip2"
 * I tested it on 2.1.88 but the way may be changed after -- masaki
 */

static int sockfd = -1, seq;
static struct sockaddr_nl snl, local;
static int loopback_if_index = 0;
static u_char anyaddr[16];


static int
sys_kernel_rt_msg (u_char *buf, int len, int my_pid)
{
	struct nlmsghdr *h;

	for (h = (struct nlmsghdr *) buf;
		NLMSG_OK (h, len); h = NLMSG_NEXT (h, len)) {

#ifdef notdef
	    if (h->nlmsg_pid != local.nl_pid || 
			(dump_code && h->nlmsg_seq != dump_code)) {
		/* skip this */
		continue;
	    }
	    else 
#endif
	    if (h->nlmsg_type == NLMSG_DONE) {
	        if (h->nlmsg_pid == my_pid) {
		    trace (TR_TRACE, INTERFACE_MASTER->trace, 
			   "netlink seq %d (done)\n", h->nlmsg_seq);
		}
		return (1);
	    }
	    else if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *nlmsgerr = (struct nlmsgerr *) NLMSG_DATA (h);
	        if (h->nlmsg_pid == my_pid) {
		    trace (TR_ERROR, INTERFACE_MASTER->trace, 
			"netlink seq %d (%s)\n", 
			h->nlmsg_seq, strerror (-nlmsgerr->error));
		}
		return (-1);
	    }
	    else if (h->nlmsg_type == RTM_NEWLINK ||
	             h->nlmsg_type == RTM_DELLINK ||
	             h->nlmsg_type == RTM_GETLINK) {
		int len = h->nlmsg_len;
		struct ifinfomsg *ifi = NLMSG_DATA (h);
		struct rtattr *rta = IFLA_RTA (ifi);
		struct rtattr *tb[IFLA_MAX + 1];

		char *name;
		int index, mtu;
		u_long flags;
		interface_t *interface;

		len -= NLMSG_LENGTH (sizeof (*ifi));
		if (len < 0)
		    continue;

                /* currently I don't want to loop back my request */
            	if (h->nlmsg_pid == my_pid)
                    continue;

		memset (tb, 0, sizeof (tb));
		while (RTA_OK (rta, len)) {
		    if (rta->rta_type <= IFLA_MAX)
			tb[rta->rta_type] = rta;
		    rta = RTA_NEXT (rta, len);
		}

		index = ifi->ifi_index;
		flags = (ifi->ifi_flags & 0xffff);
#if LINUX_VERSION_CODE <= 0x20158 /* 2.1.88 */
		name = ifi->ifi_name;
		mtu = ifi->ifi_mtu;
#else
		/* it seems changed at least in 2.1.102 */
		name = RTA_DATA (tb[IFLA_IFNAME]);
		mtu = *(int *)RTA_DATA (tb[IFLA_MTU]);
#ifdef ARPHRD_SIT
		if (ifi->ifi_type == ARPHRD_SIT) {
		    flags |= IFF_TUNNEL;
		    flags |= IFF_MULTICAST;
		    /* XXX we expect MULTICAST flag to run RIPng */
		}
#endif /* ARPHRD_SIT */
#endif
		/* DELLINK XXX */
		interface = new_interface (name, flags, mtu, index);
		if ((strcmp (name, "lo") == 0) && (flags & IFF_LOOPBACK))
		    loopback_if_index = index;
	    }
	    else if (h->nlmsg_type == RTM_NEWADDR ||
	             h->nlmsg_type == RTM_DELADDR ||
	             h->nlmsg_type == RTM_GETADDR) {
		int len = h->nlmsg_len;
		struct ifaddrmsg *ifa = NLMSG_DATA (h);
		struct rtattr *rta = IFA_RTA (ifa);
		struct rtattr *tb[IFA_MAX + 1];
		u_char destsave[16];

		interface_t *interface;
		void *addr = NULL, *dest = NULL;

		len -= NLMSG_LENGTH (sizeof (*ifa));

		if (len < 0)
		    continue;

                /* currently I don't want to loop back my request */
            	if (h->nlmsg_pid == my_pid)
                    continue;

		memset (tb, 0, sizeof (tb));
		while (RTA_OK (rta, len)) {
		    if (rta->rta_type <= IFA_MAX)
			tb[rta->rta_type] = rta;
		    rta = RTA_NEXT (rta, len);
		}

		interface = find_interface_byindex (ifa->ifa_index);
		if (interface == NULL) {
		    trace (TR_ERROR, INTERFACE_MASTER->trace,
			   "interface for index %d is not registered\n",
			   ifa->ifa_index);
		    continue;
		}

                if (BIT_TEST (interface->flags, IFF_POINTOPOINT)) {
                    if (tb[IFA_LOCAL]) {
                        addr = RTA_DATA (tb[IFA_LOCAL]);
                        if (tb[IFA_ADDRESS])
                            dest = RTA_DATA (tb[IFA_ADDRESS]);
                    }
                    else if (tb[IFA_ADDRESS])
                        addr = RTA_DATA (tb[IFA_ADDRESS]);
                }
                else {
                    if (tb[IFA_ADDRESS])
                        addr = RTA_DATA (tb[IFA_ADDRESS]);
                    if (tb[IFA_BROADCAST])
                        dest = RTA_DATA (tb[IFA_BROADCAST]);
                }

#ifdef HAVE_IPV6
#ifdef SIOCGETTUNNEL
        if (ifa->ifa_family == AF_INET6 &&
	    BIT_TEST (interface->flags, IFF_TUNNEL) &&
            BIT_TEST (interface->flags, IFF_POINTOPOINT)) {
	    if (dest == NULL && IN6_IS_ADDR_LINKLOCAL (addr)) {
	        struct ip_tunnel_parm p;
    		struct ifreq ifr;
	        memset (&p, 0, sizeof (p));
    		safestrncpy (ifr.ifr_name, interface->name, 
			     sizeof (ifr.ifr_name));
	        ifr.ifr_ifru.ifru_data = (void *) &p;
	        if (ioctl (INTERFACE_MASTER->sockfd, SIOCGETTUNNEL, 
			&ifr) == 0) {
	            /* create a link-local destination address */
		    memcpy (destsave, addr, 16);
		    memcpy (destsave + 12, &p.iph.daddr, 4);
		    dest = destsave;
	        }
	        else {
	            trace (TR_WARN, INTERFACE_MASTER->trace,
		           "SIOCGETTUNNEL for %s (%s)\n", ifr.ifr_name,
		           strerror (errno));
	        }
	    }
	}
#endif /* SIOCGETTUNNEL */
#endif /* HAVE_IPV6 */

		update_addr_of_interface ((h->nlmsg_type == RTM_DELADDR)?
			'D': 'A', interface, ifa->ifa_family,
				       addr, ifa->ifa_prefixlen, dest);
	    }
	    else if (h->nlmsg_type == RTM_NEWROUTE ||
	             h->nlmsg_type == RTM_DELROUTE ||
	             h->nlmsg_type == RTM_GETROUTE) {
		int len = h->nlmsg_len;
		struct rtmsg *rtm = NLMSG_DATA (h);
		struct rtattr *rta = RTM_RTA (rtm);
		struct rtattr *tb[RTA_MAX + 1];
		int proto = PROTO_KERNEL;

		int index = 0;
		void *dest = NULL, *nexthop = NULL;

		if (h->nlmsg_type != RTM_NEWROUTE)
		    continue;

		if (rtm->rtm_table != RT_TABLE_MAIN)
		    continue;

		if (rtm->rtm_type != RTN_UNICAST)
		    continue;

		len -= NLMSG_LENGTH (sizeof (*rtm));

		if (len < 0)
		    continue;

                /* currently I don't want to loop back my request */
            	if (h->nlmsg_pid == my_pid)
                    continue;

		memset (tb, 0, sizeof (tb));
		while (RTA_OK (rta, len)) {
		    if (rta->rta_type <= RTA_MAX)
			tb[rta->rta_type] = rta;
		    rta = RTA_NEXT (rta, len);
		}

		/* Ignore clones */
		if (rtm->rtm_flags & RTM_F_CLONED)
		    continue;
		/* Ignore redirects */
		if (rtm->rtm_protocol == RTPROT_REDIRECT)
		    continue;
		/* Ignore Route installed by kernel */
		if (rtm->rtm_protocol == RTPROT_KERNEL)
		    continue;
		/* Ignore source routes */
		if (rtm->rtm_src_len != 0)
		    continue;
		if (rtm->rtm_protocol == RTPROT_STATIC)
		    proto = RTPROT_STATIC;

		if (tb[RTA_OIF])
		    index = *(int *) RTA_DATA (tb[RTA_OIF]);

		if (tb[RTA_DST]) {
		    dest = RTA_DATA (tb[RTA_DST]);
		}
		else {
		    dest = anyaddr;
		}
		if (tb[RTA_GATEWAY]) {
		    nexthop = RTA_DATA (tb[RTA_GATEWAY]);
		}
		else {
		    proto = PROTO_CONNECTED;
		    nexthop = anyaddr;

#ifdef HAVE_IPV6
		    if (index > 0) {
			interface_t *interface;
			interface = find_interface_byindex (index);
		        if ((interface->flags & IFF_TUNNEL)  &&
				(interface->flags & IFF_POINTOPOINT) &&
			    IN6_IS_ADDR_UC_GLOBAL ((struct in6_addr *)dest) &&
				rtm->rtm_dst_len == 128 &&
				interface->primary6->prefix != NULL &&
				interface->primary6->broadcast == NULL) {
	    		/* linux sit doesn't have its destination address,
	       		so this tries to pick up one from the routing table */
	    	    	    interface->primary6->broadcast = 
				New_Prefix (AF_INET6, dest, 128);
			}
		    }
#endif /* HAVE_IPV6 */
		}
		update_kernel_route ((h->nlmsg_type == RTM_DELROUTE)?
				     'D': 'A', rtm->rtm_family,
				     dest, nexthop, rtm->rtm_dst_len, index,
				     proto);
	    }
	}
	if (len != 0) {
	    trace (TR_ERROR, INTERFACE_MASTER->trace,
		   "netlink bad size %d\n", len);
	    return (-1);
	}
    return (0);
}


static void
kernel_rtmsg_rcv (int sockfd)
{
    char buf[4096];
    struct iovec iov = {buf, sizeof (buf)};
    struct msghdr msg;
    int len;
    struct sockaddr_nl from;

    memset (&msg, 0, sizeof (msg));
    msg.msg_name = &from;
    msg.msg_namelen = sizeof (from);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if ((len = recvmsg (sockfd, &msg, 0)) < 0) {
	if (errno != EINTR) {
	    trace (TR_ERROR, INTERFACE_MASTER->trace, 
		"netlink recvmsg (%s)\n", strerror (errno));
	}
	select_enable_fd (sockfd);
	return;
    }
    if (len == 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace, "netlink EOF\n");
	select_enable_fd (sockfd);
	return;
    }
    select_enable_fd (sockfd);
    sys_kernel_rt_msg (buf, len, local.nl_pid);
    if (msg.msg_flags & MSG_TRUNC) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "netlink message truncated\n");
    }
}


static int
init_netlink (void)
{
    static int tried = 0;
    int len;
    int val = 1;

    if (sockfd >= 0)
	return (0);

    if (tried)
        return (-1);

    tried++;
    sockfd = socket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sockfd < 0) {
	trace (TR_WARN, INTERFACE_MASTER->trace, "netlink socket (%s)\n",
	       strerror (errno));
	return (-1);
    }

    memset (&local, 0, sizeof (local));
    local.nl_family = AF_NETLINK;
    local.nl_groups = 0;
    local.nl_groups = RTMGRP_LINK|RTMGRP_NOTIFY| 
#ifdef HAVE_IPV6
		      RTMGRP_IPV6_IFADDR|RTMGRP_IPV6_MROUTE|RTMGRP_IPV6_MROUTE|
#endif /* HAVE_IPV6 */
		      RTMGRP_IPV4_IFADDR|RTMGRP_IPV4_MROUTE|RTMGRP_IPV4_MROUTE;

    if (bind (sockfd, (struct sockaddr *) &local, sizeof (local)) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace, "netlink bind (%s)\n",
	       strerror (errno));
	close (sockfd);
	sockfd = -1;
	return (-1);
    }

    len = sizeof (local);
    if (getsockname (sockfd, (struct sockaddr *) &local, &len) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace, 
	       "netlink getsockname (%s)\n", strerror (errno));
	close (sockfd);
	sockfd = -1;
	return (-1);
    }

    ioctl (sockfd, FIONBIO, &val);
    select_add_fd_event ("kernel_rtmsg_rcv", sockfd, SELECT_READ, TRUE,
                          NULL, kernel_rtmsg_rcv, 1, sockfd);

    memset (&snl, 0, sizeof (snl));
    snl.nl_family = AF_NETLINK;

    seq = time (NULL);
    trace (TR_INFO, INTERFACE_MASTER->trace, "Linux netlink initialized\n");
    return (1);
}


static int
dump_by_netlink (int family, int type)
{
    struct {
	struct nlmsghdr nlm;
	struct rtgenmsg g;
    } req;

    req.nlm.nlmsg_len = sizeof (req);
    req.nlm.nlmsg_type = type;
    req.nlm.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
    req.nlm.nlmsg_pid = 0;
    req.nlm.nlmsg_seq = ++seq;
    req.g.rtgen_family = family;

    if (sendto (sockfd, (void *) &req, sizeof (req), 0,
		(struct sockaddr *) &snl, sizeof (snl)) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace, "netlink sendto (%s)\n",
	       strerror (errno));
	return (-1);
    }

    while (1) {
	char buf[4096];
	struct iovec iov = {buf, sizeof (buf)};
	struct msghdr msg;
	int len;
        struct sockaddr_nl from;

	memset (&msg, 0, sizeof (msg));
	msg.msg_name = &from;
	msg.msg_namelen = sizeof (from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if ((len = recvmsg (sockfd, &msg, 0)) < 0) {
	    if (errno == EINTR)
		continue;
	    /* I don't know why EAGAIN returns on EOF */
	    if (errno == EAGAIN)
		return (0);
	    trace (TR_ERROR, INTERFACE_MASTER->trace, "netlink recvmsg (%s)\n",
		   strerror (errno));
	    return (-errno);
	}
	if (len == 0) {
	    trace (TR_ERROR, INTERFACE_MASTER->trace, "netlink EOF\n");
	    return (-1);
	}
	if (sys_kernel_rt_msg (buf, len, 0) < 0)
	    return (-1);
        if (msg.msg_flags & MSG_TRUNC) {
	    trace (TR_ERROR, INTERFACE_MASTER->trace,
	           "netlink message truncated\n");
        }
    }
}


static int
read_interfaces_by_netlink (void)
{
    if (dump_by_netlink (AF_PACKET, RTM_GETLINK) < 0)
	return (-1);
    if (dump_by_netlink (AF_INET, RTM_GETADDR) < 0)
	return (-1);
#ifdef HAVE_IPV6
    if (dump_by_netlink (AF_INET6, RTM_GETADDR) < 0)
	return (-1);
#endif /* HAVE_IPV6 */
    return (1);
}


static int
kernel_read_rt_table_by_netlink (void)
{
    if (dump_by_netlink (AF_INET, RTM_GETROUTE) < 0)
	return (-1);
#ifdef HAVE_IPV6
    if (dump_by_netlink (AF_INET6, RTM_GETROUTE) < 0)
	return (-1);
#endif /* HAVE_IPV6 */
    return (1);
}


static int
addattr_l (struct nlmsghdr *n, int maxlen, int type, void *data, int alen)
{
	int len = RTA_LENGTH (alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN (n->nlmsg_len) + len > maxlen)
		return (-1);
	rta = (struct rtattr*)(((char*)n) + NLMSG_ALIGN (n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy (RTA_DATA (rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;
	return (0);
}


static int
route_by_netlink (int cmd, u_long flags, int family, 
		  void *dest, int bitlen, void *gw, int index)
{
    struct {
	struct nlmsghdr nlm;
	struct rtmsg    rtm;
	char		buf[1024];
    } req;
    int bytelen = 4;

#ifdef HAVE_IPV6
    if (family == AF_INET6)
	bytelen = 16;
#endif /* HAVE_IPV6 */

    memset (&req, 0, sizeof (req));
    req.nlm.nlmsg_len = NLMSG_LENGTH (sizeof (struct rtmsg));
    req.nlm.nlmsg_type = cmd;
    req.nlm.nlmsg_flags = (flags | NLM_F_REQUEST);
    req.nlm.nlmsg_seq = ++seq;
    req.rtm.rtm_family = family;
    req.rtm.rtm_table = RT_TABLE_MAIN;
    req.rtm.rtm_dst_len = bitlen;

{
    char tmp6[64], tmp7[64];
    trace (TR_TRACE, INTERFACE_MASTER->trace, "netlink seq %d "
	   "cmd %s flags 0x%x family %d dest %s/%d gw %s index %d\n",
	    seq,
	    (cmd == RTM_NEWROUTE)? "RTM_NEWROUTE":
	   ((cmd == RTM_DELROUTE)? "RTM_DELROUTE": "???"),
	   flags, family,
	   inet_ntop (family, dest, tmp6, sizeof tmp6), bitlen,
	   inet_ntop (family, gw, tmp7, sizeof tmp7),
	   index);
}
    if (cmd != RTM_DELROUTE) {
        /* req.rtm.rtm_protocol = RTPROT_BOOT; */
        req.rtm.rtm_protocol = RTPROT_MRT;
        req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
        req.rtm.rtm_type = RTN_UNICAST;
    }

    if (gw)
        addattr_l (&req.nlm, sizeof (req), RTA_GATEWAY, gw, bytelen);
    if (dest)
        addattr_l (&req.nlm, sizeof (req), RTA_DST, dest, bytelen);
    if (index > 0)
        addattr_l (&req.nlm, sizeof (req), RTA_OIF, &index, 4);

#if LINUX_VERSION_CODE <= 0x20158 /* 2.1.88 */
    req.rtm.rtm_optlen = req.nlm.nlmsg_len - NLMSG_SPACE (sizeof (req.rtm));
#endif

    if (sendto (sockfd, (void *) &req, sizeof (req), 0,
		(struct sockaddr *) &snl, sizeof (snl)) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace, "netlink sendto (%s)\n",
	       strerror (errno));
	return (-1);
    }
    return (1);
}


int
kernel_update_route_by_netlink (prefix_t * dest,
		     prefix_t * nexthop, prefix_t * oldhop,
		     int index, int oldindex)
{
    int res = -1;
    int family = dest->family;

    if (nexthop && oldhop) {
	/* I don't know how to replace a route whose change may result
	   in replacing its gateway and device -- masaki */
	/* Netlink says "File exists" at least intarface is the same */
	if (index == oldindex) {
	    route_by_netlink (RTM_DELROUTE, 0, family, 
				prefix_tochar (dest), dest->bitlen,
				prefix_tochar (oldhop), oldindex);
	    res = route_by_netlink (RTM_NEWROUTE, NLM_F_CREATE, family, 
				prefix_tochar (dest), dest->bitlen,
				prefix_tochar (nexthop), index);
	}
	else {
	    res = route_by_netlink (RTM_NEWROUTE, NLM_F_CREATE, family, 
				prefix_tochar (dest), dest->bitlen,
				prefix_tochar (nexthop), index);
	    route_by_netlink (RTM_DELROUTE, 0, family, 
				prefix_tochar (dest), dest->bitlen,
				prefix_tochar (oldhop), oldindex);
	}
    }
    else if (nexthop) {
	res = route_by_netlink (RTM_NEWROUTE, NLM_F_CREATE, family, 
				prefix_tochar (dest), dest->bitlen,
				prefix_tochar (nexthop), index);
    }
    else if (oldhop) {
	nexthop = oldhop;
	index = oldindex;
	res = route_by_netlink (RTM_DELROUTE, 0, family, 
				prefix_tochar (dest), dest->bitlen,
				prefix_tochar (nexthop), 
				0 /* XXX easy to match */);
    }
    return (res);
}

#endif /* CONFIG_RTNETLINK */

/*
 *     read_interfaces called from lib init routine
 *     must call new_interface to register configuration.
 */

#define _PATH_PROCNET_IFINET6 "/proc/net/if_inet6"
#define _PATH_PROCNET_DEV     "/proc/net/dev"


/* get interface configuration */
static interface_t *
ifstatus (char *name)
{
    struct ifreq ifr;
    int s;
    u_long flags, mtu, index = 0;
    interface_t *interface;

    safestrncpy (ifr.ifr_name, name, sizeof (ifr.ifr_name));

    if ((interface = find_interface_byname (ifr.ifr_name)))
	return (interface);

    if ((s = INTERFACE_MASTER->sockfd) < 0) {
	return (NULL);
    }

    if (ioctl (s, SIOCGIFFLAGS, (caddr_t) & ifr) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "SIOCGIFFLAGS for %s (%s)\n",
	       ifr.ifr_name, strerror (errno));
	return (NULL);
    }
    assert (sizeof (ifr.ifr_flags) == 2);
    flags = ifr.ifr_flags & 0x0000ffff;		/* short */

#ifdef ARPHRD_SIT
    if (ioctl (s, SIOCGIFHWADDR, (caddr_t) & ifr) == 0) {
	if (ifr.ifr_addr.sa_family == ARPHRD_SIT) {
	    flags |= IFF_TUNNEL;
	    flags |= IFF_MULTICAST;
	    /* XXX we expect MULTICAST flag to run RIPng */
	}
    }
#endif /* ARPHRD_SIT */

    if (ioctl (s, SIOCGIFMTU, (caddr_t) & ifr) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "SIOCSIFMTU for %s, use 576 instead (%s)\n",
	       ifr.ifr_name, strerror (errno));
	mtu = 576;
    }
    else {
	mtu = ifr.ifr_mtu;
    }

#ifdef HAVE_IPV6
#ifdef SIOGIFINDEX
    if ((s = INTERFACE_MASTER->sockfd6) < 0)
	return (NULL);

    if (ioctl (s, SIOGIFINDEX, (caddr_t) & ifr) < 0) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "SIOGIFINDEX for %s, "
	       "being assigned by mrt (%s)\n",
	       ifr.ifr_name, strerror (errno));
    }
    else {
	index = ifr.ifr_ifindex;
	assert (index != 0);
	if ((interface = find_interface_byindex (index))) {
	    trace (TR_ERROR, INTERFACE_MASTER->trace,
		   "index %d for %s has been assigned to %s\n",
		   index, ifr.ifr_name, interface->name);
	    return (interface);
	}
    }
#endif /* SIOGIFINDEX */
#endif /* HAVE_IPV6 */

    interface = new_interface (name, flags, mtu, index);
    return (interface);
}


/* get interface configuration for IPv4 */
static int
ifaddress (interface_t * interface)
{
    struct ifreq ifr;
    struct sockaddr_in addr, mask, dest;
    int s;

    if ((s = INTERFACE_MASTER->sockfd) < 0)
	return (-1);

    safestrncpy (ifr.ifr_name, interface->name, sizeof (ifr.ifr_name));
    memset (&addr, 0, sizeof (addr));
    memset (&mask, ~0, sizeof (mask));
    memset (&dest, 0, sizeof (dest));

    if (!BIT_TEST (interface->flags, IFF_TUNNEL)) {
	if (ioctl (s, SIOCGIFADDR, (caddr_t) & ifr) < 0) {
    	    if (BIT_TEST (interface->flags, IFF_UP)) {
	        trace (TR_ERROR, INTERFACE_MASTER->trace,
		       "SIOCGIFADDR for %s (%s)\n",
		       ifr.ifr_name, strerror (errno));
	    }
	    return (-1);
	}
	memcpy (&addr, &ifr.ifr_addr, sizeof (addr));
    }

    if (!BIT_TEST (interface->flags, IFF_TUNNEL)) {
	if (ioctl (s, SIOCGIFNETMASK, (caddr_t) & ifr) < 0) {
	    trace (TR_ERROR, INTERFACE_MASTER->trace,
		   "SIOCGIFNETMASK for %s (%s)\n", ifr.ifr_name,
		   strerror (errno));
	    return (-1);
	}
	memcpy (&mask, &ifr.ifr_addr, sizeof (mask));
    }

    if (BIT_TEST (interface->flags, IFF_TUNNEL)) {
#ifdef SIOCGETTUNNEL
	struct ip_tunnel_parm p;
	memset (&p, 0, sizeof (p));
	ifr.ifr_ifru.ifru_data = (void *) &p;
	if (ioctl (s, SIOCGETTUNNEL, (caddr_t) & ifr) == 0) {
	    memcpy (&dest.sin_addr, &p.iph.daddr, 4);
	}
	else {
	    trace (TR_WARN, INTERFACE_MASTER->trace,
		   "SIOCGETTUNNEL for %s (%s)\n", ifr.ifr_name,
		   strerror (errno));
	}
#endif /* SIOCGETTUNNEL */
    }
    else {
	if (BIT_TEST (interface->flags, IFF_POINTOPOINT)) {
	    if (ioctl (s, SIOCGIFDSTADDR, (caddr_t) & ifr) < 0) {
		trace (TR_ERROR, INTERFACE_MASTER->trace,
		       "SIOCGIFDSTADDR for %s (%s)\n",
		       ifr.ifr_name, strerror (errno));
		return (-1);
	    }
	}
	else {
	    if (ioctl (s, SIOCGIFBRDADDR, (caddr_t) & ifr) < 0) {
		trace (TR_ERROR, INTERFACE_MASTER->trace,
		       "SIOCGIFBRDADDR for %s (%s)\n",
		       ifr.ifr_name, strerror (errno));
		return (-1);
	    }
	}
	memcpy (&dest, &ifr.ifr_addr, sizeof (dest));
    }

    if (addr.sin_addr.s_addr != INADDR_ANY)
        add_addr_to_interface (interface, AF_INET,
			   (char *) &addr.sin_addr.s_addr,
			   mask2len ((char *) &mask.sin_addr.s_addr, 4),
			   (char *) &dest.sin_addr.s_addr);
    return (1);
}


/*
 *     read intefaces via /proc
 *     it will also be possible to do it via a SIOCGIFCONF-like ioctl
 *     but the API is still being worked out.
 *     (ioctl isn't, IMHO, a better method than /proc anyway)
 */

#ifdef HAVE_IPV6
#define PROC_PATH "/proc/net/if_inet6"
static void
iface_init6 ()
{
    FILE *fp;
    char str_addr[40];
    int plen, scope, dad_status, if_idx;
    char devname[10];
    interface_t *interface;

    if ((fp = fopen (PROC_PATH, "r")) == NULL) {
	trace (TR_ERROR, INTERFACE_MASTER->trace,
	       "fopen for %s (%s)\n",
	       PROC_PATH, strerror (errno));
	return;
    }

    while (fscanf (fp, "%32s %02x %02x %02x %02x %s\n",
		   str_addr, &if_idx, &plen, &scope, &dad_status,
		   devname) != EOF) {
	struct in6_addr addr, dest, *dest_p = NULL;
	int i, x;

	for (i = 0; i < 16; i++) {
	    sscanf (str_addr + i * 2, "%02x", &x);
	    addr.s6_addr[i] = x & 0xff;
	}
	interface = find_interface_byname (devname);

/* After 2.1.63, 
   SIOCGIFCONF has changed so that it returns only IPv4 interfaces. */
	if (interface == NULL)
	    interface = ifstatus (devname);

	assert (interface);
	assert (interface->index == if_idx);
	if (plen == 0)		/* may be fixed in the future */
	    plen = 128;

        if (BIT_TEST (interface->flags, IFF_TUNNEL)) {
#ifdef SIOCGETTUNNEL
	    if (IN6_IS_ADDR_LINKLOCAL (&addr)) {
	        struct ip_tunnel_parm p;
    		struct ifreq ifr;
	        memset (&p, 0, sizeof (p));
    		safestrncpy (ifr.ifr_name, interface->name, 
			     sizeof (ifr.ifr_name));
	        ifr.ifr_ifru.ifru_data = (void *) &p;
	        if (ioctl (INTERFACE_MASTER->sockfd, SIOCGETTUNNEL, 
			&ifr) == 0) {
	            /* create a link-local destination address */
		    memcpy (&dest, &addr, 16);
		    dest.s6_addr32[3] = p.iph.daddr;
		    dest_p = &dest;
	        }
	        else {
	            trace (TR_WARN, INTERFACE_MASTER->trace,
		           "SIOCGETTUNNEL for %s (%s)\n", ifr.ifr_name,
		           strerror (errno));
	        }
	    }
#endif /* SIOCGETTUNNEL */
        }
	add_addr_to_interface (interface, AF_INET6, &addr, plen, dest_p);
    }
    fclose (fp);
}

#endif /* HAVE_IPV6 */

int
read_interfaces ()
{
    char buffer[MAXLINE], name[MAXLINE];
    char *cp;
    interface_t *interface;
    FILE *fp;

#ifdef CONFIG_RTNETLINK
    if (init_netlink () >= 0) {
	return (read_interfaces_by_netlink ());
    }
#endif /* CONFIG_RTNETLINK */

    if ((fp = fopen (_PATH_PROCNET_DEV, "r")) == NULL)
	return (-1);

    /* eat the first two lines */
    if (fgets (buffer, sizeof (buffer), fp) == NULL)
	return (0);
    if (fgets (buffer, sizeof (buffer), fp) == NULL)
	return (0);

    while (fgets (buffer, sizeof (buffer) - 1, fp) != NULL) {

	if (fscanf (fp, "%s", name) != 1)
	    break;

	if ((cp = strrchr (name, ':')) != NULL)
	    *cp = '\0';

	if ((interface = ifstatus (name)) == NULL)
	    continue;
	ifaddress (interface);
    }
    fclose (fp);
#ifdef HAVE_IPV6
    iface_init6 ();
#endif /* HAVE_IPV6 */
    return (1);
}


/*
#define MRT_RT_ADD     KERNEL_ROUTE_ADD
#define MRT_RT_CHG     KERNEL_ROUTE_CHG
#define MRT_RT_DEL     KERNEL_ROUTE_DEL
*/

#ifdef notdef
static int rt4_fd = -1;
#endif
static int ctl_sk_4 = -1;
#ifdef HAVE_IPV6
static int rt6_fd = -1;
static int rt6_sk = -1;
static int ctl_sk_6 = -1;
#endif /* HAVE_IPV6 */


/* Pedro:
 *     masaki: maybe the select interface could have (mask, void *) 
 *     as args so that the code could now in advance which even
 *     awoke select. Not critical at all.
 */
#ifdef notdef
static void krt4_rtmsg_rcv (void *);
#ifdef HAVE_IPV6
static void krt6_rtmsg_rcv (void *);
#endif /* HAVE_IPV6 */
#endif /* notdef */
#ifdef HAVE_IPV6
static void krt6_icmp_rcv (void *);
#endif /* HAVE_IPV6 */

/* Pedro:
 *     Maybe move this to include/select.h
 */

#define SEL_MASK_READ  1
#define SEL_MASK_WRITE  2
#define SEL_MASK_ERR   4

#define DEV_ROUTE "/dev/route"
#define DEV_IPV6_ROUTE "/dev/ipv6_route"

int
kernel_init (void)
{
#ifdef HAVE_IPV6
    struct icmp6_filter filter;
#endif /* HAVE_IPV6 */
    int mask = (SEL_MASK_READ | SEL_MASK_ERR);
#ifdef notdef
    int val = 1;
#endif
    int err;

#ifdef CONFIG_RTNETLINK
    if (init_netlink () >= 0) {
	return (1);
    }
#endif /* CONFIG_RTNETLINK */

    trace (TR_INFO, INTERFACE_MASTER->trace, "Linux ioctl will be used\n");

#ifdef notdef
/* Now, the old interface is supported here */
    rt4_fd = open (DEV_ROUTE, O_RDWR);
    if (rt4_fd < 0) {
	trace (TR_ERROR, MRT->trace,
	       "open for route control device: %s, "
	       "which should be major 36, minor 0, "
	       "switching to the old interface\n",
	       DEV_ROUTE, strerror (errno));
    }
    else {
	err = ioctl (rt4_fd, FIONBIO, &val);
	if (err) {
	    trace (TR_ERROR, MRT->trace, "FIONBIO for %s (%s)\n",
		   DEV_ROUTE, strerror (errno));
	}
	else {
	    select_add_fd (rt4_fd, mask, krt4_rtmsg_rcv, NULL);
	}
    }
#endif

    ctl_sk_4 = socket (AF_INET, SOCK_DGRAM, 0);
    if (ctl_sk_4 < 0) {
	trace (TR_ERROR, MRT->trace, "socket for AF_INET (%s)\n",
	       strerror (errno));
    }

#ifdef HAVE_IPV6
#ifdef notdef
/* Now, the old interface is supported here */
    rt6_fd = open (DEV_IPV6_ROUTE, O_RDWR);
    if (rt6_fd == -1) {
	trace (TR_ERROR, MRT->trace,
	       "open for route control device: %s, "
	       "which should be major 36, minor 11, "
	       "switching to the old interface\n",
	       DEV_IPV6_ROUTE, strerror (errno));
    }
    else {
	err = ioctl (rt6_fd, FIONBIO, &val);
	if (err) {
	    trace (TR_ERROR, MRT->trace, "FIONBIO for %s (%s)\n",
		   DEV_IPV6_ROUTE, strerror (errno));
	}
	else {
	    select_add_fd (rt6_fd, mask, krt6_rtmsg_rcv, NULL);
	}
    }
#endif

    rt6_sk = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (rt6_sk < 0) {
	trace (TR_ERROR, MRT->trace, "socket for ICMPV6 (%s)\n",
	       strerror (errno));
    }
    else {
	ICMP6_FILTER_SETBLOCKALL (&filter);
	ICMP6_FILTER_SETPASS (ICMP6_DST_UNREACH, &filter);
	ICMP6_FILTER_SETPASS (ND_REDIRECT, &filter);

#ifndef ICMP6_FILTER
#define ICMP6_FILTER ICMPV6_FILTER
#endif /* ICMP6_FILTER */
	err = setsockopt (rt6_sk, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
			  sizeof (struct icmp6_filter));

	if (err < 0) {
	    trace (TR_ERROR, MRT->trace,
		   "setsockopt for ICMPV6 ICMPV6_FILTER (%s)\n",
		   strerror (errno));
	}
	else {
	    select_add_fd_event ("krt6_icmp_rcv", rt6_sk, mask, TRUE, 
				  NULL, krt6_icmp_rcv, 0);
	}
    }

    ctl_sk_6 = socket (AF_INET6, SOCK_DGRAM, 0);
    if (ctl_sk_6 < 0) {
	trace (TR_ERROR, MRT->trace, "socket for AF_INET6 (%s)\n",
	       strerror (errno));
    }

#endif /* HAVE_IPV6 */
    return 0;
}


#ifdef HAVE_IPV6

#define ADDRCOPY(D, S) memcpy(D, S, sizeof(struct in6_addr));

static int
sys_kernel_route_update6 (struct in6_rtmsg *rt)
{
    if (rt6_fd >= 0) {
        int ret;
	ret = write (rt6_fd, rt, sizeof (*rt));
	if (ret > 0)
	    return (ret);
	trace (TR_ERROR, MRT->trace, "V6 on write (%s)\n",
	      strerror (errno));
    }

    if (ctl_sk_6 >= 0) {
        int ret;
        int s_op;
        assert (rt->rtmsg_type == RTMSG_NEWROUTE || 
		rt->rtmsg_type == RTMSG_DELROUTE);
        /* try old interface */
        s_op = (rt->rtmsg_type == RTMSG_NEWROUTE) ? SIOCADDRT : SIOCDELRT;
	if ((ret = ioctl (ctl_sk_6, s_op, rt)) < 0) {
	    trace (TR_ERROR, MRT->trace, "V6 %s (%s)\n",
		   (s_op == SIOCADDRT) ? "SIOCADDRT" : "SIOCDELRT",
		   strerror (errno));
	}
	return (ret);
    }
    return (-1);
}

/*
 *     This is a temporary version until i code the moral equivalent of
 *     a routing socket in Linux IPv6 code.
 */

static int
sys_kernel_update6 (prefix_t * dest, prefix_t * nexthop, prefix_t * oldhop,
	            int index, int metric)
{
    interface_t *interface = find_interface_byindex (index);
    struct in6_rtmsg rt;
    int ret = 0;
    char tmp6[MAXLINE], tmp7[MAXLINE];

    assert (nexthop || oldhop);

    if (interface == NULL)
	return (-ENODEV);

    if (dest->bitlen == 0)
	return (-EINVAL);

    memset (&rt, 0, sizeof (struct in6_rtmsg));

    ADDRCOPY (&rt.rtmsg_dst, prefix_tochar (dest));
#define  rtmsg_prefixlen rtmsg_dst_len
    rt.rtmsg_prefixlen = dest->bitlen;
    rt.rtmsg_flags = RTF_UP;
    if (BIT_TEST (interface->flags, IFF_LOOPBACK))
	rt.rtmsg_flags |= RTF_REJECT;

    if (nexthop) {
        /* rt.rtmsg_metric = metric; */
	rt.rtmsg_metric = 128; /* XXX */
        rt.rtmsg_ifindex = index;
	rt.rtmsg_type = RTMSG_NEWROUTE;
        /*
         * Pedro suggests that the route doesn't have a gateway
         * if the gateway address is in_addr_any (all zero)
         */
	ADDRCOPY (&rt.rtmsg_gateway, prefix_tochar (nexthop));
        if (!IN6_IS_ADDR_UNSPECIFIED (prefix_toaddr6 (nexthop))) {
	    rt.rtmsg_flags |= RTF_GATEWAY;
        }

	ret = sys_kernel_route_update6 (&rt);
        trace (TR_TRACE, INTERFACE_MASTER->trace,
	       "ADD DEST: %s/%d GATE: %s IF: %d (%s)\n",
	       inet_ntop (AF_INET6, &rt.rtmsg_dst, tmp6, sizeof tmp6),
	       rt.rtmsg_prefixlen,
	       (rt.rtmsg_flags & RTF_REJECT) ? "REJECT" :
	       inet_ntop (AF_INET6, &rt.rtmsg_gateway, tmp7, sizeof tmp7),
	       index, interface ? interface->name : "?");
    }

   /* add first, then remove 
      since linux allows multiple routes for the same dest */
    if (oldhop && /* if nexthop is equal to oldhop, nothing to do */
	    (nexthop == NULL || prefix_compare2 (nexthop, oldhop) != 0)) {
	/* if metric > 0, 
	   kernel checks if it's the same with the value in the kernel */
	rt.rtmsg_metric = 0;
	/* delete it regardless of ifindex */
        rt.rtmsg_ifindex = 0;
	rt.rtmsg_type = RTMSG_DELROUTE;

	ADDRCOPY (&rt.rtmsg_gateway, prefix_tochar (oldhop));
        if (!IN6_IS_ADDR_UNSPECIFIED (prefix_toaddr6 (oldhop))) {
	    rt.rtmsg_flags |= RTF_GATEWAY;
        }
	else {
	    rt.rtmsg_flags &= ~RTF_GATEWAY;
	}
	ret = sys_kernel_route_update6 (&rt);

        trace (TR_TRACE, INTERFACE_MASTER->trace,
	       "DEL DEST: %s/%d GATE: %s IF: %d (%s)\n",
	       inet_ntop (AF_INET6, &rt.rtmsg_dst, tmp6, sizeof tmp6),
	       rt.rtmsg_prefixlen,
	       (rt.rtmsg_flags & RTF_REJECT) ? "REJECT" :
	       inet_ntop (AF_INET6, &rt.rtmsg_gateway, tmp7, sizeof tmp7),
	       index, interface ? interface->name : "?");
    }

    return (ret);
}
#endif /* HAVE_IPV6 */


static int
sys_kernel_update (prefix_t * dest, prefix_t * nexthop, prefix_t * oldhop, 
	           int index, int metric)
{
    struct rtentry rt;
    struct sockaddr_in *sin;
    int ret = 0;

    assert (nexthop || oldhop);

    memset (&rt, 0, sizeof (struct rtentry));
    sin = (struct sockaddr_in *) &rt.rt_dst;
    sin->sin_family = AF_INET;
    memcpy (&sin->sin_addr, prefix_tochar (dest), 4);
    sin = (struct sockaddr_in *) &rt.rt_genmask;
    /* sin->sin_family = AF_UNSPEC; */
    sin->sin_family = AF_INET;
    len2mask (dest->bitlen, (char *) &sin->sin_addr, 4);

    rt.rt_flags = RTF_UP;
    if (dest->bitlen == 32)
	rt.rt_flags |= RTF_HOST;

    if (nexthop) {
        sin = (struct sockaddr_in *) &rt.rt_gateway;
        sin->sin_family = AF_INET;
        memcpy (&sin->sin_addr, prefix_tochar (nexthop), 4);
        if (sin->sin_addr.s_addr != INADDR_ANY) {
	    rt.rt_flags |= RTF_GATEWAY;
        }
	rt.rt_metric = 128; /* XXX */
	if ((ret = ioctl (ctl_sk_4, SIOCADDRT, &rt)) < 0) {
	    trace (TR_ERROR, MRT->trace, "V4 SIOCADDRT (%s)\n",
	           strerror (errno));
	    return (ret);
        }
    }

    if (oldhop &&
	    (nexthop == NULL || prefix_compare2 (nexthop, oldhop) != 0)) {
        sin = (struct sockaddr_in *) &rt.rt_gateway;
        sin->sin_family = AF_INET;
        memcpy (&sin->sin_addr, prefix_tochar (oldhop), 4);
        rt.rt_flags = RTF_UP;
        if (sin->sin_addr.s_addr != INADDR_ANY) {
	    rt.rt_flags |= RTF_GATEWAY;
        }
        if (dest->bitlen == 32)
	    rt.rt_flags |= RTF_HOST;
	rt.rt_metric = 0;
	if ((ret = ioctl (ctl_sk_4, SIOCDELRT, &rt)) < 0) {
	    trace (TR_ERROR, MRT->trace, "V4 SIOCDELRT (%s)\n",
	           strerror (errno));
	    return (ret);
	}
    }
    return (ret);
}


int
sys_kernel_update_route (prefix_t * dest,
		     prefix_t * nexthop, prefix_t * oldhop,
		     int index, int oldindex)
{
    int res = -1;
    /* if metric > 0, it is required to meet with the value
       in the kernel when deleteing it */
    int metric = 0;
    int (*fn)() = sys_kernel_update;

#ifdef HAVE_IPV6
/* linux sit doesn't have its destination address, so the gateway has to be
   replaced by its link-local destination generated by this code */
/* This will cause inconsistenly in rib and kernel -- XXX */

    if (dest->family == AF_INET6 && nexthop && index > 0) {
        interface_t *interface = find_interface_byindex (index);
	if (interface && BIT_TEST (interface->flags, IFF_TUNNEL) && 
                BIT_TEST (interface->flags, IFF_POINTOPOINT) && 
		/* there may be a pseudo destination created by this code */
		/* interface->primary6->broadcast == NULL && */
		IN6_IS_ADDR_UC_GLOBAL (prefix_toaddr6 (nexthop))) {
            if (interface->link_local && interface->link_local->broadcast)
	        nexthop = interface->link_local->broadcast;
	}
    }

    if (dest->family == AF_INET6 && oldhop && oldindex > 0) {
        interface_t *interface = find_interface_byindex (oldindex);
	if (interface && BIT_TEST (interface->flags, IFF_TUNNEL) && 
                BIT_TEST (interface->flags, IFF_POINTOPOINT) && 
		/* there may be a pseudo destination created by this code */
		/* interface->primary6->broadcast == NULL && */
		IN6_IS_ADDR_UC_GLOBAL (prefix_toaddr6 (oldhop))) {
            if (interface->link_local && interface->link_local->broadcast)
	        oldhop = interface->link_local->broadcast;
	}
    }
#endif /* HAVE_IPV6 */
#ifdef CONFIG_RTNETLINK
    if (sockfd >= 0) {
	return (kernel_update_route_by_netlink (dest, nexthop, oldhop, 
						index, oldindex));
    }
#endif /* CONFIG_RTNETLINK */

#ifdef HAVE_IPV6
    if (dest->family == AF_INET6)
	fn = sys_kernel_update6;
#endif /* HAVE_IPV6 */

	if (nexthop && oldhop) {
	    res = fn (dest, nexthop, oldhop, index, metric);
	}
	else if (nexthop) {
	    res = fn (dest, nexthop, NULL, index, metric);
	}
	else if (oldhop) {
	    res = fn (dest, NULL, oldhop, oldindex, metric);
	}

    return (res);
}


#ifdef notdef
static void
krt4_rtmsg_rcv (void *arg)
{
    struct netlink_rtinfo rt;
    int err;

    if ((err = read (rt4_fd, &rt, sizeof (struct netlink_rtinfo))) > 0) {
	switch (rt.rtmsg_type) {
	case RTMSG_NEWROUTE:
	case RTMSG_DELROUTE:
	case RTMSG_NEWDEVICE:
	case RTMSG_DELDEVICE:
	    trace (TR_INFO, MRT->trace, "ICMP type %d\n", rt.rtmsg_type);
	    break;
	default:
	    trace (TR_ERROR, MRT->trace, "ICMP unknown type %d\n",
		   rt.rtmsg_type);
	}
    }

    if (err == -1) {
	trace (TR_ERROR, MRT->trace, "ICMP read (%s)\n",
	       strerror (errno));
    }
    select_enable_fd (rt4_fd);
}
#endif


#ifdef HAVE_IPV6
#ifdef notdef
static void
krt6_rtmsg_rcv (void *arg)
{
    struct in6_rtmsg rt;
    int err;

    if ((err = read (rt6_fd, &rt, sizeof (struct in6_rtmsg))) > 0) {
	switch (rt.rtmsg_type) {
	case RTMSG_NEWROUTE:
	case RTMSG_DELROUTE:
	case RTMSG_NEWDEVICE:
	case RTMSG_DELDEVICE:
	    /*
	     *      Address Resolution failed
	     */
/*          case RTMSG_AR_FAILED: why is this the same as RTMSG_NEWROUTE ? */

	    trace (TR_INFO, MRT->trace, "RTMSG type %d\n",
		   rt.rtmsg_type);
	    break;
	    /*
	     *      What else do you routing folks need
	     *      the kernel to tell you ? [Pedro]
	     */
	default:
	    trace (TR_INFO, MRT->trace, "RTMSG type %d\n",
		   rt.rtmsg_type);
	}
    }

    if (err < 0) {
	trace (TR_ERROR, MRT->trace, "RTMSG read (%s)\n",
	       strerror (errno));
    }
    select_enable_fd (rt6_fd);
}
#endif /* notdef */

#define BUFF_SIZ       2048

static void
krt6_icmp_rcv (void *arg)
{

    struct sockaddr_in6 from;
    struct msghdr mhdr;
    struct iovec iov;
    char buff[BUFF_SIZ];
    int err;

    memset (&mhdr, 0, sizeof (struct msghdr));
    memset (&from, 0, sizeof (struct sockaddr_in6));
    mhdr.msg_name = (void *) &from;
    mhdr.msg_namelen = sizeof (struct sockaddr_in6);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;

    iov.iov_base = buff;
    iov.iov_len = BUFF_SIZ;

    if ((err = recvmsg (rt6_sk, &mhdr, O_NONBLOCK)) > 0) {
	struct icmp6_hdr *hdr;

	hdr = (struct icmp6_hdr *) buff;
	trace (TR_INFO, MRT->trace, "ICMPV6 recv type=%d, code=%d\n",
	       hdr->icmp6_type, hdr->icmp6_code);
	/*
	   * process icmp here
	 */
    }

    if (err < 0) {
	trace (TR_ERROR, MRT->trace, "ICMPV6 read (%s)\n",
	       strerror (errno));
    }
    select_enable_fd (rt6_sk);
}
#endif /* HAVE_IPV6 */


/*
 *    read /proc/net/route6
 */
#ifdef HAVE_IPV6
#define PROC_NET_ROUTE6 "/proc/net/ipv6_route"
static void
krt_read_table_v6 (void)
{
    FILE *fp;
    char dest_str[40], src_str[40], nexthop_str[40], devname[16];
    int dest_masklen, src_masklen, use, refcnt, metric, index = 0;
    u_long flags;
    struct in6_addr dest6, nexthop6;
    int num;
    char buff[1024];
    interface_t *interface;

    if ((fp = fopen (PROC_NET_ROUTE6, "r")) == NULL) {
	trace (TR_ERROR, MRT->trace, "open for %s (%s)\n",
	       PROC_NET_ROUTE6, strerror (errno));
	return;
    }
    while (fgets (buff, sizeof (buff) - 1, fp)) {
	int proto = PROTO_KERNEL;

	num = sscanf (buff,
		      "%4s%4s%4s%4s%4s%4s%4s%4s %02x "
		      "%4s%4s%4s%4s%4s%4s%4s%4s %02x "
		      "%4s%4s%4s%4s%4s%4s%4s%4s "
		      "%08x %08x %08x %08lx %8s",
		      dest_str, dest_str + 5, dest_str + 10, dest_str + 15,
		 dest_str + 20, dest_str + 25, dest_str + 30, dest_str + 35,
		      &dest_masklen,
		      src_str, src_str + 5, src_str + 10, src_str + 15,
		      src_str + 20, src_str + 25, src_str + 30, src_str + 35,
		      &src_masklen,
	   nexthop_str, nexthop_str + 5, nexthop_str + 10, nexthop_str + 15,
		      nexthop_str + 20, nexthop_str + 25, nexthop_str + 30,
		      nexthop_str + 35,
		      &metric, &use, &refcnt, &flags, devname);

	if (num < 22)
	    continue;
	dest_str[4] = dest_str[9] = dest_str[14] = dest_str[19] =
	    dest_str[24] = dest_str[29] = dest_str[34] = ':';
	nexthop_str[4] = nexthop_str[9] = nexthop_str[14] = nexthop_str[19] =
	    nexthop_str[24] = nexthop_str[29] = nexthop_str[34] = ':';

	if (inet_pton (AF_INET6, dest_str, &dest6) < 0)
	    continue;
	if (inet_pton (AF_INET6, nexthop_str, &nexthop6) < 0)
	    continue;
	if (dest_masklen < 0 || dest_masklen > 128)
	    continue;

	/* Ignore source routes */
	if (src_masklen != 0)
	    continue;
	/* Ignore fallback route */
	if ((flags & RTF_REJECT) && dest_masklen == 0)
	    continue;
	/* Ignore clones */
	if (flags & RTF_CACHE)
	    continue;
	/* Ignore policy routes */
	if (flags & (RTF_POLICY | RTF_FLOW))
	    continue;
#ifdef RTF_STATIC
	if (flags & RTF_STATIC)
	    proto = PROTO_STATIC;
#endif /* RTF_STATIC */
	/* Set pseudo-device for reject routes */
	if (flags & RTF_REJECT) {
	    strcpy (devname, "lo");
	    memset (&nexthop6, 0, 16);
	    nexthop6.s6_addr[15] = 1;
	}
#ifdef notdef
	/* and ignore all non-reject loopback routes */
	else if (strcmp (devname, "lo") == 0)
	    continue;
#endif
#ifdef notdef
	else if (IN6_IS_ADDR_UNSPECIFIED (&nexthop6))
	    proto = PROTO_CONNECTED;
#endif
	/* we can't distinguish RTF_NONEXTHOP from !RTF_GATEWAY */
	else if (!BIT_TEST (flags, RTF_GATEWAY)) {
	    proto = PROTO_CONNECTED;
	    memset (&nexthop6, 0, 16);
	}
	/* I'm not sure but it was sometime */
	/* it should be a cache -- masaki */
	else if (memcmp (&dest6, &nexthop6, 16) == 0)
	    proto = PROTO_CONNECTED;

	if ((interface = find_interface_byname (devname)) == NULL)
	    continue;
#ifdef notdef
	/* Ignore local address routes */
	if (interface->flags & IFF_LOOPBACK) {
	    if (dest_masklen == 128 && memcmp (&dest6, &nexthop6, 16) == 0)
		continue;
#endif
	index = interface->index;

	if (!BIT_TEST (flags, RTF_GATEWAY) &&
		(interface->flags & IFF_TUNNEL)  &&
		(interface->flags & IFF_POINTOPOINT) &&
		IN6_IS_ADDR_UC_GLOBAL (&dest6) &&
		dest_masklen == 128 &&
		interface->primary6->prefix != NULL &&
		interface->primary6->broadcast == NULL) {
	    /* linux sit doesn't have its destination address,
	       so this tries to pick up one from the routing table */
	    interface->primary6->broadcast = New_Prefix (AF_INET6, &dest6, 128);
	}

	update_kernel_route ('A',
			   AF_INET6, &dest6, &nexthop6, dest_masklen, index,
			   proto);
    }
    fclose (fp);
}

#endif /* HAVE_IPV6 */


#define PROC_NET_ROUTE "/proc/net/route"
static void
krt_read_table_v4 (void)
{
    FILE *fp;
    char dest_str[9], nexthop_str[9], mask_str[9], devname[16];
    int masklen, metric, use, refcnt, flags, index = 0;
    struct in_addr dest, nexthop, mask;
    int num;
    char buff[1024];
    interface_t *interface;

    if ((fp = fopen (PROC_NET_ROUTE, "r")) == NULL) {
	trace (TR_ERROR, MRT->trace, "open for %s (%s)\n",
	       PROC_NET_ROUTE, strerror (errno));
	return;
    }

    /*
     * skip the first line
     */
    if (fgets (buff, sizeof (buff) - 1, fp) == NULL) {
	fclose (fp);
	return;
    }

    while (fgets (buff, sizeof (buff) - 1, fp)) {
	int proto = PROTO_KERNEL;

	num = sscanf (buff, "%s %s %s %x %d %d %d %s",
	     devname, dest_str, nexthop_str, &flags, &refcnt, &use, &metric,
		      mask_str);

	if (num < 8)
	    continue;

	if (!BIT_TEST (flags, RTF_UP))
	    continue;
#ifdef RTF_STATIC
	if (BIT_TEST (flags, RTF_STATIC))
	    proto = PROTO_STATIC;
#endif /* RTF_STATIC */

#ifdef notdef
	dest.s_addr = htonl (atox (dest_str));
	nexthop.s_addr = htonl (atox (nexthop_str));
	mask.s_addr = htonl (atox (nexthop_str));
#else
	/* This file contains in host byte order */
	dest.s_addr = atox (dest_str);
	nexthop.s_addr = atox (nexthop_str);
	mask.s_addr = atox (mask_str);
#endif
	masklen = mask2len ((char *) &mask, 4);

	if (masklen < 0 || masklen > 32)
	    continue;

	if (nexthop.s_addr == INADDR_ANY)
	    proto = PROTO_CONNECTED;
	if (!BIT_TEST (flags, RTF_GATEWAY)) {
	    proto = PROTO_CONNECTED;
	    nexthop.s_addr = INADDR_ANY;
	}

	if ((interface = find_interface_byname (devname)))
	    index = interface->index;

	update_kernel_route ('A',
		AF_INET, &dest, &nexthop, masklen, index, proto);
    }
    fclose (fp);
}


int
sys_kernel_read_rt_table (void)
{
#ifdef CONFIG_RTNETLINK
    if (init_netlink () >= 0) {
	return (kernel_read_rt_table_by_netlink ());
    }
#endif /* CONFIG_RTNETLINK */
    krt_read_table_v4 ();
#ifdef HAVE_IPV6
    krt_read_table_v6 ();
#endif /* HAVE_IPV6 */
    return (1);
}

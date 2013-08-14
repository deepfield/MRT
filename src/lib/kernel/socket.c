/*
 * $Id: socket.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>
#ifdef NT
#include <winsock2.h>
#ifdef HAVE_IPV6
#include <ws2ip6.h>
#endif /* HAVE_IPV6 */
#include <ws2tcpip.h>
#else
#include <sys/uio.h>
#endif /* NT */
/*
#include <netinet/in_systm.h>
#include <netinet/ip.h>
*/
#ifdef HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif /* HAVE_NETINET_ICMP6_H */
#ifdef linux
/* #include <linux/in.h> */
struct in_pktinfo
{
        int             ipi_ifindex;
        struct in_addr  ipi_spec_dst;
        struct in_addr  ipi_addr;
};
#endif /* linux */
#include <api6.h>
#include <igmp.h>


int
socket_open (int family, int type, int proto)
{
    int sockfd;

    if ((sockfd = socket (family, type, proto)) < 0) {
	trace (TR_ERROR, MRT->trace, "socket: %m\n");
    }
    return (sockfd);
}


int
socket_reuse (int sockfd, int yes)
{
    int ret;

    if ((ret = setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, 
	    (char *) &yes, sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt SO_REUSEADDR (%d): %m\n", yes);
	return (ret);
    }
#ifdef SO_REUSEPORT
    if ((ret = setsockopt (sockfd, SOL_SOCKET, SO_REUSEPORT, 
	    (char *) &yes, sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt SO_REUSEPORT (%d): %m\n", yes);
    }
#endif /* SO_REUSEPORT */
    return (ret);
}


int
socket_broadcast (int sockfd, int yes)
{
    int ret;

#ifdef SO_BROADCAST
    if ((ret = setsockopt (sockfd, SOL_SOCKET, SO_BROADCAST, 
	    (char *) &yes, sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt SO_BROADCAST (%d): %m\n", yes);
	return (ret);
    }
#endif /* SO_BROADCAST */
    return (ret);
}


int
socket_rcvbuf (int sockfd, int size)
{
    int ret = -1;

#ifdef SO_RCVBUF
    if ((ret = setsockopt (sockfd, SOL_SOCKET, SO_RCVBUF, (char *) &size,
		    sizeof (size))) < 0) {
	trace (TR_ERROR, MRT->trace, "setsockopt SO_RCVBUF (%d): %m\n",
	       size);
    }
#endif /* SO_RCVBUF */
    return (ret);
}


int
ip_hdrincl (int sockfd, int yes)
{
    int ret = -1;

#ifdef IP_HDRINCL
    if ((ret = setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (char *) &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace, "setsockopt IP_HDRINCL (%d): %m\n",
	       yes);
    }
#endif /* IP_HDRINCL */
    return (ret);
}


int
ip_multicast_loop (int sockfd, int yes)
{
    char cyes = yes; /* char */
    int ret = -1;

#ifdef IP_MULTICAST_LOOP
    /* disable loopback */
    if ((ret = setsockopt (sockfd, IPPROTO_IP, IP_MULTICAST_LOOP,
	        &cyes, sizeof (cyes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IP_MULTICAST_LOOP (%d): %m\n", cyes);
    }
#endif /* IP_MULTICAST_LOOP */
    return (ret);
}


int
ip_multicast_loop_get (int sockfd)
{
    char value = -1;
    int len = sizeof (value);

#ifdef IP_MULTICAST_LOOP
    if (getsockopt (sockfd, IPPROTO_IP, IP_MULTICAST_LOOP,
			&value, &len) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "getsockopt IP_MULTICAST_LOOP (%d): %m\n", value);
	return (-1);
    }
#endif /* IPV6_MULTICAST_LOOP */
    return (value);
}


int
ip_multicast_hops (int sockfd, int hops)
{
    char ttl = hops;
    int ret = -1;

#ifdef IP_MULTICAST_HOPS
    if (setsockopt (sockfd, IPPROTO_IP, IP_MULTICAST_HOPS,
			&ttl, sizeof (ttl)) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IP_MULTICAST_HOPS (%d): %m\n", ttl);
    }
#else /* IP_MULTICAST_HOPS */
#ifdef IP_MULTICAST_TTL
    if (setsockopt (sockfd, IPPROTO_IP, IP_MULTICAST_TTL,
			&ttl, sizeof (ttl)) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IP_MULTICAST_TTL (%d): %m\n", ttl);
    }
#endif /* IP_MULTICAST_TTL */
#endif /* IP_MULTICAST_HOPS */
    return (ret);
}


int
ip_recvttl (int sockfd, int yes)
{
    int ret = -1;

#ifdef IP_UNICAST_HOPS
    if ((ret = setsockopt (sockfd, IPPROTO_IP, IP_UNICAST_HOPS, &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IP_UNICAST_HOPS (%d): %m\n", yes);
    }
#else /* IP_UNICAST_HOPS */
#ifdef IP_RECVTTL
    if ((ret = setsockopt (sockfd, IPPROTO_IP, IP_RECVTTL, &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IP_RECVTTL (%d): %m\n", yes);
    }
#endif /* IP_RECVTTL */
#endif /* IP_UNICAST_HOPS */
    return (ret);
}


int
ip_pktinfo (int sockfd, int yes)
{
    int ret = -1;

#ifdef IP_PKTINFO
    if ((ret = setsockopt (sockfd, IPPROTO_IP, IP_PKTINFO, &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IP_PKTINFO (%d): %m\n", yes);
    }
#else
#ifdef IP_RECVINTERFACE
    if ((ret = setsockopt (sockfd, IPPROTO_IP, IP_RECVINTERFACE, &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IP_RECVINTERFACE (%d): %m\n", yes);
    }
#else
#ifdef IP_RECVIF
    if ((ret = setsockopt (sockfd, IPPROTO_IP, IP_RECVIF, &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IP_RECVIF (%d): %m\n", yes);
    }
#endif /* IP_RECVIF */
#endif /* IP_RECVINTERFACE */
#if defined (IP_RECVDSTADDR) && !defined(sun)
    if ((ret = setsockopt (sockfd, IPPROTO_IP, IP_RECVDSTADDR, &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IP_RECVDSTADDR: %m\n");
    }
#endif /* IP_RECVDSTADDR */
#endif /* IP_PKTINFO */
    return (ret);
}


#ifdef HAVE_IPV6

/* These functions enable getting info on recvmsg() */
/* On Solaris, some may work, but it's unknown how to get info later */
int
ipv6_pktinfo (int sockfd, int yes)
{
    int ret = -1;

#ifdef IPV6_RECVPKTINFO
    /* XXX -- This is required by INRIA IPV6 to get pktinfo 
       IPV6_PKTINFO does not work for setsockopt as RFC 2292 defines. */
    /*
     *  Receive destination address and interface from socket
     */
    if ((ret = setsockopt (sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IPV6_RECVPKTINFO: %m\n");
    }
#else /* IPV6_RECVPKTINFO */
#ifdef IPV6_PKTINFO
    /*
     *  Receive the interface info from socket (RFC 2292)
     */
    if ((ret = setsockopt (sockfd, IPPROTO_IPV6, IPV6_PKTINFO, &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IPV6_PKTINFO: %m\n");
    }
#else /* IPV6_PKTINFO */
#ifdef IP_RECVINTERFACE
    /* old INRIA IPv6 requires this */
    if (setsockopt (sockfd, IPPROTO_IPV6, IP_RECVINTERFACE, &yes,
		    sizeof (yes)) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IP_RECVINTERFACE: %m\n");
    }
#else
#ifdef IP_RECVIF
    if (setsockopt (sockfd, IPPROTO_IPV6, IP_RECVIF, &yes,
		    sizeof (yes)) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IP_RECVIF: %s\m");
    }
#endif /* IP_RECVIF */
#endif /* IP_RECVINTERFACE */
#ifdef IPV6_RECVDSTADDR
    if ((ret = setsockopt (sockfd, IPPROTO_IPV6, IPV6_RECVDSTADDR, &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IPV6_RECVDSTADDR: %m\n");
    }
#else /* IPV6_RECVDSTADDR */
#if defined(IP_RECVDSTADDR) && !defined(sun)
    if ((ret = setsockopt (sockfd, IPPROTO_IPV6, IP_RECVDSTADDR, &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IP_RECVDSTADDR: %m\n");
    }
#endif /* IP_RECVDSTADDR */
#endif /* IPV6_RECVDSTADDR */
#endif /* IPV6_PKTINFO */
#endif /* IPV6_RECVPKTINFO */
    return (ret);
}


int
ipv6_recvhops (int sockfd, int yes)
{
    int ret = -1;

#ifdef IPV6_RECVHOPS
    if ((ret = setsockopt (sockfd, IPPROTO_IPV6, IPV6_RECVHOPS, &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IPV6_RECVHOPS (%d): %m\n", yes);
    }
#else /* IPV6_RECVHOPS */
#ifdef IPV6_RECVHOPLIMIT
    if ((ret = setsockopt (sockfd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IPV6_RECVHOPLIMIT (%d): %m\n", yes);
    }
#else
#ifdef IPV6_HOPLIMIT
    if ((ret = setsockopt (sockfd, IPPROTO_IPV6, IPV6_HOPLIMIT, &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IPV6_HOPLIMIT (%d): %m\n", yes);
    }
#endif /* IPV6_HOPLIMIT */
#endif /* IPV6_RECVHOPLIMIT */
#endif /* IPV6_RECVHOPS */
    return (ret);
}


int
ipv6_unicast_hops (int sockfd, int hops)
{
    int ret = -1;
#ifndef NRL_IPV6
    int ttl = hops;
#else /* NRL_IPV6 */
/*
 * On NRL's IPV6, IPV6_MULTICAST_LOOP and IPV6_MULTICAST_HOPS
 * require a pointer to one byte (this was a log time ago...)
 */
    char ttl = hops;
#endif /* NRL_IPV6 */

#ifdef IPV6_UNICAST_HOPS
    if ((ret = setsockopt (sockfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 
			  (char *) &ttl, sizeof (ttl))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IPV6_UNICAST_HOPS (%d): %m\n", ttl);
    }
#endif /* IPV6_UNICAST_HOPS */
    return (ret);
}


int
ipv6_multicast_loop (int sockfd, int yes)
{
#ifndef NRL_IPV6    
    int value = yes;
#else /* NRL_IPV6 */
    char value = yes;
#endif /* NRL_IPV6 */
    int ret = -1;
#ifdef IPV6_MULTICAST_LOOP
    if ((ret = setsockopt (sockfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			(char *) &value, sizeof (value))) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IPV6_MULTICAST_LOOP (%d): %m\n", value);
    }
#endif /* IPV6_MULTICAST_LOOP */
    return (ret);
}


int
ipv6_multicast_loop_get (int sockfd)
{
#ifndef NRL_IPV6
    int value = -1;
#else /* NRL_IPV6 */
    char value = -1;
#endif /* NRL_IPV6 */
    int len = sizeof (value);

#ifdef IPV6_MULTICAST_LOOP
    if (getsockopt (sockfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			(char *) &value, &len) < 0) {
	trace (TR_ERROR, MRT->trace,
	       "getsockopt IPV6_MULTICAST_LOOP (%d): %m\n", value);
	return (-1);
    }
#endif /* IPV6_MULTICAST_LOOP */
    return (value);
}


int
ipv6_multicast_hops (int sockfd, int hops)
{
#ifndef NRL_IPV6
    int ttl = hops;
#else /* NRL_IPV6 */
    char ttl = hops;
#endif /* NRL_IPV6 */
    int ret = -1;

#ifdef IPV6_MULTICAST_HOPS
    if (setsockopt (sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			(char *) &ttl, sizeof (ttl)) < 0) {
#ifndef NT
	trace (TR_ERROR, MRT->trace,
	       "setsockopt IPV6_MULTICAST_HOPS (%d): %m\n", ttl);
#else
	printf("setsockopt(IPV6_MULTICAST_HOPS) failed: %u\n",
                   WSAGetLastError());
#endif /* NT */

    }
#endif /* IPV6_MULTICAST_HOPS */
    return (ret);
}


int
ipv6_hdrincl (int sockfd, int yes)
{
    int ret = -1;

#ifdef IP_HDRINCL
    if ((ret = setsockopt (sockfd, IPPROTO_IPV6, IP_HDRINCL, (char *) &yes,
		    sizeof (yes))) < 0) {
	trace (TR_ERROR, MRT->trace, "setsockopt IP_HDRINCL (%d): %m\n", yes);
    }
#endif /* IP_HDRINCL */
    return (ret);
}


#ifdef ICMP6_FILTER
int
icmp6_filter (int sockfd, struct icmp6_filter *filter)
{
    int ret = -1;

    if ((ret = setsockopt (sockfd, IPPROTO_ICMPV6, ICMP6_FILTER, (char *)filter,
		    sizeof (*filter))) < 0) {
	trace (TR_ERROR, MRT->trace, "setsockopt ICMP6_FILTER: %m\n");
    }
    return (ret);
}
#endif /* ICMP6_FILTER */

#endif /* HAVE_IPV6 */


int
join_leave_group (int sockfd, interface_t *interface, prefix_t *prefix, 
		  int join)
{
    struct ip_mreq mreq;
    char *mreqptr;
    int mreqlen;
#ifdef HAVE_IPV6
    struct ipv6_mreq mreq6;
#endif /* HAVE_IPV6 */
    int cmd;
    char *s_cmd;
    int proto;

    if (!BIT_TEST (interface->flags, IFF_UP))
		return (-1);
    if (!BIT_TEST (interface->flags, IFF_MULTICAST))
		return (-1);

    if (prefix->family == AF_INET) {
        if (interface->primary == NULL)
	    return (-1);

        memset (&mreq, 0, sizeof (mreq));
        mreq.imr_multiaddr.s_addr = prefix_tolong (prefix);
        mreq.imr_interface.s_addr = prefix_tolong (interface->primary->prefix);
        mreqptr = (char *) &mreq;
	mreqlen = sizeof (mreq);

        if (join) {
            cmd = IP_ADD_MEMBERSHIP;
            s_cmd = "IP_ADD_MEMBERSHIP";
 	}
	else {
            cmd = IP_DROP_MEMBERSHIP;
            s_cmd = "IP_DROP_MEMBERSHIP";
	}
	proto = IPPROTO_IP;
    }
#ifdef HAVE_IPV6
    else if (prefix->family == AF_INET6) {
        if (interface->primary6 == NULL)
			return (-1);
        memset (&mreq6, 0, sizeof (mreq6));
        memcpy (&mreq6.ipv6mr_multiaddr, prefix_toaddr6 (prefix), 16);

#ifdef __KAME__
        /* On KAME IPv6, it is required to modify the destination address
           as to include the outgoing interface's index */
        /* This is unnessesary when responding to a unicast address which
           includes an index */

        mreq6.ipv6mr_multiaddr.s6_addr[2] = (interface->index >> 8) & 0xff;
        mreq6.ipv6mr_multiaddr.s6_addr[3] = interface->index & 0xff;
#endif /* __KAME__ */

#ifdef IPV6MR_INTERFACE_INDEX
	assert (sizeof (mreq6.ipv6mr_interface) == 4);
        mreq6.ipv6mr_interface = interface->index;
#else
	assert (sizeof (mreq6.ipv6mr_interface) == 16);
        memcpy (&mreq6.ipv6mr_interface,
	        prefix_toaddr6 (interface->primary6->prefix), 16);
#endif /* IPV6MR_INTERFACE_INDEX */
        mreqptr = (char *) &mreq6;
		mreqlen = sizeof (mreq6);

        if (join) {
#ifdef IPV6_JOIN_MEMBERSHIP
            cmd = IPV6_JOIN_MEMBERSHIP;
            s_cmd = "IPV6_JOIN_MEMBERSHIP";
#else
            cmd = IPV6_ADD_MEMBERSHIP;
            s_cmd = "IPV6_ADD_MEMBERSHIP";
#endif /* IPV6_JOIN_MEMBERSHIP */
        }
	else {
#ifdef IPV6_LEAVE_MEMBERSHIP
            cmd = IPV6_LEAVE_MEMBERSHIP;
            s_cmd = "IPV6_LEAVE_MEMBERSHIP";
#else
            cmd = IPV6_DROP_MEMBERSHIP;
            s_cmd = "IPV6_DROP_MEMBERSHIP";
#endif /* IPV6_LEAVE_MEMBERSHIP */
	}
        proto = IPPROTO_IPV6;
    }
#endif /* HAVE_IPV6 */
    else
	return (-1);

    if (setsockopt (sockfd, proto, cmd, mreqptr, mreqlen) >= 0) {
	trace (TR_TRACE, MRT->trace, "%s %a on %s\n", 
	       s_cmd, prefix, interface->name);
	
    }
    else {
	trace (TR_ERROR, MRT->trace, "setsockopt %s %s for %s: %m\n", 
		s_cmd, prefix_toa (prefix), interface->name);
	return (-1);
    }
    return (0);
}


int
ip_multicast_if (int sockfd, interface_t *interface) 
{
    int ret = -1;

    assert (interface);
    if (interface->primary == NULL)
	return (ret);
    assert (interface->primary->prefix);
    if ((ret = setsockopt (sockfd, IPPROTO_IP, IP_MULTICAST_IF,
                    prefix_tochar (interface->primary->prefix),
                    sizeof (struct in_addr))) < 0) {
        trace (TR_ERROR, MRT->trace,
               "setsockopt IP_MULTICAST_IF for %s: %m\n",
               interface->name);
    }
    return (ret);
}


int
ip_multicast_vif (int sockfd, interface_t *interface) 
{
    int ret = -1;
    int index;

    assert (interface);
#ifdef HAVE_MROUTING
    if ((index = interface->vif_index) < 0)
	return (ret);
#ifdef IP_MULTICAST_VIF
    if ((ret = setsockopt (sockfd, IPPROTO_IP, IP_MULTICAST_VIF,
                    (char *) &index, sizeof (index))) < 0) {
        trace (TR_ERROR, MRT->trace,
               "setsockopt IP_MULTICAST_VIF for %s: %m\n",
               interface->name);
    }
#endif /* IP_MULTICAST_VIF */
#endif /* HAVE_MROUTING */
    return (ret);
}


int
send_packet (int sockfd, u_char *msg, int len, u_long flags, 
	     prefix_t *prefix, int port, interface_t *interface, 
	     u_long flowinfo)
{
    int ret = -1;
    int mc;
    u_long dontroute = flags & MSG_DONTROUTE;
    u_long multiloop = flags & MSG_MULTI_LOOP;

    assert (sockfd > 0);
    assert (msg);
    /* assert (len > 0); */ /* ricd requires zero length packet */
    assert (prefix);

    flags &= ~MSG_MULTI_LOOP; /* user defined */
    mc = prefix_is_multicast (prefix);
    if (mc) {
	/* Multicast sends fail if MSG_DONTROUTE is set */
	flags &= ~dontroute;
#ifdef HAVE_IPV6
	if (prefix->family == AF_INET6) {
	    if (multiloop && ipv6_multicast_loop_get (sockfd))
	        multiloop = 0;
	}
	else
#endif /* HAVE_IPV6 */
	if (multiloop && ip_multicast_loop_get (sockfd))
	    multiloop = 0;
    }

    if (interface != NULL && !BIT_TEST (interface->flags, IFF_VIF_TUNNEL)) {
		if (!BIT_TEST (interface->flags, IFF_UP))
            return (ret);
        if (prefix->family == AF_INET && interface->primary == NULL)
            return (ret);
#ifdef HAVE_IPV6
        if (prefix->family == AF_INET6 && interface->primary6 == NULL)
            return (ret);
#endif /* HAVE_IPV6 */
		if (mc) {
            if (!BIT_TEST (interface->flags, IFF_MULTICAST)) {
				prefix_t *old_prefix = prefix;
				
				/* fall back to unicast */
			flags |= dontroute;
			multiloop = 0;
			/* should I have a flag to allow this on interface->flags ? */
			if (BIT_TEST (interface->flags, IFF_POINTOPOINT)) {
#ifdef HAVE_IPV6
				if (prefix->family == AF_INET6 && interface->link_local->broadcast) {
					prefix = interface->link_local->broadcast;
					trace (TR_TRACE, MRT->trace, 
						"send using %a (p2p dest) in place of %a (multicast)\n", 
		               prefix, old_prefix);
				}
				else
#endif /* HAVE_IPV6 */
					if (interface->primary->broadcast) {
						prefix = interface->primary->broadcast;
                        trace (TR_TRACE, MRT->trace, 
							"send using %a (p2p dest) in place of %a (multicast)\n", 
							prefix, old_prefix);
					}
					else
						return (ret);
			}
			else if (BIT_TEST (interface->flags, IFF_BROADCAST) && interface->primary) {
				/* no broadcast in IPv6 */
				prefix = interface->primary->broadcast;
				trace (TR_TRACE, MRT->trace, 
						"send using %a (broadcast) in place of %a (multicast)\n", 
		           prefix, old_prefix);
			}
			else
				return (ret);
			}
		}
	}

    if (prefix->family == AF_INET) {
		struct sockaddr_in sin;

		if (interface && mc) {
			if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL)) {
				if (ip_multicast_vif (sockfd, interface) < 0)
					return (ret);
			}
			else if (ip_multicast_if (sockfd, interface) < 0)
				return (ret);
		}

		memset (&sin, 0, sizeof (sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = prefix_tolong (prefix);
		sin.sin_port = htons (port);
#ifdef HAVE_SA_LEN
		sin.sin_len = sizeof (sin);
#endif /* HAVE_SA_LEN */

		if (multiloop)
			ip_multicast_loop (sockfd, TRUE);
		if ((ret = sendto (sockfd, (char *) msg, len, flags,
                     (struct sockaddr *) &sin, sizeof (sin))) < 0) {
            trace (TR_ERROR, MRT->trace, "sendto %a on %s: %m\n",
                   prefix, (interface)?interface->name:"?");
        }
        else {
            trace (TR_TRACE, MRT->trace, "send %d bytes to %a on %s\n", 
		   len, prefix, (interface)?interface->name:"?");
        }
		if (multiloop)
			ip_multicast_loop (sockfd, FALSE);
	}
#ifdef HAVE_IPV6
    else if (prefix->family == AF_INET6) {
		struct sockaddr_in6 sin6;
#ifdef RFC2292
        struct msghdr mhdr;
        struct cmsghdr *cmsg;
        struct in6_pktinfo *pkt_info; 
        struct iovec iov;
        u_char chdr[sizeof (struct cmsghdr) + sizeof (struct in6_pktinfo)];
#endif /* RFC2292 */

		memset (&sin6, 0, sizeof (sin6));
		sin6.sin6_family = AF_INET6;
		memcpy (&sin6.sin6_addr, prefix_toaddr6 (prefix), 16);
		sin6.sin6_flowinfo = htonl (flowinfo);
		sin6.sin6_port = htons (port);
#ifdef HAVE_SA_LEN
		sin6.sin6_len = sizeof (sin6);
#endif /* HAVE_SA_LEN */

		if (multiloop)
			ipv6_multicast_loop (sockfd, TRUE);
#ifdef RFC2292
#ifdef __KAME__
        /* I'm not sure the recent KAME requires this.
           I'm not sure in which ways this is required */

		if (interface && !BIT_TEST (interface->flags, IFF_VIF_TUNNEL)) {
            /* On KAME IPv6, it is required to modify the destination address
               as to include the outgoing interface's index */

            sin6.sin6_addr.s6_addr[2] = (interface->index >> 8) & 0xff;
            sin6.sin6_addr.s6_addr[3] = interface->index & 0xff;
        }
#endif /* __KAME__ */
		memset (&mhdr, 0, sizeof (mhdr));
        mhdr.msg_name = (char *) &sin6;
        mhdr.msg_namelen = sizeof (sin6);
		memset (&iov, 0, sizeof (iov));
        iov.iov_base = (char *) msg;
        iov.iov_len = len;
        mhdr.msg_iov = &iov;
        mhdr.msg_iovlen = 1;
		memset (&chdr, 0, sizeof (chdr));
        cmsg = (struct cmsghdr *) chdr;
        cmsg->cmsg_len = sizeof (chdr);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        mhdr.msg_control = (void *) cmsg; 
        mhdr.msg_controllen = sizeof (chdr);
        pkt_info = (struct in6_pktinfo *) CMSG_DATA (cmsg);
		if (interface && !BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
            pkt_info->ipi6_ifindex = interface->index;
		if (interface && !BIT_TEST (interface->flags, IFF_VIF_TUNNEL)) {
	    if (prefix_is_linklocal (prefix) && interface->link_local) {
                memcpy (&pkt_info->ipi6_addr,
                        prefix_toaddr6 (interface->link_local->prefix), 16);
		trace (TR_PACKET, MRT->trace,
                   "source address will be %a\n",
                   interface->link_local->prefix);
		}
	}
	if ((ret = sendmsg (sockfd, &mhdr, flags)) < 0) {
            trace (TR_ERROR, MRT->trace, "sendmsg to %a on %s: %m\n",
                   prefix, (interface)?interface->name:"?");
        }
        else {
            trace (TR_TRACE, MRT->trace, "sendmsg %d bytes to %a on %s\n", 
		   len, prefix, (interface)?interface->name:"?");
        }
#else
	if (interface && mc) {
	    if (ipv6_multicast_if (sockfd, interface) < 0)
	        return (ret);
	}
	if ((ret = sendto (sockfd, msg, len, flags,
                     (struct sockaddr *) &sin6, sizeof (sin6))) < 0) {
	    trace (TR_ERROR, MRT->trace, "sendto %a on %s: %m\n",
                   prefix, (interface)?interface->name:"?");
			
	}
	else {
            trace (TR_TRACE, MRT->trace, "send %d bytes to %a on %s\n", 
				len, prefix, (interface)?interface->name:"?");
	}
#endif /* RFC2292 */
	if (multiloop)
	    ipv6_multicast_loop (sockfd, FALSE);
    }
#endif /* HAVE_IPV6 */
    return (ret);
}


union sockunion {
    struct sockaddr sa;
    struct sockaddr_in sin;
#ifdef HAVE_IPV6
    struct sockaddr_in6 sin6;
#endif                          /* HAVE_IPV6 */
};


int
recvmsgfrom (int sockfd, u_char *buffer, int buflen, u_long flags,
	     prefix_t ** prefix_p, int *port_p, interface_t ** interface_p,
	     prefix_t ** destin_p, int *hop_p)
{
    int ret = -1;
    prefix_t *prefix = NULL;
    interface_t *interface = NULL;
    int index = 0;
    int port;
    union sockunion from;
    union sockunion dstaddr;
    int limit = -1;
#ifdef USE_SENDRECVMSG
#ifdef INET6_ADDRSTRLEN
    char tmp6[INET6_ADDRSTRLEN];
#else
    char tmp6[128];
#endif /* HAVE_IPV6 */

    struct msghdr mhdr;
    struct cmsghdr *cmsg;
    struct iovec iov;
    u_char chdr[1024];
#else
    int fromlen = sizeof (from);
#endif /* USE_SENDRECVMSG */
    int mayigmp;
    int dontcare;

    memset (&dstaddr, 0, sizeof (dstaddr));
    mayigmp = BIT_TEST (flags, MSG_MAYIGMP);
    BIT_RESET (flags, MSG_MAYIGMP);
    dontcare = BIT_TEST (flags, MSG_DONTCARE);
    BIT_RESET (flags, MSG_DONTCARE);

#ifdef USE_SENDRECVMSG
    /* memset (&from, 0, sizeof (from));
    memset (chdr, 0, sizeof (chdr));
    memset (&iov, 0, sizeof (iov));
    memset (buffer, 0, buflen); */
    mhdr.msg_name = (void *) &from;
    mhdr.msg_namelen = sizeof (from);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = (void *) chdr;
    mhdr.msg_controllen = sizeof (chdr);
    iov.iov_base = buffer;
    iov.iov_len = buflen;

    ret = recvmsg (sockfd, &mhdr, flags);
    /* hqlip requires reception of zero length udp packet */
    if (ret < 0) {
	/* zero is error? XXX */
	trace (TR_ERROR, MRT->trace, "recvmsg: %m\n");
	return (ret);
    }
    else {
	memset (&dstaddr, 0, sizeof (dstaddr));
/* fprintf(stderr, "mhdr.msg_control = 0x%x mhdr.msg_controllen = %d\n", 
   mhdr.msg_control, mhdr.msg_controllen); */
#if 0
#ifdef __GLIBC__
/* There is a bug in GNU LIBC 2.0, so I define another one. */
#undef CMSG_NXTHDR
#define CMSG_NXTHDR(mhdr, cmsg) \
    (((unsigned char *)(cmsg) + (cmsg)->cmsg_len + sizeof(struct cmsghdr) > \
	(unsigned char *)(mhdr)->msg_control + (mhdr)->msg_controllen) ? \
	(struct cmsghdr *)NULL : \
        (struct cmsghdr *)((unsigned char *)(cmsg) \
         + (((cmsg)->cmsg_len + sizeof(long int)-1) & ~(sizeof(long int)-1))))
#endif /* __GLIBC__ */
#endif
	if (mhdr.msg_controllen > 0)
	    for (cmsg = CMSG_FIRSTHDR (&mhdr);
		 cmsg;
		 cmsg = CMSG_NXTHDR (&mhdr, cmsg)) {
/* fprintf(stderr, 
   "cmg=0x%x cmsg->cmsg_level = %d cmsg->cmsg_type = %d cmsg->cmsg_len = %d\n", 
   cmsg, cmsg->cmsg_level, cmsg->cmsg_type, cmsg->cmsg_len); */
#ifdef HAVE_IPV6
	    if (cmsg->cmsg_level == IPPROTO_IPV6)
		switch (cmsg->cmsg_type) {
#ifdef IPV6_PKTINFO
		case IPV6_PKTINFO:
		{
    		    struct in6_pktinfo *pkt_info;
		    pkt_info = (struct in6_pktinfo *) CMSG_DATA (cmsg);
		    index = pkt_info->ipi6_ifindex;
		    memcpy (&dstaddr.sin6.sin6_addr, &pkt_info->ipi6_addr, 16);
		    dstaddr.sa.sa_family = AF_INET6;
		    trace (TR_PACKET, MRT->trace,
			   "recv IPV6_PKTINFO dest = %s index = %d\n",
			   inet_ntop (AF_INET6, &dstaddr.sin6.sin6_addr,
				      tmp6, sizeof tmp6), index);
		    break;
		}
#endif /* IPV6_PKTINFO */
#ifdef IPV6_RECVINTERFACE
		case IPV6_RECVINTERFACE:
		    index = *(u_short *) CMSG_DATA (cmsg);
		    trace (TR_PACKET, MRT->trace,
			   "recv IPV6_RECVINTERFACE index = %d\n", index);
		    break;
#endif /* IPV6_RECVINTERFACE */
		    /*
		     * XXX destination address of packet should be checked 
		     * RIPNG request may not be addressed with multicast addess
		     * it may be possible later
		     */
#ifdef IPV6_RECVDSTADDR
		case IPV6_RECVDSTADDR:
		    dstaddr.sa.sa_family = AF_INET6;
		    memcpy (&dstaddr.sin6.sin6_addr, CMSG_DATA (cmsg), 16);
		    trace (TR_PACKET, MRT->trace,
			   "recv IPV6_RECVDSTADDR dest = %s\n",
			 inet_ntop (AF_INET6, &dstaddr.sin6.sin6_addr, 
				    tmp6, sizeof tmp6));
		    break;
#endif /* IPV6_RECVDSTADDR */
		    /*
		     * XXX it may be possible later checking hop limit
		     */
#ifdef IPV6_HOPLIMIT
		case IPV6_HOPLIMIT:
		    limit = *(u_char *) CMSG_DATA (cmsg);
		    trace (TR_PACKET, MRT->trace,
			   "recv IPV6_HOPLIMIT = %d\n", limit);
		    break;
#endif /* IPV6_HOPLIMIT */
#if defined(IPV6_UNICAST_HOPS) && IPV6_HOPLIMIT != IPV6_UNICAST_HOPS
		case IPV6_UNICAST_HOPS:
		    limit = *(int *) CMSG_DATA (cmsg);
		    trace (TR_PACKET, MRT->trace,
			   "recv IPV6_UNICAST_HOPS = %d\n", limit);
		    break;
#endif /* IPV6_UNICAST_HOPS */
		default:
		    trace (TR_PACKET, MRT->trace,
			"recv unknown cmsg level = %d type = %d len = %d\n",
			 cmsg->cmsg_level, cmsg->cmsg_type, cmsg->cmsg_len);
		    break;
		}
	    else 
#endif /* HAVE_IPV6 */
		switch (cmsg->cmsg_type) {
#ifdef IP_PKTINFO
		case IP_PKTINFO:
{
		    struct in_pktinfo *info;

		    info = (struct in_pktinfo *) CMSG_DATA (cmsg);
		    index = info->ipi_ifindex;
		    dstaddr.sin.sin_addr.s_addr = info->ipi_spec_dst.s_addr;
                    dstaddr.sa.sa_family = AF_INET;
                    trace (TR_PACKET, MRT->trace,
                           "recv IP_PKTINFO dest = %s index = %d\n",
                           inet_ntop (AF_INET, &dstaddr.sin.sin_addr,
                                      tmp6, sizeof tmp6), index);
		    break;
}
#endif /* IP_PKTINFO */
#ifdef IP_RECVINTERFACE
		case IP_RECVINTERFACE:
		    index = *(u_short *) CMSG_DATA (cmsg);
		    trace (TR_PACKET, MRT->trace,
			   "recv IP_RECVINTERFACE index = %d\n", index);
		    break;
#else
#ifdef IP_RECVIF
		case IP_RECVIF:
{
		    struct sockaddr_dl *sdl;

		    sdl = (struct sockaddr_dl *) CMSG_DATA (cmsg);
		    index = sdl->sdl_index;
		    trace (TR_PACKET, MRT->trace,
			   "recv IP_RECVIF index = %d\n", index);
		    break;
}
#endif /* IP_RECVIF */
#endif /* IP_RECVINTERFACE */
#ifdef IP_RECVDSTADDR
		case IP_RECVDSTADDR:
		    dstaddr.sa.sa_family = AF_INET;
		    memcpy (&dstaddr.sin.sin_addr, CMSG_DATA (cmsg), 4);
		    trace (TR_PACKET, MRT->trace,
			   "recv IP_RECVDSTADDR dest = %s\n",
			    inet_ntop (AF_INET,
				       &dstaddr.sin.sin_addr, 
				       tmp6, sizeof tmp6));
		    break;
#endif /* IP_RECVDSTADDR */
#ifdef IP_UNICAST_HOPS
		case IP_UNICAST_HOPS:
		    limit = *(int *) CMSG_DATA (cmsg);
		    trace (TR_PACKET, MRT->trace,
			   "recv IP_UNICAST_HOPS = %d\n", limit);
		    break;
#else
#ifdef IP_RECVTTL
		case IP_RECVTTL:
		    limit = *(int *) CMSG_DATA (cmsg);
		    trace (TR_PACKET, MRT->trace,
			   "recv IP_RECVTTL = %d\n", limit);
		    break;
#else
#ifdef IP_TTL
		case IP_TTL:
		    limit = *(int *) CMSG_DATA (cmsg);
		    trace (TR_PACKET, MRT->trace,
			   "recv IP_TTL = %d\n", limit);
		    break;
#endif /* IP_TTL */
#endif /* IP_RECVTTL */
#endif /* IP_UNICAST_HOPS */
		default:
		    trace (TR_PACKET, MRT->trace,
			"recv unknown cmsg level = %d type = %d len = %d\n",
			 cmsg->cmsg_level, cmsg->cmsg_type, cmsg->cmsg_len);
		    break;
		}
	    }
    }
#else /* USE_SENDRECVMSG */

#ifdef NT
	flags = 0;
#endif /* NT */

/* Solaris has IP_RECVDSTADDR, but differs. No way to know the interface */
    if ((ret = recvfrom (sockfd, (char *) buffer, buflen, flags,
			(struct sockaddr *) &from, &fromlen)) < 0) {
		trace (TR_ERROR, MRT->trace, "recvfrom: %m\n");
		return (ret);
    }
#endif /* USE_SENDRECVMSG */

#ifdef NT
#ifdef HAVE_IPV6
	index = from.sin6.sin6_scope_id;
#endif /* HAVE_IPV6 */
#endif /* NT */

    if (destin_p != NULL && dstaddr.sa.sa_family) {
		*destin_p = sockaddr_toprefix ((struct sockaddr *) &dstaddr);
    }
    if (hop_p != NULL && limit >= 0) {
		*hop_p = limit;
    }

    if (prefix_p == NULL && interface_p == NULL)
		return (ret);

    prefix = sockaddr_toprefix ((struct sockaddr *) &from);
#ifdef HAVE_IPV6
    if (from.sa.sa_family == AF_INET6) {
	port = ntohs (from.sin6.sin6_port);

#ifdef HAVE_MROUTING6
#ifdef WIDE_IPV6
        if (mayigmp && sizeof (struct mrt6msg) == ret &&
		((struct mrt6msg *) buffer)->im6_mbz == 0) {
	    /* MLD kernel message */
	    dontcare++;
        }
#endif /* WIDE_IPV6 */
#endif /* HAVE_MROUTING6 */
    }
    else
#endif /* HAVE_IPV6 */
{
    port = ntohs (from.sin.sin_port);

#ifdef HAVE_MROUTING
    if (mayigmp && ((struct ip *) buffer)->ip_p == 0) {
	/* IGMP kernel message */
	dontcare++;
    }
#endif /* HAVE_MROUTING */
}

    if (interface_p == NULL) {
        assert (prefix_p);
        *prefix_p = prefix;
        if (port_p)
	    *port_p = port;
        return (ret);
    }

    if (index > 0) {
	interface = find_interface_byindex (index);
	/* even in this case, we need to check the source
	   since it may come from through a tunnel */
#if defined(linux) && defined(HAVE_IPV6)
	/* Linux sit doesn't have its destination address */
	if (interface && (
		!BIT_TEST (interface->flags, IFF_POINTOPOINT) ||
		interface->primary6->broadcast != NULL))
#endif /* linux */
	if (interface && prefix->family == AF_INET &&
		!is_prefix_on (prefix, interface)) {
	    interface = find_tunnel_interface (prefix);
	    if (interface != NULL) {
	        trace (TR_PACKET, MRT->trace,
		   "recv tunnel source %a on %s\n",
		   prefix, interface->name);
	    }
	}
    }
#ifdef NT
	dontcare = 0;
#endif /* NT */

    if (interface == NULL && dontcare == 0) {
		gateway_t *gateway;
		/*
		* if the system doesn't supply the incoming interface index,
		* try to find among configured interfaces and gateways registered,
		*/
		if ((interface = find_interface (prefix))) {
		   trace (TR_PACKET, MRT->trace,
			   "guesses %a on %s (find_interface)\n",
			   prefix, interface->name);
		}
		else if ((gateway = find_gateway (prefix)) &&
			 gateway->interface) {

		   interface = gateway->interface;
		  trace (TR_PACKET, MRT->trace,
			   "guesses %a on %s (find_gateway)\n",
			   prefix, interface->name);
		}
	}

    if (interface == NULL && dontcare == 0) {
		trace (TR_PACKET, MRT->trace,
	       "discard packet from %a (interface unknown)\n",
	       prefix);
		ret = -1;
    }
    assert (interface_p);
    *interface_p = interface;
    if (prefix_p) {
        *prefix_p = prefix;
	if (port_p)
            *port_p = port;
    }
    else
        Deref_Prefix (prefix);
    return (ret);
}


#ifdef HAVE_IPV6
int
ipv6_multicast_if (int sockfd, interface_t *interface) 
{
    int ret = -1;
#if defined(RFC2292) || defined(NT)  
    int index;
#endif /* RFC2292 */

    assert (interface);
    if (interface->primary6 == NULL)
		return (ret);
    assert (interface->primary6->prefix);
#if defined(RFC2292) || defined(NT)
    index = interface->index;
    /* IPV6_PKTINFO will be used instead */
    if ((ret = setsockopt (sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                    &index, sizeof (int))) < 0) {
#else
    if ((ret = setsockopt (sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                    prefix_tochar (interface->primary6->prefix),
                    sizeof (struct in6_addr))) < 0) {
#endif /* RFC2292 */
            trace (TR_ERROR, MRT->trace,
                   "setsockopt IPV6_MULTICAST_IF for %s: %m\n",
                   interface->name);
    }
    return (ret);
}
#endif /* HAVE_IPV6 */


static int
inet_cksum2 (void *cp, int len, u_long sum)
{
    u_short *sp = cp;
    int odd = (len % 2);

    len /= 2;
    while (--len >= 0)
        sum += *sp++;
    if (odd) {
        u_char pad[2];
	pad[0] = *(u_char *)sp;
	pad[1] = 0;
	sp = (u_short *)pad;
	sum += *sp;
    }
    while (sum > 0xffff)
	sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum & 0xffff;
    return (sum);
}


int
inet_cksum (void *cp, int len)
{
    return (inet_cksum2 (cp, len, 0));
}


#ifdef HAVE_IPV6
int
inet6_cksum (void *cp, int len, int nh, 
	     struct in6_addr *src, struct in6_addr *dst)
{
    struct ip6_hdr ipv6;
    u_long sum = 0;
    u_short *sp = (u_short *) &ipv6;
    int i;

    /* memset (&ipv6, 0, sizeof (ipv6)); */
    ipv6.ip6_hlim = nh;
    ipv6.ip6_nxt = 0;      
    ipv6.ip6_vfc = 0;      
    ipv6.ip6_flow = 0;
    ipv6.ip6_plen = htons (len);  
    ipv6.ip6_src = *src;
    ipv6.ip6_dst = *dst;

    for (i = 0; i < sizeof (ipv6)/2; i++) {
	sum += sp[i];
    }
    return (inet_cksum2 (cp, len, sum));
}
#endif /* HAVE_IPV6 */


void
set_nonblocking (int sockfd)
{
#ifndef HAVE_LIBPTHREAD
#ifdef FIONBIO
    int optval = 1;
    if (ioctl (sockfd, FIONBIO, &optval) < 0) {
	trace (TR_ERROR, MRT->trace, "ioctl FIONBIO failed (%m)\n");
    }
#else
    if (fcntl (sockfd, F_SETFL, O_NONBLOCK) < 0) {
	trace (TR_ERROR, MRT->trace, "fcntl F_SETFL O_NONBLOCK failed (%m)\n");
    }
#endif /* FIONBIO */
#endif /* HAVE_LIBPTHREAD */
}


int
get_socket_addr (int sockfd, int remote, prefix_t **prefix_p)
{
    sockunion_t anyaddr;
    int family = AF_INET, len;
    int ret, bitlen = 32;
    void *addr = NULL;

    len = sizeof (anyaddr);
    memset (&anyaddr, 0, sizeof (anyaddr));
    if (remote)
        ret = getpeername (sockfd, (struct sockaddr *) &anyaddr, &len);
    else
        ret = getsockname (sockfd, (struct sockaddr *) &anyaddr, &len);

    if (ret >= 0) {
	if ((family = anyaddr.sa.sa_family) == AF_INET) {
	    struct sockaddr_in *sin = (struct sockaddr_in *) &anyaddr;
	    addr = &sin->sin_addr;
	    family = AF_INET;
	    bitlen = 32;
	}
#ifdef HAVE_IPV6
	else if (family == AF_INET6) {
	    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &anyaddr;
	    if (IN6_IS_ADDR_V4MAPPED (&sin6->sin6_addr)) {
		addr = ((u_char *) &sin6->sin6_addr) + 12;
		bitlen = 32;
		family = AF_INET;
	    }
	    else {
		addr = &sin6->sin6_addr;
		bitlen = 128;
		family = AF_INET6;
	    }
	}
#endif /* HAVE_IPV6 */
	if (addr && prefix_p) {
	    *prefix_p = New_Prefix (family, addr, bitlen);
	}
    }
    return (ret);
}


int
socket_bind_port (int sockfd, int family, void *addr, int lport)
{
    sockunion_t anyaddr;
    int len;

    memset (&anyaddr, 0, sizeof (anyaddr));
#ifdef HAVE_IPV6
    if (family == AF_INET6) {
        anyaddr.sin6.sin6_port = htons (lport);
        anyaddr.sin6.sin6_family = family;   
	if (addr)
            memcpy (&anyaddr.sin6.sin6_addr, addr, 16);
	len = sizeof (anyaddr.sin6);
    }
    else
#endif /* HAVE_IPV6 */
    {
        anyaddr.sin.sin_port = htons (lport);
        anyaddr.sin.sin_family = family;   
	if (addr)
            memcpy (&anyaddr.sin.sin_addr, addr, 4);
	len = sizeof (anyaddr.sin);
    }

#ifdef IPV6_BINDV6ONLY
    /* bind with any address makes a socket for both v4 and v6 */
    /* XXX this is KAME only. I need to check it with other platforms */
    if (family == AF_INET6) {
	int yes = 1;
	setsockopt (sockfd, IPPROTO_IPV6, IPV6_BINDV6ONLY, &yes, sizeof (yes));
    }
#endif /* IPV6_BINDV6ONLY */
    if (bind (sockfd, (struct sockaddr *) &anyaddr, len) < 0) {
        trace (TR_ERROR, MRT->trace,
               "Could not bind to port %d (%m)\n", lport);
        close (sockfd);
        return (-1);
    }   

    return (sockfd);
}


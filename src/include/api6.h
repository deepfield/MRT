/*
 * $Id: api6.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#include <config.h>
#ifdef HAVE_IPV6

#ifndef _API6_H
#define _API6_H
#include <sys/types.h>
#ifndef NT
#include <netinet/in.h>
#include <arpa/inet.h> /* inet_ntop defined there */
#endif /* NT */ 
#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif /* HAVE_NETINET_IP6_H */
#ifdef HAVE_NETINET_ICMP6_H
#include <netinet/icmp6.h>
#endif /* HAVE_NETINET_ICMP6_H */
#if defined (__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
/* OK */
#else /* __GLIBC__ */
#ifdef __linux__
#include <netinet/ipv6.h>
#include <netinet/icmpv6.h>
#endif /* __linux__ */
#ifdef NRL_IPV6
#include <netinet6/in6_types.h>
#include <netinet6/in6.h>
#endif /* NRL_IPV6 */
#endif /* __GLIBC__ */

#ifndef RFC2292
struct ip6_hdr {
        union {
                struct ip6_hdrctl {
                        u_long  ip6_un1_flow; /* 20 bits of flow-ID */
                        u_short ip6_un1_plen; /* payload length */
                        u_char  ip6_un1_nxt;  /* next header */
                        u_char  ip6_un1_hlim; /* hop limit */
                } ip6_un1;
                u_char ip6_un2_vfc;   /* 4 bits version, 4 bits class */
        } ip6_ctlun;
        struct in6_addr ip6_src;        /* source address */
        struct in6_addr ip6_dst;        /* destination address */
};

#define ip6_vfc         ip6_ctlun.ip6_un2_vfc
#define ip6_flow        ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen        ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt         ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim        ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops        ip6_ctlun.ip6_un1.ip6_un1_hlim

#endif /* RFC2292 */
#ifndef IPNGVERSION
#define IPNGVERSION    6
#endif /* IPNGVERSION */

/*
 * The API draft defines only the way to have access in byte.
 * Many implementations provide 32-bit access but the field name may vary.
 */
struct _in6_addr32 {
    u_long _s6_addr32[4];
};

/*
 * These are not defined in the API draft
 */
#define IN6_IS_ADDR_UC_GLOBAL(a) \
    (((a)->s6_addr[0] & 0xe0) == 0x20)

#define IN6_ADDR_COPY(a, b) \
    (*(struct in6_addr *)(a) = *(struct in6_addr *)(b))

#define IN6_ADDR_COMP(a, b) ( \
    (((struct _in6_addr32 *)(a))->_s6_addr32[0] - \
        ((struct _in6_addr32 *)(b))->_s6_addr32[0]) || \
    (((struct _in6_addr32 *)(a))->_s6_addr32[1] -  \
        ((struct _in6_addr32 *)(b))->_s6_addr32[1]) || \
    (((struct _in6_addr32 *)(a))->_s6_addr32[2] -  \
        ((struct _in6_addr32 *)(b))->_s6_addr32[2]) || \
    (((struct _in6_addr32 *)(a))->_s6_addr32[3] -  \
        ((struct _in6_addr32 *)(b))->_s6_addr32[3]))

extern const struct in6_addr in6addr_any;

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN   46
#endif /* INET6_ADDRSTRLEN */

#ifndef IN6_IS_ADDR_UNSPECIFIED

#define IN6_IS_ADDR_UNSPECIFIED(a) ( \
    ((struct _in6_addr32 *)(a))->_s6_addr32[0] == 0 && \
    ((struct _in6_addr32 *)(a))->_s6_addr32[1] == 0 && \
    ((struct _in6_addr32 *)(a))->_s6_addr32[2] == 0 && \
    ((struct _in6_addr32 *)(a))->_s6_addr32[3] == 0)

#define IN6_IS_ADDR_LOOPBACK(a) ( \
    ((struct _in6_addr32 *)(a))->_s6_addr32[0] == 0 && \
    ((struct _in6_addr32 *)(a))->_s6_addr32[1] == 0 && \
    ((struct _in6_addr32 *)(a))->_s6_addr32[2] == 0 && \
    ((struct _in6_addr32 *)(a))->_s6_addr32[3] == htonl(1))

#define IN6_IS_ADDR_MULTICAST(a) ((a)->s6_addr[0] == 0xff)

#ifdef notdef
extern __inline__ IN6_IS_ADDR_LINKLOCAL (struct in6_addr *a)
{
    return ((a->s6_addr32[0] & __constant_htonl (0xFFC00000)) == 
	    __constant_htonl(0xFE800000));
}

extern __inline__ IN6_IS_ADDR_V4MAPPED (struct in6_addr *a)
{
    return ((a->s6_addr32[0] | a->s6_addr32[1] | a->s6_addr32[2]) == 0
            && (a->s6_addr32[3] & __constant_htonl (0xFF000000)));
}

#endif

#define IN6_IS_ADDR_LINKLOCAL(a) \
    ((a)->s6_addr[0] == 0xfe && ((a)->s6_addr[1] & 0xc0) == 0x80)

#define IN6_IS_ADDR_SITELOCAL(a) \
    ((a)->s6_addr[0] == 0xfe && ((a)->s6_addr[1] & 0xc0) == 0xc0)

#define IN6_IS_ADDR_V4MAPPED(a) ( \
    ((struct _in6_addr32 *)(a))->_s6_addr32[0] == 0 && \
    ((struct _in6_addr32 *)(a))->_s6_addr32[1] == 0 && \
    ((struct _in6_addr32 *)(a))->_s6_addr32[2] == htonl(0x0000ffff))

#define IN6_IS_ADDR_V4COMPAT(a) ( \
    ((struct _in6_addr32 *)(a))->_s6_addr32[0] == 0 && \
    ((struct _in6_addr32 *)(a))->_s6_addr32[1] == 0 && \
    ((struct _in6_addr32 *)(a))->_s6_addr32[2] == 0 && \
    ntohl(((struct _in6_addr32 *)(a))->_s6_addr32[3]) > 1)

#endif /* IN6_IS_ADDR_UNSPECIFIED */


#if defined (__linux__) || defined (NRL_IPV6) || (defined (SOLARIS_IPV6) && !defined (RFC2292))

#if defined (__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
  /* nothing */
#else /* __GLIBC__ */

#ifndef _LINUX_ICMPV6_H

struct icmp6_filter {
  u_long data[8];
};

struct icmp6_hdr {
   u_char     icmp6_type;   /* type field */
   u_char     icmp6_code;   /* code field */
   u_short    icmp6_cksum;  /* checksum field */
   union {
      u_long   icmp6_un_data32[1]; /* type-specific field */
      u_short  icmp6_un_data16[2]; /* type-specific field */
      u_char   icmp6_un_data8[4];  /* type-specific field */
   } icmp6_dataun;
};

#define icmp6_data32    icmp6_dataun.icmp6_un_data32
#define icmp6_data16    icmp6_dataun.icmp6_un_data16
#define icmp6_data8     icmp6_dataun.icmp6_un_data8
#define icmp6_pptr      icmp6_data32[0]  /* parameter prob */
#define icmp6_mtu       icmp6_data32[0]  /* packet too big */
#define icmp6_id        icmp6_data16[0]  /* echo request/reply */
#define icmp6_seq       icmp6_data16[1]  /* echo request/reply */
#define icmp6_maxdelay  icmp6_data16[0]  /* mcast group membership */

#endif /* _LINUX_ICMPV6_H */

#ifdef __linux__
#include <asm/bitops.h>
#endif /* __linux__ */

/* Linux and NRL have ICMPV6_... */

#define ICMP6_FILTER_WILLPASS(type, filterp) \
	 (test_bit(type, filterp) == 0)

#define ICMP6_FILTER_WILLBLOCK(type, filterp) \
	 test_bit(type, filterp)

#define ICMP6_FILTER_SETPASS(type, filterp) \
	 clear_bit(type & 0x1f, &((filterp)->data[type >> 5]))

#define ICMP6_FILTER_SETBLOCK(type, filterp) \
	 set_bit(type & 0x1f, &((filterp)->data[type >> 5]))

#define ICMP6_FILTER_SETPASSALL(filterp) \
	 memset(filterp, 0, sizeof(struct icmp6_filter));

#define ICMP6_FILTER_SETBLOCKALL(filterp) \
	 memset(filterp, 0xFF, sizeof(struct icmp6_filter));

#ifndef ICMP6_DST_UNREACH
#define ICMP6_DST_UNREACH             1
#define ICMP6_PACKET_TOO_BIG          2
#define ICMP6_TIME_EXCEEDED           3
#define ICMP6_PARAM_PROB              4
#endif /* ICMP6_DST_UNREACH */

#ifndef ND_ROUTER_SOLICIT
#define ND_ROUTER_SOLICIT           133
#define ND_ROUTER_ADVERT            134
#define ND_NEIGHBOR_SOLICIT         135
#define ND_NEIGHBOR_ADVERT          136
#define ND_REDIRECT                 137
#endif /* ND_ROUTER_SOLICIT */

#endif /* __GLIBC__ */
#endif /* __linux__ || NRL_IPV6 */

/*
 * differences in multicast definitions
 */
#ifdef NRL_IPV6
#define ipv6mr_multiaddr i6mr_multiaddr
#define ipv6mr_interface i6mr_interface
#endif /* NRL_IPV6 */
#ifdef HAVE_IPV6MR_IFINDEX
#define ipv6mr_interface ipv6mr_ifindex
#endif /* HAVE_IPV6MR_IFINDEX */

#if defined(IPV6_JOIN_GROUP) && !defined(IPV6_ADD_MEMBERSHIP)
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif /* IPV6_JOIN_GROUP && !IPV6_ADD_MEMBERSHIP */
#if defined(IPV6_LEAVE_GROUP) && !defined(IPV6_DROP_MEMBERSHIP)
#define IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP
#endif /* IPV6_LEAVE_GROUP && !IPV6_DROP_MEMBERSHIP */

#ifndef ICMP6_MEMBERSHIP_QUERY
#define ICMP6_MEMBERSHIP_QUERY	      130  /* group membership query */
#define ICMP6_MEMBERSHIP_REPORT	      131  /* group membership report */
#define ICMP6_MEMBERSHIP_REDUCTION    132  /* group membership termination */
#endif /* ICMP6_MEMBERSHIP_QUERY */

#ifndef IPV6_PRIORITY_CONTROL
#define IPV6_PRIORITY_CONTROL          0x0700
#endif /* IPV6_PRIORITY_CONTROL */

#endif /* _API6_H */
#endif /* HAVE_IPV6 */

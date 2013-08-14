/*
 * $Id: igmp.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _IGMP_H
#define _IGMP_H

#include <mrt.h>

#ifdef HAVE_IGMP
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <net/route.h>
#include <netinet/igmp.h>
#undef MRT_VERSION
#ifdef HAVE_NETINET_IP_MROUTE_H
#include <netinet/ip_mroute.h>
#else
#ifdef linux
/* avoid conflicts */
#define _LINUX_IN_H
#include <linux/mroute.h>
#endif /* linux */
#endif /* HAVE_NETINET_IP_MROUTE_H */

/* at least, NetBSD puts the following in _KERNEL part */
#ifndef IGMPMSG_NOCACHE
struct igmpmsg {
    u_long          unused1;
    u_long          unused2;
    u_char          im_msgtype;                 /* what type of message     */
#define IGMPMSG_NOCACHE         1
#define IGMPMSG_WRONGVIF        2
    u_char          im_mbz;                     /* must be zero             */
    u_char          im_vif;                     /* vif rec'd on             */
    u_char          unused3;
    struct in_addr  im_src, im_dst;
};
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP IPPROTO_ENCAP
#ifndef IPPROTO_ENCAP
#define IPPROTO_ENCAP 4
#endif /* IPPROTO_ENCAP */
#endif /* IPPROTO_IPIP */
#endif /* IGMPMSG_NOCACHE */

#ifdef HAVE_IPV6
#ifdef WIDE_IPV6
#include <netinet6/ip6_mroute.h>
#endif /* WIDE_IPV6 */
#endif /* HAVE_IPV6 */

#ifndef IGMP_MEMBERSHIP_QUERY
#define IGMP_MEMBERSHIP_QUERY           0x11    /* membership query         */
#define IGMP_V1_MEMBERSHIP_REPORT       0x12    /* Ver. 1 membership report */
#define IGMP_V2_MEMBERSHIP_REPORT       0x16    /* Ver. 2 membership report */
#define IGMP_V2_LEAVE_GROUP             0x17    /* Leave-group message      */
   
#define IGMP_DVMRP                      0x13    /* DVMRP routing message    */
#define IGMP_PIM                        0x14    /* PIM routing message      */
 
#define IGMP_MTRACE_RESP                0x1e  /* traceroute resp.(to sender)*/
#define IGMP_MTRACE                     0x1f  /* mcast traceroute messages  */
#endif /* IGMP_MEMBERSHIP_QUERY */

#define IGMP_MAX_PDU		4096 /* v4 igmp and v6 icmp group */

#define	IGMP_ROBUSTNESS_VARIABLE		2
#define	IGMP_QUERY_INTERVAL			125
#define	IGMP_QUERY_RESPONSE_INTERVAL		10
#define	IGMP_GROUP_MEMBERSHIP_INTERVAL		\
	    (IGMP_ROBUSTNESS_VARIABLE * IGMP_QUERY_INTERVAL + \
					IGMP_QUERY_RESPONSE_INTERVAL)
#define	IGMP_OTHER_QUERIER_PRESENT_INTERVAL	\
	    (IGMP_ROBUSTNESS_VARIABLE * IGMP_QUERY_INTERVAL + \
					IGMP_QUERY_RESPONSE_INTERVAL / 2)
#define	IGMP_STARTUP_QUERY_INTERVAL	(IGMP_QUERY_INTERVAL / 4)
#define	IGMP_STARTUP_QUERY_COUNT		IGMP_ROBUSTNESS_VARIABLE
#define	IGMP_LAST_MEMBER_QUERY_INTERVAL		1
#define	IGMP_LAST_MEMBER_QUERY_COUNT		IGMP_ROBUSTNESS_VARIABLE

#define IGMPV6_TIMER_SCALE 1000

typedef int (*recv_call_fn_t) (interface_t *, u_long , prefix_t *,
                 	       int, u_char *, int);
typedef int (*recv_km_call_fn_t) (int, prefix_t *, prefix_t *, interface_t *, 
				  int);

#define IGMP_QUERIER 0x40000000  /* igmp querier */

#define MRTMSG_NOCACHE 	  1
#define MRTMSG_WRONGIF 	  2
#define MRTMSG_EXPIRE     3
#define MRTMSG_USAGE      4
#define MRTMSG_RESOLVE    5
#define MRTMSG_CACHE      6
#define MRTMSG_NEWMEMBER  7
#define MRTMSG_DELMEMBER  8
#define MRTMSG_UPDATE	  9
#define MRTMSG_TYPEMAX    9

typedef struct _igmp_info_t {
    u_long flags;
    interface_t *interface;
    HASH_TABLE *membership;             /* connected groups */
    mtimer_t *igmp_query_timer; 
    int igmp_query_count;
    prefix_t *igmp_querier_prefix; 
    mtimer_t *igmp_querier_timer;
    LINKED_LIST *ll_query_reqs;
} igmp_info_t;  
    

typedef struct _igmp_t {
    int proto;			/* PROTO_IGMP or PROTO_IGMPV6 */
    interface_bitset_t interface_mask;	/* mask of interfaces configed for */
    interface_bitset_t force_leaf_mask;	/* interfaces forced to be leaf */
    LINKED_LIST *ll_interfaces;	/* enabled igmp interface */
    HASH_TABLE *hash;		/* hash of prefixes */
    igmp_info_t *igmp_info[MAX_INTERFACES];
    trace_t *trace;
    int timer_scale;	/* timer scale is different in v4 and v6 */

    schedule_t *schedule;
    mtimer_t *timer;		/* timer used for sending update */
    mtimer_t *age;		/* aging routes */
    mtimer_t *flash;		/* flash update */

    int sockfd;
    prefix_t *all_hosts;
    prefix_t *all_routers;

    recv_km_call_fn_t recv_km_call_fn;
    recv_call_fn_t recv_dvmrp_call_fn;
    recv_call_fn_t recv_pim_call_fn;
} igmp_t;


typedef struct _igmp_group_t {  
    prefix_t *group;
    prefix_t *reporter;
    time_t ctime;	/* time received */
    int interval;	/* timeout interval since group specific query on
			   non-querier router sets different timeout value */
} igmp_group_t; 


extern igmp_t *IGMP;
#ifdef HAVE_IPV6
extern igmp_t *IGMPv6;
#endif /* HAVE_IPV6 */

int igmp_send (igmp_t *mrtigmp, prefix_t *dst, prefix_t *group, 
	       int type, int code, u_char *data, int datalen, 
	       interface_t *interface);

igmp_info_t *igmp_get_igmp_info (igmp_t *igmp, interface_t *interface);
int igmp_is_querier (igmp_t *igmp, interface_t *interface);
int igmp_init (int proto, trace_t * tr);
int igmp_interface (int proto, interface_t *interface, int on);
int igmp_show_group (uii_connection_t *uii);
#ifdef HAVE_IPV6
int igmp6_show_group (uii_connection_t *uii);
#endif /* HAVE_IPV6 */
#if defined(HAVE_MROUTING) || defined(HAVE_MROUTING6)
void kernel_mfc_request (int type, int family, void *dst, void *src, 
			 int index);
#endif /* HAVE_MROUTING || HAVE_MROUTING6 */
igmp_group_t *igmp_test_membership (prefix_t *group, interface_t *interface);

#if !defined(MRT_INIT) && defined(DVMRP_INIT)
#define MRT_INIT DVMRP_INIT
#define MRT_DONE DVMRP_DONE
#define MRT_ADD_VIF DVMRP_ADD_VIF
#define MRT_DEL_VIF DVMRP_DEL_VIF
#define MRT_ADD_MFC DVMRP_ADD_MFC
#define MRT_DEL_MFC DVMRP_DEL_MFC
#endif /* !MRT_INIT && DVMRP_INIT */

#include "cache.h"
#endif /* HAVE_IGMP */
#endif /* _IGMP_H */

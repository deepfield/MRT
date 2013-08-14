/*
 * $Id: igmp.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>
#ifdef HAVE_IGMP
#include <api6.h>
#include <igmp.h>
#include <pim.h>

igmp_t *IGMP;
#ifdef HAVE_IPV6
igmp_t *IGMPv6;

char *s_icmp_group [] = {
    "ICMP6_MEMBERSHIP_QUERY",
    "ICMP6_MEMBERSHIP_REPORT",
    "ICMP6_MEMBERSHIP_REDUCTION",
};
#endif /* HAVE_IPV6 */


char *s_igmp_type [] = {
    "IGMP_MEMBERSHIP_QUERY",
    "IGMP_V1_MEMBERSHIP_REPORT",
    "IGMP_DVMRP",
    "IGMP_PIM",
    "IGMP_CISCO_TRACE",
    "IGMP_V2_MEMBERSHIP_REPORT",
    "IGMP_V2_LEAVE_GROUP",
    "UNKNOWN (0x18)",
    "UNKNOWN (0x19)",
    "UNKNOWN (0x1a)",
    "UNKNOWN (0x1b)",
    "UNKNOWN (0x1c)",
    "UNKNOWN (0x1d)",
    "IGMP_MTRACE_RESP",
    "IGMP_MTRACE",
};

char *s_igmpmsg [] = {
    "UNKNOWN",
    "IGMPMSG_NOCACHE",
    "IGMPMSG_WRONGVIF",
};


igmp_info_t *
igmp_get_igmp_info (igmp_t *igmp, interface_t *interface)
{
    igmp_info_t *igmp_info;
    assert (igmp);
    assert (interface);
    if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
	return (NULL);
    assert (interface->index >= 0 && interface->index < MAX_INTERFACES);
    igmp_info = igmp->igmp_info[interface->index];
    assert (igmp_info);
    return (igmp_info);
}


int 
igmp_is_querier (igmp_t *igmp, interface_t *interface)
{
     igmp_info_t *igmp_info = igmp_get_igmp_info (igmp, interface);
     return (igmp_info && (igmp_info->flags & IGMP_QUERIER));
}


int 
igmp_send (igmp_t *mrtigmp, prefix_t *dst, prefix_t *group, int type, int code, 
	   u_char *data, int datalen, interface_t *interface)
{
    int ret = -1;
    u_char buffer[IGMP_MAX_PDU];
    prefix_t *source = NULL;
    int ip_in_ip = 0;
    prefix_t *realdst = dst;
    int ttl = MAXTTL;
    u_long flags = 0;
    int dst_is_mc;

    assert (dst);
    dst_is_mc = prefix_is_multicast (dst);

    if (interface) {
        /*
         * ipmulti kernel doesn't decapsulate unicasts.
         */
#ifdef HAVE_MROUTING
        if (dst_is_mc && BIT_TEST (interface->flags, IFF_VIF_TUNNEL)) {
	    ip_in_ip++;
	    source = interface->tunnel_source;
	    realdst = interface->tunnel_destination;
	    assert (source);
	}
#endif /* HAVE_MROUTING */
	if (mrtigmp->proto == PROTO_IGMP) {
            if (interface->primary)
	        source = interface->primary->prefix;
	}
	else {
#ifdef HAVE_IPV6
            if (interface->link_local)
	        source = interface->link_local->prefix;
#endif /* HAVE_IPV6 */
	}
    }

    if (dst_is_mc) {
	/* must have an interface */
	assert (interface);
	if (!ip_in_ip) {
#ifdef HAVE_IPV6
	    if (dst->family == AF_INET6) {
	        if (ICMP6_MEMBERSHIP_QUERY /* ||
	                prefix_compare2 (mrtigmp->all_hosts, dst) == 0 ||
	                prefix_compare2 (mrtigmp->all_routers, dst) == 0 */) {
	            flags |= MSG_MULTI_LOOP;
		}
	    }
	    else
#endif /* HAVE_IPV6 */
	    if (type == IGMP_DVMRP || type == IGMP_MEMBERSHIP_QUERY /* ||
	            prefix_compare2 (mrtigmp->all_hosts, dst) == 0 ||
	            prefix_compare2 (mrtigmp->all_routers, dst) == 0 */) {
	        flags |= MSG_MULTI_LOOP;
	    }
	}
    }

if (mrtigmp->proto == PROTO_IGMP) {
    struct igmp *igmphdr;
    struct ip *iphdr;

    iphdr = (struct ip *) buffer;
    if (ip_in_ip) {
        memset (iphdr, 0, sizeof (*iphdr));
	iphdr->ip_v   = IPVERSION;
    	iphdr->ip_hl  = sizeof (*iphdr) / 4;
    	iphdr->ip_tos = 0xc0;          /* Internet Control */
    	iphdr->ip_off = 0;		    /* no fragments */
    	iphdr->ip_ttl = MAXTTL;        /* applies to unicasts only */
    	iphdr->ip_p   = IPPROTO_IPIP;
    	iphdr->ip_src.s_addr = prefix_tolong (source);
    	iphdr->ip_dst.s_addr = prefix_tolong (realdst);
    	iphdr->ip_len = 2 * sizeof (*iphdr) + sizeof (*igmphdr) + datalen;
#ifdef __linux__
    	iphdr->ip_len = htons (iphdr->ip_len);
#endif /* __linux__ */
	iphdr++;
    }

    memset (iphdr, 0, sizeof (*iphdr));
    /* These may not be required for raw socket */
    iphdr->ip_v = IPVERSION;
    iphdr->ip_hl = sizeof (*iphdr) / 4;
    iphdr->ip_tos = 0xc0;	/* icmp */
    iphdr->ip_off = 0;	/* no fragments */

    iphdr->ip_p = IPPROTO_IGMP;
    iphdr->ip_src.s_addr = (source)? prefix_tolong (source): INADDR_ANY;
    iphdr->ip_dst.s_addr = prefix_tolong (dst);
    iphdr->ip_len = sizeof (*iphdr) + sizeof (*igmphdr) + datalen;
#ifndef __linux__
    if (ip_in_ip)
#endif /* __linux__ */
    iphdr->ip_len = htons (iphdr->ip_len);
    iphdr->ip_id = 0; /* leave it to the kernel */
    iphdr->ip_sum = 0; /* leave it to the kernel */
    iphdr->ip_ttl = ttl;

    if (ip_in_ip) {
	static int ip_id = 1; /* XXX */
	iphdr->ip_id = htons (ip_id++);
	iphdr->ip_sum = 0;
	iphdr->ip_sum = inet_cksum (iphdr, iphdr->ip_hl * 4);
	assert (inet_cksum (iphdr, iphdr->ip_hl * 4) == 0);
    }
    iphdr++;

    igmphdr = (struct igmp *) iphdr;
    memset (igmphdr, 0, sizeof (*igmphdr));
    igmphdr->igmp_type = type;
    igmphdr->igmp_code = code;
    if (group)
        igmphdr->igmp_group.s_addr = prefix_tolong (group);
    else
        igmphdr->igmp_group.s_addr = 0;
    igmphdr->igmp_cksum = 0;

    assert (datalen == 0 || data != NULL);
    if (datalen > 0) {
	assert ((u_char *)(igmphdr + 1) + datalen - buffer <= sizeof (buffer));
	memcpy (igmphdr + 1, data, datalen);
    }
    igmphdr->igmp_cksum = inet_cksum (igmphdr, sizeof (*igmphdr) + datalen);
    assert (inet_cksum (igmphdr, sizeof (*igmphdr) + datalen) == 0);

    if ((ret = send_packet (mrtigmp->sockfd, buffer, 
			    (u_char *)(igmphdr + 1) - buffer + datalen, 
			    flags, realdst, 0,
			    interface, 0)) >= 0)
        trace (TR_PACKET, mrtigmp->trace,
	       "send %s for %s to %a on %s\n", 
	       s_igmp_type[type - IGMP_MEMBERSHIP_QUERY],
	       (group)?prefix_toa (group):"general", realdst, 
	       (interface)? interface->name: "?");
}
#ifdef HAVE_IPV6
else {
    struct icmp6_hdr *icmp6;

    icmp6 = (struct icmp6_hdr *) buffer;
    memset (icmp6, 0, sizeof (*icmp6));
    icmp6->icmp6_type = type;
    icmp6->icmp6_maxdelay = htons (code); /* code is delay */
    icmp6->icmp6_code = 0;
    assert (datalen == 0 || data != NULL);
    if (group)
       memcpy (icmp6 + 1, prefix_tochar (group), 16);
    else
       memset (icmp6 + 1, 0, 16);
    if (datalen > 0)
	memcpy ((char *)(icmp6 + 1) + 16, data, datalen);
    icmp6->icmp6_cksum = 0;

    if ((ret = send_packet (mrtigmp->sockfd, buffer, 
			    sizeof (*icmp6) + 16 + datalen, 
			    flags, realdst, 0,
			    interface, IPV6_PRIORITY_CONTROL)) >= 0)
        trace (TR_PACKET, mrtigmp->trace,
	       "send %s for %s to %a on %s\n", 
	       s_icmp_group[type - ICMP6_MEMBERSHIP_QUERY],
	       (group)?prefix_toa (group):"general", realdst, 
	       (interface)? interface->name: "?");
}
#endif /* HAVE_IPV6 */
    return (ret);
}


static igmp_group_t *
igmp_membership_report (igmp_t *igmp, interface_t *interface, prefix_t *group, 
			prefix_t *reporter)
{
    igmp_info_t *igmp_info;
    igmp_group_t *igmp_group;

    igmp_info = igmp_get_igmp_info (igmp, interface);

    if ((igmp_group = HASH_Lookup (igmp_info->membership, group)) == NULL) {
	igmp_group = New (igmp_group_t);
	igmp_group->group = Ref_Prefix (group);
	HASH_Insert (igmp_info->membership, igmp_group);
	trace (TR_TRACE, igmp->trace, "group %a on %s joined\n", 
	       group, interface->name);
	if (igmp->recv_km_call_fn)
            igmp->recv_km_call_fn (MRTMSG_NEWMEMBER, group, reporter, 
				   interface, 0);
    }
    else {
	trace (TR_TRACE, igmp->trace, "group %a on %s updated\n",
	       group, interface->name);
        assert (igmp_group->reporter);
        Deref_Prefix (igmp_group->reporter);
     }
    igmp_group->reporter = Ref_Prefix (reporter);
    time (&igmp_group->ctime);
    igmp_group->interval = IGMP_GROUP_MEMBERSHIP_INTERVAL;
    return (igmp_group);
}


static int
igmp_send_group_query (igmp_t *igmp, interface_t *interface, prefix_t *group)
{
    assert (igmp);
    assert (interface);
    assert (group);
#ifdef HAVE_IPV6
    if (igmp->proto == PROTO_IGMPV6)
        return (igmp_send (igmp, group, group, 
	               ICMP6_MEMBERSHIP_QUERY,
		       IGMP_LAST_MEMBER_QUERY_INTERVAL * igmp->timer_scale,
                       NULL, 0, interface));
    else
#endif /* HAVE_IPV6 */
    return (igmp_send (igmp, group, group, 
	               IGMP_MEMBERSHIP_QUERY,
		       IGMP_LAST_MEMBER_QUERY_INTERVAL * igmp->timer_scale,
                       NULL, 0, interface));
}


typedef struct _igmp_query_req_t {
    prefix_t *group;
    mtimer_t *timer;
    int count;
} igmp_query_req_t;


static void
destroy_igmp_query_req (igmp_query_req_t *qreq)
{
    assert (qreq);
    Deref_Prefix (qreq->group);
    Destroy_Timer (qreq->timer);
    Delete (qreq);
}


static void
igmp_timer_group_query (igmp_t *igmp, interface_t *interface, 
			igmp_query_req_t *qreq)
{
    assert (igmp);
    assert (interface);
    assert (qreq);

    if (--qreq->count >= 0) {
        igmp_send_group_query (igmp, interface, qreq->group);
	if (qreq->count == 0)
	    Timer_Set_Time (qreq->timer, IGMP_LAST_MEMBER_QUERY_INTERVAL);
    }
    else {
	igmp_info_t *igmp_info = igmp_get_igmp_info (igmp, interface);
	igmp_group_t *igmp_group;

	Timer_Turn_OFF (qreq->timer);
	/* make sure there is one */
	igmp_group = HASH_Lookup (igmp_info->membership, qreq->group);
	if (igmp_group != NULL) {
	    HASH_Remove (igmp_info->membership, igmp_group);
	    trace (TR_TRACE, igmp->trace, "group %a on %s left\n", 
	           qreq->group, interface->name);
	    if (igmp->recv_km_call_fn)
                igmp->recv_km_call_fn (MRTMSG_DELMEMBER, qreq->group, NULL, 
				       interface, 0);
	}
	else {
	    trace (TR_ERROR, igmp->trace, 
		   "group %a on %s not found after the last query\n", 
	           qreq->group, interface->name);
	}
	/* we need to remove this here from the linked list */
	LL_Remove (igmp_info->ll_query_reqs, qreq);
    }
}


static void
igmp_leave_group (igmp_t *igmp, interface_t *interface, prefix_t *group, 
		  prefix_t *reporter)
{
    igmp_info_t *igmp_info = igmp_get_igmp_info (igmp, interface);
    igmp_group_t *igmp_group;
    int count;

    if (!BIT_TEST (igmp_info->flags, IGMP_QUERIER))
	return;

    igmp_group = HASH_Lookup (igmp_info->membership, group);
    if (igmp_group == NULL) {
	trace (TR_WARN, igmp->trace, "no group record for %a on %s\n", 
	       group, interface->name);
	return;
    }

    count = IGMP_LAST_MEMBER_QUERY_COUNT;
    igmp_send_group_query (igmp, interface, group);

    if (--count > 0) {
	mtimer_t *timer;
	igmp_query_req_t *qreq;

	qreq = New (igmp_query_req_t);
	timer = New_Timer2 ("igmp querier timer", 
			    IGMP_LAST_MEMBER_QUERY_INTERVAL, 0, 
			    igmp->schedule, igmp_timer_group_query, 
			    3, igmp, interface, qreq);
	/* group prefix has to be preserved until all queries are sent */
	qreq->group = Ref_Prefix (group);
	qreq->timer = timer;
	qreq->count = count;
	LL_Add (igmp_info->ll_query_reqs, qreq);
	Timer_Turn_ON (timer);
    }
}


static void
igmp_membership_query (igmp_t *igmp, interface_t *interface, 
		       prefix_t *group, prefix_t *source, int max_resp_time)
{
    igmp_group_t *igmp_group;
    igmp_info_t *igmp_info = igmp_get_igmp_info (igmp, interface);
    int result;

	assert (igmp_info);
        assert (igmp_info->igmp_querier_prefix);

	result = prefix_compare2 (igmp_info->igmp_querier_prefix, source);
	if (result == 0) {
	    Timer_Reset_Time (igmp_info->igmp_querier_timer);
	    trace (TR_INFO, igmp->trace, "update querier %a on %s\n", 
		   source, interface->name);
	}
	else if (result > 0) {
	    /* this querier has lower ip address than the current */
	    Timer_Reset_Time (igmp_info->igmp_querier_timer);
	    /* timeout might be happened and queued XXX */
	    trace (TR_INFO, igmp->trace, 
		   "change querier to %a from %a on %s\n", 
		   source, 
		   igmp_info->igmp_querier_prefix, 
		   interface->name);
	    Deref_Prefix (igmp_info->igmp_querier_prefix);
	    igmp_info->igmp_querier_prefix = Ref_Prefix (source);
    	    if (BIT_TEST (igmp_info->flags, IGMP_QUERIER)) {
    	        BIT_RESET (igmp_info->flags, IGMP_QUERIER);
		/* don't make it off during startup stage,
		   although I'm not sure RFC requires this */
		if (igmp_info->igmp_query_count >= IGMP_STARTUP_QUERY_COUNT)
		    Timer_Turn_OFF (igmp_info->igmp_query_timer);
	    }
	}
	else {
	    trace (TR_INFO, igmp->trace, "neglect querier %a on %s\n", 
		   source, interface->name);
	}

	if (!BIT_TEST (interface->flags, IGMP_QUERIER) && group != NULL) {
	    igmp_group = HASH_Lookup (igmp_info->membership, group);
	    if (igmp_group != NULL && igmp_group->ctime > 0) {
		time_t now, newt, left;

		time (&now);
		newt = IGMP_LAST_MEMBER_QUERY_COUNT 
			* max_resp_time / igmp->timer_scale;
		if (now + newt < igmp_group->ctime + igmp_group->interval) {
		    igmp_group->interval = now + newt - igmp_group->ctime;
		    left = time_left (igmp->age);
#define IGMP_MIN_TIMEOUT_INTERVAL 5
		    if (left >= IGMP_MIN_TIMEOUT_INTERVAL && left > newt)
    		        Timer_Set_Time (igmp->age, newt);
		}
	    }
	}
}


void
igmp_receive (igmp_t *igmp)
{
    u_char buffer[IGMP_MAX_PDU], *cp = buffer;
    int len;
    int type, delay, code;
    prefix_t *source = NULL;
    prefix_t *group = NULL;
    interface_t *interface = NULL;

    assert (igmp);
if (igmp->proto == PROTO_IGMP) {
    struct ip *ip;
    int hlen;
    struct igmp *igmp2;

    assert (igmp == IGMP);
    /* kernel sends an igmp-like packet to routing daemon 
       but it doesn't provide incoming interface info */
    len = recvmsgfrom (igmp->sockfd, buffer, sizeof (buffer), 
		       O_NONBLOCK|MSG_MAYIGMP, &source, NULL, &interface,
		       NULL, NULL);
    select_enable_fd_mask (igmp->sockfd, SELECT_READ);
    if (len <= 0)
	goto ignore;

    assert (source);

#ifdef HAVE_MROUTING
    if (((struct ip *) cp)->ip_p == 0) {
	struct igmpmsg *msg = (struct igmpmsg *) cp;
	int type = MRTMSG_NOCACHE;

	if (msg->im_msgtype != IGMPMSG_NOCACHE &&
	    msg->im_msgtype != IGMPMSG_WRONGVIF) {
            trace (TR_WARN, igmp->trace,
                   "recv kernel message from %a len %d (unknown type %d)\n",
                   source, len, msg->im_msgtype);
	    goto ignore;
	}
	if (msg->im_msgtype == IGMPMSG_WRONGVIF) {
	    type = MRTMSG_WRONGIF;
	    if (INTERFACE_MASTER->vindex2if[msg->im_vif] == NULL) {
                trace (TR_WARN, igmp->trace,
                       "recv kernel message from %a len %d (unknown vif %d)\n",
                       source, len, msg->im_vif);
	        goto ignore;
	    }
	}
	kernel_mfc_request (type, AF_INET, &msg->im_dst, &msg->im_src, 
			   (msg->im_msgtype != IGMPMSG_NOCACHE)? 
			    msg->im_vif: -1);
	goto ignore;
    }
#endif /* HAVE_MROUTING */

    assert (interface);

    ip = (struct ip *) cp;
    if (ip->ip_v != IPVERSION) {
        trace (TR_WARN, igmp->trace,
               "packet from %a on %s len %d (first byte 0x%x)"
	       " is not an IP packet, trying icmp\n",
               source, interface->name, len, *cp);
	goto icmp_test;
    }
    hlen = ip->ip_hl * 4;
#ifdef __linux__
    /* ignore received len */
    len = ntohs (ip->ip_len) - hlen;
#else
#ifndef sun
    if (len != hlen + ip->ip_len) {
        trace (TR_TRACE, igmp->trace,
               "packet from %a on %s expected len %d+%d but %d\n",
               source, interface->name, 
	       hlen, ip->ip_len, len);
	goto ignore;
    }
#endif /* sun */
    len -= hlen;
#endif /* __linux__ */
    cp += hlen;

icmp_test:
    igmp2 = (struct igmp *) cp;

    if (inet_cksum (igmp2, len)) {
        trace (TR_WARN, igmp->trace,
               "packet from %a on %s len %d bad igmp checksum\n",
               source, interface->name, len); 
        goto ignore;
    }

    if (igmp2->igmp_type < IGMP_MEMBERSHIP_QUERY || 
	    igmp2->igmp_type > IGMP_MTRACE) {
	trace (TR_WARN, igmp->trace,
	       "recv unsupported type %d from %a on %s len %d, ignore!\n",
	       igmp2->igmp_type, source, interface->name, len);
	goto ignore;
    }

    type = igmp2->igmp_type;
    code = delay = igmp2->igmp_code;
    if (igmp2->igmp_group.s_addr != 0)
        group = New_Prefix (AF_INET, &igmp2->igmp_group, 32);

    trace (TR_PACKET, igmp->trace,
	   "recv %s for %s from %a on %s len %d\n", 
	   s_igmp_type[type - IGMP_MEMBERSHIP_QUERY],
	   (group)?prefix_toa (group):"general", source, 
	   interface->name, len);

    switch (type) {
    case IGMP_V1_MEMBERSHIP_REPORT:
    case IGMP_V2_MEMBERSHIP_REPORT:
    case IGMP_MEMBERSHIP_QUERY:
    case IGMP_V2_LEAVE_GROUP:
        if (!BITX_TEST (&igmp->interface_mask, interface->index)) {
            trace (TR_WARN, igmp->trace,
                   "packet from %a len %d on disabled interface %s\n",
                   source, len, interface->name);         
            goto ignore;
        }
	break;
    case IGMP_DVMRP:
    case IGMP_PIM:
    case IGMP_MTRACE_RESP:
    case IGMP_MTRACE:
    default:
	break;
    }

    switch (type) {
    case IGMP_V1_MEMBERSHIP_REPORT:
    case IGMP_V2_MEMBERSHIP_REPORT:
	igmp_membership_report (igmp, interface, group, source);
	break;
    case IGMP_MEMBERSHIP_QUERY:
	if (delay == 0) {
	    /* igmp version 1 query */
    	    trace (TR_ERROR, igmp->trace, 
		   "won't work with igmp version 1 router %a on %s\n",
	   	   source, interface->name);
	    break;
	}
	igmp_membership_query (igmp, interface, group, source, delay);
	break;
    case IGMP_V2_LEAVE_GROUP:
	igmp_leave_group (igmp, interface, group, source);
	break;
    case IGMP_DVMRP:
	if (igmp->recv_dvmrp_call_fn)
	    igmp->recv_dvmrp_call_fn (interface, ntohl (prefix_tolong (group)), 
			     source, code,
			     (u_char *) (igmp2 + 1), len - sizeof (*igmp2));
	break;
    case IGMP_PIM:
	if (igmp->recv_pim_call_fn)
	    igmp->recv_pim_call_fn (interface, ntohl (prefix_tolong (group)), 
			   source, code,
			   (u_char *) (igmp2 + 1), len - sizeof (*igmp2));
	break;
    case IGMP_MTRACE_RESP:
    case IGMP_MTRACE:
    default:
	break;
    }
}
#ifdef HAVE_IPV6
else if (igmp->proto == PROTO_IGMPV6) {
#ifndef WIDE_IPV6
    struct ip6_hdr *ipv6;
#endif /* WIDE_IPV6 */
    struct icmp6_hdr *icmp6;
    u_long flags = O_NONBLOCK;

#ifdef WIDE_IPV6
    flags |= MSG_MAYIGMP;
#endif /* WIDE_IPV6 */
    assert (igmp == IGMPv6);
    len = recvmsgfrom (igmp->sockfd, buffer, sizeof (buffer), flags,
		       &source, NULL, &interface, NULL, NULL);
    select_enable_fd_mask (igmp->sockfd, SELECT_READ);
    if (len <= 0)
	goto ignore;

#ifdef HAVE_MROUTING6
#ifdef WIDE_IPV6
    if (sizeof (struct mrt6msg) == len &&
        ((struct mrt6msg *) cp)->im6_mbz == 0) {
	struct mrt6msg *msg = (struct mrt6msg *) cp;
	int type = MRTMSG_NOCACHE;

	if (msg->im6_msgtype != MRT6MSG_NOCACHE &&
	    msg->im6_msgtype != MRT6MSG_WRONGMIF) {
            trace (TR_WARN, igmp->trace,
                   "recv kernel message from %a len %d (unknown type %d)\n",
                   source, len, msg->im6_msgtype);
	    goto ignore;
	}
	if (msg->im6_msgtype == MRT6MSG_WRONGMIF)
	    type = MRTMSG_WRONGIF;
	kernel_mfc_request (type, AF_INET6, &msg->im6_dst, &msg->im6_src, 
			    msg->im6_mif);
	goto ignore;
    }
#endif /* WIDE_IPV6 */
#endif /* HAVE_MROUTING6 */

    assert (source);
    assert (interface);

    if (!BITX_TEST (&igmp->interface_mask, interface->index)) {
        trace (TR_WARN, igmp->trace,
               "packet from %a len %d on disabled interface %s\n", 
               source, len, interface->name);         
        goto ignore;
    }

#ifndef WIDE_IPV6
    /* in case an IPv6 header is included */
    ipv6 = (struct ip6_hdr *) cp;
    if ((ipv6->ip6_vfc >> 4) != IPNGVERSION) {
        trace (TR_WARN, igmp->trace,
               "packet from %a on %s len %d (ip6_vfc 0x%x)"
	       " is not an IPv6 packet, trying icmp\n",
               source, interface->name, len, ipv6->ip6_vfc);
	goto icmp6_test;
    }
    /* the kernel already converted it into host oder */
#ifdef __linux__
    ipv6->ip6_plen = ntohs (ipv6->ip6_plen);
#endif /* __linux__ */
#ifndef sun
    if (len != sizeof (*ipv6) + ipv6->ip6_plen) {
        trace (TR_WARN, igmp->trace,
               "packet from %a on %s expected len %d+%d but %d\n",
               source, interface->name, 
	       sizeof (*ipv6), ipv6->ip6_plen, len);
	/* goto ignore; */
    }
#endif /* sun */
    if (ipv6->ip6_nxt != IPPROTO_ICMPV6) {
        trace (TR_WARN, igmp->trace,
               "packet from %a on %s len %d with next header %d\n",
               source, interface->name, len, ipv6->ip6_nxt);
	goto ignore;
    }

    /* destroy ip header to make pseudo one */
    ipv6->ip6_hlim = ipv6->ip6_nxt;
    ipv6->ip6_nxt = 0;
    ipv6->ip6_vfc = 0;
    ipv6->ip6_flow = 0;
    ipv6->ip6_plen = htons (ipv6->ip6_plen);

    if (inet_cksum (ipv6, sizeof (*ipv6) + ntohs (ipv6->ip6_plen))) {
        trace (TR_WARN, igmp->trace,
               "packet from %a on %s len %d bad icmp checksum\n",
               source, interface->name, len); 
        goto ignore;
    }
    cp = (u_char *)(ipv6 + 1);
    len -= sizeof (*ipv6);
icmp6_test:
#endif /* WIDE_IPV6 */

    if (len < sizeof (*icmp6)) {
        trace (TR_WARN, igmp->trace,
               "packet from %a on %s wrong len %d\n",
               source, interface->name, len);
	goto ignore;
    }

    icmp6 = (struct icmp6_hdr *)cp;
    cp += sizeof (*icmp6);
    type = icmp6->icmp6_type;
    delay = ntohs (icmp6->icmp6_maxdelay);
    code = icmp6->icmp6_code;

    if (type < ICMP6_MEMBERSHIP_QUERY || type > ICMP6_MEMBERSHIP_REDUCTION ||
	    code != 0) {
        trace (TR_WARN, igmp->trace,
               "packet from %a on %s len %d bad icmp type (%d) or code (%d)\n",
               source, interface->name, len, type, code);
        goto ignore;
    }

    group = New_Prefix (AF_INET6, cp, 128);
    trace (TR_TRACE, igmp->trace,
               "recv %s for %a from %a on %s len %d\n",
               s_icmp_group[type - ICMP6_MEMBERSHIP_QUERY],
	       group, source, interface->name, len);

        if (!BITX_TEST (&igmp->interface_mask, interface->index)) {
            trace (TR_WARN, igmp->trace,
                   "packet from %a len %d on disabled interface %s\n",
                   source, len, interface->name);         
            goto ignore;
	}

    switch (type) {
    case ICMP6_MEMBERSHIP_QUERY:
	igmp_membership_query (igmp, interface, group, source, delay);
	break;
    case ICMP6_MEMBERSHIP_REPORT:
	igmp_membership_report (igmp, interface, group, source);
	break;
    case ICMP6_MEMBERSHIP_REDUCTION:
	igmp_leave_group (igmp, interface, group, source);
	break;
    default:
	assert (0);
	break;
    }
}
#endif /* HAVE_IPV6 */
else {
    assert (0);
    return;
}

  ignore:
    if (source)
	Deref_Prefix (source);
    if (group)
	Deref_Prefix (group);
}


static void
igmp_timeout_groups (igmp_t *igmp)
{
    interface_t *interface;
    time_t now, nexttime, t;

    time (&now);
    nexttime = now + IGMP_GROUP_MEMBERSHIP_INTERVAL;

    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
	igmp_info_t *igmp_info;
        igmp_group_t *igmp_group;

	if (!BITX_TEST (&igmp->interface_mask, interface->index))
	    continue;
	if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
	    continue;
	igmp_info = igmp_get_igmp_info (igmp, interface);
	HASH_Iterate (igmp_info->membership, igmp_group) {
	loop:
	    if (igmp_group->ctime > 0 /* timeout on */ &&
		now - igmp_group->ctime >= igmp_group->interval) {
		 /* deleteing a hash item while looping */
	        igmp_group_t *next = HASH_GetNext (igmp_info->membership, 
						   igmp_group);
		HASH_Remove (igmp_info->membership, igmp_group);
		if (next == NULL)
		    break;
		igmp_group = next;
		goto loop;
	    }
	    else if ((t = igmp_group->ctime + igmp_group->interval)
			< nexttime) {
		nexttime = t;
	    }
	
	}
    }
    if ((t = nexttime - now) <= 0) 
        t = IGMP_MIN_TIMEOUT_INTERVAL;   /* don't want so strict? */
    Timer_Set_Time (igmp->age, t);
    Timer_Turn_ON (igmp->age);
}


/*
 * initialize igmp stuff
 */
int
igmp_init (int proto, trace_t * tr)
{
    igmp_t *igmp;
    char *name = "IGMP";
    char *igmp_all_hosts = "224.0.0.1";
    char *igmp_all_routers = "224.0.0.2";
    int timer_scale = IGMP_TIMER_SCALE;

    igmp = New (igmp_t);
#ifdef HAVE_IPV6
    if (proto == PROTO_IGMPV6) {
	IGMPv6 = igmp;
	name = "IGMPv6";
        igmp_all_hosts = "ff02::1";
        igmp_all_routers = "ff02::2";
        timer_scale = IGMPV6_TIMER_SCALE;
    }
    else
#endif /* HAVE_IPV6 */
    IGMP = igmp;
    igmp->trace = trace_copy (tr);
    igmp->proto = proto;
    igmp->sockfd = -1;
    igmp->all_hosts = ascii2prefix (0, igmp_all_hosts);
    igmp->all_routers = ascii2prefix (0, igmp_all_routers);
    igmp->timer_scale = timer_scale;

    set_trace (igmp->trace, TRACE_PREPEND_STRING, name, 0);
    igmp->schedule = New_Schedule (name, igmp->trace);
    igmp->ll_interfaces = LL_Create (0);
    memset (&igmp->interface_mask, 0, sizeof (igmp->interface_mask));

    igmp->age = New_Timer2 ("igmp aging timer", 
			   IGMP_GROUP_MEMBERSHIP_INTERVAL,
                           TIMER_ONE_SHOT, igmp->schedule,
                           igmp_timeout_groups, 1, igmp);

    mrt_thread_create2 (name, igmp->schedule, NULL, NULL);
    return (1);
}



static void
igmp_start (int proto)
{
    igmp_t *igmp = IGMP;
    int sockfd;

#ifdef HAVE_IPV6
    if (proto == PROTO_IGMPV6) {
	igmp = IGMPv6;
        sockfd = socket_open (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (sockfd > 0) {
#ifdef ICMP6_FILTER
	    struct icmp6_filter filt;
#endif /* ICMP6_FILTER */

    	    socket_reuse (sockfd, 1);
	    /* it's hard to get check sum 
	       because of source address selection */
	    ip_hdrincl (sockfd, 0);
	    /* on INRIA IPV6, ipv6 header is included on reception of icmp */
    	    ipv6_multicast_loop (sockfd, 0);
	    ipv6_pktinfo (sockfd, 1);
	    ipv6_recvhops (sockfd, 1);
	    ipv6_multicast_hops (sockfd, 1);

#ifdef ICMP6_FILTER
	    ICMP6_FILTER_SETBLOCKALL (&filt);
	    ICMP6_FILTER_SETPASS (ICMP6_MEMBERSHIP_QUERY, &filt);
            ICMP6_FILTER_SETPASS (ICMP6_MEMBERSHIP_REPORT, &filt);
            ICMP6_FILTER_SETPASS (ICMP6_MEMBERSHIP_REDUCTION, &filt);
	    icmp6_filter (sockfd, &filt);
#endif /* ICMP6_FILTER */
	}
    }
    else
#endif /* HAVE_IPV6 */
    if (proto == PROTO_IGMP) {
        sockfd = socket_open (AF_INET, SOCK_RAW, IPPROTO_IGMP);
        if (sockfd > 0) {
    	    socket_reuse (sockfd, 1);
	    ip_hdrincl (sockfd, 1);
    	    ip_multicast_loop (sockfd, 0);
	    ip_pktinfo (sockfd, 1);
	    ip_recvttl (sockfd, 1);
        }
    }
    else {
	assert (0);
	return;
    }

    if (sockfd < 0) {
	trace (TR_ERROR, igmp->trace, "aborted due to error(s)\n");
	return;
    }
    Timer_Turn_ON (igmp->age);
    select_add_fd_event ("igmp_receive", sockfd, SELECT_READ, 1,
                         igmp->schedule, igmp_receive, 1, igmp);
    igmp->sockfd = sockfd;

#ifdef HAVE_MROUTING
    if (proto == PROTO_IGMP) {
	int version;
        /* mc_init() and other functions expect IGMP->sockfd opened */
        mc_mrtinit ();
        if ((version = mc_mrtversion ()) >= 0)
            trace (TR_INFO, igmp->trace, "MRT version: %x\n", version);
    }
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
    if (proto == PROTO_IGMPV6) {
	mc6_mrtinit ();
    }
#endif /* HAVE_MROUTING6 */
}


static void
igmp_stop (int proto)
{
    igmp_t *igmp = NULL;

    if (proto == PROTO_IGMP) {
        igmp = IGMP;
#ifdef HAVE_MROUTING
        mc_mrtdone ();
#endif /* HAVE_MROUTING */
    }
#ifdef HAVE_IPV6
    if (proto == PROTO_IGMPV6) {
	igmp = IGMPv6;
#ifdef HAVE_MROUTING6
        mc6_mrtdone ();
#endif /* HAVE_MROUTING6 */
    }
#endif /* HAVE_IPV6 */
    assert (igmp);

    if (igmp->sockfd >= 0) {
	trace (TR_INFO, igmp->trace, "Closing scoket %d\n", igmp->sockfd);
	select_delete_fdx (igmp->sockfd);
	igmp->sockfd = -1;
    }

    Timer_Turn_OFF (igmp->age);
    clear_schedule (igmp->schedule);
    LL_Clear (igmp->ll_interfaces);
    memset (&igmp->interface_mask, 0, sizeof (igmp->interface_mask));
}


int
igmp_send_query (igmp_t *igmp, interface_t *interface)
{
#ifdef HAVE_IPV6
    if (igmp->proto == PROTO_IGMPV6) {
        return (igmp_send (igmp, igmp->all_hosts, NULL, ICMP6_MEMBERSHIP_QUERY,
                           IGMP_MAX_HOST_REPORT_DELAY * igmp->timer_scale,
                           NULL, 0, interface));
    }
    else
#endif /* HAVE_IPV6 */
    return (igmp_send (igmp, igmp->all_hosts, NULL, IGMP_MEMBERSHIP_QUERY,
                       IGMP_MAX_HOST_REPORT_DELAY * igmp->timer_scale,
                       NULL, 0, interface));
}


static void
igmp_querier_timeout (igmp_t *igmp, interface_t *interface)
{
    igmp_info_t *igmp_info = igmp_get_igmp_info (igmp, interface);

    /* this happens when a querier was chosen after timer fired */
    /* timer is running */
    if (igmp_info->igmp_querier_timer->time_next_fire > 0)
	return;
    trace (TR_INFO, igmp->trace, "timed out querier %a on %s\n", 
	   igmp_info->igmp_querier_prefix, interface->name);
    Deref_Prefix (igmp_info->igmp_querier_prefix);
#ifdef HAVE_IPV6
    if (igmp->proto == PROTO_IGMPV6) {
        assert (interface->link_local);
        igmp_info->igmp_querier_prefix = 
	    Ref_Prefix (interface->link_local->prefix);
    }
    else
#endif /* HAVE_IPV6*/
    igmp_info->igmp_querier_prefix = Ref_Prefix (interface->primary->prefix);
    BIT_SET (igmp_info->flags, IGMP_QUERIER);
    Timer_Turn_ON (igmp_info->igmp_query_timer);
    trace (TR_INFO, igmp->trace, "new querier %a on %s\n", 
	   igmp_info->igmp_querier_prefix, 
	   interface->name);
    ++igmp_info->igmp_query_count /* just for information */;
    igmp_send_query (igmp, interface);
}


static int
igmp_show_m_group (igmp_t *igmp, uii_connection_t *uii)
{
    interface_t *interface;
    igmp_info_t *igmp_info;
    igmp_group_t *igmp_group;
    char date[MAXLINE];
    time_t now;

    time (&now);
    uii_add_bulk_output (uii, "%-20s %5s %8s %s\n", 
		"Group Address", "If", "Timeleft", "Last Reporter");
    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
	if (!BITX_TEST (&igmp->interface_mask, interface->index))
	    continue;
	if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
	    continue;
	igmp_info = igmp_get_igmp_info (igmp, interface);
        HASH_Iterate (igmp_info->membership, igmp_group) {
	    uii_add_bulk_output (uii, "%-20a %5s %8s %a\n",
		    igmp_group->group, interface->name,
		    etime2ascii (igmp_group->ctime + igmp_group->interval
				 - now, date),
		    igmp_group->reporter);
	}
    }
    uii_add_bulk_output (uii, "%-20s %5s %8s %s\n", 
		"Group Address", "If", "Timeleft", "Current Querier");
    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
	if (!BITX_TEST (&igmp->interface_mask, interface->index))
	    continue;
	if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
	    continue;
	igmp_info = igmp_get_igmp_info (igmp, interface);
	if (igmp_info->igmp_querier_prefix) {
	    uii_add_bulk_output (uii, "%-20s %5s %8s %a\n",
				"QUERIER", interface->name, 
			(igmp_info->igmp_querier_timer->time_next_fire > 0)?
				etime2ascii (time_left (
				    igmp_info->igmp_querier_timer), date):
				"----",
				igmp_info->igmp_querier_prefix);
	}
    }
    return (1);
}


int
igmp_show_group (uii_connection_t *uii)
{
    return (igmp_show_m_group (IGMP, uii));
}


#ifdef HAVE_IPV6
int
igmp6_show_group (uii_connection_t *uii)
{
    return (igmp_show_m_group (IGMPv6, uii));
}
#endif /* HAVE_IPV6 */


static void
igmp_delete_group (igmp_group_t *igmp_group)
{
    Deref_Prefix (igmp_group->group);
    Deref_Prefix (igmp_group->reporter);
    Delete (igmp_group);
}


static void
igmp_make_query (igmp_t *igmp, interface_t *interface)
{
    igmp_info_t *igmp_info = igmp_get_igmp_info (igmp, interface);

    if (igmp_info->igmp_query_timer == NULL)
	return;
    if (igmp_info->igmp_query_timer->time_next_fire <= 0)
	return;
    igmp_send_query (igmp, interface);
    if (++igmp_info->igmp_query_count >= IGMP_STARTUP_QUERY_COUNT) {
        Timer_Set_Time (igmp_info->igmp_query_timer, 
			IGMP_QUERY_INTERVAL);
	if (!BIT_TEST (igmp_info->flags, IGMP_QUERIER))
            Timer_Turn_OFF (igmp_info->igmp_query_timer);
    }
}


/*
 * turn on/off the interface
 */
int
igmp_interface (int proto, interface_t *interface, int on)
{
    igmp_t *igmp = IGMP;

#ifdef HAVE_IPV6
    if (proto == PROTO_IGMPV6)
	igmp = IGMPv6;
    else
#endif /* HAVE_IPV6 */

    if (proto == PROTO_IGMP) {
	if (!BIT_TEST (interface->flags, IFF_VIF_TUNNEL) &&
		interface->primary == NULL)
	    return (-1);
    }

#ifdef HAVE_IPV6
    if (proto == PROTO_IGMPV6) {
	if (!BIT_TEST (interface->flags, IFF_VIF_TUNNEL) &&
		interface->link_local == NULL)
	    return (-1);
    }
#endif /* HAVE_IPV6 */

    if (!BIT_TEST (interface->flags, IFF_VIF_TUNNEL) &&
        !BIT_TEST (interface->flags, IFF_MULTICAST))
	return (-1);

    if (on) {
	if (LL_GetCount (igmp->ll_interfaces) <= 0)
	    igmp_start (proto);
        if (igmp->sockfd < 0)
	    return (-1);
#ifdef HAVE_MROUTING
	if (proto == PROTO_IGMP) {
	    if (mc_add_vif (interface) < 0)
		return (-1);
	    assert (interface->vif_index >= 0);
	}
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
	if (proto == PROTO_IGMPV6) {
	    if (mc6_add_vif (interface) < 0)
		return (-1);
	}
#endif /* HAVE_MROUTING6 */
	LL_Add (igmp->ll_interfaces, interface);
	BITX_SET (&igmp->interface_mask, interface->index);
	BGP4_BIT_SET (interface->protocol_mask, igmp->proto);
	if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
	    interface->flags |= IFF_UP;
    }
    else {
	if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
	    interface->flags &= ~IFF_UP;
	BGP4_BIT_RESET (interface->protocol_mask, igmp->proto);
	LL_Remove (igmp->ll_interfaces, interface);
	BITX_RESET (&igmp->interface_mask, interface->index);
#ifdef HAVE_MROUTING
	if (proto == PROTO_IGMP) {
	    mc_del_vif (interface);
	    assert (interface->vif_index < 0);
	}
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
	if (proto == PROTO_IGMPV6) {
	    mc6_del_vif (interface);
	}
#endif /* HAVE_MROUTING6 */
	if (LL_GetCount (igmp->ll_interfaces) <= 0)
	    igmp_stop (proto);
    }

    if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
	return (0);

    if (on) {
        igmp_group_t igmp_group;
	igmp_info_t *igmp_info = New (igmp_info_t);

        assert (igmp->igmp_info[interface->index] == NULL);
        igmp->igmp_info[interface->index] = igmp_info;

#define IGMP_TABLE_HASH_SIZE 23
	igmp_info->membership = HASH_Create (IGMP_TABLE_HASH_SIZE,
                             HASH_KeyOffset,
                             HASH_Offset (&igmp_group, &igmp_group.group),
                             HASH_LookupFunction, gen_lookup_fn,
                             HASH_HashFunction, gen_hash_fn,
                             HASH_DestroyFunction, igmp_delete_group,
                             0);

	    igmp_info->ll_query_reqs = LL_Create (LL_DestroyFunction,
						  destroy_igmp_query_req, 0);

	    BIT_SET (igmp_info->flags, IGMP_QUERIER);
#ifdef HAVE_IPV6
	    if (igmp->proto == PROTO_IGMPV6)
	        igmp_info->igmp_querier_prefix = 
		    Ref_Prefix (interface->link_local->prefix);
	    else
#endif /* HAVE_IPV6 */
	    igmp_info->igmp_querier_prefix = 
		Ref_Prefix (interface->primary->prefix);
	    igmp_info->igmp_querier_timer = New_Timer2 (
		"igmp querier timer", IGMP_OTHER_QUERIER_PRESENT_INTERVAL, 
		TIMER_ONE_SHOT, igmp->schedule, 
		igmp_querier_timeout, 2, igmp, interface);
            Timer_Turn_ON (igmp_info->igmp_querier_timer);
	    trace (TR_INFO, igmp->trace, "new querier %a on %s\n", 
		   igmp_info->igmp_querier_prefix, 
		   interface->name);
	    igmp_info->igmp_query_count = 0;
	    igmp_info->igmp_query_timer = New_Timer2 (
				  "igmp query timer",
                                  IGMP_QUERY_INTERVAL, 0, 
				  igmp->schedule, igmp_make_query, 
				  2, igmp, interface);
            igmp_send_query (igmp, interface);
            if (++igmp_info->igmp_query_count < IGMP_STARTUP_QUERY_COUNT) {
                Timer_Set_Time (igmp_info->igmp_query_timer, 
				IGMP_STARTUP_QUERY_INTERVAL);
                Timer_Turn_ON (igmp_info->igmp_query_timer);
	    }
    }

    /*
     * Join the specified multicast address
     */

    /* XXX */
    if (on != 2)
        join_leave_group (igmp->sockfd, interface, igmp->all_routers, on);

    if (!on) {
	igmp_info_t *igmp_info;

        igmp_info = igmp->igmp_info[interface->index];
        igmp->igmp_info[interface->index] = NULL;
	assert (igmp_info);

	if (igmp_info->igmp_query_timer != NULL) {
    	    Destroy_Timer (igmp_info->igmp_query_timer);
	}
	if (igmp_info->igmp_querier_prefix) {
            Deref_Prefix (igmp_info->igmp_querier_prefix);
	}
	if (igmp_info->igmp_querier_timer) {
            Destroy_Timer (igmp_info->igmp_querier_timer);
	}
	HASH_Destroy (igmp_info->membership);
	LL_Destroy (igmp_info->ll_query_reqs);
	Delete (igmp_info);
    }
    return (0);
}


static char *
s_mrtmsg[] = {
    "",
    "NOCACHE",
    "WRONGIF",
    "EXPIRE",
    "USAGE",
    "RESOLVE",
    "CACHE",
    "NEWMEMBER",
    "DELMEMBER",
};


#if defined(HAVE_MROUTING) || defined(HAVE_MROUTING6)
void
kernel_mfc_request (int type, int family, void *dst, void *src, int index)
{
    igmp_t *igmp = IGMP;
    int bitlen = 32;
    char srcstr[64], dststr[64];

#ifdef HAVE_MROUTING6
    if (family == AF_INET6) {
	igmp = IGMPv6;
	bitlen = 128;
    }
#endif /* HAVE_MROUTING6 */

    assert (type > 0 && type <= MRTMSG_TYPEMAX);
    trace (TR_TRACE, igmp->trace, 
	   "recv kernel message %s for %s from %s index %d\n",
           s_mrtmsg[type], inet_ntop (family, dst, dststr, sizeof (dststr)),
           inet_ntop (family, src, srcstr, sizeof (srcstr)), index);

    if (igmp->recv_km_call_fn) {
        prefix_t *group = New_Prefix (family, dst, bitlen);
        prefix_t *source = New_Prefix (family, src, bitlen);
	interface_t *parent = NULL;
	if (type == MRTMSG_USAGE) {
	    /* the argument index has the number used */
	    schedule_event2 ("recv_km_call_fn",
                      	     igmp->schedule, (event_fn_t) igmp->recv_km_call_fn,
                      	     5, type, group, source, parent, index);
	}
	else {
	    if (/* type != MRTMSG_NOCACHE && */ index > 0)
	        parent = find_interface_byindex (index);
            igmp->recv_km_call_fn (type, group, source, parent, 0);
            Deref_Prefix (source);
            Deref_Prefix (group);
	}
    }
}
#endif /* HAVE_MROUTING || HAVE_MROUTING6 */


igmp_group_t *
igmp_test_membership (prefix_t *group, interface_t *interface)
{
    igmp_t *igmp = IGMP;
    igmp_info_t *igmp_info;

#ifdef HAVE_IPV6
    if (group->family == AF_INET6)
	igmp = IGMPv6;
#endif /* HAVE_IPV6 */
    igmp_info = igmp_get_igmp_info (igmp, interface);
    if (igmp_info == NULL)
	return (NULL);
    return (HASH_Lookup (igmp_info->membership, group));
}

#endif /* HAVE_IGMP */

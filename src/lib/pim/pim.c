/*
 * $Id: pim.c,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
 */

#include <mrt.h>

#if defined(HAVE_MROUTING) || defined(HAVE_MROUTING6)
#include <api6.h>
#include <array.h>
#include <config_file.h>
#include <igmp.h>
#include <pim.h>
/*#include <netinet/in_systm.h>*/
/*#include <netinet/ip.h>*/
#ifdef HAVE_IPV6
#include <netinet/ip6.h>
#endif /* HAVE_IPV6 */

static int pim_send_hello (pim_t *pim, int index);
static void pim_recv_join_prune_graft (pim_t *pim, 
		int type, interface_t *interface,
        	prefix_t *from, u_char *cp, int len);

#ifdef HAVE_MROUTING
pim_t *PIM;
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
pim_t *PIMv6;
#endif /* HAVE_MROUTING6 */

char *s_pim [] =
{
    "Hello",
    "Register",
    "Register-Stop",
    "Join/Prune",
    "Bootstrap",
    "Assert",
    "Graft",
    "Graft-Ack",
    "Candidate-RP-Advertisement",
};


static pim_neighbor_t *
pim_index_to_neighbor (pim_t *pim, int index)
{
    pim_neighbor_t *nbr;

    if (index <= 0)
	return (FALSE);
    nbr = pim->index2neighbor[index];
    if (nbr == NULL)
	return (FALSE);
    if (BIT_TEST (nbr->flags, PIM_NEIGHBOR_DELETE))
	return (FALSE);
    return (nbr);
}


static void
pim_delete_neighbor (pim_neighbor_t *nbr)
{
    Destroy_Timer (nbr->timeout);
    Deref_Prefix (nbr->prefix);
    Delete (nbr);
}


static void
pim_timeout_neighbor (pim_t *pim, pim_neighbor_t *nbr)
{
    pim_interface_t *vif;
   /* since timeout event is queued, it may happen after deletion is done.
      so the info remains and reused later */
    if (BIT_TEST (nbr->flags, PIM_NEIGHBOR_DELETE))
	return;
    BIT_SET (nbr->flags, PIM_NEIGHBOR_DELETE);
    trace (TR_WARN, pim->trace, 
	   "router %a on %s holdtime %d index %d timeout\n", 
	    nbr->prefix, nbr->interface->name, nbr->holdtime, nbr->index);

    cache_update_parent_down (pim->proto, nbr->index);

    vif = pim->pim_interfaces[nbr->interface->index];
    assert (vif);
    if (!(nbr->flags & PIM_NEIGHBOR_MYSELF)) {
        if (--vif->nbr_count <= 0) {
	    vif->flags |= PIM_VIF_LEAF;
	    BITX_SET (&pim->interface_leaf, nbr->interface->index);
	    cache_update_to_leaf (pim->proto, nbr->interface->index);
	}
    }
}


static pim_neighbor_t *
pim_lookup_neighbor (pim_t *pim, interface_t *interface, prefix_t *source)
{
    pim_neighbor_t *nbr;
    pim_interface_t *vif;

    assert (BITX_TEST (&pim->interface_mask, interface->index));
    vif = pim->pim_interfaces[interface->index];
    assert (vif);

    LL_Iterate (vif->ll_neighbors, nbr) {
	if (prefix_compare_wolen (source, nbr->prefix) == 0)
	    break;
    }

    return (nbr);
}


static pim_neighbor_t *
pim_register_neighbor (pim_t *pim, interface_t *interface, prefix_t *source,
		       int holdtime)
{
    pim_neighbor_t *nbr;
    pim_interface_t *vif;
    int i;

    assert (interface);
    vif = pim->pim_interfaces[interface->index];

    assert (pim);
    assert (vif);
    assert (source);

	/* zero is reserved for now */
	for (i = 1; i < MAX_PIM_NEIGHBORS; i++) {
	    if (pim->index2neighbor[i] == NULL)
		break;
	}
	if (i >= MAX_PIM_NEIGHBORS) {
	    trace (TR_ERROR, pim->trace, 
		   "too many PIM neighbors (%d)\n", i);
	    return (NULL);
	}
	nbr = New (pim_neighbor_t);
	nbr->prefix = Ref_Prefix (source);
	nbr->interface = vif->interface;
	nbr->index = i;
	nbr->holdtime = holdtime;
	nbr->flags = 0;
	if (holdtime < 0) {
    	    BIT_SET (nbr->flags, PIM_NEIGHBOR_DELETE);
	}
	if (find_interface_local (source))
	    nbr->flags |= PIM_NEIGHBOR_MYSELF;
	else if (holdtime >= 0) {
	    vif->nbr_count++;
	    vif->flags &= ~PIM_VIF_LEAF;
	    BITX_RESET (&pim->interface_leaf, nbr->interface->index);
	    cache_update_to_router (pim->proto, nbr->interface->index);
        }
	pim->index2neighbor[i] = nbr;
        time (&nbr->ctime);
	LL_Add (vif->ll_neighbors, nbr);
	if (holdtime != 0xffff) {
            nbr->timeout = New_Timer2 ("PIM neighbors timer", 
				holdtime, TIMER_ONE_SHOT, pim->schedule, 
				pim_timeout_neighbor, 2, pim, nbr);
	    if (holdtime != 0)
	        Timer_Turn_ON (nbr->timeout);
	}
	return (nbr);
}


static void
pim_recover_neighbor (pim_t *pim, pim_interface_t *vif, pim_neighbor_t *nbr,
		      int holdtime)
{
    assert (BIT_TEST (nbr->flags, PIM_NEIGHBOR_DELETE));
    BIT_RESET (nbr->flags, PIM_NEIGHBOR_DELETE);
    if (nbr->holdtime != holdtime) {
	nbr->holdtime = holdtime;
        Timer_Set_Time (nbr->timeout, holdtime);
    }
    if (holdtime != 0xffff)
        Timer_Turn_ON (nbr->timeout);
    trace (TR_WARN, pim->trace, 
	   "router %a on %s holdtime %d index %d recovered\n", 
	   nbr->prefix, nbr->interface->name, nbr->holdtime, nbr->index);
    if (!(nbr->flags & PIM_NEIGHBOR_MYSELF)) {
        vif->nbr_count++;
	vif->flags &= ~PIM_VIF_LEAF;
	BITX_RESET (&pim->interface_leaf, nbr->interface->index);
    	cache_update_parent_up (pim->proto, nbr->index);
	cache_update_to_router (pim->proto, nbr->interface->index);
    }
}


static void
pim_recv_hello (pim_t *pim, interface_t *interface, prefix_t *source, 
		u_char *data, int datalen)
{
    pim_neighbor_t *nbr;
    u_char *endp = data + datalen;
    pim_interface_t *vif;
    int optype, optlen;
    int holdtime = PIM_TIMER_HELLO_HOLDTIME;

    if (!BITX_TEST (&pim->interface_mask, interface->index) ||
	    BITX_TEST (&pim->force_leaf_mask, interface->index)) {
        trace (TR_WARN, pim->trace,
               "hello from %a on disabled interface %s\n",                     
               source, interface->name);         
        return;
    }

    while (endp - data > 0) {

	if (endp - data < 4) {
	    trace (TR_ERROR, pim->trace, 
	           "wrong datalen (%d) remained to get an option\n",
	           endp - data);
	    return;
	}
	MRT_GET_SHORT (optype, data);
	MRT_GET_SHORT (optlen, data);
	if (optype == 1 /* holdtime */) {
	    if (optlen != 2) {
	        trace (TR_ERROR, pim->trace, 
	               "wrong option length %d for holdtime\n", optlen);
		data += optlen;
	    }
	    else {
#ifdef YIXIN_PIMV6
	        MRT_GET_LONG (holdtime, data);
#else
	        MRT_GET_SHORT (holdtime, data);
#endif /* YIXIN_PIMV6 */
	        trace (TR_INFO, pim->trace, 
	               "holdtime %d\n", holdtime);
	    }
	}
	else {
	    trace (TR_ERROR, pim->trace, 
	           "wrong optlen code %d len %d\n", optype, optlen);
	    data += optlen;
	}
    }

    vif = pim->pim_interfaces[interface->index];
    assert (vif);

    nbr = pim_lookup_neighbor (pim, interface, source);
    if (nbr == NULL) {
	nbr = pim_register_neighbor (pim, interface, source, holdtime);
	if (holdtime == 0)
	    pim_timeout_neighbor (pim, nbr);
	/* this is new to me */
	pim_send_hello (pim, interface->index);
    }
    else if (BIT_TEST (nbr->flags, PIM_NEIGHBOR_DELETE)) {
	pim_recover_neighbor (pim, vif, nbr, holdtime);
    }
    else if (nbr->holdtime != holdtime) {
	trace (TR_WARN, pim->trace, 
		"router %a on %s holdtime changed (%d -> %d)\n", 
		source, nbr->interface->name, nbr->holdtime, holdtime);
	nbr->holdtime = holdtime;
	if (holdtime == 0) {
	    Timer_Turn_OFF (nbr->timeout);
	    pim_timeout_neighbor (pim, nbr);
	}
	else {
	    Timer_Set_Time (nbr->timeout, holdtime);
	}
     }
     else {
	    Timer_Reset_Time (nbr->timeout);
    }
}


void
pim_receive (pim_t *pim)
{
    u_char buffer[PIM_MAX_PDU], *cp = buffer;
    int len = 0, cksum;
    u_char cc;
    int type, version, zero;
    prefix_t *source = NULL;
#ifdef INRIA_IPV6
    prefix_t *destin = NULL;
#endif /* INRIA_IPV6 */
    interface_t *interface = NULL;
    gateway_t *gateway;

    assert (pim);
#ifdef HAVE_MROUTING
if (pim->proto == PROTO_PIM) {
    struct ip *ip;
    int hlen;

    assert (pim == PIM);
    len = recvmsgfrom (pim->sockfd, buffer, sizeof (buffer), O_NONBLOCK,
		       &source, NULL, &interface, NULL, NULL);
    select_enable_fd_mask (pim->sockfd, SELECT_READ);
    if (len <= 0)
	return;

    assert (source);
    assert (interface);

    if (!BITX_TEST (&pim->interface_mask, interface->index)) {
        trace (TR_WARN, pim->trace,
               "packet from %a len %d on disabled interface %s\n",
               source, len, interface->name);         
        goto ignore;
    }

    ip = (struct ip *) cp;
    if (ip->ip_v != IPVERSION) {
        trace (TR_WARN, pim->trace,
               "packet from %a on %s len %d (first byte 0x%x)"
               " is not an IP packet, trying pim\n",
               source, interface->name, len, *cp);
        goto pim_test; 
    }   
    hlen = ip->ip_hl * 4;
#ifdef __linux__
    /* ignore received len */
    ip->ip_len = ntohs (ip->ip_len);
    len = ip->ip_len - hlen;
#else
#ifndef sun
    /* solaris doesn't seem to fill the right length in ip->ip_len */
    if (len != hlen + ip->ip_len) {
        trace (TR_TRACE, pim->trace,
               "packet from %a on %s expected len %d but %d\n",
               source, interface->name, hlen + ip->ip_len, len);
	goto ignore;
    }
#endif /* sun */
    len -= hlen;
#endif /* __linux__ */
    cp = (u_char *)(ip + 1);

pim_test:
    if (inet_cksum (cp, len)) {
        trace (TR_WARN, pim->trace,
               "packet from %a on %s len %d bad pim checksum\n",
               source, interface->name, len); 
        goto ignore;
    }
}
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
if (pim->proto == PROTO_PIMV6) {
#ifndef WIDE_IPV6
    struct ip6_hdr *ipv6;
#endif /* WIDE_IPV6 */

    assert (pim == PIMv6);
#ifdef INRIA_IPV6
    /* packet destination is required to compute PIM IPV6 checksum */
    len = recvmsgfrom (pim->sockfd, buffer, sizeof (buffer), O_NONBLOCK,
		       &source, NULL, &interface, &destin, NULL);
#else
    len = recvmsgfrom (pim->sockfd, buffer, sizeof (buffer), O_NONBLOCK,
		       &source, NULL, &interface, NULL, NULL);
#endif /* INRIA_IPV6 */
    select_enable_fd_mask (pim->sockfd, SELECT_READ);
    if (len <= 0)
	return;

    assert (source);
    assert (interface);

    if (!BITX_TEST (&pim->interface_mask, interface->index)) {
        trace (TR_WARN, pim->trace,
               "packet from %s len %d on disabled interface %s\n",
               source, len, interface->name);         
        goto ignore;
    }

#ifndef WIDE_IPV6
    /* in case an IPv6 header is included */
    ipv6 = (struct ip6_hdr *) cp;
    if ((ipv6->ip6_vfc >> 4) != IPNGVERSION) {
        trace (TR_WARN, pim->trace,
               "packet from %a on %s len %d (ip6_vfc 0x%x)"
	       " is not an IPv6 packet, trying icmp\n",
               source, interface->name, len, ipv6->ip6_vfc);
	goto pim6_test;
    }
    /* the kernel already converted it into host oder */
#ifdef __linux__
    ipv6->ip6_plen = ntohs (ipv6->ip6_plen);
#endif /* __linux__ */
#ifndef sun
    if (len != sizeof (*ipv6) + ipv6->ip6_plen) {
        trace (TR_WARN, pim->trace,
			"packet from %a on %s expected len %d but %d\n",
               source, interface->name, 
	       sizeof (*ipv6) + ipv6->ip6_plen, len);
	goto ignore;
    }
#endif /* sun */
    if (ipv6->ip6_nxt != IPPROTO_PIMV6) {
        trace (TR_WARN, pim->trace,
               "packet from %a on %s len %d with next header %d\n",
               source, interface->name, len, ipv6->ip6_nxt);
	goto ignore;
    }
    cp = (u_char *)(ipv6 + 1);
    len -= sizeof (*ipv6);

pim6_test:
    if (destin == NULL) {
        trace (TR_WARN, pim->trace,
               "packet from %a on %s len %d, dest address unavailable\n",
               source, interface->name, len);
	goto ignore;
    }
    if (inet6_cksum (cp, len, IPPROTO_PIMV6, 
		     prefix_toaddr6 (source), prefix_toaddr6 (destin))) {
        trace (TR_WARN, pim->trace,
               "packet from %a to %a on %s len %d bad pim v6 checksum\n",
               source, destin, interface->name, len); 
        goto ignore;
    }
#endif /* WIDE_IPV6 */
}
#endif /* HAVE_MROUTING6 */

    MRT_GET_BYTE (cc, cp);
    version = cc >> 4;
    type = cc & 0x0f;
    MRT_GET_BYTE (zero, cp);
    MRT_GET_SHORT (cksum, cp);

/* XXX check only with the interface */
    if (find_interface_local (source)) {
	trace (TR_PACKET, pim->trace,
	       "loopback from %a on %s len %d\n",
	       source, interface->name, len);
	if (type != PIM_HELLO)
	    goto ignore;
    }

    if (version != PIM_VERSION) {
	trace (TR_WARN, pim->trace,
	       "unsupported version %d from %a on %s len %d\n",
	       version, source, interface->name, len);
	goto ignore;
    }

    if (zero) {
	trace (TR_WARN, pim->trace,
	       "non-zero pad field (value 0x%x) from %a on %s len %d\n",
	       zero, source, interface->name, len);
/* XXX  goto ignore; */
    }

    if (type >= PIM_MAX_TYPE) {
	trace (TR_WARN, pim->trace,
	       "unsupported message type %d from %a on %s len %d, ignore!\n",
	       type, source, len, interface->name);
	goto ignore;
    }

    trace (TR_PACKET, pim->trace,
	   "recv [%s] from %a on %s len %d\n", s_pim[type],
	   source, interface->name, len);

    gateway = add_gateway (source, 0, interface);
    len -= 4;

    switch (type) {
    case PIM_HELLO:
	    pim_recv_hello (pim, interface, source, cp, len);
            break;
    case PIM_REGISTER:
            break;
    case PIM_REGISTER_STOP:
            break;
    case PIM_BOOTSTRAP:
            break;
    case PIM_ASSERT:
            break;
    case PIM_JOIN_PRUNE:
    case PIM_GRAFT:
    case PIM_GRAFT_ACK:
	    pim_recv_join_prune_graft (pim, type, interface, source, cp, len);
            break;
    case PIM_CANDIDATE_RP_ADVERTISEMENT:
            break;
    }
  ignore:
    if (source)
	Deref_Prefix (source);
#ifdef INRIA_IPV6
    if (destin)
	Deref_Prefix (destin);
#endif /* INRIA_IPV6 */
}


int 
pim_send (pim_t *pim, prefix_t *dst, int type, u_char *data, int datalen, 
	  pim_interface_t *vif, int loop)
{
    int ret = -1;
    u_char buffer[PIM_MAX_PDU];
    u_char *cp = buffer, *pim_packet, *checksum_p;
    prefix_t *source = NULL;
    int ip_in_ip = 0;
    prefix_t *realdst = dst;
    int ttl = MAXTTL;
    u_long flags = 0;
    u_long checksum;
    interface_t *interface = vif->interface;
    int len;

    if (interface) {
#ifdef HAVE_MROUTING
        if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL)) {
	    ip_in_ip++;
	    source = interface->tunnel_source;
	    realdst = interface->tunnel_destination;
	    assert (source);
	    loop = 0;
	}
#endif /* HAVE_MROUTING */
	if (pim->proto == PROTO_PIM) {
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

#ifdef HAVE_MROUTING
if (pim->proto == PROTO_PIM) {
    struct ip *iphdr;

    iphdr = (struct ip *) cp;
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
    	iphdr->ip_len = 2 * sizeof (*iphdr) + 4 + datalen;
#ifdef __linux__
    	iphdr->ip_len = htons (iphdr->ip_len);
#endif /* __linux__ */
	iphdr++;
    }

    memset (iphdr, 0, sizeof (*iphdr));
    /* These may not be required for raw socket */
    iphdr->ip_v = IPVERSION;
    iphdr->ip_hl = sizeof (*iphdr) / 4;
    iphdr->ip_tos = 0;
    iphdr->ip_off = 0;	/* no fragments */

    iphdr->ip_p = IPPROTO_PIM;
    iphdr->ip_src.s_addr = (source)? prefix_tolong (source): INADDR_ANY;
    iphdr->ip_dst.s_addr = prefix_tolong (dst);
    iphdr->ip_len = sizeof (*iphdr) + 4 + datalen;
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

    cp = (u_char *) iphdr;
}
#endif /* HAVE_MROUTING */

    pim_packet = cp;
    MRT_PUT_BYTE ((PIM_VERSION << 4) | (type & 0x0f), cp);
    MRT_PUT_BYTE (0, cp);
checksum_p = cp;
    MRT_PUT_SHORT (0, cp);

    assert (datalen == 0 || data != NULL);
    if (datalen > 0) {
	assert (cp - buffer + datalen <= sizeof (buffer));
	memcpy (cp, data, datalen);
	cp += datalen;
    }
    len = (type == PIM_REGISTER)? 8: (cp - pim_packet);
#ifdef HAVE_IPV6
    if (pim->proto == PROTO_PIMV6) {
	assert (source);
        checksum = inet6_cksum (pim_packet, len, IPPROTO_PIMV6, 
		       prefix_toaddr6 (source), prefix_toaddr6 (realdst));
    }
    else
#endif /* HAVE_IPV6 */
    checksum = inet_cksum (pim_packet, 
			  (type == PIM_REGISTER)? 8: cp - pim_packet);
    MRT_PUT_NETSHORT (checksum, checksum_p);

    if (loop)
	flags |= MSG_MULTI_LOOP;

    if ((ret = send_packet (pim->sockfd, buffer, 
			    cp - buffer, flags, realdst, 0,
			    interface, 0)) >= 0)
        trace (TR_PACKET, pim->trace, "send [%s] to %a on %s len %d\n", 
	       	s_pim[type], realdst, 
		(interface)? interface->name: "?", cp - buffer);
    return (ret);
}


static int
pim_send_hello (pim_t *pim, int index)
{
    u_char buffer[PIM_MAX_PDU], *cp = buffer;
    pim_interface_t *vif;

    /* interface was already deleted */
    if ((vif = pim->pim_interfaces[index]) == NULL)
	return (-1);

    MRT_PUT_SHORT (1, cp); /* holdtime */
    MRT_PUT_SHORT (2, cp);
#ifdef YIXIN_PIMV6
    MRT_PUT_LONG (PIM_TIMER_HELLO_HOLDTIME, cp);
#else
    MRT_PUT_SHORT (PIM_TIMER_HELLO_HOLDTIME, cp);
#endif /* YIXIN_PIMV6 */
    return (pim_send (pim, pim->all_routers, PIM_HELLO, 
		      buffer, cp - buffer, vif, TRUE));
}


static u_char *
pim_put_enc_uni (prefix_t *prefix, u_char *cp)
{
    int afi = AFI_IP;
    int len = 4;

#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6) {
	afi = AFI_IP6;
        len = 16;
   }
#endif /* HAVE_IPV6 */
    MRT_PUT_BYTE (afi, cp);
    MRT_PUT_BYTE (0, cp); /* native encoding */
    MRT_PUT_DATA (prefix_tochar (prefix), len, cp);
    return (cp);
}


static u_char *
pim_put_enc_multi (prefix_t *prefix, u_char *cp)
{
    int afi = AFI_IP;
    int len = 4;

#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6) {
	afi = AFI_IP6;
        len = 16;
   }
#endif /* HAVE_IPV6 */
    MRT_PUT_BYTE (afi, cp);
    MRT_PUT_BYTE (0, cp); /* native encoding */
    MRT_PUT_BYTE (0, cp); /* reserved */
    MRT_PUT_BYTE (len * 8, cp); /* mask len */
    MRT_PUT_DATA (prefix_tochar (prefix), len, cp);
    return (cp);
}


static u_char *
pim_put_enc_src (prefix_t *prefix, u_char *cp)
{
    int afi = AFI_IP;
    int len = 4;

#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6) {
	afi = AFI_IP6;
        len = 16;
   }
#endif /* HAVE_IPV6 */
    MRT_PUT_BYTE (afi, cp);
    MRT_PUT_BYTE (0, cp); /* native encoding */
    MRT_PUT_BYTE (0, cp); /* S, W, R bits and reserved */
    MRT_PUT_BYTE (len * 8, cp); /* mask len */
    MRT_PUT_DATA (prefix_tochar (prefix), len, cp);
    return (cp);
}


#define PIM_MSG_JOIN  1
#define PIM_MSG_PRUNE 2
#define PIM_MSG_GRAFT 3
#define PIM_MSG_GRAFT_ACK 4

static int
pim_send_join_prune_graft (pim_t *pim, int type, 
			   prefix_t *prefix, int holdtime, 
			   prefix_t *group, prefix_t *source,
			   interface_t *interface)
{
    u_char buffer[PIM_MAX_PDU], *cp = buffer;
    pim_interface_t *vif;
    int code;
    prefix_t *dest = pim->all_routers;

    /* interface was already deleted */
    if ((vif = pim->pim_interfaces[interface->index]) == NULL)
	return (-1);

    cp = pim_put_enc_uni (prefix, cp);
    MRT_PUT_BYTE (0, cp); /* reserved */
    MRT_PUT_BYTE (1, cp); /* number of groups */
    MRT_PUT_SHORT (holdtime, cp);
    cp = pim_put_enc_multi (group, cp);
    if (type == PIM_MSG_JOIN || type == PIM_MSG_GRAFT || 
	    type == PIM_MSG_GRAFT_ACK) {
    	MRT_PUT_SHORT (1, cp); /* number of joins */
    	MRT_PUT_SHORT (0, cp); /* number of prunes */
	if (type == PIM_MSG_JOIN)
	    code = PIM_JOIN_PRUNE;
	else if (type == PIM_MSG_GRAFT)
	    code = PIM_GRAFT;
	else
	    code = PIM_GRAFT_ACK;
    }
    else {
	assert (type == PIM_MSG_PRUNE);
    	MRT_PUT_SHORT (0, cp); /* number of joins */
    	MRT_PUT_SHORT (1, cp); /* number of prunes */
	code = PIM_JOIN_PRUNE;
    }
    if (type == PIM_MSG_GRAFT || type == PIM_MSG_GRAFT_ACK) {
	assert (prefix);
	dest = prefix;
    }
    cp = pim_put_enc_src (source, cp);
    return (pim_send (pim, dest, code, buffer, cp - buffer, vif, TRUE));
}


/* these prefix memories must be allocated as static */

static u_char *
pim_get_enc_uni (prefix_t *prefix, u_char *cp)
{
    int family = AF_INET;
    int len = 4;
    int afi, enc;
    u_char addr[16];

    MRT_GET_BYTE (afi, cp);
#ifdef HAVE_IPV6
    if (afi == AFI_IP6) {
	family = AF_INET6;
        len = 16;
    }
    else
#endif /* HAVE_IPV6 */
    if (afi != AFI_IP)
	return (NULL);
    MRT_GET_BYTE (enc, cp); /* must be 0 */
    if (enc != 0)
        return (NULL);
    MRT_GET_DATA (addr, len, cp);
    if (prefix)
         New_Prefix2 (family, addr, len * 8, prefix);
    return (cp);
}


static u_char *
pim_get_enc_multi (prefix_t *prefix, u_char *cp)
{
    int family = AF_INET;
    int len = 4;
    int afi, enc, reserved, masklen;
    u_char addr[16];

    MRT_GET_BYTE (afi, cp);
#ifdef HAVE_IPV6
    if (afi == AFI_IP6) {
	family = AF_INET6;
        len = 16;
    }
    else
#endif /* HAVE_IPV6 */
    if (afi != AFI_IP)
	return (NULL);
    MRT_GET_BYTE (enc, cp); /* must be 0 */
    if (enc != 0)
        return (NULL);
    MRT_GET_BYTE (reserved, cp);
    MRT_GET_BYTE (masklen, cp);
    if (masklen != len * 8)
	return (NULL);
    MRT_GET_DATA (addr, len, cp);
    if (prefix)
        New_Prefix2 (family, addr, masklen, prefix);
    return (cp);
}


static u_char *
pim_get_enc_src (prefix_t *prefix, u_char *cp)
{
    int family = AF_INET;
    int len = 4;
    int afi, enc, reserved, masklen;
    u_char addr[16];

    MRT_GET_BYTE (afi, cp);
#ifdef HAVE_IPV6
    if (afi == AFI_IP6) {
	family = AF_INET6;
        len = 16;
    }
    else
#endif /* HAVE_IPV6 */
    if (afi != AFI_IP)
	return (NULL);
    MRT_GET_BYTE (enc, cp); /* must be 0 */
    if (enc != 0)
        return (NULL);
    MRT_GET_BYTE (reserved, cp);
    MRT_GET_BYTE (masklen, cp);
    if (masklen != len * 8)
	return (NULL);
    MRT_GET_DATA (addr, len, cp);
    if (prefix)
        New_Prefix2 (family, addr, masklen, prefix);
    return (cp);
}


static int
pim_comp_graft (pim_graft_t *p, pim_graft_t *q)
{
    return (q->expire - p->expire);
}


static void
pim_timeout_graft (pim_t *pim)
{
    time_t now;
    pim_graft_t *graft;
    int need_sort = 0;

    time (&now);
    LL_Iterate (pim->ll_grafts, graft) {
	pim_neighbor_t *nbr;
	/* acknowledged */
	if (!BIT_TEST (graft->entry->flags, CACHE_PIM_GRAFT) ||
	     BIT_TEST (graft->entry->flags, CACHE_DELETE)) {
	    pim_graft_t *prev = LL_GetPrev (pim->ll_grafts, graft);
	    LL_Remove (pim->ll_grafts, graft);
	    graft = prev;
	    continue;
	}

	if (graft->expire > now)
	    break;

	if ((nbr = pim_index_to_neighbor (pim, graft->entry->parent_index)) 
		!= NULL) {
            pim_send_join_prune_graft (pim, PIM_MSG_GRAFT, nbr->prefix, 0,
                    graft->entry->group, graft->entry->source, nbr->interface);
	}
	graft->expire = now + graft->holdtime;
	need_sort++;
    }
    if (need_sort)
        LL_Sort (pim->ll_grafts);

    graft = LL_GetHead (pim->ll_grafts);
    if (graft) {
        Timer_Set_Time (pim->graft_timer, graft->expire - now);
        Timer_Turn_ON (pim->graft_timer);
    }
}


static void
pim_send_graft (pim_t *pim, cache_entry_t *entry, pim_neighbor_t *nbr)
{
    pim_graft_t *graft;
    time_t now;

    if (BIT_TEST (entry->flags, CACHE_PIM_GRAFT)) {
      	trace (TR_PACKET, pim->trace, "graft running "
      		"for group %a source %a from %a on %s\n",
             	entry->group, entry->source, 
		nbr->prefix, nbr->interface->name);
	return;
    }

    time (&now);
    BIT_SET (entry->flags, CACHE_PIM_GRAFT);
    graft = New (pim_graft_t);
    graft->neighbor = nbr;
    graft->holdtime = 3 /* XXX */;
    graft->entry = entry;
    graft->received = now;
    graft->expire = now + graft->holdtime;
    LL_Add (pim->ll_grafts, graft);
    if (LL_GetHead (pim->ll_grafts) == graft) {
        Timer_Set_Time (pim->graft_timer, graft->holdtime);
        Timer_Turn_ON (pim->graft_timer);
    }
    pim_send_join_prune_graft (pim, PIM_MSG_GRAFT, nbr->prefix, 0, 
			entry->group, entry->source, nbr->interface);
}


static int
pim_comp_prune (pim_prune_t *p, pim_prune_t *q)
{
    return (q->expire - p->expire);
}


static void
pim_timeout_prune (pim_t *pim)
{
    time_t now;
    pim_prune_t *prune;
    int need_sort = 0;

    time (&now);
    LL_Iterate (pim->ll_prunes, prune) {
	if (prune->expire > now) {
	    break;
	}
	if (!BIT_TEST (prune->flags, PIM_PRUNE_RUN)) {

	    BIT_SET (prune->flags, PIM_PRUNE_RUN);
	    prune->expire = now + prune->holdtime;
	    need_sort++;

	    assert (BITX_TEST (&prune->entry->routers, 
		    prune->neighbor->interface->index));
	    BITX_RESET (&prune->entry->routers, 
		       prune->neighbor->interface->index);

            trace (TR_PACKET, pim->trace, "prune in effect "
	           "for group %a source %a holdtime %d from %a on %s\n",
                   prune->entry->group, prune->entry->source, 
		   prune->entry->holdtime, prune->neighbor->prefix, 
		   prune->neighbor->interface->name);
	    if (!BITX_TEST (&prune->entry->children,
                     prune->neighbor->interface->index)) {
	        cache_update_mfc (prune->entry);
	    }
	    if (BIT_TEST (prune->entry->flags, CACHE_NEGATIVE)) {
		pim_neighbor_t *nbr;
		pim_prune_t *p;
		int holdtime = 0;
		/* find the maximum prune timer among all */
		assert (prune->entry->ll_prunes);
		LL_Iterate (prune->entry->ll_prunes, p) {
		    if (holdtime == 0 || holdtime < p->holdtime)
			holdtime = p->holdtime;
		}
		if (holdtime > 0) {
		    prune->entry->holdtime = holdtime;
		    prune->entry->expire = now + holdtime;
		}
		if ((nbr = pim_index_to_neighbor (pim, 
				prune->entry->parent_index)) != NULL) {
                    pim_send_join_prune_graft (pim, PIM_MSG_PRUNE, nbr->prefix, 
			   PIM_DATA_TIMEOUT, prune->entry->group, 
			   prune->entry->source, nbr->interface);
		}
	    }
        }
	else {
	    int need_graft = 0;
	    pim_prune_t *prev;
	    assert (!BITX_TEST (&prune->entry->routers, 
		    prune->neighbor->interface->index));
	    need_graft = BIT_TEST (prune->entry->flags, CACHE_NEGATIVE);
	    BITX_SET (&prune->entry->routers, 
		     prune->neighbor->interface->index);
            trace (TR_PACKET, pim->trace, "prune timeout "
	           "for group %a source %a holdtime %d from %a on %s\n",
                   prune->entry->group, prune->entry->source, 
		   prune->entry->holdtime, prune->neighbor->prefix, 
		   prune->neighbor->interface->name);
	    if (!BITX_TEST (&prune->entry->children, 
		     prune->neighbor->interface->index)) {
	        cache_update_mfc (prune->entry);
	    }
	    if (need_graft) {
		pim_neighbor_t *nbr;
		prune->entry->holdtime = PIM_DATA_TIMEOUT;
		prune->entry->expire = now + PIM_DATA_TIMEOUT;
		if ((nbr = pim_index_to_neighbor (pim, 
				prune->entry->parent_index)) != NULL) {
		    pim_send_graft (pim, prune->entry, nbr);
		}
	    }
	    prev = LL_GetPrev (pim->ll_prunes, prune);
	    LL_RemoveFn (prune->entry->ll_prunes, prune, NULL);
	    LL_Remove (pim->ll_prunes, prune);
	    prune = prev;
	}
    }

    if (need_sort)
        LL_Sort (pim->ll_prunes);

    prune = LL_GetHead (pim->ll_prunes);
    if (prune) {
        Timer_Set_Time (pim->prune_timer, prune->expire - now);
        Timer_Turn_ON (pim->prune_timer);
    }
}


static int
pim_comp_join (pim_join_t *p, pim_join_t *q)
{
    return (q->expire - p->expire);
}


static void
pim_timeout_join (pim_t *pim)
{
    time_t now;
    pim_join_t *join;

    time (&now);
    LL_Iterate (pim->ll_joins, join) {
	pim_neighbor_t *nbr;
	pim_join_t *prev;

	if (join->expire > now) {
	    break;
	}
	if ((nbr = pim_index_to_neighbor (pim, join->entry->parent_index))
                != NULL) {
            pim_send_join_prune_graft (pim, PIM_MSG_JOIN, nbr->prefix, 0,
                    join->entry->group, join->entry->source, nbr->interface);
	}
	prev = LL_GetPrev (pim->ll_joins, join);
	LL_RemoveFn (join->entry->ll_joins, join, NULL);
	LL_Remove (pim->ll_joins, join);
	join = prev;
    }

    join = LL_GetHead (pim->ll_joins);
    if (join) {
        Timer_Set_Time (pim->join_timer, join->expire - now);
        Timer_Turn_ON (pim->join_timer);
    }
}


static void
pim_recv_prune (pim_t *pim, pim_neighbor_t *nbr, int holdtime, 
		prefix_t *group, prefix_t *source, pim_neighbor_t *target)
{
    cache_entry_t *entry;
    time_t now;

    time (&now);
    entry = cache_lookup (source, group);
    if (entry == NULL) {
        trace (TR_PACKET, pim->trace, "prune no entry "
	       "for group %p source %p holdtime %d from %a on %s\n",
               group, source, holdtime, nbr->prefix, nbr->interface->name);
	return;
    }

    if (target == NULL || BIT_TEST (target->flags, PIM_NEIGHBOR_MYSELF)) {
	pim_prune_t *prune = NULL;

	if (!BITX_TEST (&entry->routers, nbr->interface->index)) {
            trace (TR_PACKET, pim->trace, "prune non-outgoing if "
	           "for group %a source %a holdtime %d from %a on %s\n",
                   group, source, holdtime, nbr->prefix, nbr->interface->name);
	    return;
	}

        if (entry->ll_prunes == NULL) {
            entry->ll_prunes = LL_Create (LL_DestroyFunction, FDelete, 0);
	}
	else {
	    LL_Iterate (entry->ll_prunes, prune) {
	        if (prune->neighbor == nbr)
		    break;
	    }
	}

	if (prune == NULL) {
	    prune = New (pim_prune_t);
	    prune->neighbor = nbr;
            prune->received = now;
            prune->holdtime = holdtime;
	    prune->entry = entry;
	    if (nbr->interface->flags & IFF_POINTOPOINT) {
		/* immediately */
                prune->expire = now + 0;
	    }
	    else {
		/* XXX */
#define PIM_PRUNE_RUN_DELAY 5
                prune->expire = now + PIM_PRUNE_RUN_DELAY;
	    }
            LL_Add (entry->ll_prunes, prune);
            LL_Add (pim->ll_prunes, prune);
            trace (TR_PACKET, pim->trace, "prune scheduled "
	           "for group %a source %a holdtime %d from %a on %s\n",
                   group, source, holdtime, nbr->prefix, nbr->interface->name);
	    if (LL_GetHead (pim->ll_prunes) == prune) {
        	Timer_Set_Time (pim->prune_timer, PIM_PRUNE_RUN_DELAY);
        	Timer_Turn_ON (pim->prune_timer);
	    }
	}
	else {
	    /* update ??? */
	    LL_RemoveFn (entry->ll_prunes, prune, NULL);
	    LL_RemoveFn (pim->ll_prunes, prune, NULL);
	    assert (prune->entry == entry);
	    prune->received = now;
	    prune->holdtime = holdtime;
	    if (!BIT_TEST (prune->flags, PIM_PRUNE_RUN))
                prune->expire = now + PIM_PRUNE_RUN_DELAY;
	    else
                prune->expire = now + holdtime;
	    LL_Add (entry->ll_prunes, prune);
	    LL_Add (pim->ll_prunes, prune);
       	    trace (TR_PACKET, pim->trace, "prune update scheduled "
	           "for group %a source %a holdtime %d from %a on %s\n",
               	    group, source, holdtime, nbr->prefix, nbr->interface->name);
	    if (LL_GetHead (pim->ll_prunes) == prune) {
        	Timer_Set_Time (pim->prune_timer, prune->expire - now);
        	Timer_Turn_ON (pim->prune_timer);
	    }
	}
    }
    else {
	if (entry->parent_index != target->index) {
       	    trace (TR_PACKET, pim->trace, 
		   "prune addressed to non-upstream %a "
	           "for group %a source %a holdtime %d from %a on %s\n",
		    pim->index2neighbor[entry->parent_index]->prefix,
               	    group, source, holdtime, nbr->prefix, nbr->interface->name);
	    return;
	}
	if (entry->parent_index == target->index &&
		!BIT_TEST (entry->flags, CACHE_NEGATIVE)) {
	    pim_join_t *join;
	    join = New (pim_join_t);
	    join->neighbor = nbr;
            join->received = now;
            join->holdtime = rand () % (3 + 1) /* XXX */;
	    join->entry = entry;
            join->expire = now + join->holdtime;
	    LL_Add (entry->ll_joins, join);
	    LL_Add (pim->ll_joins, join);
       	    trace (TR_PACKET, pim->trace, "prune-override-join scheduled "
	           "for group %a source %a holdtime %d from %a on %s\n",
               	    group, source, holdtime, nbr->prefix, nbr->interface->name);
	    if (LL_GetHead (pim->ll_joins) == join) {
        	Timer_Set_Time (pim->join_timer, join->holdtime);
        	Timer_Turn_ON (pim->join_timer);
	    }
	}
    }
}


static void
pim_recv_join (pim_t *pim, pim_neighbor_t *nbr, int holdtime, 
	       prefix_t *group, prefix_t *source, pim_neighbor_t *target)
{
    cache_entry_t *entry;
    time_t now;

    time (&now);
    entry = cache_lookup (source, group);
    if (entry == NULL) {
        trace (TR_PACKET, pim->trace, "join no entry "
	       "for group %a source %a holdtime %d from %a on %s\n",
               group, source, holdtime, nbr->prefix, nbr->interface->name);
	return;
    }
    if (target == NULL || BIT_TEST (target->flags, PIM_NEIGHBOR_MYSELF)) {
	pim_prune_t *prune = NULL;

	if (entry->ll_prunes) {
	    LL_Iterate (entry->ll_prunes, prune) {
	        if (prune->neighbor->interface == nbr->interface)
		    break;
	    }
	}

	if (prune) {
            trace (TR_PACKET, pim->trace, "join cancelled prune "
	           "for group %a source %a holdtime %d from %a on %s\n",
                   entry->group, entry->source, entry->holdtime, nbr->prefix, 
		   nbr->interface->name);
	    if (prune == LL_GetHead (pim->ll_prunes)) {
		LL_RemoveFn (entry->ll_prunes, prune, NULL);
		LL_Remove (pim->ll_prunes, prune);
		prune = LL_GetHead (pim->ll_prunes);
        	Timer_Set_Time (pim->prune_timer, prune->expire - now);
        	Timer_Turn_ON (pim->prune_timer);
	    }
	    else {
		LL_RemoveFn (entry->ll_prunes, prune, NULL);
		LL_Remove (pim->ll_prunes, prune);
	    }
	}
	else {
            trace (TR_PACKET, pim->trace, "join no match prune "
	           "for group %a source %a holdtime %d from %a on %s\n",
                   entry->group, entry->source, entry->holdtime, nbr->prefix, 
		   nbr->interface->name);
	}
    }
    else {
	pim_join_t *join;

	LL_Iterate (entry->ll_joins, join) {
	    if (join->neighbor->interface == nbr->interface)
		break;
	}

	if (join) {
            trace (TR_PACKET, pim->trace, "join removed join "
	           "for group %a source %a holdtime %d from %a on %s\n",
                   entry->group, entry->source, entry->holdtime, nbr->prefix, 
		   nbr->interface->name);
	    if (join == LL_GetHead (pim->ll_joins)) {
		LL_RemoveFn (entry->ll_joins, join, NULL);
		LL_Remove (pim->ll_joins, join);
		join = LL_GetHead (pim->ll_joins);
        	Timer_Set_Time (pim->join_timer, join->expire - now);
        	Timer_Turn_ON (pim->join_timer);
	    }
	    else {
		LL_RemoveFn (entry->ll_joins, join, NULL);
		LL_Remove (pim->ll_joins, join);
	    }
	}
	else {
            trace (TR_PACKET, pim->trace, "join no match join "
	           "for group %a source %a holdtime %d from %a on %s\n",
                   entry->group, entry->source, entry->holdtime, nbr->prefix, 
		   nbr->interface->name);
	}
    }
}


static void
pim_recv_graft (pim_t *pim, pim_neighbor_t *nbr,
	        prefix_t *group, prefix_t *source, pim_neighbor_t *target)
{
    cache_entry_t *entry;
    time_t now;

    if (target == NULL || BIT_TEST (target->flags, PIM_NEIGHBOR_MYSELF)) {
	/* send an ack back anyway */
        pim_send_join_prune_graft (pim, PIM_MSG_GRAFT_ACK, nbr->prefix, 0,
				   group, source, nbr->interface);
    }

    time (&now);
    entry = cache_lookup (source, group);
    if (entry == NULL) {
        trace (TR_PACKET, pim->trace, "graft no entry "
	       "for group %a source %a from %a on %s\n",
               group, source, nbr->prefix, nbr->interface->name);
	return;
    }
    if (target == NULL || BIT_TEST (target->flags, PIM_NEIGHBOR_MYSELF)) {
	pim_prune_t *prune = NULL;
	int need_graft = 0;

	if (entry->ll_prunes) {
	    LL_Iterate (entry->ll_prunes, prune) {
	        if (prune->neighbor == nbr)
		    break;
	    }
	}
	if (prune) {
            trace (TR_PACKET, pim->trace, "graft cancelled prune "
	       "for group %a source %a from %a on %s\n",
               group, source, nbr->prefix, nbr->interface->name);
	    LL_RemoveFn (prune->entry->ll_prunes, prune, NULL);
	    LL_Remove (pim->ll_prunes, prune);
	    /* don't need to worry about the timer. It will fire as it is */
	}

	if (BITX_TEST (&entry->routers, nbr->interface->index)) {
            trace (TR_PACKET, pim->trace, "graft already? "
	           "for group %a source %a from %a on %s\n",
                   group, source, nbr->prefix, nbr->interface->name);
	    return;
	}

	need_graft = BIT_TEST (entry->flags, CACHE_NEGATIVE);
	BITX_SET (&entry->routers, nbr->interface->index);
	if (!BITX_TEST (&entry->children, nbr->interface->index)) {
	    cache_update_mfc (entry);
	}
	assert (!BIT_TEST (entry->flags, CACHE_NEGATIVE));
	if (need_graft) {
	    pim_neighbor_t *nbr2;
	    entry->holdtime = PIM_DATA_TIMEOUT;
	    entry->expire = now + PIM_DATA_TIMEOUT;
	    if ((nbr2 = pim_index_to_neighbor (pim, entry->parent_index))
                != NULL) {
		pim_send_graft (pim, entry, nbr2);
	    }
	}
    }
    else {
        trace (TR_PACKET, pim->trace, "graft not at me "
	       "for group %a source %a from %a on %s\n",
               group, source, nbr->prefix, nbr->interface->name);
    }
}


static void 
pim_recv_graft_ack (pim_t *pim, pim_neighbor_t *nbr,
               prefix_t *group, prefix_t *source)
{           
    cache_entry_t *entry;
    time_t now;
            
    time (&now);   
    entry = cache_lookup (source, group);
    if (entry == NULL) {
        trace (TR_PACKET, pim->trace, "graft ack no entry "
               "for group %a source %a from %a on %s\n",
               group, source, nbr->prefix, nbr->interface->name);
        return;
    }       
    if (!BIT_TEST (entry->flags, CACHE_PIM_GRAFT)) {
        trace (TR_PACKET, pim->trace, "graft ack already done? "
               "for group %a source %a from %a on %s\n",
               group, source, nbr->prefix, nbr->interface->name);
        return;
    }
    BIT_RESET (entry->flags, CACHE_PIM_GRAFT);
    /* later the corresponding graft entry will be removed */
    trace (TR_PACKET, pim->trace, "graft acknowledged "
           "for group %a source %a from %a on %s\n",
           group, source, nbr->prefix, nbr->interface->name);
}


static void
pim_recv_join_prune_graft (pim_t *pim, int type, interface_t *interface, 
			   prefix_t *from, u_char *cp, int len)
{
    u_char *endp = cp + len;
    int holdtime, reserved, ngroups;
    int njoins, nprunes;
    prefix_t prefix, group, source;
    pim_neighbor_t *nbr, *target = NULL;

    if (!BITX_TEST (&pim->interface_mask, interface->index) ||
	    BITX_TEST (&pim->force_leaf_mask, interface->index)) {
        trace (TR_WARN, pim->trace,
               "join/prune/graft from %a on disabled interface %s\n",
               from, interface->name);         
        return;
    }

    nbr = pim_lookup_neighbor (pim, interface, from);
    if (nbr == NULL) {
        trace (TR_WARN, pim->trace,
               "join/prune/graft from %a on %s was not from my neighbor\n",
               from, interface->name);         
	nbr = pim_register_neighbor (pim, interface, from, -1);
	return;
    }

    if (cp + 6 + 4 + 8 + 4 > endp)
	goto error;
    cp = pim_get_enc_uni (&prefix, cp);
    if (cp == NULL)
	goto error;
    if (type != PIM_GRAFT_ACK) {
	if (!prefix_is_unspecified (&prefix)) {
            target = pim_lookup_neighbor (pim, interface, &prefix);
	    if (target == NULL) {
                trace (TR_PACKET, pim->trace,
                       "join/prune/graft from %a on %s to unknown %a\n",
                       from, interface->name, &prefix);         
		return;
	    }
	}
    }
    MRT_GET_BYTE (reserved, cp);
    MRT_GET_BYTE (ngroups, cp);
    MRT_GET_SHORT (holdtime, cp);
    cp = pim_get_enc_multi (&group, cp);
    if (cp == NULL)
	goto error;
    while (ngroups--) {
        if (cp + 2 + 2 > endp)
	    goto error;
    	MRT_GET_SHORT (njoins, cp); /* number of joins */
    	MRT_GET_SHORT (nprunes, cp); /* number of prunes */
	while (njoins--) {
            if (cp + 8 > endp)
	        goto error;
    	    cp = pim_get_enc_src (&source, cp);
	    if (cp == NULL) {
		goto error;
	    }
	    if (type == PIM_GRAFT)
	        pim_recv_graft (pim, nbr, &group, &source, target);
	    else if (type == PIM_GRAFT_ACK)
	        pim_recv_graft_ack (pim, nbr, &group, &source);
	    else
	        pim_recv_join (pim, nbr, holdtime, &group, &source, target);
	}
	while (nprunes--) {
            if (cp + 8 > endp)
	        goto error;
    	    cp = pim_get_enc_src (&source, cp);
	    if (cp == NULL)
		goto error;
	    if (type == PIM_GRAFT || type == PIM_GRAFT_ACK) {
        	trace (TR_WARN, pim->trace,
                   "graft with prunes??? from %a on %s\n",                     
                   from, interface->name);
		return;
	    }
	    pim_recv_prune (pim, nbr, holdtime, &group, &source, target);
            if (target == NULL || 
			BIT_TEST (target->flags, PIM_NEIGHBOR_MYSELF)) {
		pim_send_join_prune_graft (pim, PIM_MSG_PRUNE,
                           &prefix, holdtime, &group, &source,
			   interface);
	    }
	}
    }
    if (cp != endp) {
        trace (TR_WARN, pim->trace,
               "packet length mismatch (%d) from %a on %s\n",
               cp - endp, from, interface->name);
    }
    return;

error:
    if (cp == 0) {
        trace (TR_WARN, pim->trace,
               "error in encorded address from %a on %s\n",                     
               from, interface->name);
    }
    else {
        trace (TR_WARN, pim->trace,
               "packet too short from %a on %s\n",                     
               from, interface->name);
    }
    return;
}


static void
pim_find_parent (pim_t *pim, cache_entry_t *entry, interface_t **parent_p,
		 int *parent_index_p)
{
    interface_t *parent = NULL;
    int parent_index = -1;

    /* a packet generated from myself */
    if ((parent = find_interface_local (entry->source)) != NULL) {
	parent_index = 0 /* myself */;
        trace (TR_TRACE, pim->trace,
               "local loopback on %s for source %a group %a\n", 
		parent->name, entry->source, entry->group);
    }
    else {
        nexthop_t *nexthop = NULL;
        if (MRT->rib_find_upstream) {
	    nexthop = MRT->rib_find_upstream (entry->source, SAFI_MULTICAST);
	    if (nexthop == NULL)
	        nexthop = MRT->rib_find_upstream (entry->source, 
						  SAFI_UNICAST);
	}
        if (nexthop == NULL || nexthop->interface == NULL) {
	    parent = NULL;
            trace (TR_TRACE, pim->trace,
                   "no route found (source %a group %a)\n", 
		    entry->source, entry->group);
        }
	else {
    	    pim_interface_t *vif;

	    parent = nexthop->interface;
	    if ((vif = pim->pim_interfaces[parent->index]) == NULL) {
	        parent = NULL;
                trace (TR_TRACE, pim->trace,
                       "upstream %s is not enabled for pim (source %a group %a)\n", 
		        nexthop->interface->name, entry->source, entry->group);
            }
	    else {
		if (nexthop->prefix == NULL || 
			prefix_is_unspecified (nexthop->prefix)) {
	    	    parent_index = 0 /* direct */;
        	    trace (TR_TRACE, pim->trace,
               	    	   "direct on %s for source %a group %a\n", 
			    nexthop->interface->name, entry->source, entry->group);
		}
		else {
    		    pim_neighbor_t *nbr;
    	    	    if ((nbr = pim_lookup_neighbor (pim, nexthop->interface, 
					    nexthop->prefix)) == NULL) {
        		trace (TR_TRACE, pim->trace,
               	       		"upstream %a on %s is not a pim neighbor "
				"for source %a group %a\n", 
				nexthop->prefix, nexthop->interface->name, 
				entry->source, entry->group);
			nbr = pim_register_neighbor (pim, nexthop->interface, 
					     nexthop->prefix, -1);
		    }
		    else {
        		trace (TR_TRACE, pim->trace,
               			"upstream %a found on %s for source %a group %a\n", 
				nbr->prefix, nbr->interface->name, 
				entry->source, entry->group);
		    }
	    	    parent_index = nbr->index;
		}
	    }
	}
    }
    if (parent_p)
	*parent_p = parent;
    if (parent_index_p)
	*parent_index_p = parent_index;
}


static void
pim_check_route_change (pim_t *pim)
{
    cache_entry_t *entry;
    cache_t *cache = proto2cache (pim->proto);

    HASH_Iterate (cache->hash, entry) {
        interface_t *parent = NULL;
        int parent_index = -1;

	if (BIT_TEST (entry->flags, CACHE_DELETE))
	    continue;
	
	pim_find_parent (pim, entry, &parent, &parent_index);

	if (entry->parent == parent && entry->parent_index == parent_index)
	    continue;

	if (entry->parent_index >= 0 &&
		!BIT_TEST (entry->flags, CACHE_NEGATIVE)) {
	    pim_neighbor_t *nbr;
    	    nbr = pim_index_to_neighbor (pim, entry->parent_index);
	    pim_send_join_prune_graft (pim, PIM_MSG_PRUNE, nbr->prefix,
                           PIM_DATA_TIMEOUT, entry->group,
                           entry->source, nbr->interface);
	    if (entry->parent != parent)
	        BITX_SET (&entry->routers, entry->parent->index);
	}

	if (parent && entry->parent != parent)
	    BITX_RESET (&entry->routers, parent->index);

	entry->parent = parent;
	entry->parent_index = parent_index;

	cache_update_mfc (entry);

	if (entry->parent_index >= 0 &&
		!BIT_TEST (entry->flags, CACHE_NEGATIVE)) {
	    pim_neighbor_t *nbr;
    	    nbr = pim_index_to_neighbor (pim, entry->parent_index);
	    pim_send_graft (pim, entry, nbr);
	}
    }
}


static int
pim_update_call_fn (int code, cache_t *cache, cache_entry_t *entry)
{
    pim_t *pim = NULL;
    pim_interface_t *vif;
    int need_prune = 1;
    interface_t *parent;
    int parent_index;
    pim_neighbor_t *nbr;

    assert (entry);
    assert (entry->group);
#ifdef HAVE_MROUTING
    if (entry->group->family == AF_INET)
        pim = PIM;
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
    if (entry->group->family == AF_INET6)
	pim = PIMv6;
#endif /* HAVE_MROUTING6 */
    assert (pim);

    switch (code) {
    case MRTMSG_NOCACHE:
	pim_find_parent (pim, entry, &parent, &parent_index);
	entry->parent = parent;
	entry->parent_index = parent_index;

        if (parent == NULL) {
            return (-1);
        }

	if (parent_index == 0) /* myself or direct */ {
	    /* don't need to send a prune */
	    need_prune = 0;
	    goto check;
	}

	if ((nbr = pim_index_to_neighbor (pim, parent_index)) == NULL)
	    return (-1);

    check:
 	assert (entry->parent);
	LL_Iterate (pim->ll_pim_interfaces, vif) {
	    if (vif->interface == entry->parent)
		continue;
	    if (igmp_test_membership (entry->group, vif->interface)) {
		BITX_SET (&entry->children, vif->interface->index);
		need_prune = 0;
	    }
	    if ((vif->flags & PIM_VIF_LEAF) == 0) {
		BITX_SET (&entry->routers, vif->interface->index);
		need_prune = 0;
	    }
	}
	entry->holdtime = PIM_DATA_TIMEOUT;
	if (need_prune && (nbr = pim_index_to_neighbor (pim, 
				entry->parent_index)) != NULL) {
	    /* PIM doesn't need to resend a prune since hold time is 
	       less than 210 sec instead of ~2 hours in case of dvmrp */
	    pim_send_join_prune_graft (pim, PIM_MSG_PRUNE,
                           nbr->prefix, PIM_DATA_TIMEOUT,
                           entry->group, entry->source, nbr->interface);
	}
	return (1);
    case MRTMSG_UPDATE:
{	int init_zero;
	int nmem = 0;
 	assert (entry->parent);
	init_zero = (ifor (&entry->children, &entry->routers, NULL, 
			    sizeof (entry->children)) == 0);
	memset (&entry->children, 0, sizeof (entry->children));
	memset (&entry->routers, 0, sizeof (entry->routers));
	LL_Iterate (pim->ll_pim_interfaces, vif) {
	    if (vif->interface == entry->parent)
		continue;
	    if (igmp_test_membership (entry->group, vif->interface)) {
		BITX_SET (&entry->children, vif->interface->index);
		nmem++;
	    }
	    if ((vif->flags & PIM_VIF_LEAF) == 0) {
		BITX_SET (&entry->routers, vif->interface->index);
		nmem++;
	    }
	}

        trace (TR_TRACE, pim->trace,
           "cache entry updated for source %a group %a parent %s nmem %d\n", 
		entry->source, entry->group, entry->parent->name, nmem);

	entry->holdtime = PIM_DATA_TIMEOUT;
	if ((nbr = pim_index_to_neighbor (pim, entry->parent_index)) != NULL) {
	    if (init_zero && nmem > 0) {
	        pim_send_graft (pim, entry, nbr);
	    } else if (!init_zero && nmem == 0) {
	        pim_send_join_prune_graft (pim, PIM_MSG_PRUNE,
                               nbr->prefix, PIM_DATA_TIMEOUT,
                               entry->group, entry->source, nbr->interface);
	    }
	}
	break;
}
    case MRTMSG_RESOLVE:
    case MRTMSG_EXPIRE:
    case MRTMSG_WRONGIF:
	break;
    case MRTMSG_NEWMEMBER:
	/* This is called only if the first new member appears */
	if ((nbr = pim_index_to_neighbor (pim, entry->parent_index))
                != NULL) {
	    pim_send_graft (pim, entry, nbr);
	}
	break;
    case MRTMSG_DELMEMBER:
	/* This is called only if the last member left */
	if ((nbr = pim_index_to_neighbor (pim, entry->parent_index))
                != NULL) {
            pim_send_join_prune_graft (pim, PIM_MSG_PRUNE, nbr->prefix, 
		   PIM_DATA_TIMEOUT, entry->group, 
		   entry->source, nbr->interface);
	}
	break;
    default:
	assert (0);
	break;
    }
    return (0);
}


/*
 * initialize pim stuff
 */
int
pim_init (int proto, trace_t * tr)
{
    pim_t *pim;
    char *name = NULL;
    char *pim_all_routers = NULL;
    igmp_t *igmp = NULL;

    pim = New (pim_t);
#ifdef HAVE_MROUTING
    if (proto == PROTO_PIM) {
	name = "PIM";
        pim_all_routers = "224.0.0.13";
	igmp = IGMP;
	PIM = pim;
    }
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
    if (proto == PROTO_PIMV6) {
	name = "PIMv6";
        pim_all_routers = "ff02::d";
	igmp = IGMPv6;
	PIMv6 = pim;
    }
#endif /* HAVE_MROUTING6 */
    assert (igmp);
    pim->trace = trace_copy (tr);
    pim->proto = proto;
    pim->sockfd = -1;
    pim->all_routers = ascii2prefix (0, pim_all_routers);

    set_trace (pim->trace, TRACE_PREPEND_STRING, name, 0);
    pim->schedule = igmp->schedule; /* run in igmp thread */
    pim->ll_pim_interfaces = LL_Create (0);
    memset (&pim->interface_mask, 0, sizeof (pim->interface_mask));
    pim->prune_timer = New_Timer2 ("PIM prune timer", 
				0, TIMER_ONE_SHOT, pim->schedule, 
				pim_timeout_prune, 1, pim);
    pim->ll_prunes = LL_Create (LL_CompareFunction, pim_comp_prune,
                                  LL_AutoSort, True,
                                  LL_DestroyFunction, FDelete, 0);
    pim->join_timer = New_Timer2 ("PIM join timer", 
				0, TIMER_ONE_SHOT, pim->schedule, 
				pim_timeout_join, 1, pim);
    pim->ll_joins = LL_Create (LL_CompareFunction, pim_comp_join,
                                  LL_AutoSort, True,
                                  LL_DestroyFunction, FDelete, 0);
    pim->graft_timer = New_Timer2 ("PIM graft timer", 
				0, TIMER_ONE_SHOT, pim->schedule, 
				pim_timeout_graft, 1, pim);
    pim->ll_grafts = LL_Create (LL_CompareFunction, pim_comp_graft,
                                  LL_AutoSort, True,
                                  LL_DestroyFunction, FDelete, 0);
#define PIM_ROUTE_CAHNGE_INTERVAL 15
    pim->route_timer = New_Timer2 ("PIM route timer", 
				PIM_ROUTE_CAHNGE_INTERVAL, 0,
				pim->schedule, 
				pim_check_route_change, 1, pim);

    return (1);
}


static void
pim_start (int proto)
{
    pim_t *pim = NULL;
    igmp_t *igmp = NULL;
    int family = 0;
    int sockfd = -1;

#ifdef HAVE_MROUTING
    if (proto == PROTO_PIM) {
    	pim = PIM;
    	igmp = IGMP;
    	family = AF_INET;
        sockfd = socket_open (family, SOCK_RAW, IPPROTO_PIM);
        if (sockfd >= 0) {
    	    socket_reuse (sockfd, 1);
	    socket_rcvbuf (sockfd, PIM_MAX_PDU);
	    ip_hdrincl (sockfd, 1);
    	    ip_multicast_loop (sockfd, 0);
	    ip_pktinfo (sockfd, 1);
    	    ip_recvttl (sockfd, 1);
        }
        if (CACHE == NULL) {
            /* XXX conflicts with dvmrp */
	    cache_init (family, pim->trace);
	}
	CACHE->update_call_fn = pim_update_call_fn;
    }
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
    if (proto == PROTO_PIMV6) {
	pim = PIMv6;
	igmp = IGMPv6;
	family = AF_INET6;
        sockfd = socket_open (family, SOCK_RAW, IPPROTO_PIMV6);
        if (sockfd >= 0) {
    	    socket_reuse (sockfd, 1);
	    socket_rcvbuf (sockfd, PIM_MAX_PDU);
#ifndef WIDE_IPV6
	    ip_hdrincl (sockfd, 0);
#endif /* WIDE_IPV6 */
    	    ipv6_multicast_loop (sockfd, 0);
	    ipv6_pktinfo (sockfd, 1);
	    ipv6_recvhops (sockfd, 1);
	    ipv6_multicast_hops (sockfd, 1);
	}
        if (CACHE6 == NULL) {
            /* XXX conflicts with dvmrp */
	    cache_init (family, pim->trace);
	}
	CACHE6->update_call_fn = pim_update_call_fn;
    }
#endif /* HAVE_MROUTING6 */
    assert (pim);

    if (sockfd < 0) {
	trace (TR_ERROR, pim->trace, "aborted due to error(s)\n");
	return;
    }
    select_add_fd_event ("pim_receive", sockfd, SELECT_READ, 1,
                         pim->schedule, pim_receive, 1, pim);
    pim->sockfd = sockfd;
    Timer_Turn_ON (pim->route_timer);
}


static void
pim_stop (int proto)
{
    pim_t *pim = NULL;
    int proto_igmp = -1;
    pim_interface_t *vif;
    pim_prune_t *prune;
    pim_join_t *join;

#ifdef HAVE_MROUTING
    if (proto == PROTO_PIM) {
        pim = PIM;
        proto_igmp = PROTO_IGMP;
    }
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
    if (proto == PROTO_PIMV6) {
	pim = PIMv6;
        proto_igmp = PROTO_IGMPV6;
    }
#endif /* HAVE_MROUTING6 */
    assert (pim);

    Timer_Turn_OFF (pim->prune_timer);
    LL_Iterate (pim->ll_prunes, prune) {
	LL_RemoveFn (prune->entry->ll_prunes, prune, NULL);
    }
    LL_Clear (pim->ll_prunes);
    Timer_Turn_OFF (pim->join_timer);
    LL_Iterate (pim->ll_joins, join) {
	LL_RemoveFn (join->entry->ll_joins, join, NULL);
    }
    LL_Clear (pim->ll_joins);
    Timer_Turn_OFF (pim->graft_timer);
    LL_Clear (pim->ll_grafts);
    Timer_Turn_OFF (pim->route_timer);

    if (pim->sockfd >= 0) {
	trace (TR_INFO, pim->trace, "Closing scoket %d\n", pim->sockfd);
	select_delete_fdx (pim->sockfd);
	pim->sockfd = -1;
    }

    LL_Iterate (pim->ll_pim_interfaces, vif) {
        igmp_interface (proto_igmp, vif->interface, OFF); 
        pim->pim_interfaces[vif->interface->index] = NULL;
        Timer_Turn_OFF (vif->hello);
        Destroy_Timer (vif->hello);
        LL_Destroy (vif->ll_neighbors);
        Delete (vif);
    }
    LL_Clear (pim->ll_pim_interfaces);
    memset (&pim->interface_mask, 0, sizeof (pim->interface_mask));
    memset (&pim->force_leaf_mask, 0, sizeof (pim->force_leaf_mask));
}


/*
 * turn on/off the interface
 */
int
pim_activate_interface (int proto, interface_t *interface, int on)
{
    pim_t *pim = NULL;
    int proto_igmp = -1;
    pim_interface_t *vif = NULL;

#ifdef HAVE_MROUTING
    if (proto == PROTO_PIM) {
        pim = PIM;
        proto_igmp = PROTO_IGMP;
    }
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
    if (proto == PROTO_PIMV6) {
	pim = PIMv6;
        proto_igmp = PROTO_IGMPV6;
    }
#endif /* HAVE_MROUTING6 */
    assert (pim);

    if (!BIT_TEST (interface->flags, IFF_MULTICAST) &&
        !BIT_TEST (interface->flags, IFF_VIF_TUNNEL)) {
        trace (TR_ERROR, pim->trace,
               "on interface %s ignored due to NBMA\n",
               interface->name);
        return (-1);
    }   

    if (on) {
	if (BITX_TEST (&pim->interface_mask, interface->index))
	    return (0);
	if (BGP4_BIT_TEST (interface->protocol_mask, PROTO_DVMRP))
            return (0);
    }
    else {
	if (!BITX_TEST (&pim->interface_mask, interface->index))
	    return (0);
    }

    if (on) {

	if (BITX_TEST (&pim->force_leaf_mask, interface->index))
            on = 2; /* XXX */
        if (igmp_interface (proto_igmp, interface, on) < 0)
	    return (-1);

       /* someone may want to use mrtd for debugging, so mrouting is turned on
          even if there is only one multicast interface */

	if (LL_GetCount (pim->ll_pim_interfaces) <= 0)
	    pim_start (proto);
        if (pim->sockfd < 0)
	    return (-1);

	vif = New (pim_interface_t);
	vif->interface = interface;
	vif->ll_neighbors = LL_Create (LL_DestroyFunction, 
				       pim_delete_neighbor, 0);
	vif->flags = PIM_VIF_LEAF;
        vif->hello = New_Timer2 ("PIM hello timer", PIM_TIMER_HELLO_PERIOD, 0,
                               	 pim->schedule, (event_fn_t) pim_send_hello, 
				 2, pim, interface->index);
        timer_set_jitter2 (vif->hello, -50, 50); /* i'm not sure */
	pim->pim_interfaces [interface->index] = vif;
	LL_Add (pim->ll_pim_interfaces, vif);
	BITX_SET (&pim->interface_mask, interface->index);
    }

    /*
     * Join the specified multicast address
     */

    if (!BITX_TEST (&pim->force_leaf_mask, interface->index)) {
        join_leave_group (pim->sockfd, interface, pim->all_routers, on);
	if (on) {
	    pim_send_hello (pim, interface->index);
    	    Timer_Turn_ON (vif->hello);
	}
    }

    if (!on) {
	cache_update_to_down (pim->proto, interface->index);
	vif = pim->pim_interfaces[interface->index];
	pim->pim_interfaces[interface->index] = NULL;
	LL_Remove (pim->ll_pim_interfaces, vif);
        igmp_interface (proto_igmp, interface, on);
    	Timer_Turn_OFF (vif->hello);
	Destroy_Timer (vif->hello);
	LL_Destroy (vif->ll_neighbors);
	Delete (vif);
	BITX_RESET (&pim->interface_mask, interface->index);
	if (LL_GetCount (pim->ll_pim_interfaces) <= 0)
	    pim_stop (proto);
    }
    return (1);
}


int
pim_show_neighbors (uii_connection_t *uii, int proto)
{
    pim_interface_t *vif;
    pim_neighbor_t *nbr;
    pim_t *pim = NULL;
    time_t now;

#ifdef HAVE_MROUTING
    if (proto == PROTO_PIM)
        pim = PIM;
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
    if (proto == PROTO_PIMV6)
	pim = PIMv6;
#endif /* HAVE_MROUTING6 */
    assert (pim);

    time (&now);
    uii_add_bulk_output (uii, "%c %-25s %7s %8s %8s %5s\n",
            ' ', "Neighbor Address", "If", "Timeleft", "Holdtime", "Index");
    LL_Iterate (pim->ll_pim_interfaces, vif) {
	char strbuf[64] = "";

	if (vif->ll_neighbors == NULL || LL_GetCount (vif->ll_neighbors) == 0)
	    continue;

	LL_Iterate (vif->ll_neighbors, nbr) {
	    int c = 'P';
	    if (vif->flags & PIM_VIF_LEAF)
	        c = 'L';
	    if (BIT_TEST (nbr->flags, PIM_NEIGHBOR_DELETE))
	        c = 'D';
            uii_add_bulk_output (uii, "%c %-25a %7s %8d %8d %5d%s\n",
		    c, nbr->prefix, nbr->interface->name,
		    BIT_TEST (nbr->flags, PIM_NEIGHBOR_DELETE)?
			0:time_left (nbr->timeout),
                    nbr->holdtime, nbr->index, strbuf);
	}
    }
    return (1);
}

#endif /* HAVE_MROUTING || HAVE_MROUTING6 */

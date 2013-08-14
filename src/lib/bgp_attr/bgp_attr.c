/*
 * $Id: bgp_attr.c,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#include <mrt.h>
#include <aspath.h>
#include <bgp.h>
#include <ctype.h>

/*
 * BGP4+ code was originally written 
 *     by Francis Dupont <Francis.Dupont@inria.fr>.
 */

static int num_active_bgp_attr = 0;

#define bgp_attr_len(len) (1 /*attr flag*/ + 1 /*attr type*/ + 1 /*len*/ \
                           + (((len) > 255)? 1: 0) /* ext len */ + (len))

void
bgp_trace_attr (u_long flag, trace_t *tr, bgp_attr_t *attr, int type)
{
    u_long attribs = attr->attribs;

    if (type > 0) {
	if (!(attribs = BGP4_BIT_TEST (attribs, type)))
	    return;
    }

    /* avoid from evaluations */
    if (!(tr && BIT_TEST (tr->flags, flag)))
      return;

if (type >= 0) {
    /* type == 0 means "all types" available */

    if (BGP4_BIT_TEST (attribs, PA4_TYPE_ORIGIN))
	trace (flag, tr, "  %s: %s\n", bgptype2string (PA4_TYPE_ORIGIN),
				       origin2string (attr->origin));
    if (BGP4_BIT_TEST (attribs, PA4_TYPE_ASPATH))
	trace (flag, tr, "  %s: %A\n", bgptype2string (PA4_TYPE_ASPATH),
				       attr->aspath);
    if (BGP4_BIT_TEST (attribs, PA4_TYPE_NEXTHOP)) {
        if (attr->nexthop4)
	    trace (flag, tr, "  %s: %s\n", bgptype2string (PA4_TYPE_NEXTHOP),
		   prefix_toa (attr->nexthop4->prefix));
	trace (flag, tr, "  %s: %s\n", bgptype2string (PA4_TYPE_NEXTHOP),
				       prefix_toa (attr->nexthop->prefix));
    }
    if (BGP4_BIT_TEST (attribs, PA4_TYPE_METRIC))
	trace (flag, tr, "  %s: %d\n", bgptype2string (PA4_TYPE_METRIC),
				       attr->multiexit);
    if (BGP4_BIT_TEST (attribs, PA4_TYPE_LOCALPREF))
	trace (flag, tr, "  %s: %d\n", bgptype2string (PA4_TYPE_LOCALPREF),
				       attr->local_pref);
    if (BGP4_BIT_TEST (attribs, PA4_TYPE_ATOMICAGG))
	trace (flag, tr, "  %s\n", bgptype2string (PA4_TYPE_ATOMICAGG));
    if (BGP4_BIT_TEST (attribs, PA4_TYPE_AGGREGATOR))
	trace (flag, tr, "  %s: AS%d %s\n", 
	       bgptype2string (PA4_TYPE_AGGREGATOR),
	       attr->aggregator.as, prefix_toa (attr->aggregator.prefix));
    if (BGP4_BIT_TEST (attribs, PA4_TYPE_ORIGINATOR_ID))
	trace (flag, tr, "  %s: %s\n", bgptype2string (PA4_TYPE_ORIGINATOR_ID),
				       prefix_toa (attr->originator));
    if (BGP4_BIT_TEST (attribs, PA4_TYPE_CLUSTER_LIST))
	trace (flag, tr, "  %s: %s\n", bgptype2string (PA4_TYPE_CLUSTER_LIST),
				       cluster_list_toa (attr->cluster_list));
    if (BGP4_BIT_TEST (attribs, PA4_TYPE_COMMUNITY))
	trace (flag, tr, "  %s: %s\n", bgptype2string (PA4_TYPE_COMMUNITY),
				       community_toa (attr->community));
    if (BGP4_BIT_TEST (attribs, PA4_TYPE_DPA))
	trace (flag, tr, "  %s: AS%d %d\n", bgptype2string (PA4_TYPE_DPA),
				       attr->dpa.as, attr->dpa.value);
}
if (type <= 0) {
    if (attr->opt_trans_list) {
	u_char *xp;
	/* assume they are sorted */
	LL_Iterate (attr->opt_trans_list, xp) {
	    int flags, code, len;
	    u_char *xp2 = xp;

	    GET_PATH_ATTR (flags, code, len, xp2);
	    trace (flag, tr, "  UNKNOWN: flags 0x%x code %d len %d\n", 
		   flags, code, len);
	}
    }
}
}


void
bgp_trace_attr2 (bgp_attr_t * attr, trace_t * tr)
{
    trace (TR_PACKET, tr, "attribute:\n");
    bgp_trace_attr (TR_PACKET, tr, attr, 0);
#ifdef HAVE_IPV6
    if (attr->link_local)
	trace (TR_PACKET, tr, "  %s: %s\n", 
	       bgptype2string (PA4_TYPE_NEXTHOP),
	       prefix_toa (attr->link_local->prefix));
#endif /* HAVE_IPV6 */
}


/*
 * Given a pointer (and size) of BGP packet in memory, 
 * return linked lists of withdrawn prefixes, announced prefixes
 * and a BGP attribute structure
 */
int
bgp_process_update_packet (u_char * cp, int length, bgp_peer_t *peer)
{
    u_char *cpend = cp + length;
    int withlen;
    int attrlen;
    u_char *attrp;

    assert (peer);
    assert (peer->ll_withdraw == NULL);
    assert (peer->ll_announce == NULL);
    assert (peer->attr == NULL);
    peer->ll_withdraw = NULL;
    peer->ll_announce = NULL;
    peer->attr = NULL;
    peer->safi = 0;

    BGP_GET_V4UPDATE_UNREACH (withlen, cp);

    if (withlen + cp + BGP_ATTR_SIZE_LEN > cpend) {
	trace (TR_ERROR, peer->trace, "bad withdraw length %d\n", withlen);
	peer->subcode = BGP_ERRUPD_ATTRLIST; /* XXX */
	goto error;
    }

    if (withlen > 0) {

	u_char *cpend = cp + withlen;

	if (peer->ll_withdraw == NULL) {
	    peer->ll_withdraw = LL_Create (LL_DestroyFunction, Deref_Prefix, 0);
	    peer->safi = AFI_IP;
	}

        trace (TR_PACKET, peer->trace, "recv withdraw:\n");

        while (cp < cpend) {
            int bitlen;
            struct in_addr dest;
            prefix_t *prefix;

	    BGP_GET_BITCOUNT (bitlen, cp);
	    if (bitlen < 0 || bitlen > 32) {
	        trace (TR_ERROR, peer->trace, "bad bitlen %d (withdraw)\n", 
		       bitlen);
		peer->subcode = BGP_ERRUPD_BADNET;
		goto error;
	    }
	    BGP_GET_PREFIX (bitlen, &dest, cp);
	    prefix = New_Prefix (AF_INET, &dest, bitlen);
	    LL_Add (peer->ll_withdraw, prefix);

	     if (okay_trace (peer->trace, TR_PACKET))
	       trace (TR_PACKET, peer->trace, "  %s\n", prefix_toax (prefix));
        }
        if (cp != cpend) {
	    trace (TR_ERROR, peer->trace, "bad byte count %d (withdraw)\n", 
		   cp - cpend);
	    peer->subcode = BGP_ERRUPD_BADNET;
	    goto error;
        }
    }

    BGP_GET_UPDATE (attrlen, attrp, cp);

    if (attrlen + attrp > cpend) {
	trace (TR_ERROR, peer->trace, "bad attribute length %d\n", attrlen);
	peer->subcode = BGP_ERRUPD_ATTRLIST;
	goto error;
    }
    if (attrlen) {
        if (bgp_munge_attributes (attrlen, attrp, peer) == NULL &&
	    peer->code > 0)
	    return (-1);
    }

    if (cp >= cpend)
	return (0);

    /* this may be too strict but right now MRT doesn't accept the both */
    if (peer->ll_announce && LL_GetCount (peer->ll_announce) > 0) {
	trace (TR_ERROR, peer->trace, 
		"can't include both old and mp announces\n");
	peer->subcode = BGP_ERRUPD_ATTRLIST;
	goto error;
    }

    trace (TR_PACKET, peer->trace, "recv announce:\n");
    if (cp < cpend) {
	if (peer->safi > 0 && peer->safi != AFI_IP) {
	    trace (TR_ERROR, peer->trace,
	           "inconsistent safi %d\n", AFI_IP);
	    peer->code = BGP_ERR_UPDATE;
	    peer->subcode = BGP_ERRUPD_OPTATTR;
	    return (-1);
	}
	peer->safi = AFI_IP;
    }
    while (cp < cpend) {
	int bitlen;
        struct in_addr dest;
	prefix_t *prefix;

	BGP_GET_BITCOUNT (bitlen, cp);
	if (bitlen < 0 || bitlen > 32) {
	    trace (TR_ERROR, peer->trace, "bad bitlen %d (announce)\n", bitlen);
	    peer->subcode = BGP_ERRUPD_BADNET;
	    goto error;
	}
	BGP_GET_PREFIX (bitlen, &dest, cp);
	prefix = New_Prefix (AF_INET, &dest, bitlen);

	if (peer->ll_announce == NULL) {
	    peer->ll_announce = LL_Create (LL_DestroyFunction,
				      Deref_Prefix, 0);
	}

	LL_Add (peer->ll_announce, prefix);
	if (okay_trace (peer->trace, TR_PACKET))
	  trace (TR_PACKET, peer->trace, "  %s\n", prefix_toax (prefix));
    }
    if (cp != cpend) {
	trace (TR_ERROR, peer->trace, "bad byte count %d (announce)\n", 
	      cp - cpend);
	peer->subcode = BGP_ERRUPD_ATTRLIST;
error:
	peer->code = BGP_ERR_UPDATE;
	if (peer->ll_withdraw) {
	    LL_Destroy (peer->ll_withdraw);
	    peer->ll_withdraw = NULL;
	}
	if (peer->ll_announce) {
	    LL_Destroy (peer->ll_announce);
	    peer->ll_announce = NULL;
	}
	if (peer->attr) {
	    bgp_deref_attr (peer->attr);
	    peer->attr = NULL;
	}
	return (-1);
    }
    return (0);
}


static int
bgp_get_announced_mp_prefixes (u_char * cp, u_char * cpend, bgp_peer_t *peer)
{
    u_char dest[16];
    u_short afi, plen;
    u_char safi, nhalen, nsnpa;
    int i;
    char tmp6[64];
#ifdef HAVE_IPV6
    u_char lladdr[16];
#endif /* HAVE_IPV6 */
    int autoset = 0;
    prefix_t *prefix;

    int bgp4plus = (BIT_TEST (peer->options, BGP_BGP4PLUS_01)? 1: 0);

    if (cpend - cp < PA4_LEN_MPREACHNLRI) {
	trace (TR_ERROR, peer->trace,
	       "recv invalid length %d detected (announce)\n", cpend - cp);
	peer->code = BGP_ERR_UPDATE;
	peer->subcode = BGP_ERRUPD_OPTATTR;
	return (-1);
    }

    BGP_GET_SHORT (afi, cp);
    BGP_GET_BYTE (safi, cp);
    BGP_GET_BYTE (nhalen, cp);

    trace (TR_PACKET, peer->trace,
	   "announce afi %d safi %d nhalen %d\n",
	   afi, safi, nhalen);

#ifdef HAVE_IPV6
    if (afi != AFI_IP && afi != AFI_IP6) {
#else
    if (afi != AFI_IP) {
#endif /* HAVE_IPV6 */
	trace (TR_ERROR, peer->trace,
	       "recv announce unrecognize afi %d\n", afi);
	peer->code = BGP_ERR_UPDATE;
	peer->subcode = BGP_ERRUPD_OPTATTR;
	return (-1);
    }
#if defined(HAVE_MROUTING) || defined(HAVE_MROUTING6)
    if (safi != SAFI_UNICAST && safi != SAFI_MULTICAST) {
#else
    if (safi != SAFI_UNICAST) {
#endif /* HAVE_MROUTING || HAVE_MROUTING6 */
	trace (TR_ERROR, peer->trace,
	       "recv announce unrecognize safi %d\n", safi);
	peer->code = BGP_ERR_UPDATE;
	peer->subcode = BGP_ERRUPD_OPTATTR;
	return (-1);
    }
    if (peer->safi > 0 && peer->safi != safi) {
	trace (TR_ERROR, peer->trace,
	       "recv inconsistent safi %d\n", safi);
	peer->code = BGP_ERR_UPDATE;
	peer->subcode = BGP_ERRUPD_OPTATTR;
	return (-1);
    }
    peer->safi = safi;

#ifdef HAVE_IPV6
    if (afi == AFI_IP6) {
        if (nhalen != 16 && nhalen != 32) {
	    trace (TR_ERROR, peer->trace, 
	       "recv announce unrecognize nhalen %d\n", nhalen);
	    peer->code = BGP_ERR_UPDATE;
	    peer->subcode = BGP_ERRUPD_OPTATTR;
	    return (-1);
        }
    }
#endif /* HAVE_IPV6 */
    if (afi == AFI_IP) {
        if (nhalen != 0 && nhalen != 4) { /* XXX I don't know -- masaki */
	    trace (TR_ERROR, peer->trace, 
	           "recv announce unrecognize nhalen %d\n", nhalen);
	    peer->code = BGP_ERR_UPDATE;
	    peer->subcode = BGP_ERRUPD_OPTATTR;
	    return (-1);
        }
    }

#ifdef HAVE_IPV6
    if (afi == AFI_IP6) {
        BGP_GET_ADDR6 (dest, cp);
        trace (TR_PACKET, peer->trace, "  %s: %s\n",
	       bgptype2string (PA4_TYPE_NEXTHOP),
	       inet_ntop (AF_INET6, dest, tmp6, sizeof tmp6));

        if (nhalen == 32) {
	    BGP_GET_ADDR6 (lladdr, cp);
	    trace (TR_PACKET, peer->trace, "  %s: %s\n",
	           bgptype2string (PA4_TYPE_NEXTHOP),
	           inet_ntop (AF_INET6, lladdr, tmp6, sizeof tmp6));
        }
    }
#endif /* HAVE_IPV6 */

    if (afi == AFI_IP) {
	if (nhalen == 4) {
            BGP_GET_ADDR (dest, cp);
            trace (TR_PACKET, peer->trace, "  %s: %s\n",
	           bgptype2string (PA4_TYPE_NEXTHOP),
	           inet_ntop (AF_INET, dest, tmp6, sizeof tmp6));
	}
    }

    BGP_GET_BYTE (nsnpa, cp);
    if (nsnpa > 0) {
	trace (TR_PACKET, peer->trace,
	       "recv announce Number of SNPAs = %d\n", nsnpa);
	/* skip SNPAs */
	for (i = 0; i < (u_int) nsnpa; i++) {
	    BGP_GET_BYTE (nhalen, cp);
	    cp += (nhalen + 1) >> 1;
	}
    }

    if (cp >= cpend) {
	/* no prefix infomation */
        if (cpend == cp && bgp4plus == 0) {
    	    if (!BIT_TEST (peer->options, BGP_BGP4PLUS_01_RCVD)) {
    	        BIT_SET (peer->options, BGP_BGP4PLUS_01_RCVD);
	        trace (TR_ERROR, peer->trace,
	               "recv announce draft version should be 1\n");
	    }
	    bgp4plus = 1;
	    if (BIT_TEST (peer->options, BGP_BGP4PLUS_AUTO)) {
    	        autoset++;
	    }
	    else {
	        /* send notification */
	        peer->code = BGP_ERR_UPDATE;
	        peer->subcode = BGP_ERRUPD_OPTATTR;
	        return (-1);
	    }
	}
	goto finish;
    }

    BGP_GET_SHORT (plen, cp);
    if (cpend == cp + plen && bgp4plus != 0) {
	if (!BIT_TEST (peer->options, BGP_BGP4PLUS_00_RCVD)) {
	    trace (TR_ERROR, peer->trace,
	           "recv announce draft version should be 0\n");
	    BIT_SET (peer->options, BGP_BGP4PLUS_00_RCVD);
	}
	bgp4plus = 0;
	if (BIT_TEST (peer->options, BGP_BGP4PLUS_AUTO)) {
    	    autoset++;
	}
	else {
	    /* send notification */
	    peer->code = BGP_ERR_UPDATE;
	    peer->subcode = BGP_ERRUPD_OPTATTR;
	    return (-1);
	}
    }
    if (cpend != cp + plen && bgp4plus == 0) {
    	if (!BIT_TEST (peer->options, BGP_BGP4PLUS_01_RCVD)) {
    	    BIT_SET (peer->options, BGP_BGP4PLUS_01_RCVD);
	    trace (TR_ERROR, peer->trace,
	           "recv announce draft version should be 1\n");
	}
	bgp4plus = 1;
	if (BIT_TEST (peer->options, BGP_BGP4PLUS_AUTO)) {
    	    autoset++;
	}
	else {
	    /* send notification */
	    peer->code = BGP_ERR_UPDATE;
	    peer->subcode = BGP_ERRUPD_OPTATTR;
	    return (-1);
	}
    }
    cp -= 2;

    if (bgp4plus == 0) {
	BGP_GET_SHORT (plen, cp);
	trace (TR_PACKET, peer->trace,
	       "recv announce draft 0 len %d\n", plen);
	if (cp + plen != cpend) {
	    trace (TR_ERROR, peer->trace,
		   "recv announce left %d bytes at the end\n",
		   cpend - (cp + plen));
	    peer->code = BGP_ERR_UPDATE;
	    peer->subcode = BGP_ERRUPD_OPTATTR;
	    return (-1);
	}
	if (plen <= 0)
	    return (0);
	cpend = cp + plen;
    }

    assert (peer->attr);
#ifdef HAVE_IPV6
    if (afi == AFI_IP6) {
        if (peer->attr->nexthop) {
	    assert (peer->attr->nexthop->prefix->family == AF_INET);
	    peer->attr->nexthop4 = peer->attr->nexthop;
	    /* save ipv4 nexthop */
	    /* we don't have to count up */
        }

        /* XXX do we need to keep v4/v6 nexthop ? */
        prefix = New_Prefix (AF_INET6, dest, 128);
if (!BIT_TEST (peer->options, BGP_TRANSPARENT_NEXTHOP)) {
        if (!prefix_is_global (prefix) || prefix_is_multicast (prefix)) {
	    trace (TR_ERROR, peer->trace, 
	       "nexthop %a is unacceptable\n", prefix);
	    peer->code = BGP_ERR_UPDATE;
	    peer->subcode = BGP_ERRUPD_NEXTHOP;
	    Deref_Prefix (prefix);
	    return (-1);
	}
}
        peer->attr->nexthop = add_nexthop (prefix, 
		(BIT_TEST (peer->options, BGP_INTERNAL) ||
		 BIT_TEST (peer->options, BGP_PEER_SELF) ||
                 BIT_TEST (peer->options, BGP_EBGP_MULTIHOP))? NULL:
		(peer->gateway)? peer->gateway->interface: NULL);
        /* XXX so, PA4_TYPE_NEXTHOP changes its meaning */
        BGP4_BIT_SET (peer->attr->attribs, PA4_TYPE_NEXTHOP);
        Deref_Prefix (prefix);
        /* XXX old version of MRT puts 0 for link local */
        if (nhalen == 32) {
	    prefix = New_Prefix (AF_INET6, lladdr, 128);
if (!prefix_is_unspecified (prefix)) {
if (!BIT_TEST (peer->options, BGP_TRANSPARENT_NEXTHOP)) {
            if (!prefix_is_linklocal (prefix) || prefix_is_multicast (prefix)) {
	        trace (TR_ERROR, peer->trace, 
	           "nexthop %a is not link-local\n", prefix);
	        peer->code = BGP_ERR_UPDATE;
	        peer->subcode = BGP_ERRUPD_NEXTHOP;
	        Deref_Prefix (prefix);
	        return (-1);
	    }
}
		/* don't need in the following cases */
	    if (!BIT_TEST (peer->options, BGP_INTERNAL) &&
	        !BIT_TEST (peer->options, BGP_PEER_SELF) &&
	        !BIT_TEST (peer->options, BGP_EBGP_MULTIHOP)) {
	        peer->attr->link_local = add_nexthop (prefix, 
			 (peer->gateway)? peer->gateway->interface: NULL);
	    }
}
            Deref_Prefix (prefix);
        }
    }
#endif /* HAVE_IPV6 */
    if (afi == AFI_IP) {
	if (nhalen > 0) {
            if (peer->attr->nexthop) {
	        assert (peer->attr->nexthop->prefix->family == AF_INET);
	        peer->attr->nexthop4 = peer->attr->nexthop;
	        /* save ipv4 nexthop */
	        /* we don't have to count up */
            }
            /* XXX do we need to keep the original nexthop ? */
            prefix = New_Prefix (AF_INET, dest, 32);
if (!BIT_TEST (peer->options, BGP_TRANSPARENT_NEXTHOP)) {
            if (!prefix_is_global (prefix) || prefix_is_multicast (prefix)) {
	        trace (TR_ERROR, peer->trace, 
	               "nexthop %a is unacceptable\n", prefix);
	        peer->code = BGP_ERR_UPDATE;
	        peer->subcode = BGP_ERRUPD_NEXTHOP;
	        Deref_Prefix (prefix);
	        return (-1);
	    }
}
            peer->attr->nexthop = add_nexthop (prefix, 
		(BIT_TEST (peer->options, BGP_INTERNAL) ||
		 BIT_TEST (peer->options, BGP_PEER_SELF) ||
                 BIT_TEST (peer->options, BGP_EBGP_MULTIHOP))? NULL:
		(peer->gateway)? peer->gateway->interface: NULL);
            Deref_Prefix (prefix);
            /* XXX so, PA4_TYPE_NEXTHOP changes its meaning */
            BGP4_BIT_SET (peer->attr->attribs, PA4_TYPE_NEXTHOP);
	}
    }

    if (BIT_TEST (peer->options, BGP_INTERNAL) || 
	BIT_TEST (peer->options, BGP_EBGP_MULTIHOP)) {
	/* may be indirect */
    }
#ifdef notdef
    /* XXX route server may not have direct connection */
    else if (!BIT_TEST (peer->attr->nexthop->flags, GATEWAY_LOCAL) &&
	     !BIT_TEST (peer->attr->nexthop->flags, GATEWAY_DIRECT)) {
	trace (TR_ERROR, peer->trace, 
	       "nexthop %a is not direct\n", peer->attr->nexthop->prefix);
	peer->code = BGP_ERR_UPDATE;
	peer->subcode = BGP_ERRUPD_NEXTHOP;
	return (-1);
   }
#endif

    trace (TR_PACKET, peer->trace, "recv announce:\n");
    while (cp < cpend) {
        int bitlen;
	prefix_t *prefix = NULL;

	BGP_GET_BITCOUNT (bitlen, cp);
#ifdef HAVE_IPV6
	if (afi == AFI_IP6) {
	    if (bitlen < 0 || bitlen > 128) {
	        trace (TR_ERROR, peer->trace, 
		       "bad bitlen %d (announce)\n", bitlen);
	        peer->code = BGP_ERR_UPDATE;
	        peer->subcode = BGP_ERRUPD_BADNET;
	        return (-1);
	    }
	    BGP_GET_PREFIX6 (bitlen, dest, cp);
	    prefix = New_Prefix (AF_INET6, dest, bitlen);
	}
#endif /* HAVE_IPV6 */
	if (afi == AFI_IP) {
	    if (bitlen < 0 || bitlen > 32) {
	        trace (TR_ERROR, peer->trace, 
		       "bad bitlen %d (announce)\n", bitlen);
	        peer->code = BGP_ERR_UPDATE;
	        peer->subcode = BGP_ERRUPD_BADNET;
	        return (-1);
	    }
	    BGP_GET_PREFIX (bitlen, dest, cp);
	    prefix = New_Prefix (AF_INET, &dest, bitlen);
	}

	if (prefix) {
	    trace (TR_PACKET, peer->trace, "  %p\n", prefix);
	    if (peer->ll_announce == NULL)
	        peer->ll_announce = LL_Create (LL_DestroyFunction, 
					       Deref_Prefix, 0);
	    LL_Add (peer->ll_announce, prefix);
	}
    }

  finish:
    if (cp != cpend) {
	trace (TR_ERROR, peer->trace, "bad byte count %d (announce)\n", 
	      cp - cpend);
	peer->code = BGP_ERR_UPDATE;
	peer->subcode = BGP_ERRUPD_ATTRLIST;
	return (-1);
    }

    if (bgp4plus) {
    	BIT_SET (peer->options, BGP_BGP4PLUS_01_RCVD);
    }
    /*
     * Only if the packet was processed, fix the version automatically
     */
    if (autoset) {
	if (bgp4plus) {
    	    BIT_SET (peer->options, BGP_BGP4PLUS_01);
	    trace (TR_INFO, peer->trace, "version changed from 0 to 1\n");
	}
	else if (BIT_TEST (peer->options, BGP_BGP4PLUS_01_RCVD)) {
    	    BIT_RESET (peer->options, BGP_BGP4PLUS_01);
	    trace (TR_INFO, peer->trace, "version changed from 1 to 0\n");
	}
    }
    return (1);
}


static int
bgp_get_withdrawn_mp_prefixes (u_char * cp, u_char * cpend, bgp_peer_t *peer)
{
    u_short afi, plen;
    u_char safi;
    u_char dest[16];
    int autoset = 0;

    int bgp4plus = (BIT_TEST (peer->options, BGP_BGP4PLUS_01)? 1: 0);

    if (cpend - cp < PA4_LEN_MPUNRNLRI) {
	trace (TR_ERROR, peer->trace,
	       "recv invalid length %d detected (withdraw)\n", cpend - cp);
	peer->subcode = BGP_ERRUPD_OPTATTR;
	return (-1);
    }

    BGP_GET_SHORT (afi, cp);
    BGP_GET_BYTE (safi, cp);
    trace (TR_PACKET, peer->trace, "recv withdraw afi %d safi %d\n",
	   afi, safi);

#ifdef HAVE_IPV6
    if (afi != AFI_IP && afi != AFI_IP6) {
#else
    if (afi != AFI_IP) {
#endif /* HAVE_IPV6 */
	trace (TR_ERROR, peer->trace,
	       "recv withdraw unrecognize afi %d\n", afi);
	peer->subcode = BGP_ERRUPD_OPTATTR;
	return (-1);
    }
#if defined(HAVE_MROUTING) || defined(HAVE_MROUTING6)
    if (safi != SAFI_UNICAST && safi != SAFI_MULTICAST) {
#else
    if (safi != SAFI_UNICAST) {
#endif /* HAVE_MROUTING || HAVE_MROUTING6 */
	trace (TR_ERROR, peer->trace,
	       "recv withdraw unrecognize safi %d\n", safi);
	peer->subcode = BGP_ERRUPD_OPTATTR;
	return (-1);
    }
    if (peer->safi > 0 && peer->safi != safi) {
	trace (TR_ERROR, peer->trace,
	       "recv inconsistent safi %d\n", safi);
	peer->code = BGP_ERR_UPDATE;
	peer->subcode = BGP_ERRUPD_OPTATTR;
	return (-1);
    }
    peer->safi = safi;

    if (cp >= cpend) {
	/* no prefix infomation */
        if (cpend == cp && bgp4plus == 0) {
    	    if (!BIT_TEST (peer->options, BGP_BGP4PLUS_01_RCVD)) {
    	        BIT_SET (peer->options, BGP_BGP4PLUS_01_RCVD);
	        trace (TR_ERROR, peer->trace,
	               "recv announce draft version should be 1\n");
	    }
	    bgp4plus = 1;
	    if (BIT_TEST (peer->options, BGP_BGP4PLUS_AUTO)) {
    	        autoset++;
	    }
	    else {
	        /* send notification */
	        peer->code = BGP_ERR_UPDATE;
	        peer->subcode = BGP_ERRUPD_OPTATTR;
	        return (-1);
	    }
	}
	goto finish;
    }

    BGP_GET_SHORT (plen, cp);
    if (cpend == cp + plen && bgp4plus != 0) {
	if (!BIT_TEST (peer->options, BGP_BGP4PLUS_00_RCVD)) {
	    trace (TR_ERROR, peer->trace,
	       "recv withdraw draft version should be 0\n");
	    BIT_SET (peer->options, BGP_BGP4PLUS_00_RCVD);
	}
	bgp4plus = 0;
	if (BIT_TEST (peer->options, BGP_BGP4PLUS_AUTO)) {
    	    autoset++;
	}
	else {
	    /* send notification */
	    peer->subcode = BGP_ERRUPD_OPTATTR;
	    return (-1);
	}
    }
    if (cpend != cp + plen && bgp4plus == 0) {
    	if (!BIT_TEST (peer->options, BGP_BGP4PLUS_01_RCVD)) {
    	    BIT_SET (peer->options, BGP_BGP4PLUS_01_RCVD);
	    trace (TR_ERROR, peer->trace,
	           "recv withdraw draft version should be 1\n");
	}
	bgp4plus = 1;
	if (BIT_TEST (peer->options, BGP_BGP4PLUS_AUTO)) {
    	    autoset++;
	}
	else {
	    /* send notification */
	    peer->subcode = BGP_ERRUPD_OPTATTR;
	    return (-1);
	}
    }
    cp -= 2;

    if (bgp4plus == 0) {
	BGP_GET_SHORT (plen, cp);
	trace (TR_PACKET, peer->trace,
	       "recv withdraw draft 0 len %d\n", plen);
	if (cpend != cp + plen) {
	    trace (TR_ERROR, peer->trace,
		   "recv withdraw left %d bytes at the end\n",
		   cpend - (cp + plen));
	    peer->subcode = BGP_ERRUPD_OPTATTR;
	    return (-1);
	}
	cpend = cp + plen;

	if (plen <= 0)
	    return (0);
    }

    trace (TR_PACKET, peer->trace, "recv withdraw:\n");
    while (cp < cpend) {
        int bitlen;
	prefix_t *prefix = NULL;

	BGP_GET_BITCOUNT (bitlen, cp);
#ifdef HAVE_IPV6
	if (afi == AFI_IP6) {
	    if (bitlen < 0 || bitlen > 128) {
	        trace (TR_ERROR, peer->trace, 
			"bad bitlen %d (withdraw)\n", bitlen);
	        peer->subcode = BGP_ERRUPD_BADNET;
	        return (-1);
	    }
	    BGP_GET_PREFIX6 (bitlen, dest, cp);
	    prefix = New_Prefix (AF_INET6, dest, bitlen);
	}
#endif /* HAVE_IPV6 */
	if (afi == AFI_IP) {
	    if (bitlen < 0 || bitlen > 32) {
	        trace (TR_ERROR, peer->trace, 
			"bad bitlen %d (withdraw)\n", bitlen);
	        peer->subcode = BGP_ERRUPD_BADNET;
	        return (-1);
	    }
	    BGP_GET_PREFIX (bitlen, dest, cp);
	    prefix = New_Prefix (AF_INET, dest, bitlen);
	}

	if (prefix) {
	    trace (TR_PACKET, peer->trace, "  %p\n", prefix);
	    if (peer->ll_withdraw == NULL)
	        peer->ll_withdraw = LL_Create (LL_DestroyFunction, 
					       Deref_Prefix, 0);
	    LL_Add (peer->ll_withdraw, prefix);
	}
    }

  finish:
    if (cp != cpend) {
	trace (TR_ERROR, peer->trace, "bad byte count %d (withdraw)\n", 
	      cp - cpend);
	peer->subcode = BGP_ERRUPD_ATTRLIST;
	return (-1);
    }

    if (bgp4plus) {
        BIT_SET (peer->options, BGP_BGP4PLUS_01_RCVD);
    }
    /*
     * Only if the packet was processed, fix the version automatically
     */
    if (autoset) {
	if (bgp4plus) {
    	    BIT_SET (peer->options, BGP_BGP4PLUS_01);
	    trace (TR_INFO, peer->trace, "version changed from 0 to 1\n");
	}
	else if (!BIT_TEST (peer->options, BGP_BGP4PLUS_01_RCVD)) {
    	    BIT_RESET (peer->options, BGP_BGP4PLUS_01);
	    trace (TR_INFO, peer->trace, "version changed from 1 to 0\n");
	}
    }
    return (1);
}


static int
bgp_unknown_attr_compare (u_char *a, u_char *b)
{
    int acode, bcode;
    int flags, len;

    GET_PATH_ATTR (flags, acode, len, a);
    GET_PATH_ATTR (flags, bcode, len, b);

    return (acode - bcode);
}


/* 
 * Given a length and byte string from a BGP4 packet, return origin,
 * linked list of as_path_segments, and other attributes
 */
bgp_attr_t *
bgp_munge_attributes (int attrlen, u_char * cp, bgp_peer_t *peer)
{
    u_char *endp;
    u_int flags;
    u_int code;
    u_char seen[256];
    int len = 0;
    u_long value;
    u_char *at;
    prefix_t *prefix;

    assert (peer);
    assert (peer->attr == NULL);
    peer->attr = bgp_new_attr (PROTO_BGP);
    memset (seen, 0, sizeof seen);
    endp = cp + attrlen;

    trace (TR_PACKET, peer->trace, "recv attribute:\n");
    while (cp < endp) {

	if (endp - cp < bgp_attr_len (0)) {
	    trace (TR_ERROR, peer->trace, 
		   "bad remaining length %d\n", endp - cp);
	    peer->subcode = BGP_ERRUPD_ATTRLIST;
	    goto error;
	}
	GET_PATH_ATTR (flags, code, len, cp);
	at = cp;

#ifdef notdef
	trace (TR_PACKET, peer->trace,
	       "recv flags = %x, code %d, len = %d, cp = %x, endp = %x\n",
	       flags, code, len, cp, endp);
#endif

	if (seen[code]) {
	    /* duplicate code */
	    trace (TR_ERROR, peer->trace, 
		   "duplicate attribute: flags 0x%x code %d len %d\n", 
		    flags, code, len);
	    peer->subcode = BGP_ERRUPD_ATTRLIST;
	    goto error;
	}
	else {
	    seen[code]++;
	}

 	/* this may be too strict but right now MRT doesn't accept them */
	if (code == PA4_TYPE_MPUNRNLRI && peer->ll_withdraw &&
		LL_GetCount (peer->ll_withdraw) > 0) {
	    trace (TR_ERROR, peer->trace, 
		   "can't include both old and mp withdraws\n");
	    peer->subcode = BGP_ERRUPD_ATTRLIST;
	    goto error;
	}

	if (cp + len > endp) {
	    trace (TR_ERROR, peer->trace, "bad attribute length %d\n", len);
	    peer->subcode = BGP_ERRUPD_LENGTH;
	    goto error;
	}

	/* check the case that should not happen */
	/* well-known but non-transitive and well-known but partial set */
	if (!BIT_TEST(flags, PA_FLAG_OPT)) {
            if (!BIT_TEST(flags, PA_FLAG_TRANS) || 
		 BIT_TEST(flags, PA_FLAG_PARTIAL)) {
	        trace (TR_ERROR, peer->trace, "bad flags 0x%x (code %d)\n", 
		      flags, code);
	        peer->subcode = BGP_ERRUPD_FLAGS;
		goto error;
            }
        }
        /* optional non-transitive must has Partial bit 0 */
	if (BIT_TEST(flags, PA_FLAG_OPT) && !BIT_TEST(flags, PA_FLAG_TRANS) &&
		BIT_TEST(flags, PA_FLAG_PARTIAL)) {
	   trace (TR_ERROR, peer->trace, "bad flags 0x%x (code %d)\n", 
		  flags, code);
	    peer->subcode = BGP_ERRUPD_FLAGS;
	    goto error;
        }
#ifdef notdef
	/* The flag was already reset in GET_PATH_ATTR */
	/* Extended bit may be 1 only if the length is greater than 255 */
	if (BIT_TEST(flags, PA_FLAG_EXTLEN) && len > 255) {
	   trace (TR_ERROR, peer->trace, 
		  "extended flag set but len %d <= 255 (code %d)\n", 
		  len, code);
	    peer->subcode = BGP_ERRUPD_FLAGS;
	    goto error;
	}
#endif

	switch (code) {
	case PA4_TYPE_INVALID:
	default:
	    break;
	case PA4_TYPE_ORIGIN:
	case PA4_TYPE_ASPATH:
	case PA4_TYPE_NEXTHOP:
	case PA4_TYPE_LOCALPREF:
	case PA4_TYPE_ATOMICAGG:
	    /* Well-known Transitive */
	    if ((flags & PA_FLAG_OPTTRANS) != PA_FLAG_TRANS) {
	        trace (TR_ERROR, peer->trace, "bad flags 0x%x (code %d)\n", 
		      flags, code);
	        peer->subcode = BGP_ERRUPD_FLAGS;
		goto error;
	    }
	    break;
	case PA4_TYPE_METRIC:	/* multiexit */
	case PA4_TYPE_ORIGINATOR_ID:
	case PA4_TYPE_CLUSTER_LIST:
	case PA4_TYPE_ADVERTISER:
	case PA4_TYPE_RCID_PATH:
	case PA4_TYPE_MPUNRNLRI:
	case PA4_TYPE_MPREACHNLRI:
	    /* Optional Non-Transitive */
	    if ((flags & PA_FLAG_OPTTRANS) != PA_FLAG_OPT) {
	        trace (TR_ERROR, peer->trace, "bad flags 0x%x (code %d)\n", 
		      flags, code);
	        peer->subcode = BGP_ERRUPD_FLAGS;
		goto error;
	    }
	    break;
	case PA4_TYPE_COMMUNITY:
	case PA4_TYPE_AGGREGATOR:
	case PA4_TYPE_DPA:
	    /* Optional Transitive */
	    if ((flags & PA_FLAG_OPTTRANS) != (PA_FLAG_OPT | PA_FLAG_TRANS)) {
	        trace (TR_ERROR, peer->trace, "bad flags 0x%x (code %d)\n", 
		      flags, code);
	        peer->subcode = BGP_ERRUPD_FLAGS;
		goto error;
	    }
	    break;
	}

	switch (code) {
	case PA4_TYPE_INVALID:
	    trace (TR_ERROR, peer->trace, "code %d is invalid\n");
	    peer->subcode = BGP_ERRUPD_ATTRLIST;
	    goto error;
	case PA4_TYPE_ORIGIN:
	    if (len != PA4_LEN_ORIGIN) {
	        trace (TR_ERROR, peer->trace, "bad length %d (origin)\n", len);
	        peer->subcode = BGP_ERRUPD_LENGTH;
		goto error;
	    }
	    BGP_GET_BYTE (peer->attr->origin, cp);
	    if (/* peer->attr->origin < 0 || */ peer->attr->origin > 2) {
	        trace (TR_ERROR, peer->trace, "bad prigin code %d\n", 
		       peer->attr->origin);
	        peer->subcode = BGP_ERRUPD_ORIGIN;
		goto error;
	    }
	    BGP4_BIT_SET (peer->attr->attribs, code);
	    bgp_trace_attr (TR_PACKET, peer->trace, peer->attr, code);
	    break;
	case PA4_TYPE_ASPATH:
	    if (len == 0) {
		/* NULL aspath for iBGP */
	        peer->attr->aspath = NULL;
	        peer->attr->home_AS = 0;
	    }
	    else if ((len % PA4_LEN_ASPATH) != 0) {
	        trace (TR_ERROR, peer->trace, "bad length %d (aspath)\n", len);
	        peer->subcode = BGP_ERRUPD_LENGTH;
		goto error;
	    }
	    else {
	        if ((peer->attr->aspath = munge_aspath (len, cp)) == NULL) {
		    peer->subcode = BGP_ERRUPD_ASPATH;
	            goto error;
		}
		peer->attr->aspath = aspath_reduce (peer->attr->aspath);
	        peer->attr->home_AS = bgp_get_home_AS (peer->attr->aspath);
	        cp += len;
	    }
	    BGP4_BIT_SET (peer->attr->attribs, code);
	    bgp_trace_attr (TR_PACKET, peer->trace, peer->attr, code);
	    break;
	case PA4_TYPE_NEXTHOP:
	    if (len != PA4_LEN_NEXTHOP) {
	        trace (TR_ERROR, peer->trace, "bad length %d (nexthop)\n", len);
		peer->subcode = BGP_ERRUPD_LENGTH;
	        goto error;
	    }
	    BGP_GET_NETLONG (value, cp);
	    prefix = New_Prefix (AF_INET, &value, 32);
if (!BIT_TEST (peer->options, BGP_TRANSPARENT_NEXTHOP)) {
            if (!prefix_is_global (prefix) || prefix_is_multicast (prefix)) {
	        trace (TR_ERROR, peer->trace, 
	               "nexthop %a is unacceptable\n", prefix);
	        peer->subcode = BGP_ERRUPD_NEXTHOP;
	        Deref_Prefix (prefix);
	        goto error;
	    }
}
	    peer->attr->nexthop = add_nexthop (prefix, 
			(BIT_TEST (peer->options, BGP_INTERNAL) ||
			 BIT_TEST (peer->options, BGP_PEER_SELF) ||
                 	 BIT_TEST (peer->options, BGP_EBGP_MULTIHOP))? NULL:
			(peer->gateway)? peer->gateway->interface: NULL);
	    Deref_Prefix (prefix);
	    BGP4_BIT_SET (peer->attr->attribs, code);
	    bgp_trace_attr (TR_PACKET, peer->trace, peer->attr, code);
	    break;
	case PA4_TYPE_METRIC:	/* multiexit */
	    if (len != PA4_LEN_METRIC) {
	        trace (TR_ERROR, peer->trace, "bad length %d (metric)\n", len);
		peer->subcode = BGP_ERRUPD_LENGTH;
	        goto error;
	    }
	    BGP_GET_LONG (peer->attr->multiexit, cp);
	    BGP4_BIT_SET (peer->attr->attribs, code);
	    bgp_trace_attr (TR_PACKET, peer->trace, peer->attr, code);
	    break;
	case PA4_TYPE_LOCALPREF:
	    if (len != PA4_LEN_LOCALPREF) {
	        trace (TR_ERROR, peer->trace, "bad length %d (localpref)\n", 
		       len);
		peer->subcode = BGP_ERRUPD_LENGTH;
	        goto error;
	    }
	    BGP_GET_LONG (peer->attr->local_pref, cp);
	    BGP4_BIT_SET (peer->attr->attribs, code);
	    bgp_trace_attr (TR_PACKET, peer->trace, peer->attr, code);
	    break;
	case PA4_TYPE_ATOMICAGG:
	    if (len != PA4_LEN_ATOMICAGG) {
	        trace (TR_ERROR, peer->trace, "bad length %d (atomicagg)\n", 
		       len);
		peer->subcode = BGP_ERRUPD_LENGTH;
	        goto error;
	    }
	    BGP4_BIT_SET (peer->attr->attribs, code);
	    bgp_trace_attr (TR_PACKET, peer->trace, peer->attr, code);
	    break;
	case PA4_TYPE_AGGREGATOR:
	    if (len != PA4_LEN_AGGREGATOR) {
	        trace (TR_ERROR, peer->trace, "bad length %d (aggregator)\n", 
		       len);
		peer->subcode = BGP_ERRUPD_LENGTH;
	        goto error;
	    }
	    BGP_GET_SHORT (peer->attr->aggregator.as, cp);
	    BGP_GET_NETLONG (value, cp);
	    peer->attr->aggregator.prefix = 
			New_Prefix (AF_INET, (u_char *) & value, 32);
	    BGP4_BIT_SET (peer->attr->attribs, code);
	    bgp_trace_attr (TR_PACKET, peer->trace, peer->attr, code);
	    break;
	case PA4_TYPE_ORIGINATOR_ID:
	    if (len != PA4_LEN_ORIGINATOR_ID) {
	        trace (TR_ERROR, peer->trace, 
		      "bad length %d (originator)\n", len);
		peer->subcode = BGP_ERRUPD_LENGTH;
	        goto error;
	    }
	    BGP_GET_NETLONG (value, cp);
	    peer->attr->originator = 
			New_Prefix (AF_INET, (u_char *) & value, 32);
	    BGP4_BIT_SET (peer->attr->attribs, code);
	    bgp_trace_attr (TR_PACKET, peer->trace, peer->attr, code);
	    break;
	case PA4_TYPE_CLUSTER_LIST:
	    if ((len % PA4_LEN_CLUSTER_LIST) != 0) {
	        trace (TR_ERROR, peer->trace, 
			"bad length %d (cluster_list)\n", len);
	        peer->subcode = BGP_ERRUPD_LENGTH;
		goto error;
	    }
	    if (len > 0) {
	        if ((peer->attr->cluster_list = munge_cluster_list (len, cp)) 
			== NULL) {
		    peer->subcode = BGP_ERRUPD_OPTATTR;
	            goto error;
		}
	        cp += len;
	        BGP4_BIT_SET (peer->attr->attribs, code);
	        bgp_trace_attr (TR_PACKET, peer->trace, peer->attr, code);
	    }
	    break;
	case PA4_TYPE_COMMUNITY:
	    if ((len % PA4_LEN_COMMUNITY) != 0) {
	        trace (TR_ERROR, peer->trace, 
			"bad length %d (community)\n", len);
	        peer->subcode = BGP_ERRUPD_LENGTH;
		goto error;
	    }
	    if (len > 0) {
	        if ((peer->attr->community = munge_community (len, cp)) 
			== NULL) {
		    peer->subcode = BGP_ERRUPD_OPTATTR;
	            goto error;
		}
	        cp += len;
	        BGP4_BIT_SET (peer->attr->attribs, code);
	        bgp_trace_attr (TR_PACKET, peer->trace, peer->attr, code);
	    }
	    break;
	case PA4_TYPE_DPA:
	    if (len != PA4_LEN_DPA) {
	        trace (TR_ERROR, peer->trace, "bad length %d (dpa)\n", len);
		peer->subcode = BGP_ERRUPD_LENGTH;
	        goto error;
	    }
	    BGP_GET_SHORT (peer->attr->dpa.as, cp);
	    BGP_GET_LONG (peer->attr->dpa.value, cp);
	    BGP4_BIT_SET (peer->attr->attribs, code);
	    bgp_trace_attr (TR_PACKET, peer->trace, peer->attr, code);
	    break;
	case PA4_TYPE_MPUNRNLRI:
	    if (len < PA4_LEN_MPUNRNLRI) {
	        trace (TR_ERROR, peer->trace, "bad length %d (mpunreach)\n",
		       len);
		peer->subcode = BGP_ERRUPD_LENGTH;
	        goto error;
	    }
	    else {
	        if (bgp_get_withdrawn_mp_prefixes (cp, cp + len, peer) < 0) {
		    /* the function sets codes */
		    goto error;
	        }
	        cp += len;
	        /* don't need to set attr->attribs with this code */
	    }
	    break;
	case PA4_TYPE_MPREACHNLRI:
	    if (len < PA4_LEN_MPREACHNLRI) {
	        trace (TR_ERROR, peer->trace, "bad length %d (mpreach)\n", len);
		peer->subcode = BGP_ERRUPD_LENGTH;
	        goto error;
	    }
	    else {
	        if (bgp_get_announced_mp_prefixes (cp, cp + len, peer) < 0) {
		    /* the function sets codes */
                    goto error;
	        }
	        cp += len;
	        /* don't need to set attr->attribs with this code */
	    }
	    break;
	case PA4_TYPE_ADVERTISER:
	case PA4_TYPE_RCID_PATH:
		/* These are optional non-transitive, so I can ignore them */
	default:
	    trace (TR_WARN, peer->trace, "recv %s %s %s attribute: "
		   "flags 0x%x code %d len %d\n", 
		BIT_TEST (flags, PA_FLAG_OPT)? "optional": "mandatory",
		BIT_TEST (flags, PA_FLAG_TRANS)? "transitive": "non-transitive",
		BIT_TEST (flags, PA_FLAG_PARTIAL)? "partial": "non-partial", 
		flags, code, len);

	    /* save unknown optional transitive attributes */
	    if ((flags & PA_FLAG_OPTTRANS) == PA_FLAG_OPTTRANS) {
		u_char *xp, *xp2;
		u_long f = flags;

		xp2 = xp = NewArray (u_char, bgp_attr_len (len));
		/* BIT_SET (f, PA_FLAG_PARTIAL); */
		/* set partial flag on sending out */
		PATH_PUT_ATTR (f, code, len, xp);
		BGP_PUT_DATA (cp, len, xp);

		if (peer->attr->opt_trans_list == NULL)
		    peer->attr->opt_trans_list = 
			LL_Create (LL_DestroyFunction, FDelete,
				   LL_CompareFunction, bgp_unknown_attr_compare,
				   LL_AutoSort, True, 0);
		LL_Add (peer->attr->opt_trans_list, xp2);
	    }
	    cp += len;

	    if (!BIT_TEST (flags, PA_FLAG_OPT)) {
	        trace (TR_ERROR, peer->trace, "unknown well-known attribute: "
		   "flags 0x%x code %d len %d\n", flags, code, len);
		peer->subcode = BGP_ERRUPD_UNKNOWN;
	        goto error;
	    }
	    break;
	}

	if (at + len != cp) {
	    trace (TR_ERROR, peer->trace, 
		   "bad attribute length %d (should be %d)\n", len, cp - at);
	    peer->subcode = BGP_ERRUPD_LENGTH;
	    goto error;
	}
    }

    if (cp != endp) {
	trace (TR_ERROR, peer->trace, "recv byte count %d\n", cp - endp);
	peer->subcode = BGP_ERRUPD_LENGTH;
error:
	peer->code = BGP_ERR_UPDATE;
        bgp_deref_attr (peer->attr);
	peer->attr = NULL;
	return (NULL);
    }

    if (peer->attr->attribs == 0) {
	/* No attributes. Probably only IPv6 stuff */
        bgp_deref_attr (peer->attr);
	peer->attr = NULL;
    }

    peer->code = peer->subcode = 0;
    return (peer->attr);
}


#ifdef notdef
static int
bgp_attr_estimate_len (bgp_attr_t * attr)
{
    int len = 0;

	if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGIN))
	    len += bgp_attr_len (1); /* origin */ ;

	if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH)) {
	    len += bgp_attr_len (aspath_attrlen (attr->aspath));
	}

	if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP)) {
	    /* ipv4 next hop */
	    if (attr->nexthop->prefix->family == AF_INET || attr->nexthop4)
	    len += bgp_attr_len (4);
	}

	if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_METRIC))
	    len += bgp_attr_len (4);
	if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_LOCALPREF))
	    len += bgp_attr_len (4);
	if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ATOMICAGG))
	    len += bgp_attr_len (0);
	if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_AGGREGATOR))
	    len += bgp_attr_len (2 + 4);
	if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGINATOR_ID))
	    len += bgp_attr_len (4);
	if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_CLUSTER_LIST))
	    len += bgp_attr_len (LL_GetCount (attr->cluster_list) * 4);
	if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_DPA))
	    len += bgp_attr_len (2 + 4);
	if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_COMMUNITY)) {
	    assert (attr->community);
	    len += bgp_attr_len (attr->community->len * 4);
	}

    return (len);
}
#endif


/* 
 * Given a pointer to allocated memory (cp), fill in memory with BGP
 * attributes in BGP4 packet format, and return pointer to end of 
 * attributes block.
 */

u_char *
bgp_add_attributes (u_char * cp, int cplen, bgp_attr_t * attr, trace_t * tr)
{
    u_char *end = cp + cplen;

    assert (cp);

    /* The sequence is meaningful because the order should be 
       in ascending order of attribute type */

    /* PA4_TYPE_ORIGIN 1 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGIN)) {
	if (cp + bgp_attr_len (PA4_LEN_ORIGIN) >= end)
	    return (NULL);
	bgp_trace_attr (TR_PACKET, tr, attr, PA4_TYPE_ORIGIN);
	PATH_PUT_ATTR (PA_FLAG_TRANS, PA4_TYPE_ORIGIN, PA4_LEN_ORIGIN, cp);
	if (attr->origin != 3) /* Aggregate is 3 internally */
	    BGP_PUT_BYTE (attr->origin, cp);
	else /* Agrregate route is incomplete */
	    BGP_PUT_BYTE (2, cp);
    }

    /* PA4_TYPE_ASPATH 2 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH)) {
	u_char *xp;
	int alen = aspath_attrlen (attr->aspath);

	/* NULL aspath brings a NULL */
	if (cp + bgp_attr_len (alen) >= end)
	    return (NULL);
	bgp_trace_attr (TR_PACKET, tr, attr, PA4_TYPE_ASPATH);
	PATH_PUT_ATTR (PA_FLAG_TRANS, PA4_TYPE_ASPATH, alen, cp);
	xp = cp;
	cp = unmunge_aspath (attr->aspath, cp);
	assert (alen == (cp - xp));
    }

    /* PA4_TYPE_NEXTHOP 3 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP)) {
	nexthop_t *nexthop = attr->nexthop;
	assert (nexthop);

	if (nexthop->prefix->family != AF_INET && attr->nexthop4)
	    nexthop = attr->nexthop4;

	if (nexthop && nexthop->prefix->family == AF_INET) {
	    if (cp + bgp_attr_len (PA4_LEN_NEXTHOP) >= end)
		return (NULL);
	    
	    trace (TR_PACKET, tr, "  %s: %a\n", 
		     bgptype2string (PA4_TYPE_NEXTHOP),
		     nexthop->prefix);
	    PATH_PUT_ATTR (PA_FLAG_TRANS, PA4_TYPE_NEXTHOP, 
			   PA4_LEN_NEXTHOP, cp);
	    BGP_PUT_NETLONG (prefix_tolong (nexthop->prefix), cp);
	}
    }

    /* PA4_TYPE_METRIC 4 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_METRIC)) {
	if (cp + bgp_attr_len (PA4_LEN_METRIC) >= end)
	    return (NULL);
	bgp_trace_attr (TR_PACKET, tr, attr, PA4_TYPE_METRIC);
	PATH_PUT_ATTR (PA_FLAG_OPT, PA4_TYPE_METRIC, PA4_LEN_METRIC, cp);
	BGP_PUT_LONG (attr->multiexit, cp);
    }

    /* PA4_TYPE_LOCALPREF 5 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_LOCALPREF)) {
	if (cp + bgp_attr_len (PA4_LEN_LOCALPREF) >= end)
	    return (NULL);
	bgp_trace_attr (TR_PACKET, tr, attr, PA4_TYPE_LOCALPREF);
	PATH_PUT_ATTR (PA_FLAG_TRANS, PA4_TYPE_LOCALPREF, 
		    PA4_LEN_LOCALPREF, cp);
	BGP_PUT_LONG (attr->local_pref, cp);
    }

    /* PA4_TYPE_ATOMICAGG 6 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ATOMICAGG)) {
	if (cp + bgp_attr_len (PA4_LEN_ATOMICAGG) >= end)
	    return (NULL);
	bgp_trace_attr (TR_PACKET, tr, attr, PA4_TYPE_ATOMICAGG);
	PATH_PUT_ATTR (PA_FLAG_TRANS, PA4_TYPE_ATOMICAGG, 
		       PA4_LEN_ATOMICAGG, cp);
    }

    /* PA4_TYPE_AGGREGATOR 7 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_AGGREGATOR)) {
	assert (attr->aggregator.prefix);
	assert (attr->aggregator.prefix->family == AF_INET);
	if (cp + bgp_attr_len (PA4_LEN_AGGREGATOR) >= end)
	    return (NULL);
	bgp_trace_attr (TR_PACKET, tr, attr, PA4_TYPE_AGGREGATOR);
	PATH_PUT_ATTR (PA_FLAG_OPT | PA_FLAG_TRANS, PA4_TYPE_AGGREGATOR, 
		       PA4_LEN_AGGREGATOR, cp);
	BGP_PUT_SHORT (attr->aggregator.as, cp);
	BGP_PUT_NETLONG (prefix_tolong (attr->aggregator.prefix), cp);
    }

    /* PA4_TYPE_COMMUNITY 8 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_COMMUNITY)) {
	int clen;
	assert (attr->community);
	clen = attr->community->len * PA4_LEN_COMMUNITY;
	if (cp + bgp_attr_len (clen) >= end)
	    return (NULL);
	bgp_trace_attr (TR_PACKET, tr, attr, PA4_TYPE_COMMUNITY);
	PATH_PUT_ATTR (PA_FLAG_OPT | PA_FLAG_TRANS, PA4_TYPE_COMMUNITY,
		      clen, cp);
	cp = unmunge_community (attr->community, cp);
    }

    /* PA4_TYPE_ORIGINATOR_ID 9 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGINATOR_ID)) {
	assert (attr->originator);
	if (cp + bgp_attr_len (PA4_LEN_ORIGINATOR_ID) >= end)
	    return (NULL);
	bgp_trace_attr (TR_PACKET, tr, attr, PA4_TYPE_ORIGINATOR_ID);
	PATH_PUT_ATTR (PA_FLAG_OPT, PA4_TYPE_ORIGINATOR_ID, 
		       PA4_LEN_ORIGINATOR_ID, cp);
	BGP_PUT_NETLONG (prefix_tolong (attr->originator), cp);
    }

    /* PA4_TYPE_CLUSTER_LIST 10 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_CLUSTER_LIST)) {
	int clen;
	assert (attr->cluster_list);
	clen = LL_GetCount (attr->cluster_list) * PA4_LEN_CLUSTER_LIST;
	if (cp + bgp_attr_len (clen) >= end)
	    return (NULL);
	bgp_trace_attr (TR_PACKET, tr, attr, PA4_TYPE_CLUSTER_LIST);
	PATH_PUT_ATTR (PA_FLAG_OPT, PA4_TYPE_CLUSTER_LIST, clen, cp);
	cp = unmunge_cluster_list (attr->cluster_list, cp);
    }

    /* PA4_TYPE_DPA 11 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_DPA)) {
	if (cp + bgp_attr_len (PA4_LEN_DPA) >= end)
	    return (NULL);
	bgp_trace_attr (TR_PACKET, tr, attr, PA4_TYPE_DPA);
	PATH_PUT_ATTR (PA_FLAG_OPT | PA_FLAG_TRANS, PA4_TYPE_DPA, 
			   PA4_LEN_DPA, cp);
	BGP_PUT_SHORT (attr->dpa.as, cp);
	BGP_PUT_LONG (attr->dpa.value, cp);
    }

    /* PA4_TYPE_ADVERTISER 12 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ADVERTISER)) {
    }

    /* PA4_TYPE_RCID_PATH 13 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_RCID_PATH)) {
    }

    /* PA4_TYPE_MPREACHNLRI 14 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_MPREACHNLRI)) {
	assert (0); /* should not happen */
    }

    /* PA4_TYPE_MPREACHNLRI 15 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_MPREACHNLRI)) {
	assert (0); /* should not happen */
    }

    if (attr->opt_trans_list) {
	u_char *xp;
	bgp_trace_attr (TR_PACKET, tr, attr, -1);
	/* assume they are sorted */
	LL_Iterate (attr->opt_trans_list, xp) {
	    int flags, code, len;
	    u_char *xp2 = xp;

	    GET_PATH_ATTR (flags, code, len, xp2);
	    if (cp + bgp_attr_len (len) >= end)
	        return (NULL);
	    BIT_SET (flags, PA_FLAG_PARTIAL); /* set partial flag */
	    PATH_PUT_ATTR (flags, code, len, cp);
	    BGP_PUT_DATA (xp2, len, cp);
	}
    }

    assert (cp < end);
    return (cp);
}


/* XXX */
#ifdef HAVE_IPV6
u_char *
bgp_add_attr_ipv6 (u_char * cp, int cplen, bgp_attr_t * attr, trace_t * tr)
{
    int afi = AFI_IP6;
    int safi = SAFI_UNICAST;
    int nhalen = 16;
    u_char *end = cp + cplen;
    int bgp4plus = 1; /* always new version */
    int plen = 0;
    int xlen;

    assert (cp);

    if (attr->link_local)
	nhalen += 16;
    if (bgp4plus == 0)
	xlen = plen + 4 + nhalen + 1 + 2;
    else
	xlen = plen + 4 + nhalen + 1;

    if (cp + bgp_attr_len (0 + xlen) >= end)
	return (NULL);
    PATH_PUT_ATTR (PA_FLAG_OPT, PA4_TYPE_MPREACHNLRI, xlen, cp);
    BGP_PUT_SHORT (afi, cp);	/* afi */
    BGP_PUT_BYTE (safi, cp);	/* safi */
    BGP_PUT_BYTE (nhalen, cp);

    trace (TR_PACKET, tr,
	   "fill ipv6 nexthop info afi %d safi %d nhalen %d\n",
	   afi, safi, nhalen);


    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP)) {
	assert (attr->nexthop);
	if (attr->nexthop->prefix->family == AF_INET6) {
            if (okay_trace (tr, TR_PACKET)) 
		trace (TR_PACKET, tr, "  %s: %a\n", 
			bgptype2string (PA4_TYPE_NEXTHOP),
	       		attr->nexthop->prefix);
	    BGP_PUT_ADDR6 (prefix_tochar (attr->nexthop->prefix), cp);
	}
	else {
	    /* this happen when sending ipv6 routes over ipv6 tcp */
	    /* nexthop-self gets nexthop from local side of tcp connection */
	    assert (attr->nexthop->prefix->family == AF_INET);
	    trace (TR_ERROR, tr, "No NEXT_HOP for IPv6 -- Use Compat one\n");
            if (okay_trace (tr, TR_PACKET)) 
		trace (TR_PACKET, tr, "  %s: ::%a\n", 
			bgptype2string (PA4_TYPE_NEXTHOP),
	       		attr->nexthop->prefix);
	    memset (cp, 0, 12);
            cp += 12;
	    BGP_PUT_ADDR (prefix_tochar (attr->nexthop->prefix), cp);
	}
    }
    else {
	trace (TR_ERROR, tr, "No NEXT_HOP for IPv6\n");
	trace (TR_PACKET, tr, "  %s: ::\n",
	       bgptype2string (PA4_TYPE_NEXTHOP));
	memset (cp, 0, 16);
        cp += 16;
    }

    if (nhalen == 32) {
      if (okay_trace (tr,TR_PACKET)) 
	trace (TR_PACKET, tr, "  %s: %s\n", 
	       bgptype2string (PA4_TYPE_NEXTHOP),
	       prefix_toa (attr->link_local->prefix));
      BGP_PUT_ADDR6 (prefix_tochar (attr->link_local->prefix), cp);
    }

    BGP_PUT_BYTE (0, cp);	/* Number of SNPAs */

    if (bgp4plus == 0) {
	trace (TR_PACKET, tr,
	       "send announce draft 0 len %d\n", plen);
	BGP_PUT_SHORT (plen, cp);
    }
    assert (cp < end);
    return (cp);
}
#endif /* HAVE_IPV6 */


bgp_attr_t *
bgp_new_attr (int type)
{
    bgp_attr_t *attr;

    attr = New (bgp_attr_t);
    attr->type = type;
    attr->ref_count = 1;
    attr->tag = 0;
    attr->options = 0;
    attr->attribs = 0;
    attr->nexthop = NULL;
    attr->gateway = NULL;
    attr->nodelete = 0;
    attr->opt_trans_list = NULL;
    num_active_bgp_attr++;
    pthread_mutex_init (&attr->mutex_lock, NULL);

    return (attr);
}


bgp_attr_t *
bgp_ref_attr (bgp_attr_t * attr)
{
    pthread_mutex_lock (&attr->mutex_lock);
    assert (attr->ref_count > 0);
    attr->ref_count++;
    pthread_mutex_unlock (&attr->mutex_lock);
    return (attr);
}


void
bgp_deref_attr (bgp_attr_t * attr)
{
    pthread_mutex_lock (&attr->mutex_lock);

    assert (attr->ref_count > 0);
    if (--attr->ref_count <= 0) {

	if (attr->nodelete == 0) {
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP)) {
		assert (attr->nexthop);
		/* nexthop can be nexthop in attribute
			or one from 4+ extension */
		deref_nexthop (attr->nexthop);
	    }
	    else {
		assert (attr->nexthop == NULL);
	    }
	    if (attr->direct)
		deref_nexthop (attr->direct);
	    /* if (attr->gateway) Delete (attr->gateway); */
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH)) {
	        if (attr->aspath)
		    Delete_ASPATH (attr->aspath);
	    }
	    else {
		assert (attr->aspath == NULL);
	    }
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_AGGREGATOR)) {
		assert (attr->aggregator.prefix);
		Deref_Prefix (attr->aggregator.prefix);
	    }
	    else {
		assert (attr->aggregator.prefix == NULL);
	    }
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGINATOR_ID)) {
		assert (attr->originator);
		Deref_Prefix (attr->originator);
	    }
	    else {
		assert (attr->originator == NULL);
	    }
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_CLUSTER_LIST)) {
		assert (attr->cluster_list);
		Delete_cluster_list (attr->cluster_list);
	    }
	    else {
		assert (attr->cluster_list == NULL);
	    }
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_COMMUNITY)) {
		assert (attr->community);
		Delete_community (attr->community);
	    }
	    else {
		assert (attr->community == NULL);
	    }
	    if (attr->nexthop4) {
		deref_nexthop (attr->nexthop4);
	    }
#ifdef HAVE_IPV6
	    if (attr->link_local) {
		deref_nexthop (attr->link_local);
	    }
#endif /* HAVE_IPV6 */
	    if (attr->opt_trans_list)
		LL_Destroy (attr->opt_trans_list);
	}
	pthread_mutex_destroy (&attr->mutex_lock);
        num_active_bgp_attr--;
	Delete (attr);
	return;
    }

    pthread_mutex_unlock (&attr->mutex_lock);
}


/* 
 * return 1 if BGP attributes are the same 
 */
int
bgp_compare_attr (bgp_attr_t * a1, bgp_attr_t * a2)
{
    if (a1->gateway->AS != a2->gateway->AS)
	return (-1);

    if (a1->attribs ^ a2->attribs)
	return (-1);

    if (BGP4_BIT_TEST (a1->attribs, PA4_TYPE_ORIGIN) &&
        a1->origin != a2->origin)
	return (-1);

    if (BGP4_BIT_TEST (a1->attribs, PA4_TYPE_ASPATH) &&
        compare_aspaths (a1->aspath, a2->aspath) < 0)
	return (-1);

    if (BGP4_BIT_TEST (a1->attribs, PA4_TYPE_NEXTHOP) &&
	a1->nexthop != a2->nexthop)
	return (-1);

    if (a1->nexthop4 || a2->nexthop4) {
	if (!a1->nexthop4 || !a2->nexthop4)
	    return (-1);
	if (a1->nexthop4 != a2->nexthop4)
	    return (-1);
    }
#ifdef HAVE_IPV6
    if (a1->link_local || a2->link_local) {
	if (!a1->link_local || !a2->link_local)
	    return (-1);
	if (a1->link_local != a2->link_local)
	    return (-1);
    }
#endif /* HAVE_IPV6 */
    if (BGP4_BIT_TEST (a1->attribs, PA4_TYPE_METRIC) &&
	a1->multiexit != a2->multiexit)
	return (-1);
    if (BGP4_BIT_TEST (a1->attribs, PA4_TYPE_LOCALPREF) &&
	a1->local_pref != a2->local_pref)
	return (-1);
    if (BGP4_BIT_TEST (a1->attribs, PA4_TYPE_AGGREGATOR) &&
	(a1->aggregator.as != a2->aggregator.as ||
	prefix_compare2 (a1->aggregator.prefix, a2->aggregator.prefix) != 0))
	return (-1);
    if (BGP4_BIT_TEST (a1->attribs, PA4_TYPE_COMMUNITY) &&
	community_compare (a1->community, a2->community) < 0)
	return (-1);
    if (BGP4_BIT_TEST (a1->attribs, PA4_TYPE_DPA) &&
	(a1->dpa.as != a2->dpa.as || a1->dpa.value != a2->dpa.value))
	return (-1);

    /* XXX give up to compare them */
    if (a1->opt_trans_list || a2->opt_trans_list)
	return (-1);

    /* don't need to compare direct */
    return (1);
}


/* 
 * here is where we actually build update packets and 
 * schedule them to be sent off. 
 * NOTE: It is is the responsibility of bgp peer to delete buffer memory!
 */

int
bgp_create_pdu (LINKED_LIST * ll_with_prefixes, LINKED_LIST * ll_ann_prefixes,
		bgp_attr_t * attr, int safi,
		/* these argument are used by bgp daemon */
		bgp_peer_t * peer, void (*fn) (),
		/* these argument are used by tools like route_atob */
		u_char * pdu_memory, int pdu_len, int bgp4plus)
{
    prefix_t *p_with_prefix = NULL, *p_ann_prefix = NULL;
    int afi = 0;
    trace_t *tr = MRT->trace;
    u_char *start_pdu, *maxend;
    prefix_t *prefix;

    if (peer) {
	tr = peer->trace;
        bgp4plus = (BIT_TEST (peer->options, BGP_BGP4PLUS_01)? 1: 0);
    }
    else {
	assert (pdu_memory);
    }

    if (pdu_memory && pdu_len > 0) {
	start_pdu = pdu_memory;
	maxend = pdu_memory + pdu_len;
    }
    else {
	start_pdu = NewArray (u_char, BGPMAXPACKETSIZE - BGP_HEADER_LEN);
	maxend = start_pdu + BGPMAXPACKETSIZE - BGP_HEADER_LEN;
    }

    if (ll_with_prefixes) {
	p_with_prefix = LL_GetHead (ll_with_prefixes);
	LL_Iterate (ll_with_prefixes, prefix) {
	    assert (p_with_prefix->family == prefix->family);
	}
#ifdef HAVE_IPV6
	if (p_with_prefix && p_with_prefix->family == AF_INET6)
	    afi = AFI_IP6;
#endif /* HAVE_IPV6 */
    }
    if (ll_ann_prefixes) {
	p_ann_prefix = LL_GetHead (ll_ann_prefixes);
	LL_Iterate (ll_ann_prefixes, prefix) {
	    assert (p_ann_prefix->family == prefix->family);
	}
#ifdef HAVE_IPV6
	if (p_ann_prefix && p_ann_prefix->family == AF_INET6)
	    afi = AFI_IP6;
#endif /* HAVE_IPV6 */
	assert (attr);
    }

    if (p_with_prefix && p_ann_prefix) {
        assert (p_with_prefix->family == p_ann_prefix->family);
    }

    while (p_with_prefix || p_ann_prefix) {

        u_char *p_total_attrib_len, *p_unfeasible_len;
	u_char *cp = start_pdu; /* reset the pointer */
	int overflow = 0;
        int announce4 = 0;
        int num_prefixes = 0;
	int first;
        u_char *start_attr;
        u_char *start_mp;
	int emit_attr = 0;

        trace (TR_DEBUG, tr, "send ---- start\n");

	p_unfeasible_len = cp;
	/* skip unfeasible route length for now */
	BGP_PUT_SHORT (0, cp);

	/* 
	 * search IPv4 withdrawn prefixes and add them first
	 */
	first = 1;
	while (p_with_prefix && (afi == 0 || afi == AFI_IP) && 
				(safi == 0 || safi == SAFI_UNICAST)) {

	    if (cp + BGP_PREFIX_LEN (p_with_prefix->bitlen) + 1 <= maxend) {
		if (first) {
	    	    trace (TR_PACKET, tr, "send withdraw:\n");
		    first = 0;
		}
		BGP_PUT_PREFIX (p_with_prefix->bitlen,
				prefix_tochar (p_with_prefix), cp);
		if (okay_trace (tr, TR_PACKET)) 
		  trace (TR_PACKET, tr, "  %s\n", prefix_toax (p_with_prefix));
		p_with_prefix = LL_GetNext (ll_with_prefixes, p_with_prefix);

		num_prefixes++;
		if (peer && peer->maximum_prefix > 0 && 
			num_prefixes >= peer->maximum_prefix) {
		    overflow++;
		    break;
		}
	    }
	    else {
		overflow++;
		break;
	    }
	}
	assert (cp <= maxend);

	if (cp - start_pdu - 2 > 0) {
	    trace (TR_PACKET, tr, "send withdraw len = %d\n",
	           cp - start_pdu - 2);
	    /* put in withdrawn routes length */
	    BGP_PUT_SHORT (cp - start_pdu - 2, p_unfeasible_len);
	    p_unfeasible_len -= 2;
	}

	/* skip total path attribute length for now */
	p_total_attrib_len = cp;
	BGP_PUT_SHORT (0, cp);
	start_attr = cp;

	/* if there is at least one announce route,
	   emit the attribute */
	if (!overflow && p_ann_prefix) {

	    cp = bgp_add_attributes (cp, maxend - cp, attr, tr);

	    if (cp == NULL) {
		trace (TR_ERROR, tr, "too large attributes\n");
		if (!(pdu_memory && pdu_len > 0))
		    Delete (start_pdu);
		return (-1);
	    }

	    trace (TR_PACKET, tr, "send attribute len updated = %d\n",
		   cp - start_attr);
	    emit_attr = cp - start_attr;

	    /* Now put in attribute length */
	    BGP_PUT_SHORT (cp - start_attr, p_total_attrib_len);
	    p_total_attrib_len -= 2;
        }

	/* 
	 * add IPv4 announce if no more ipv4 withdraw
	 */
	while (!overflow && p_ann_prefix && (afi == 0 || afi == AFI_IP) && 
		(safi == 0 || safi == SAFI_UNICAST)) {

	    if (cp + BGP_PREFIX_LEN (p_ann_prefix->bitlen) + 1 <= maxend) {
		if (announce4 == 0)
	    	    trace (TR_PACKET, tr, "send announce:\n");

		BGP_PUT_PREFIX (p_ann_prefix->bitlen,
				prefix_tochar (p_ann_prefix), cp);
		if (okay_trace (tr, TR_PACKET)) 
		  trace (TR_PACKET, tr, "  %s\n", prefix_toax (p_ann_prefix));
		announce4++;
		p_ann_prefix = LL_GetNext (ll_ann_prefixes, p_ann_prefix);

		num_prefixes++;
		if (peer && peer->maximum_prefix > 0 && 
			num_prefixes >= peer->maximum_prefix) {
		    overflow++;
		    break;
		}
	    }
	    else {
		overflow++;
		break;
	    }
	}
	assert (cp <= maxend);

	if (afi == 0)
	   afi = AFI_IP;
	if (safi == 0)
	   safi = SAFI_UNICAST;

	/* 
	 * add MP announce routes if no more ipv4 withdrawn & announce routes 
	 */
	if (!overflow && p_ann_prefix) {

	    prefix_t *pref = p_ann_prefix;
	    int xlen, plen = 0;
    	    int nhalen = 0; /* no IPv4 nexthop in MP */

	    assert (afi != AFI_IP || safi != SAFI_UNICAST);
#ifdef HAVE_IPV6
	    if (afi == AFI_IP6) {
    	        nhalen = 16;
	        if (attr->link_local && 
		        attr->link_local->prefix->family == AF_INET6)
		    nhalen += 16;
	    }
#endif /* HAVE_IPV6 */

	    while (pref) {

		plen += 1;	/* prefix's length field */
		plen += BGP_PREFIX_LEN (pref->bitlen);

		if (bgp4plus == 0)
		    xlen = plen + 4 + nhalen /* next hop */  + 1 + 2;
		else
		    xlen = plen + 4 + nhalen /* next hop */  + 1;
		if (cp + 3 + xlen + (xlen > 255 ? 1 : 0) > maxend) {
		    plen -= BGP_PREFIX_LEN (pref->bitlen);
		    plen -= 1;
		    overflow++;
		    break;
		}

		pref = LL_GetNext (ll_ann_prefixes, pref);

		num_prefixes++;
		if (peer && peer->maximum_prefix > 0 && 
			num_prefixes >= peer->maximum_prefix) {
		    overflow++;
		    break;
		}
	    }

if (plen > 0) {

	    if (bgp4plus == 0)
		xlen = plen + 4 + nhalen + 1 + 2;
	    else
		xlen = plen + 4 + nhalen + 1;

	    /* estimation is required because if xlen > 255,
	       length field becomes 2 octets */
	    PATH_PUT_ATTR (PA_FLAG_OPT, PA4_TYPE_MPREACHNLRI, xlen, cp);
	    start_mp = cp; /* to check later */

	    BGP_PUT_SHORT (afi, cp);	/* afi */
	    BGP_PUT_BYTE (safi, cp);	/* safi */
	    BGP_PUT_BYTE (nhalen, cp);

	    trace (TR_PACKET, tr,
		   "send announce afi %d safi %d nhalen %d\n",
		   afi, safi, nhalen);

	    trace (TR_PACKET, tr,
		   "send announce draft version %d\n",
		   bgp4plus);

if (nhalen > 0) {
#ifdef HAVE_IPV6
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP)) {
		assert (attr->nexthop);
		if (attr->nexthop->prefix->family == AF_INET6) {

		    trace (TR_PACKET, tr, "  %s: %a\n", 
		           bgptype2string (PA4_TYPE_NEXTHOP),
		           attr->nexthop->prefix);
		    BGP_PUT_ADDR6 (prefix_tochar (attr->nexthop->prefix), cp);
	        }
	        else {
	    	    /* this happen when sending ipv6 routes over ipv6 tcp */
	    	    /* nexthop-self gets nexthop from local side of 
			tcp connection */
	    	    assert (attr->nexthop->prefix->family == AF_INET);
	    	    trace (TR_ERROR, tr, 
				"No NEXT_HOP for IPv6 -- Use Compat one\n");
            	    if (okay_trace (tr, TR_PACKET)) 
			    trace (TR_PACKET, tr, "  %s: ::%a\n", 
				    bgptype2string (PA4_TYPE_NEXTHOP),
	       			    attr->nexthop->prefix);
	    	    memset (cp, 0, 12);
            	    cp += 12;
	    	    BGP_PUT_ADDR (prefix_tochar (attr->nexthop->prefix), cp);
		}
	    }
	    else {
		trace (TR_ERROR, tr, "No NEXT_HOP for IPv6\n");
		trace (TR_PACKET, tr, "  %s: ::\n",
		       bgptype2string (PA4_TYPE_NEXTHOP));
		memset (cp, 0, 16);
	        cp += 16;
	    }

	    if (nhalen == 32) {
		trace (TR_PACKET, tr, "  %s: %a\n", 
		       bgptype2string (PA4_TYPE_NEXTHOP),
		       attr->link_local->prefix);
	      BGP_PUT_ADDR6 (prefix_tochar (attr->link_local->prefix), cp);
	    }
#endif /* HAVE_IPV6 */
}

#ifdef notdef
	    trace (TR_PACKET, tr,
		   "send announce number of SNAPs = %d\n", 0);
#endif
	    BGP_PUT_BYTE (0, cp);	/* Number of SNPAs */

	    if (bgp4plus == 0) {
		trace (TR_PACKET, tr,
		       "send announce draft 0 len %d\n", plen);
		BGP_PUT_SHORT (plen, cp);
	    }

	    trace (TR_PACKET, tr, "send announce:\n");

	    while (p_ann_prefix != pref) {
#ifdef HAVE_IPV6
	        if (afi == AFI_IP6)
		    BGP_PUT_PREFIX6 (p_ann_prefix->bitlen,
				     prefix_tochar (p_ann_prefix), cp);
#endif /* HAVE_IPV6 */
	        if (afi == AFI_IP)
		    BGP_PUT_PREFIX (p_ann_prefix->bitlen,
				     prefix_tochar (p_ann_prefix), cp);
		trace (TR_PACKET, tr, "  %p\n", p_ann_prefix);
		p_ann_prefix = LL_GetNext (ll_ann_prefixes, p_ann_prefix);
	    }
	    assert (cp <= maxend);
	    assert (start_mp + xlen == cp);
	    BGP_PUT_SHORT (cp - start_attr, p_total_attrib_len);
	    p_total_attrib_len -= 2;
	    trace (TR_PACKET, tr, "send attribute len updated = %d\n",
		   cp - start_attr);
}
	}

	/*
	 * add MP withdrawn prefixes as a multi-protocol attribute
	 * this should follow MP announce to avoid sorting by attr code
	 */
	if (!overflow && p_with_prefix) {
	    prefix_t *pref = p_with_prefix;
	    int xlen, plen = 0;

	    assert (afi != AFI_IP || safi != SAFI_UNICAST);
	    if (peer && BIT_TEST (peer->options, BGP_PEER_CISCO)) {
	        /* some old cisco IPv6 version requires mandatory attributes 
   	    	   even in case of IPv6 withdraw only */
		/* If there is not, it sends a notification saying well-known 
		   attribute missing  */
	    	if (emit_attr == 0) {
	            PATH_PUT_ATTR (PA_FLAG_TRANS, PA4_TYPE_ORIGIN, 1, cp);
	            BGP_PUT_BYTE (0, cp);

	            PATH_PUT_ATTR (PA_FLAG_TRANS, PA4_TYPE_ASPATH, 2, cp);
                    BGP_PUT_BYTE (PA_PATH_SEQ, cp);
                    BGP_PUT_BYTE (0, cp);

	            PATH_PUT_ATTR (PA_FLAG_TRANS, PA4_TYPE_NEXTHOP, 4, cp);
	            BGP_PUT_NETLONG (0, cp);

                    PATH_PUT_ATTR (PA_FLAG_TRANS, PA4_TYPE_LOCALPREF, 4, cp);
                    BGP_PUT_LONG (0, cp);
	        }
	    }

	    /* estimate the length needed */
	    while (pref) {

		plen += 1;
		plen += BGP_PREFIX_LEN (pref->bitlen);

		if (bgp4plus == 0)
		    xlen = plen + 3 + 2;
		else
		    xlen = plen + 3;
		if (cp + 3 + xlen + (xlen > 255 ? 1 : 0) > maxend) {
		    plen -= BGP_PREFIX_LEN (pref->bitlen);
		    plen -= 1;
		    overflow++;
		    break;
		}
		pref = LL_GetNext (ll_with_prefixes, pref);

		num_prefixes++;
		if (peer && peer->maximum_prefix > 0 && 
			num_prefixes >= peer->maximum_prefix) {
		    overflow++;
		    break;
		}
	    }

	    if (bgp4plus == 0)
		xlen = plen + 3 + 2;
	    else
		xlen = plen + 3;
	    PATH_PUT_ATTR (PA_FLAG_OPT, PA4_TYPE_MPUNRNLRI, xlen, cp);
	    start_mp = cp;

	    BGP_PUT_SHORT (afi, cp);	/* afi */
	    BGP_PUT_BYTE (safi, cp);	/* safi */
	    trace (TR_PACKET, tr,
		   "send withdraw afi %d safi %d\n",
		   afi, safi);

	    trace (TR_PACKET, tr, "send withdraw draft version %d\n",
		   bgp4plus);
	    if (bgp4plus == 0) {
		trace (TR_PACKET, tr,
		       "send withdraw draft 0 len %d\n", plen);
		BGP_PUT_SHORT (plen, cp);
	    }

	    trace (TR_PACKET, tr, "send withdraw:\n");
	    while (p_with_prefix != pref) {
#ifdef HAVE_IPV6
	        if (afi == AFI_IP6)
		    BGP_PUT_PREFIX6 (p_with_prefix->bitlen,
				     prefix_tochar (p_with_prefix), cp);
#endif /* HAVE_IPV6 */
	        if (afi == AFI_IP)
		    BGP_PUT_PREFIX (p_with_prefix->bitlen,
				    prefix_tochar (p_with_prefix), cp);
		trace (TR_PACKET, tr, "  %p\n", p_with_prefix);
		p_with_prefix = LL_GetNext (ll_with_prefixes, p_with_prefix);
	    }
	    assert (cp <= maxend);
	    assert (start_mp + xlen == cp);
	    BGP_PUT_SHORT (cp - start_attr, p_total_attrib_len);
	    p_total_attrib_len -= 2;
	    trace (TR_PACKET, tr, "send attribute len updated = %d\n",
		   cp - start_attr);
	}

	trace (TR_PACKET, tr,
	       "send ---- end (%d prefixes, len = %d)\n",
	       num_prefixes, cp - start_pdu);
	if (pdu_memory && pdu_len > 0) {
	    if (overflow)
		return (-1);
	    return (cp - start_pdu);
	}
	else if (peer && fn) {
	    /* schedule for sending it */
	    (*fn) (peer, cp - start_pdu, start_pdu);
	}
    }
    if (!(pdu_memory && pdu_len > 0)) {
	Delete (start_pdu);
    }
    return (0);
}


bgp_attr_t *
bgp_copy_attr (bgp_attr_t * attr)
{
    bgp_attr_t *new_attr;

    assert (attr);
    new_attr = bgp_new_attr (attr->type);

    new_attr->attribs = attr->attribs;
    new_attr->gateway = attr->gateway;
    new_attr->tag = attr->tag;
    new_attr->options = attr->options;
    new_attr->original = attr->original;

    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP))
	new_attr->nexthop = ref_nexthop (attr->nexthop);
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH))
	new_attr->aspath = aspath_copy (attr->aspath);
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGIN))
	new_attr->origin = attr->origin;

    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_METRIC))
	new_attr->multiexit = attr->multiexit;
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_LOCALPREF))
	new_attr->local_pref = attr->local_pref;
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_DPA))
	new_attr->dpa = attr->dpa;
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_COMMUNITY)) {
	assert (attr->community);
	new_attr->community = community_copy (attr->community);
    }
    if (attr->nexthop4)
	new_attr->nexthop4 = ref_nexthop (attr->nexthop4);
#ifdef HAVE_IPV6
    if (attr->link_local)
	new_attr->link_local = ref_nexthop (attr->link_local);
#endif /* HAVE_IPV6 */
    if (attr->direct)
	new_attr->direct = ref_nexthop (attr->direct);

    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_AGGREGATOR)) {
	new_attr->aggregator.as = attr->aggregator.as;
	new_attr->aggregator.prefix = Ref_Prefix (attr->aggregator.prefix);
    }
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGINATOR_ID)) {
	new_attr->originator = Ref_Prefix (attr->originator);
    }
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_CLUSTER_LIST)) {
	new_attr->cluster_list = cluster_list_copy (attr->cluster_list);
    }
    new_attr->home_AS = attr->home_AS;

    if (attr->opt_trans_list) {
	u_char *xp;
	new_attr->opt_trans_list = 
		LL_Create (LL_DestroyFunction, FDelete,
			   LL_CompareFunction, bgp_unknown_attr_compare,
			   LL_AutoSort, True, 0);
	LL_Iterate (attr->opt_trans_list, xp) {
	    /* xp can not be changed in iteration */
	    int flags, code, len;
	    u_char *cp, *cp2, *xp2 = xp;

	    GET_PATH_ATTR (flags, code, len, xp2);
	    cp2 = cp = NewArray (u_char, bgp_attr_len (len));
	    PATH_PUT_ATTR (flags, code, len, cp);
	    memcpy (cp, xp2, len);
	    LL_Add (new_attr->opt_trans_list, cp2);
	}
    }
    return (new_attr);
}

/*
 * $Id: bgp_msg.c,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#include <mrt.h>
#include <aspath.h>
#include <bgp.h>
#include <ctype.h>

extern char *s_origins[];
static char zero[16];


char *sbgp_states[] =
{
    "NULL",
    "Idle",
    "Connect",
    "Active",
    "Opensent",
    "Openconfirm",
    "Established",
    "Destroyed",
    NULL,
};

char *sbgp_pdus[] =
{
    "NULL",
    "Open",
    "Update",
    "Notification",
    "Keepalive",
    NULL,
};

char *sbgp_events[] =
{
    "NULL",
    "Start",
    "Stop",
    "Open",
    "Closed",
    "OpenFail",
    "Error",
    "ConnectRetry",
    "HoldTime",
    "KeepAlive",
    "RecvOpen",
    "RecvKeepAlive",
    "RecvUpdate",
    "RecvNotify",
    NULL,
};


char *s_bgp_error[] =
{
    "UNUSED",
    "Message Header Error",
    "Open Message Error",
    "Update Message Error",
    "Hold Timer Expired",
    "Finite State Machine Error",
    "Cease",
    NULL,
};

char *s_bgp_error_header[] =
{
    "UNUSED",
    "Connection Not Synchronized",
    "Bad Message Length",
    "Bad Message Type",
    NULL,
};

char *s_bgp_error_open[] =
{
    "UNUSED",
    "Unsupported Version Number",
    "Bad Peer AS",
    "Bad BGP Identifier",
    "Unsupported Optional Parameter",
    "Authentication Failure",
    "Unacceptable Hold Time",
    "Unsupported Capability",
    NULL,
};

char *s_bgp_error_update[] =
{
    "UNUSED",
    "Malformed Attribute List",
    "Unrecognized Well-known Attribute",
    "Missing Well-known Attribute",
    "Attribute Flags Error",
    "Attribute Length Error",
    "Invalid ORIGIN Attribute",
    "AS Routing Loop",
    "Invalid NEXT_HOP Attribute",
    "Optional Attribute Error",
    "Invalid Network Field",
    "Malformed AS_PATH",
    NULL,
};


/*
 * return human readable string of BGP notify error
 */
char *
bgp_notify_to_string (int code, int subcode)
{
    char *s_code = NULL, *s_subcode = NULL;
    char *tmpx;
    THREAD_SPECIFIC_STORAGE (tmpx);

    if (code >= 0 && code < BGP_ERR_MAX) {
	s_code = s_bgp_error[code];

        switch (code) {
	case BGP_ERR_HEADER:
	    if (subcode >= 0 && subcode < BGP_ERRHDR_MAX)
		s_subcode = s_bgp_error_header[subcode];
	    break;
	case BGP_ERR_OPEN:
	    if (subcode >= 0 && subcode < BGP_ERROPN_MAX)
		s_subcode = s_bgp_error_open[subcode];
	    break;
	case BGP_ERR_UPDATE:
	    if (subcode >= 0 && subcode < BGP_ERRUPD_MAX)
		s_subcode = s_bgp_error_update[subcode];
	    break;
        }
    }
    if (s_code && s_subcode)
	sprintf (tmpx, "%s/%s", s_code, s_subcode);
    else if (s_code && subcode > 0)
	sprintf (tmpx, "%s/%d", s_code, subcode);
    else if (s_code)
	sprintf (tmpx, "%s", s_code);
    else if (code > 0 && subcode > 0)
	sprintf (tmpx, "%d/%d", code, subcode);
    else /* if (code > 0) */
	sprintf (tmpx, "%d", code);
    return (tmpx);
}


char *
bgpmessage2string (int type)
{
    if (type > 0 && type < BGP_PACKET_MAX)
        return (sbgp_pdus[type]);
    return (sbgp_pdus[0]);
}   


u_char *
bgp_process_mrt_msg (int type, int subtype, u_char * cp, int length,
	int *family_p, gateway_t **gateway_from, gateway_t **gateway_to)
{
    u_char saddr[16], daddr[16];
    int sas, das;
    prefix_t *prefix;
    gateway_t *from = NULL;
    gateway_t *to = NULL;
    int plen = 4;
    int family = AF_INET;

if (type == MSG_PROTOCOL_BGP4MP) {
    int afi, index;

    BGP_GET_SHORT (sas, cp);
    BGP_GET_SHORT (das, cp);
    BGP_GET_SHORT (index, cp); /* XXX */
    BGP_GET_SHORT (afi, cp);
    if (afi != AFI_IP && afi != AFI_IP6) {
	return (NULL);
    }
#ifdef HAVE_IPV6
    if (afi == AFI_IP6) {
        plen = 16;
	family = AF_INET6;
    }
#endif /* HAVE_IPV6 */
    BGP_GET_DATA (&saddr, plen, cp);
    BGP_GET_DATA (&daddr, plen, cp);
}
else {

#ifdef HAVE_IPV6
    if (type == MSG_PROTOCOL_BGP4PLUS) {
	plen = 16;
	family = AF_INET6;
    }
    else if (type == MSG_PROTOCOL_BGP4PLUS_01) {
	plen = 16;
	family = AF_INET6;
    }
#endif /* HAVE_IPV6 */

    /* from */
    BGP_GET_SHORT (sas, cp);
    BGP_GET_DATA (&saddr, plen, cp);
    /* to */
    BGP_GET_SHORT (das, cp);
    BGP_GET_DATA (&daddr, plen, cp);
}

    if (memcmp (saddr, zero, plen) != 0) {
        prefix = New_Prefix (family, &saddr, plen * 8);
        from = add_gateway (prefix, sas, NULL);
        Deref_Prefix (prefix);
    }
    if (memcmp (daddr, zero, plen) != 0) {
        prefix = New_Prefix (family, &daddr, plen * 8);
        to = add_gateway (prefix, das, NULL);
        Deref_Prefix (prefix);
    }

    *gateway_from = from;
    *gateway_to = to;
    *family_p = family;

    return (cp);
}


/* 
 * Process an MRT BGP update message. Fill in pp_attr
 * and ll_ann_prefixes and ll_with_prefixes.
 * XXX This function is used by programs other than mrtd
 */
int
bgp_process_update_msg (int type, int subtype, u_char * value, int length,
			gateway_t ** gateway_to, bgp_attr_t ** pp_attr,
			LINKED_LIST ** ll_with_prefixes,
			LINKED_LIST ** ll_ann_prefixes)
{
    u_char *cp = value;
    int bgp4plus = DEFAULT_BGP4PLUS_VERSION;
    bgp_peer_t *peer;
    char str[MAXLINE];
    gateway_t *from, *to;
    int family;
    int ret;

    cp = bgp_process_mrt_msg (type, subtype, cp, length, &family, &from, &to);
    if (cp == NULL)
	return (-1);

if (type == MSG_PROTOCOL_BGP4MP) {
    int hdrtype, hdrlen;

    BGP_GET_HEADER (cp, hdrlen, hdrtype, cp);
    bgp4plus = (subtype != BGP4MP_MESSAGE_OLD);
    assert (hdrtype == BGP_UPDATE);
    if (cp + hdrlen - BGP_HEADER_LEN != value + length) {
	trace (TR_ERROR, MRT->trace, 
	       "bgp_process_update_msg length error (%x,%x)\n", 
	       cp + hdrlen - BGP_HEADER_LEN, value + length);
    }
}
else {

#ifdef HAVE_IPV6
    if (type == MSG_PROTOCOL_BGP4PLUS_01) {
	bgp4plus = 1;
    }
#endif /* HAVE_IPV6 */

}
    /* create a pseudo peer */
    peer = New (bgp_peer_t);
    peer->trace = trace_copy (MRT->trace);
    if (bgp4plus) {
        BIT_SET (peer->options, BGP_BGP4PLUS_01);
    }

    if (from == NULL) {
#ifdef HAVE_IPV6
        if (family == AF_INET6)
           strcpy (str, "BGP4+");
        else
#endif /* HAVE_IPV6 */
        strcpy (str, "BGP");
    }
    else {
#ifdef HAVE_IPV6
        if (family == AF_INET6)
            sprintf (str, "BGP4+ %s", prefix_toa (from->prefix));
        else
#endif /* HAVE_IPV6 */
            sprintf (str, "BGP %s", prefix_toa (from->prefix));
    }
    set_trace (peer->trace, TRACE_PREPEND_STRING, str, 0);

    length -= (cp - value);

    if ((ret = bgp_process_update_packet (cp, length, peer)) < 0) {
	/* code and subcode available */
    }
    else {
        /* in case of withdraw only */
        if (peer->attr == NULL)
	    peer->attr = bgp_new_attr (PROTO_BGP);
        peer->attr->gateway = from;
    }

    /* setting return values */
    *gateway_to = to;
    *pp_attr = peer->attr;
    *ll_with_prefixes = peer->ll_withdraw;
    *ll_ann_prefixes = peer->ll_announce;

    Destroy_Trace (peer->trace);
    Delete (peer);

    return (ret);
}


int
mrt_bgp_msg_type (mrt_msg_t *msg)
{
if (msg->type == MSG_PROTOCOL_BGP4MP) {
    u_char *cp = msg->value;
    int sas, das;
    int plen = 4;
    int afi, index;
    int hdrtype, hdrlen;
    u_char saddr[16], daddr[16];

    if (msg->length < 2 * 4)
	return (-1);
    BGP_GET_SHORT (sas, cp);
    BGP_GET_SHORT (das, cp);
    BGP_GET_SHORT (index, cp); /* XXX */
    BGP_GET_SHORT (afi, cp);
    if (afi != AFI_IP && afi != AFI_IP6) {
	return (-1);
    }
#ifdef HAVE_IPV6
    if (afi == AFI_IP6) {
        plen = 16;
    }
#endif /* HAVE_IPV6 */
    if (msg->length < 2 * 4 + plen * 2)
	return (-1);
    BGP_GET_DATA (&saddr, plen, cp);
    BGP_GET_DATA (&daddr, plen, cp);
    if (msg->length < 2 * 4 + plen * 2 + 19)
	return (-1);
    BGP_GET_HEADER (cp, hdrlen, hdrtype, cp);
    assert ((cp - msg->value) <= msg->length);
    return (hdrtype);
}
else {
    if ((msg->type == MSG_PROTOCOL_BGP ||
         msg->type == MSG_PROTOCOL_BGP4PLUS ||
         msg->type == MSG_PROTOCOL_BGP4PLUS_01) &&
	 msg->subtype == MSG_BGP_UPDATE)
    return (BGP_UPDATE);
}
    return (0);
}


static u_char *
bgp_fill_update (u_char *cp, int type, int subtype,
		 gateway_t *gateway_from, gateway_t *gateway_to)
{
    int plen = 4;
    int afi = AFI_IP;

    if (gateway_from)
        trace (TR_TRACE, MRT->trace, "FROM: %s AS%d\n",
               prefix_toa (gateway_from->prefix), gateway_from->AS);
    if (gateway_to)
        trace (TR_TRACE, MRT->trace, "TO: %s AS%d\n",
               prefix_toa (gateway_to->prefix), gateway_to->AS);

    if (type == MSG_PROTOCOL_BGP4MP) {
#ifdef HAVE_IPV6
	if (gateway_from == NULL || 
		gateway_from->prefix->family == AF_INET6) {
	    plen = 16;
	    afi = AFI_IP6;
	}
#endif /* HAVE_IPV6 */
    }
#ifdef HAVE_IPV6
    if (type == MSG_PROTOCOL_BGP4PLUS) {
	assert (gateway_from == NULL ||
		gateway_from->prefix->family == AF_INET6);
	plen = 16;
    }
    if (type == MSG_PROTOCOL_BGP4PLUS_01) {
	assert (gateway_from == NULL ||
		gateway_from->prefix->family == AF_INET6);
	plen = 16;
    }
#endif /* HAVE_IPV6 */

if (type == MSG_PROTOCOL_BGP4MP) {
    BGP_PUT_SHORT ((gateway_from)? gateway_from->AS: 0, cp);
    BGP_PUT_SHORT ((gateway_to)? gateway_to->AS: 0, cp);
    BGP_PUT_SHORT ((gateway_to && gateway_to->interface)? 
			gateway_to->interface->index: 0, cp);
    BGP_PUT_SHORT (afi, cp);

    if (gateway_from == NULL) {
	BGP_PUT_ZERO (plen, cp);
    }
    else {
        BGP_PUT_DATA (prefix_tochar (gateway_from->prefix), plen, cp);
    }
    if (gateway_to == NULL) {
	BGP_PUT_ZERO (plen, cp);
    }
    else {
        BGP_PUT_DATA (prefix_tochar (gateway_to->prefix), plen, cp);
    }
}
else {
    /* from */
    if (gateway_from == NULL) {
	memset (cp, 0, plen + 2);
	cp += (plen + 2);
    }
    else {
	BGP_PUT_SHORT (gateway_from->AS, cp);
        BGP_PUT_DATA (prefix_tochar (gateway_from->prefix), plen, cp);
    }

if (subtype != MSG_BGP_STATE_CHANGE) {
    /* to */
    if (gateway_to == NULL) {
	memset (cp, 0, plen + 2);
	cp += (plen + 2);
    }
    else {
	BGP_PUT_SHORT (gateway_to->AS, cp);
        BGP_PUT_DATA (prefix_tochar (gateway_to->prefix), plen, cp);
    }
}
}

    return (cp);
}


/* 
 * Create MRT update message. Take in pointer to
 * buffer of allocated memory, and attr and with and
 * ann prefixes. Return pointer to end of buffer
 * filled in with MRT update message. Set size to size
 * filled in.
 */
u_char *
bgp_create_update_msg (int type, int subtype, 
		       int * size, bgp_attr_t * attr,
		       LINKED_LIST * ll_ann_prefixes,
		       LINKED_LIST * ll_with_prefixes,
		       gateway_t * gateway_to)
{
    u_char *cp, *start_pdu, *end_pdu, *bgp_packet;
    int len;

    cp = start_pdu = NewArray (u_char, MAX_MSG_SIZE);
    end_pdu = start_pdu + MAX_MSG_SIZE;

    cp = bgp_fill_update (cp, type, subtype, attr->gateway, gateway_to);
    bgp_packet = cp;
    if (type == MSG_PROTOCOL_BGP4MP) {
	assert (subtype == BGP4MP_MESSAGE || subtype == BGP4MP_MESSAGE_OLD);
        memset (bgp_packet, 0xff, BGP_HEADER_MARKER_LEN);
        BGP_PUT_HDRTYPE (BGP_UPDATE, bgp_packet);
        cp = bgp_packet + BGP_HEADER_LEN;
    }

    len = bgp_create_pdu (ll_with_prefixes, ll_ann_prefixes, attr,
			  SAFI_UNICAST, NULL, NULL, cp, end_pdu - cp, 
			  TRUE /* always new format */);

    cp += len;
    *size = cp - start_pdu;
    if (type == MSG_PROTOCOL_BGP4MP)
        BGP_PUT_HDRLEN (cp - bgp_packet, bgp_packet);
    return (start_pdu);
}


u_char *
bgp_create_update_msg2 (int type, int subtype, int * size, u_char * packet,
		        gateway_t * gateway_from, gateway_t * gateway_to)
{
    u_char *cp, *start_pdu, *end_pdu;
    int len = *size;

    cp = start_pdu = NewArray (u_char, MAX_MSG_SIZE);
    end_pdu = start_pdu + MAX_MSG_SIZE;

    cp = bgp_fill_update (cp, type, subtype, gateway_from, gateway_to);
    if (len > 0) {
        memcpy (cp, packet, len);
        *size = (cp + len) - start_pdu;
    }
    return (start_pdu);
}


void 
bgp_process_sync_msg (int type, int subtype, u_char *msg, 
		      int length, int *viewno, char *filename)
{
    BGP_GET_SHORT (*viewno, msg);
    length -= 2;
    strncpy (filename, (char *)msg, length);
    filename[length] = '\0';
}


void 
bgp_process_state_msg (int type, int subtype,
		       u_char *msg, int length, gateway_t ** gateway,
		       u_short * old_state, u_short * new_state)
{
    u_char *cp, sip[16], dip[16];
    int sas, das;
    prefix_t *prefix;
    int plen = 4;
    int family = AF_INET;
    gateway_t *gateway_from;
#ifdef notdef
    gateway_t *gateway_to;
#endif /* notdef */

#ifdef HAVE_IPV6
    if (type == MSG_PROTOCOL_BGP4PLUS || type == MSG_PROTOCOL_BGP4PLUS_01) {
	plen = 16;
        family = AF_INET6;
    }
#endif /* HAVE_IPV6 */

    cp = msg;

if (type == MSG_PROTOCOL_BGP4MP) {
    int afi, index;

    BGP_GET_SHORT (sas, cp);
    BGP_GET_SHORT (das, cp);
    BGP_GET_SHORT (index, cp);
    BGP_GET_SHORT (afi, cp);
    if (afi != AFI_IP && afi != AFI_IP6) {
	return;
    }
#ifdef HAVE_IPV6
    if (afi == AFI_IP6) {
        plen = 16;
        family = AF_INET6;
    }
#endif /* HAVE_IPV6 */
    BGP_GET_DATA (sip, plen, cp);
    BGP_GET_DATA (dip, plen, cp);
}
else {
    /* from */
    BGP_GET_SHORT (sas, cp);
    BGP_GET_DATA (sip, plen, cp);

#ifdef notdef
    /* to */
    BGP_GET_SHORT (das, cp);
    BGP_GET_DATA (dip, plen, cp);
#endif
}
    prefix = New_Prefix (family, sip, plen * 8);
    gateway_from = add_gateway (prefix, sas, NULL);
    Deref_Prefix (prefix);
#ifdef notdef
    prefix = New_Prefix (family, dip, plen * 8);
    gateway_to = add_gateway (prefix, das, NULL);
    Deref_Prefix (prefix);
#endif

    BGP_GET_SHORT (*old_state, cp);
    BGP_GET_SHORT (*new_state, cp);

    *gateway = gateway_from;
    return;
}


char *
bgp_attr_toa (bgp_attr_t * attr)
{
    char *tmpx;
    char *cp;

    THREAD_SPECIFIC_STORAGE (tmpx);

    sprintf (tmpx, "%s|%s|%s|%d|%d|%s|%s|",
	     aspath_toa (attr->aspath),
	     origin2string (attr->origin),
	     attr->nexthop ? prefix_toa (attr->nexthop->prefix) : "none",
	     (int) attr->local_pref,
	     (int) attr->multiexit,
	     community_toa (attr->community),
	     BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ATOMICAGG) ? "AG" : "NAG");

    /* I don't think we can call prefix_toa twice in the same call */
    cp = tmpx + strlen (tmpx);
    sprintf (cp, "%s|",  attr->aggregator.prefix ? 
			     prefix_toa (attr->aggregator.prefix) : "");

    return (tmpx);
}


void
bgp_print_attr (bgp_attr_t * attr)
{
    assert (attr);

    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGIN))
	printf ("%s: %s\n", bgptype2string (PA4_TYPE_ORIGIN),
			    origin2string (attr->origin));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH))
	printf ("%s: %s\n", bgptype2string (PA4_TYPE_ASPATH),
			    aspath_toa (attr->aspath));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP))
	printf ("%s: %s\n", bgptype2string (PA4_TYPE_NEXTHOP),
			    prefix_toa (attr->nexthop->prefix));
#ifdef HAVE_IPV6
    if (attr->link_local)
	printf ("%s: %s\n", bgptype2string (PA4_TYPE_NEXTHOP),
			    prefix_toa (attr->link_local->prefix));
    if (attr->nexthop4)
	printf ("%s: %s\n", bgptype2string (PA4_TYPE_NEXTHOP),
			    prefix_toa (attr->nexthop4->prefix));
#endif /* HAVE_IPV6 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_METRIC))
	printf ("%s: %ld\n", bgptype2string (PA4_TYPE_METRIC),
			     attr->multiexit);
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_LOCALPREF))
	printf ("%s: %ld\n", bgptype2string (PA4_TYPE_LOCALPREF),
			     attr->local_pref);
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ATOMICAGG))
	printf ("%s\n", bgptype2string (PA4_TYPE_ATOMICAGG));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_AGGREGATOR))
	printf ("%s: AS%d %s\n", bgptype2string (PA4_TYPE_AGGREGATOR),
				 attr->aggregator.as,
				 prefix_toa (attr->aggregator.prefix));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGINATOR_ID))
	printf ("%s: %s\n", bgptype2string (PA4_TYPE_ORIGINATOR_ID),
			    prefix_toa (attr->originator));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_CLUSTER_LIST))
	printf ("%s: %s\n", bgptype2string (PA4_TYPE_CLUSTER_LIST),
			    cluster_list_toa (attr->cluster_list));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_COMMUNITY))
	printf ("%s: %s\n", bgptype2string (PA4_TYPE_COMMUNITY),
			    community_toa (attr->community));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_DPA))
	printf ("%s: AS%d %ld\n", bgptype2string (PA4_TYPE_DPA),	
				  attr->dpa.as, attr->dpa.value);
}


#ifdef notdef
/* just i'm lazy to write a code to check buffer overflow */
void
bgp_uii_attr (uii_connection_t *uii, bgp_attr_t * attr)
{
    assert (attr);

    if (attr->gateway)
        uii_add_bulk_output (uii, "FROM: %s AS%d\n",
                                 prefix_toa (attr->gateway->prefix),
                                 attr->gateway->AS);

    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGIN))
	uii_add_bulk_output (uii, "%s: %s\n", bgptype2string (PA4_TYPE_ORIGIN),
			    origin2string (attr->origin));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH))
	uii_add_bulk_output (uii, "%s: %A\n", bgptype2string (PA4_TYPE_ASPATH),
			    attr->aspath);
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP)) {
	if (attr->direct)
	    uii_add_bulk_output (uii, "%s: %s via %s\n", 
			    bgptype2string (PA4_TYPE_NEXTHOP),
			    prefix_toa (attr->nexthop->prefix),
			    prefix_toa (attr->direct->prefix));
	else
	    uii_add_bulk_output (uii, "%s: %s\n", 
			    bgptype2string (PA4_TYPE_NEXTHOP),
			    prefix_toa (attr->nexthop->prefix));
    }
#ifdef HAVE_IPV6
    if (attr->link_local)
	uii_add_bulk_output (uii, "%s: %s\n", bgptype2string (PA4_TYPE_NEXTHOP),
			    prefix_toa (attr->link_local->prefix));
    if (attr->nexthop4)
	uii_add_bulk_output (uii, "%s: %s\n", bgptype2string (PA4_TYPE_NEXTHOP),
			    prefix_toa (attr->nexthop4->prefix));
#endif /* HAVE_IPV6 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_METRIC))
	uii_add_bulk_output (uii, "%s: %ld\n", bgptype2string (PA4_TYPE_METRIC),
			     attr->multiexit);
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_LOCALPREF))
	uii_add_bulk_output (uii, "%s: %ld\n", 
			     bgptype2string (PA4_TYPE_LOCALPREF),
			     attr->local_pref);
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ATOMICAGG))
	uii_add_bulk_output (uii, "%s\n", bgptype2string (PA4_TYPE_ATOMICAGG));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_AGGREGATOR))
	uii_add_bulk_output (uii, "%s: AS%d %s\n", 
				 bgptype2string (PA4_TYPE_AGGREGATOR),
				 attr->aggregator.as,
				 prefix_toa (attr->aggregator.prefix));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGINATOR_ID))
	uii_add_bulk_output (uii, "%s: %s\n", 
			    bgptype2string (PA4_TYPE_ORIGINATOR_ID),
			    prefix_toa (attr->originator));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_CLUSTER_LIST))
	uii_add_bulk_output (uii, "%s: %s\n", 
			    bgptype2string (PA4_TYPE_CLUSTER_LIST),
			    cluster_list_toa (attr->cluster_list));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_COMMUNITY))
	uii_add_bulk_output (uii, "%s: %s\n", 
			    bgptype2string (PA4_TYPE_COMMUNITY),
			    community_toa (attr->community));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_DPA))
	uii_add_bulk_output (uii, "%s: AS%d %ld\n", 
			          bgptype2string (PA4_TYPE_DPA),	
				  attr->dpa.as, attr->dpa.value);
}
#endif


int
bgp_attr_buffer (bgp_attr_t * attr, buffer_t *buffer)
{
    return buffer_printf (buffer, "%A|%s|%s|%d|%d|%s|%s|%s|",
	     attr->aspath,
	     origin2string (attr->origin),
	     attr->nexthop ? prefix_toa (attr->nexthop->prefix) : "none",
	     (int) attr->local_pref,
	     (int) attr->multiexit,
	     community_toa (attr->community),
	     BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ATOMICAGG) ? "AG" : "NAG",
    	     attr->aggregator.prefix ? 
		prefix_toa (attr->aggregator.prefix) : "");
}


void
bgp_print_attr_buffer (bgp_attr_t * attr, buffer_t * buffer, int mode)
{
    assert (attr);

    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGIN))
	buffer_printf (buffer, "%B: %s\n", PA4_TYPE_ORIGIN, 
		       origin2string (attr->origin));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH))
	buffer_printf (buffer, "%B: %A\n", PA4_TYPE_ASPATH, attr->aspath);
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP)) {
	if (mode == 1 && attr->direct)
	    buffer_printf (buffer, "%B: %a via %a\n", 
			    PA4_TYPE_NEXTHOP,
			    attr->nexthop->prefix,
			    attr->direct->prefix);
	else
	    buffer_printf (buffer, "%B: %a\n", PA4_TYPE_NEXTHOP, 
			   attr->nexthop->prefix);
    }
#ifdef HAVE_IPV6
    if (attr->link_local)
	buffer_printf (buffer, "%B: %a\n", PA4_TYPE_NEXTHOP, 
		       attr->link_local->prefix);
    if (attr->nexthop4)
	buffer_printf (buffer, "%B: %a\n", PA4_TYPE_NEXTHOP, 
		       attr->nexthop4->prefix);
#endif /* HAVE_IPV6 */
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_METRIC))
	buffer_printf (buffer, "%B: %d\n", PA4_TYPE_METRIC, attr->multiexit);
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_LOCALPREF))
	buffer_printf (buffer, "%B: %d\n", PA4_TYPE_LOCALPREF, 
		       attr->local_pref);
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ATOMICAGG))
	buffer_printf (buffer, "%B\n", PA4_TYPE_ATOMICAGG);
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_AGGREGATOR))
	buffer_printf (buffer, "%B: AS%d %a\n", PA4_TYPE_AGGREGATOR,
				 attr->aggregator.as,
				 attr->aggregator.prefix);
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGINATOR_ID))
	buffer_printf (buffer, "%B: %a\n", PA4_TYPE_ORIGINATOR_ID, 
		       attr->originator);
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_CLUSTER_LIST))
	buffer_printf (buffer, "%B: %s\n", PA4_TYPE_CLUSTER_LIST,
			    cluster_list_toa (attr->cluster_list));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_COMMUNITY))
	buffer_printf (buffer, "%B: %s\n", PA4_TYPE_COMMUNITY,
			    community_toa (attr->community));
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_DPA))
	buffer_printf (buffer, "%B: AS%d %d\n", PA4_TYPE_DPA,	
				  attr->dpa.as, attr->dpa.value);
}


/* just i'm lazy to write a code to check buffer overflow */
void
bgp_uii_attr (uii_connection_t *uii, bgp_attr_t * attr)
{
    assert (attr);

    if (uii->answer == NULL)
	uii->answer = New_Buffer (0);
    bgp_print_attr_buffer (attr, uii->answer, 1);
}


int
bgp_scan_attr (char *line, bgp_attr_t *attr, trace_t *tr)
{
    char *cp = line;
    int code;

    assert (line);

    if ((code = string2bgptype (&cp)) <= 0)
	return (0);

    if (code == PA4_TYPE_ATOMICAGG) {
	/* check to make sure */
	if (*cp == '\0' || isspace (*cp)) {
    	    BGP4_BIT_SET (attr->attribs, code);
	    bgp_trace_attr (TR_PACKET, tr, attr, code);
	    return (code);
	}
	return (0);
    }

    if (*cp != ':' && !isspace (*cp)) {
	return (0);
    }

    do {
        cp++;
    } while (isspace (*cp));

    switch (code) {

    case PA4_TYPE_ORIGIN: {
	int i;
	for (i = 0; i < 3; i++) {
	    if (strncasecmp (cp, s_origins[i], strlen (s_origins[i])) == 0) {
		attr->origin = i;
    	        BGP4_BIT_SET (attr->attribs, code);
	        bgp_trace_attr (TR_PACKET, tr, attr, code);
		return (code);
	    }
	}
	return (-1);
    }
    case PA4_TYPE_ASPATH: {
	aspath_t *aspath;
	aspath = aspth_from_string (cp);
	if (aspath == NULL) {
	    return (-1);
	}
	if (attr->aspath)
	    Delete_ASPATH (attr->aspath);
	attr->aspath = aspath;
    	BGP4_BIT_SET (attr->attribs, code);
	bgp_trace_attr (TR_PACKET, tr, attr, code);
        return (code);
    }
    case PA4_TYPE_NEXTHOP: {
	prefix_t *prefix;
#ifdef HAVE_IPV6
	prefix = ascii2prefix (0, cp);
	if (prefix == NULL) {
	    return (-1);
	}
	if (prefix->family == AF_INET6) {
	    if (attr->nexthop && attr->nexthop->prefix->family == AF_INET) {
		attr->nexthop4 = attr->nexthop;  /* save */
                attr->nexthop = NULL;
	    }
	    if (IN6_IS_ADDR_LINKLOCAL (prefix_toaddr6 (prefix))) {
		attr->link_local = add_nexthop (prefix, NULL);
		if (attr->nexthop == NULL)
		    attr->nexthop = ref_nexthop (attr->link_local);
	    }
	    else {
		if (attr->nexthop)
		    deref_nexthop (attr->nexthop);
		attr->nexthop = add_nexthop (prefix, NULL);
	    }
	}
	else {
	    if (attr->nexthop && attr->nexthop->prefix->family == AF_INET6) {
		if (attr->nexthop4)
		    deref_nexthop (attr->nexthop4);
		attr->nexthop4 = add_nexthop (prefix, NULL);
	    }
	    else {
		if (attr->nexthop)
		    deref_nexthop (attr->nexthop);
		attr->nexthop = add_nexthop (prefix, NULL);
	    }
	}
    	BGP4_BIT_SET (attr->attribs, code);
	trace (TR_PACKET, tr, "  %s: %s\n", bgptype2string (PA4_TYPE_NEXTHOP),
				       prefix_toa (prefix));
#else
	prefix = ascii2prefix (AF_INET, cp);
	if (prefix == NULL) {
	    return (-1);
	}
	if (attr->nexthop)
	    deref_nexthop (attr->nexthop);
	attr->nexthop = add_nexthop (prefix, NULL);
    	BGP4_BIT_SET (attr->attribs, code);
	bgp_trace_attr (TR_PACKET, tr, attr, code);
#endif /* HAVE_IPV6 */
        return (code);
    }
    case  PA4_TYPE_METRIC: {
	int value;
	if (sscanf (cp, "%d", &value) < 1)
	    return (-1);
	attr->multiexit = value;
    	BGP4_BIT_SET (attr->attribs, code);
	bgp_trace_attr (TR_PACKET, tr, attr, code);
	return (code);
    }
    case PA4_TYPE_LOCALPREF: {
	int value;
	if (sscanf (cp, "%d", &value) < 1)
	    return (-1);
	attr->local_pref = value;
    	BGP4_BIT_SET (attr->attribs, code);
	bgp_trace_attr (TR_PACKET, tr, attr, code);
	return (code);
    }
    case PA4_TYPE_AGGREGATOR: {
	int as; char str[MAXLINE];
	if (sscanf (cp, "AS%d %s", &as, str) < 2)
	    return (-1);
	attr->aggregator.as = as;
	if (attr->aggregator.prefix)
	    Deref_Prefix (attr->aggregator.prefix);
	attr->aggregator.prefix = ascii2prefix (AF_INET, str);
    	BGP4_BIT_SET (attr->attribs, code);
	bgp_trace_attr (TR_PACKET, tr, attr, code);
	return (code);
    }
    case PA4_TYPE_COMMUNITY: {
	community_t *community;
	community = community_from_string (cp);
	if (community == NULL)
	    return (-1);
	if (attr->community)
	    Delete_community (attr->community);
	attr->community = community;
    	BGP4_BIT_SET (attr->attribs, code);
	bgp_trace_attr (TR_PACKET, tr, attr, code);
	return (code);
    }
    case PA4_TYPE_ORIGINATOR_ID: {
	prefix_t *prefix;
	prefix = ascii2prefix (AF_INET, cp);
	if (prefix == NULL)
	    return (-1);
	if (attr->originator)
	    Deref_Prefix (attr->originator);
	attr->originator = prefix;
    	BGP4_BIT_SET (attr->attribs, code);
	bgp_trace_attr (TR_PACKET, tr, attr, code);
	return (code);
    }
    case PA4_TYPE_CLUSTER_LIST: {
	cluster_list_t *cluster_list;
	cluster_list = cluster_list_from_string (cp);
	if (cluster_list == NULL)
	    return (-1);
	if (attr->cluster_list)
	    Delete_cluster_list (attr->cluster_list);
	attr->cluster_list = cluster_list;
    	BGP4_BIT_SET (attr->attribs, code);
	bgp_trace_attr (TR_PACKET, tr, attr, code);
	return (code);
    }
    case PA4_TYPE_DPA: {
	int as, value;
	if (sscanf (cp, "AS%d %d", &as, &value) < 2)
	    return (-1);
	attr->dpa.as = as;
	attr->dpa.value = value;
    	BGP4_BIT_SET (attr->attribs, code);
	bgp_trace_attr (TR_PACKET, tr, attr, code);
	return (code);
    }
    default:
	break;
    }
    return (-1);
}



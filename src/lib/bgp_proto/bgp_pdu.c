/*
 * $Id: bgp_pdu.c,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#include <mrt.h>
#include <bgp.h>


static int process_pdu (bgp_peer_t * peer);

/*
 * return 0 if an error can be ignored 
 */

int
bgp_read (bgp_peer_t *peer, int sockfd, u_char *ptr, int len)
{
    int n;
    trace_t *tr;

    tr = (peer)? peer->trace: BGP->trace;
    
    /* NT looks it likes recv() rather than read(). It's ok for unix */
    n = recv (sockfd, ptr, len, 0);

    if (n < 0) {

	/* I defined error codes of NT in mrt.h -- masaki */
	switch (socket_errno ()) {
        case EWOULDBLOCK:
#if     defined(EAGAIN) && EAGAIN != EWOULDBLOCK
        case EAGAIN:
#endif  /* EAGAIN */
	    /* this happens because of non-blocking io */
	    return (0);
        case EINTR:
        case ENETUNREACH:
        case EHOSTUNREACH:
	    trace (TR_INFO, tr, 
		   "READ FAILED (%m) -- OKAY TO IGNORE\n");
	    return (0);
	default:
	    trace (TR_WARN, tr, "READ FAILED (%m)\n");
	    return (-1);
	}
    }
    else if (n == 0) {
	trace (TR_WARN, tr, "READ FAILED EOF???\n");
	return (-1);
    }

    trace (TR_PACKET, tr, "READ (%d bytes)\n", n);
    return (n);
}


/*
 * reads data on socket as much as it can
 * returns the length or -1 on error
 * peer->start_ptr will have the pointer
 * peer->read_ptr keeps the end of data
 */
static int
bgp_fill_packet (bgp_peer_t *peer)
{
    int len, n;

    assert (peer);
    assert (peer->read_ptr >= peer->buffer);
    assert (peer->read_ptr <= peer->buffer + sizeof (peer->buffer));
    assert (peer->start_ptr >= peer->buffer);
    assert (peer->start_ptr <= peer->buffer + sizeof (peer->buffer));

    if ((len = peer->read_ptr - peer->start_ptr) == 0) {
	/* reset the pointers */
	peer->start_ptr = peer->buffer;
	peer->read_ptr = peer->buffer;
    }

    if (peer->buffer + sizeof (peer->buffer) - peer->read_ptr 
		< BGPMAXPACKETSIZE) {
	/* need to move them to the start to get more */
	memcpy (peer->buffer, peer->start_ptr, len);
	peer->start_ptr = peer->buffer;
	peer->read_ptr = peer->buffer + len;
    }

    if ((n = bgp_read (peer, peer->sockfd, peer->read_ptr, 
			BGPMAXPACKETSIZE)) < 0) {
	/* will not send notification for this kind of error */
	bgp_sm_process_event (peer, BGPEVENT_CLOSED);
	return (-1);
    }
    else if (n == 0) {
	return (0);
    }

    peer->read_ptr += n;
    assert (peer->read_ptr <= peer->buffer + sizeof (peer->buffer));

    return (len + n);
}


/* 
 * Masaki's version is get_packet ()
 * fills in buffer and returns 1 if full one has arrived
 *                     returns 0 if not, -1 on error
 */
static int
get_packet (bgp_peer_t *peer)
{
    int pdu_len, len;
    u_char *cp;

    peer->packet = NULL;

    /* need to be filled at least a header in buffer */
    /* check if the requested length of data already in buffer */
    if ((len = peer->read_ptr - peer->start_ptr) < BGP_HEADER_LEN) {
	return (0);
    }

    cp = peer->start_ptr;

    BGP_GET_HDRLEN (pdu_len, cp);
    if (pdu_len < BGP_HEADER_LEN || pdu_len > BGPMAXPACKETSIZE) {
        peer->start_ptr = peer->read_ptr; /* eat up the input */
        bgp_send_notify_word (peer, BGP_ERR_HEADER, BGP_ERRHDR_LENGTH, pdu_len);
	bgp_sm_process_event (peer, BGPEVENT_ERROR);
	return (-1);
    }

    /* see if the total length packet in buffer */
    /* check if the requested length of data already in buffer */
    if (len < pdu_len) {
	return (0);
    }

    peer->packet = peer->start_ptr;
    peer->start_ptr += pdu_len;
    return (1);
}


/*
 * Gets packet from peer and starts processing
 */
static int
bgp_get_pdu2 (bgp_peer_t * peer)
{
    int ret, i;

    /* may be closed since we might be on a schedule queue */
    if (peer->sockfd < 0)
	return (-1);

/* too many continuous reads may result in hold timer expire
   since we can't send a keep alive during the period */
#define BGP_N_CONTINUOUS_READS 10
    for (i = 0; i < BGP_N_CONTINUOUS_READS; i++) {

        if ((ret = get_packet (peer)) < 0) {
	    /* sockfd should be closed and deleted */
            assert (peer->sockfd < 0);
    	    return (-1);
        }
        else if (ret == 0) {
	    /* not enough data arrived */
	    assert (peer->sockfd >= 0);
	    select_enable_fd_mask (peer->sockfd, SELECT_READ);
    	    return (0);
        }
   
        if ((ret = process_pdu (peer)) < 0) {
	    /* sockfd should be closed and deleted */
            assert (peer->sockfd < 0);
	    return (-1);
        }

	/* in case a notification arrived */
	if (peer->sockfd < 0)
	    return (-1);
    }

    assert (peer->sockfd >= 0);
    /* re-schedule myself to allow other events hapen */
    schedule_event2 ("bgp_get_pdu2", peer->schedule,
                     (event_fn_t) bgp_get_pdu2, 1, peer);
    return (1);
}


int
bgp_get_pdu (bgp_peer_t * peer)
{
    int ret;

    /* I know that the return value will not be used, but leave as it was */

    if ((ret = bgp_fill_packet (peer)) < 0) {
        /* sockfd should be closed and deleted */
        assert (peer->sockfd < 0);
        return (-1);
    }
    else if (ret == 0) {
        assert (peer->sockfd >= 0);
        select_enable_fd_mask (peer->sockfd, SELECT_READ);
        return (ret);
    }

    return (bgp_get_pdu2 (peer));
}


/* prepare the header info into buffer */
static int 
bgp_prepare_header (u_char *buffer, int type, u_char *data, int len)
{
    u_char *cp = buffer;

    assert (len >= 0 && len <= BGPMAXPACKETSIZE - BGP_HEADER_LEN);

    /* set auth field */
    memset (buffer, 0xff, BGP_HEADER_MARKER_LEN);

    BGP_PUT_HDRLEN (BGP_HEADER_LEN + len, cp);
    BGP_PUT_HDRTYPE (type, cp);

    /* it could be possible to avoid copying 
       if the header space is reserved by the caller */
    if (len > 0) {
        BGP_SKIP_HEADER (cp);
	memcpy (cp, data, len);
    }
    return (BGP_HEADER_LEN + len);
}


/* packet hold a bgp backet including a header */
static void
bgp_dump_msg (bgp_peer_t *peer, u_char *packet, int length, int dir)
{
    int hdrtype, hdrlen;

    assert (length >= BGP_HEADER_LEN && length <= BGPMAXPACKETSIZE);

    if (BGP->dump_direction <= 0)
	return;
    /* 1 - receiving, 2 -- sending, 3 -- both */
    if ((BGP->dump_direction & dir) == 0)
	return;

    BGP_GET_HDRLEN (hdrlen, packet);
    BGP_GET_HDRTYPE (hdrtype, packet);

    if (BGP->dump_new_format) {
        if (BGP4_BIT_TEST (BGP->dump_update_types, hdrtype)) {
    	    bgp_write_mrt_msg (peer, BGP4MP_MESSAGE, packet, length);
	}
    }
    else {
        if (BGP4_BIT_TEST (BGP->dump_update_types, hdrtype)) {
	    if (hdrtype == BGP_OPEN)
    	        bgp_write_mrt_msg (peer, MSG_BGP_OPEN, 
				   packet + BGP_HEADER_LEN, 
				   length - BGP_HEADER_LEN);
	    else if (hdrtype == BGP_KEEPALIVE)
    	        bgp_write_mrt_msg (peer, MSG_BGP_KEEPALIVE, 
				   packet + BGP_HEADER_LEN, 
				   length - BGP_HEADER_LEN);
	    else if (hdrtype == BGP_NOTIFY)
    	        bgp_write_mrt_msg (peer, MSG_BGP_NOTIFY, 
				   packet + BGP_HEADER_LEN, 
				   length - BGP_HEADER_LEN);
	    else if (hdrtype == BGP_UPDATE)
    	        bgp_write_mrt_msg (peer, MSG_BGP_UPDATE, 
				   packet + BGP_HEADER_LEN, 
				   length - BGP_HEADER_LEN);
	}
    }
}


/* 
 * munge bgp packet
 * Process notifications here -- deal with errors immediately
 */
static int 
process_pdu (bgp_peer_t * peer)
{
    int type;
    int length;
    int error = 0;
    u_char *cp;

    assert (peer);
    assert (peer->packet);

    peer->num_packets_recv++;

    cp = peer->packet;
    BGP_GET_HDRTYPE (type, cp);
    BGP_GET_HDRLEN (length, cp);

    if (type >= BGP_OPEN && type < BGP_PACKET_MAX) {
        trace (TR_PACKET, peer->trace, "recv %s (%d bytes)\n",
	       sbgp_pdus[type], length);
    }

    bgp_dump_msg (peer, peer->packet, length, DUMP_DIR_RECV);

    switch (type) {
        case BGP_OPEN:
	    if (length < BGP_HEADER_LEN+BGP_OPEN_MIN_LEN) {
		error = 1;
		break;
	    }
	    bgp_sm_process_event (peer, BGPEVENT_RECVOPEN);
	    break;
	case BGP_UPDATE:
	    if (length < BGP_HEADER_LEN+BGP_UPDATE_MIN_LEN) {
		error = 1;
		break;
	    }
    	    peer->num_updates_recv++;
	    bgp_sm_process_event (peer, BGPEVENT_RECVUPDATE);
	    break;
	case BGP_NOTIFY:
	    if (length < BGP_HEADER_LEN+BGP_NOTIFY_MIN_LEN) {
		error = 1;
		break;
	    }
    	    peer->num_notifications_recv++;
	    bgp_process_notify (peer);
	    bgp_sm_process_event (peer, BGPEVENT_RECVNOTIFY);
	    break;
	case BGP_KEEPALIVE:
	    if (length != BGP_HEADER_LEN) {
		error = 1;
		break;
	    }
	    bgp_sm_process_event (peer, BGPEVENT_RECVKEEPALIVE);
	    break;
	default:
            trace (TR_ERROR, peer->trace, 
		"recv unknown message type %d (%d bytes)\n", type, length);
	    bgp_send_notify_byte (peer, BGP_ERR_HEADER, BGP_ERRHDR_TYPE, type);
	    bgp_sm_process_event (peer, BGPEVENT_ERROR);
	    return (-1);
    }
    if (error > 0) {
        trace (TR_ERROR, peer->trace, 
	    "recv %s with bad length %d\n", sbgp_pdus[type], length);
	bgp_send_notify_word (peer, BGP_ERR_HEADER, BGP_ERRHDR_LENGTH, length);
	bgp_sm_process_event (peer, BGPEVENT_ERROR);
	return (-1);
    }
    return (1);
}


/* 
 * munge update pdu info into withdrawn routes,  announced routes and 
 * aspath
 */
int 
bgp_process_update (bgp_peer_t * peer)
{
    int type, length;
    u_char *cp;

    assert (peer);
    assert (peer->packet);
    cp = peer->packet;
    BGP_GET_HDRTYPE (type, cp);
    BGP_GET_HDRLEN (length, cp);
    assert (type == BGP_UPDATE);
    assert (length >= BGP_HEADER_LEN+BGP_UPDATE_MIN_LEN && 
	    length <= BGPMAXPACKETSIZE);
    BGP_SKIP_HEADER (cp);
    length -= BGP_HEADER_LEN;

    if (BGP->update_call_fn)
	return (BGP->update_call_fn (peer, cp, length));

    return (1);
}


/* 
 * cp will be used to process another connection in case of racing
 */
int 
bgp_process_open (bgp_peer_t * peer)
{
    int version;
    int as;
    time_t holdtime;
    int optlen;
    u_long id;
    char tmpx[MAXLINE];
    int packetlen;
    u_char *optdata;
    u_char *cp = peer->packet;
    int one_third;

    BGP_GET_HDRLEN (packetlen, cp);
    BGP_SKIP_HEADER (cp);

    version = BGP_GET_VERSION (cp);
    if (version != DEFAULT_BGP_VERSION) {
	trace (TR_ERROR, peer->trace,
	       "running BGP 3 or earlier! (version = %d)\n", version);
	bgp_send_notify_word (peer, BGP_ERR_OPEN, BGP_ERROPN_VERSION,
			      DEFAULT_BGP_VERSION);
	return (-1);
    }

    BGP_GET_OPEN (version, as, holdtime, id, optlen, cp);

    trace (TR_PACKET, peer->trace,
	   "recv %s AS %d, HOLDTIME %d, ID %s, OPTLEN %d\n",
	   bgpmessage2string (BGP_OPEN),
	   as, holdtime, inet_ntop (AF_INET, &id, tmpx, sizeof (tmpx)), 
	   optlen);

    if (id == 0L || id == ~0L) {
        trace (TR_ERROR, peer->trace, "invalid router id: %s\n",
	       inet_ntop (AF_INET, &id, tmpx, sizeof (tmpx)));
	bgp_send_notification (peer, BGP_ERR_OPEN, BGP_ERROPN_BGPID);
	return (-1);
    }

    if (peer->packet + packetlen != cp + optlen) {
        trace (TR_ERROR, peer->trace, 
	       "invalid optional parameter length = %d (should be %d)\n",
	       optlen, peer->packet + packetlen - cp);
	/* XXX no error code defined */
	optlen = peer->packet + packetlen - cp;
    }

    optdata = cp;
    while (cp < optdata + optlen) {
	int type, plen;
	u_char *optdata1;
	/* Gated is wrong. Old cisco IOS has the same bug. */
        /* This is not an auth code, but the length of optional parameters. */

	BGP_GET_BYTE (type, cp);
	BGP_GET_BYTE (plen, cp);
        if (optdata + optlen < cp + plen) {
            trace (TR_ERROR, peer->trace, 
	           "invalid parameter length = %d (should be <= %d)\n",
	           plen, optdata + optlen - cp);
	    /* XXX no error code defined */
	    plen = optdata + optlen - cp;
        }
	optdata1 = cp;
	switch (type) {

	case 1: /* Authentication Information */ {
	    int authcode, authdatalen;
    	    u_char *authdata;

	    BGP_GET_BYTE (authcode , cp);
	    authdata = cp;
	    authdatalen = plen - 1;
	    cp += authdatalen;
    	    trace (TR_PACKET, peer->trace,
	   	   "recv %s with authentication information "
		    "code = %d len = %d\n",
		    bgpmessage2string (BGP_OPEN),
	   	    authcode, authdatalen);
            trace (TR_ERROR, peer->trace, 
		   "authentication unsupported (code: %d)\n", authcode);
	    bgp_send_notification (peer, BGP_ERR_OPEN, BGP_ERROPN_OPTPARAM);
	    return (-1); }

	case 2: /* Capabilities Negotiation */
	    /* draft-ietf-idr-bgp4-cap-neg-02.txt */
	    while (cp < optdata1 + plen) {
		int capcode, capdatalen;
		u_char *capdata;

		BGP_GET_BYTE (capcode , cp);
		BGP_GET_BYTE (capdatalen , cp);
        	if (optdata1 + plen < cp + capdatalen) {
            	    trace (TR_ERROR, peer->trace, 
	           	    "invalid capability length = %d "
			    "(should be <= %d)\n",
	           	    capdatalen, optdata1 + plen - cp);
	    	        /* XXX no error code defined */
	    	    capdatalen = optdata1 + plen - cp;
        	}
		capdata = cp;
		cp += capdatalen;
    		trace (TR_PACKET, peer->trace,
	   	        "recv %s with capabilities negotiation "
			"code = %d len = %d\n",
		        bgpmessage2string (BGP_OPEN), capcode, capdatalen);
		switch (capcode) {

		case 1: /* Multiprotocol Extensions */ {
		    int afi, safi;
		    if (capdatalen != 4) {
            	        trace (TR_ERROR, peer->trace, 
	           	        "length (%d) should be 4\n", capdatalen);
	    	        capdatalen = 4;
		    }
		    BGP_GET_SHORT (afi, capdata);
		    BGP_GET_SHORT (safi, capdata);
		    safi &= 0x00ff;
		    peer->cap_opt_received |= AFISAFI2CAP (afi, safi);
    	    	    trace (TR_INFO, peer->trace,
	   	   	        "recv %s with MP capability"
				" afi = %d safi = %d\n", 
				bgpmessage2string (BGP_OPEN), afi, safi);
		    break; }
		case 128: /* I don't know but cisco sends this */
		default:
        	    trace (TR_WARN, peer->trace, 
		           "capability unsupported (code %d len %d)\n", 
			   capcode, capdatalen);
/* don't send for the time being */
#ifdef notdef
		    bgp_send_notify_byte (peer, BGP_ERR_OPEN, 
				       	  BGP_ERROPN_CAPABILITY, capcode);
		    return (-1);
#else
		    break;
#endif
		}
	    }
	    break;

	default:
            trace (TR_ERROR, peer->trace, 
		   "unknown optional parameter code: %d\n", type);
	    bgp_send_notification (peer, BGP_ERR_OPEN, BGP_ERROPN_OPTPARAM);
	    cp += plen;
	    return (-1);
	}
	
    }

    peer->cap_opt_negotiated = peer->cap_opt_requesting;
    if (peer->cap_opt_received) {
	u_long cap_opt_ok;

	cap_opt_ok = (peer->cap_opt_received & peer->cap_opt_requesting);
	peer->cap_opt_negotiated = cap_opt_ok;
	if (cap_opt_ok != peer->cap_opt_requesting) {
	    int afi, safi;

	    /* now cap_opt_ok holds ng */
	    cap_opt_ok = (peer->cap_opt_requesting & ~cap_opt_ok);
	    for (afi = 1; afi < AFI_MAX; afi++) {
	        for (safi = 1; safi < SAFI_MAX; safi++) {
		    if (BIT_TEST (cap_opt_ok, AFISAFI2CAP (afi, safi))) {
            		trace (TR_INFO, peer->trace,
   	            		"recv Open with lack of capability"
		    		" afi = %d safi = %d\n", afi, safi);
		    }
		}
	    }
	    if (cap_opt_ok) {
                bgp_send_notification (peer, BGP_ERR_OPEN, 
			               BGP_ERROPN_CAPABILITY);
		return (-1);
	    }
	}
    }

    /* set as if default (peer_as = 0) and check if valid AS */
    /* XXX bad way to change the gateway structure */
    if (peer->peer_as == 0) {
	if (as == peer->local_bgp->this_as)
	    BIT_SET (peer->options, BGP_INTERNAL);
    }
    else if (peer->peer_as != as) {
	bgp_send_notification (peer, BGP_ERR_OPEN, BGP_ERROPN_AS);
	return (-1);
    }

    if (holdtime != 0 && holdtime < BGP_MIN_HOLDTIME) {
	bgp_send_notification (peer, BGP_ERR_OPEN, BGP_ERROPN_BADHOLDTIME);
	return (-1);
    }

    if (peer->HoldTime_Interval >= 0) {
	/* this is required to reset the hold time set at open */
	if (holdtime > peer->HoldTime_Interval)
	    holdtime = peer->HoldTime_Interval;
    }
    /* not enforced by user */ 
    else if (holdtime > BGP->Default_HoldTime_Interval) {
	holdtime = BGP->Default_HoldTime_Interval;
    }

    one_third = holdtime / 3;

    assert (peer->timer_HoldTime);
    Timer_Set_Time (peer->timer_HoldTime, holdtime);
    trace (TR_INFO, peer->trace, "Set holdtime to %d\n", holdtime);

    if (holdtime != 0 && one_third < 1)
	one_third = 1;
    assert (peer->timer_KeepAlive);
    if (peer->KeepAlive_Interval < 0) {
        Timer_Set_Time (peer->timer_KeepAlive, one_third);
        trace (TR_INFO, peer->trace, "Set keepalive to %d\n", one_third);
    }

#ifdef notdef
    if (holdtime > 0) {
	Timer_Turn_ON (peer->timer_KeepAlive);
	Timer_Reset_Time (peer->timer_HoldTime);
    }
    else {
	/* keepalive remains off */
	Timer_Turn_OFF (peer->timer_HoldTime);
    }
#endif

    if (peer_set_gateway (peer, as, id) < 0)
	return (-1);

    return (1);
}


int 
bgp_process_notify (bgp_peer_t * peer)
{
    u_char *cp = peer->packet;
    u_char code, subcode;
    int length, datalen, data;

    BGP_GET_HDRLEN (length, cp);
    BGP_SKIP_HEADER (cp);

    BGP_GET_NOTIFY(code, subcode, cp);
    datalen = length - (BGP_HEADER_LEN+BGP_NOTIFY_MIN_LEN);

    peer->code = code;
    peer->subcode = subcode;

    if (datalen == 0) {
        trace (TR_ERROR, peer->trace, "recv %s %s\n",
	       bgpmessage2string (BGP_NOTIFY),
	       bgp_notify_to_string (code, subcode));
    }
    else if (datalen == 1) {
	BGP_GET_BYTE (data, cp);
        trace (TR_ERROR, peer->trace, 
	       "recv %s %s with byte data %d\n",
	       bgpmessage2string (BGP_NOTIFY),
	       bgp_notify_to_string (code, subcode), data);
    }
    else if (datalen == 2) {
	BGP_GET_SHORT (data, cp);
        trace (TR_ERROR, peer->trace, 
	       "recv %s %s with word data %d\n",
	       bgpmessage2string (BGP_NOTIFY),
	       bgp_notify_to_string (code, subcode), data);
    }
    else {
        trace (TR_ERROR, peer->trace, 
	       "recv %s %s with bad data len %d\n",
	       bgpmessage2string (BGP_NOTIFY),
	       bgp_notify_to_string (code, subcode), datalen);
	return (-1);
    }

    return (1);
}


static int 
bgp_write (int sockfd, u_char *packet, int len, int offset)
{
    int ret, hdrtype, hdrlen;
    assert (len >= BGP_HEADER_LEN && len <= BGPMAXPACKETSIZE);

    BGP_GET_HDRLEN (hdrlen, packet);
    BGP_GET_HDRTYPE (hdrtype, packet);
    if (offset > 0) {
        trace (TR_TRACE, BGP->trace, 
	   "send packet type %s hdr %d + data %d bytes on fd %d (offset %d)\n",
	   bgpmessage2string (hdrtype), BGP_HEADER_LEN, hdrlen, sockfd,
	   offset);
    }
    else {
        trace (TR_TRACE, BGP->trace, 
	   "send packet type %s hdr %d + data %d bytes on fd %d\n",
	   bgpmessage2string (hdrtype), BGP_HEADER_LEN, hdrlen, sockfd);
    }

    /* NT looks it likes send() rather than write(). It's ok for unix */
    ret = send (sockfd, packet + offset, len - offset, 0);
    if (ret < 0) {
	switch (socket_errno ()) {
            case EWOULDBLOCK:
#if defined(EAGAIN) && EAGAIN != EWOULDBLOCK
            case EAGAIN:
#endif  /* EAGAIN */
	        /* this happens because of non-blocking io */
                /* return (offset); */
            case EINTR:
            case ENETUNREACH:
            case EHOSTUNREACH:
                trace (TR_INFO, BGP->trace,
                       "WRITE FAILED on %d (%m) -- OKAY TO IGNORE\n", sockfd);
                return (offset);
	    default:
	        break;
	}
        trace (TR_ERROR, BGP->trace, 
	       "WRITE FAILED on %d (%m)\n", sockfd);
	return (-1);
    }

    offset += ret;
    if (len != offset) {
        trace (TR_WARN, BGP->trace, 
	       "WRITE FAILED on fd %d (requested len %d but %d written)\n",
	       sockfd, len, offset);
    }
    return (offset);
}


/* this is used for unknown peer */
static int 
bgp_send_packet (int sockfd, int type, u_char *data, int len)
{
    u_char buffer[BGPMAXPACKETSIZE];
    int buflen;

    assert (len >= 0 && len <= BGPMAXPACKETSIZE - BGP_HEADER_LEN);
    buflen = bgp_prepare_header (buffer, type, data, len);
    if (bgp_write (sockfd, buffer, buflen, 0) != buflen)
	return (-1);
    return (buflen);
}


void
bgp_packet_del (bgp_packet_t *bgp_packet)
{
    Destroy (bgp_packet->data);
    Destroy (bgp_packet);
}


int
bgp_flush_queue (bgp_peer_t * peer)
{   
    bgp_packet_t *bgp_packet;
    int ret, i;
    
/* too many continuous writes may result in hold timer expire
   since we can't accept a keep alive during the period */
#define BGP_N_CONTINUOUS_WRITES 10
    for (i = 0;i < BGP_N_CONTINUOUS_WRITES; i++) {

        pthread_mutex_lock (&peer->send_mutex_lock);
        bgp_packet = LL_GetHead (peer->send_queue);
        if (bgp_packet == NULL) {
	    /* end of queue */
            pthread_mutex_unlock (&peer->send_mutex_lock);
	    return (1);
        }
        LL_RemoveFn (peer->send_queue, bgp_packet, NULL);
        pthread_mutex_unlock (&peer->send_mutex_lock);

	if (bgp_packet->offset <= 0) {
	    int type;
	    /* 1st time */
            bgp_dump_msg (peer, bgp_packet->data, bgp_packet->len, 
			  DUMP_DIR_SEND);
            peer->num_packets_sent++;
    	    BGP_GET_HDRTYPE (type, bgp_packet->data);
            if (type == BGP_UPDATE)
                peer->num_updates_sent++;
            else if (type == BGP_NOTIFY)
                peer->num_notifications_sent++;
	}
        ret = bgp_write (peer->sockfd, bgp_packet->data, bgp_packet->len, 
			 bgp_packet->offset);

        if (ret < 0) {
    	    bgp_packet_del (bgp_packet);
	    bgp_sm_process_event (peer, BGPEVENT_ERROR);
	    return (-1);
	}
        if (ret != bgp_packet->len) {
	    /* try again */
	    assert (bgp_packet->offset <= ret);
	    assert (bgp_packet->len > ret);
	    bgp_packet->offset = ret;
            pthread_mutex_lock (&peer->send_mutex_lock);
	    LL_Prepend (peer->send_queue, bgp_packet);
	    select_enable_fd_mask (peer->sockfd, SELECT_WRITE);
            pthread_mutex_unlock (&peer->send_mutex_lock);
	    return (0);
        }
	/* success full */
	bgp_packet_del (bgp_packet);
    }
    select_enable_fd_mask (peer->sockfd, SELECT_WRITE);
    return (0);
}   


static int 
bgp_send_peer (bgp_peer_t *peer, int type, u_char *data, int len, int priority)
{
#ifndef HAVE_LIBPTHREAD
    bgp_packet_t *bgp_packet, *bp;
#endif /* HAVE_LIBPTHREAD */
    u_char buffer[BGPMAXPACKETSIZE];
    int buflen;

    assert (len >= 0 && len <= BGPMAXPACKETSIZE - BGP_HEADER_LEN);
    buflen = bgp_prepare_header (buffer, type, data, len);
#ifndef HAVE_LIBPTHREAD
    if (priority >= 2) {
        pthread_mutex_lock (&peer->send_mutex_lock);
	if (LL_GetCount (peer->send_queue) > 0) {
	    bp = LL_GetHead (peer->send_queue);
	    /* flush out the incomplete packet */
	    if (bp->offset > 0) {
    	        if (bgp_write (peer->sockfd, bp->data, bp->len, bp->offset) != 
			       bp->len) {
        	    pthread_mutex_unlock (&peer->send_mutex_lock);
		    return (-1);
		}
	        LL_Remove (peer->send_queue, bp);
	    }
	}
        pthread_mutex_unlock (&peer->send_mutex_lock);
#endif /* HAVE_LIBPTHREAD */
    bgp_dump_msg (peer, buffer, buflen, DUMP_DIR_SEND);
    peer->num_packets_sent++;
    if (type == BGP_UPDATE)
        peer->num_updates_sent++;
    else if (type == BGP_NOTIFY)
        peer->num_notifications_sent++;
    if (bgp_write (peer->sockfd, buffer, buflen, 0) != buflen)
	return (-1);
    return (1);
#ifndef HAVE_LIBPTHREAD
    }
#endif /* HAVE_LIBPTHREAD */

#ifndef HAVE_LIBPTHREAD
    bgp_packet = New (bgp_packet_t);
    bgp_packet->len = len + 19 /* bgp header */;
    bgp_packet->offset = 0;
    bgp_packet->data = NewArray (u_char, bgp_packet->len);
    bgp_prepare_header (bgp_packet->data, type, data, len);
    pthread_mutex_lock (&peer->send_mutex_lock);
    if (priority > 0) {
	if ((bp = LL_GetHead (peer->send_queue)) != NULL && bp->offset > 0) {
	    LL_RemoveFn (peer->send_queue, bp, NULL);
            LL_Prepend (peer->send_queue, bgp_packet);
            LL_Prepend (peer->send_queue, bp);
	    /* keep the incomplete packet ahead */
	}
	else {
            LL_Prepend (peer->send_queue, bgp_packet);
	}
    }
    else
        LL_Append (peer->send_queue, bgp_packet);
    if (LL_GetCount (peer->send_queue) == 1) {
	select_enable_fd_mask (peer->sockfd, SELECT_WRITE);
    }
    pthread_mutex_unlock (&peer->send_mutex_lock);
    trace (TR_PACKET, peer->trace, "send %s (%d bytes) queued\n",
           bgpmessage2string (type), len);
    return (1);
#endif /* HAVE_LIBPTHREAD */
}


void
bgp_reset_cap_opt (bgp_peer_t *peer)
{
    int i;
    view_t *view;

    peer->cap_opt_requesting = 0;
    peer->cap_opt_received = 0;
    peer->cap_opt_negotiated = 0;
    for (i = 0; i < MAX_BGP_VIEWS; i++) {
	view = BGP->views[i];
	if (view == NULL)
	    continue;
	if (view->local_bgp == NULL)
	    continue;
	if (!BITX_TEST (&peer->view_mask, i))
	    continue;
	peer->cap_opt_requesting |= AFISAFI2CAP (view->afi, view->safi);
    }
}


/*
 * send an open pdu
 */
int 
bgp_send_open (bgp_peer_t * peer)
{
    u_char buffer[BGPMAXPACKETSIZE], *cp = buffer;
    char tmpx[MAXLINE];
    int optlen = 0;
    time_t holdtime = BGP->Default_HoldTime_Interval;

    u_long id = (peer->local_bgp->this_id)?
			peer->local_bgp->this_id: MRT->default_id;

    if (peer->HoldTime_Interval >= 0) /* specified by user */
	holdtime = peer->HoldTime_Interval;

    BGP_PUT_OPEN (DEFAULT_BGP_VERSION, peer->local_bgp->this_as, holdtime,
		  id, optlen, cp);
    if (!BIT_TEST (peer->options, BGP_DONTSEND_CAPABILITY)) {
        int type = 2 /* Capability */;
        int clen = 0;
        u_char *optlen_base;
        u_char *clen_base;
        int afi, safi;

        optlen_base = cp;

        BGP_PUT_BYTE (type, cp);
        BGP_PUT_BYTE (clen, cp);
        clen_base = cp;
        for (afi = 1; afi < AFI_MAX; afi++) {
            for (safi = 1; safi < SAFI_MAX; safi++) {
	        if (BIT_TEST (peer->cap_opt_requesting, 
				AFISAFI2CAP (afi, safi))) {
    		    int capcode = 1 /* MP */;
    		    int capdatalen = 4;
    	            BGP_PUT_BYTE (capcode , cp);
                    BGP_PUT_BYTE (capdatalen , cp);
		    BGP_PUT_SHORT (afi, cp);
		    BGP_PUT_SHORT (safi, cp);
    		    trace (TR_PACKET, peer->trace,
	   	        "send %s with capability afi=%d safi=%d\n", 
		        bgpmessage2string (BGP_OPEN), afi, safi);
	        }
	    }
        }
        clen_base[-1] = clen = cp - clen_base;
        optlen_base[-1] = optlen = cp - optlen_base;
    }

    if (bgp_send_peer (peer, BGP_OPEN, buffer, cp - buffer, 2) <= 0) {
	trace (TR_ERROR, peer->trace, "send %s failed\n",
	       bgpmessage2string (BGP_OPEN));
	return (-1);
    }

    /* can't set open hold time in case of incoming 
       where open was already received */
    /* Timer_Set_Time (peer->timer_HoldTime, BGP_OPEN_TIMEOUT);
    Timer_Turn_ON (peer->timer_HoldTime); */
    trace (TR_PACKET, peer->trace,
	   "send %s with own AS %d, HOLDTIME %d, ID %s, OPTLEN %d\n",
	   bgpmessage2string (BGP_OPEN), 
	   peer->local_bgp->this_as, holdtime,
	   inet_ntop (AF_INET, &id, tmpx, sizeof (tmpx)), optlen);
    return (1);
}


int 
bgp_send_keepalive (bgp_peer_t * peer)
{
    int ret;

    ret = bgp_send_peer (peer, BGP_KEEPALIVE, NULL, 0, 1);
    Timer_Reset_Time (peer->timer_KeepAlive);
    return (ret);
}


/* 
 * Send notification error message to sockfd
 * prefix and port are informational
 */
int 
bgp_send_notification2 (int sockfd, prefix_t * prefix, int port,
		       int code, int subcode)
{
    u_char note[2], *cp = note;

    BGP_PUT_BYTE (code, cp);
    BGP_PUT_BYTE (subcode, cp);

    if (bgp_send_packet (sockfd, BGP_NOTIFY, note, cp - note) <= 0) {
	trace (TR_ERROR, BGP->trace, "%s (port %d) send %s failed\n", 
		   prefix_toa (prefix), port, bgpmessage2string (BGP_NOTIFY));
	return (-1);
    }

    trace (TR_WARN, BGP->trace, 
	   "%s (port %d) send %s %d/%d: %s\n",
	   prefix_toa (prefix), port, 
	   bgpmessage2string (BGP_NOTIFY),
	   code, subcode, 
	   bgp_notify_to_string (code, subcode));
    return (1);
}


static int 
bgp_send_notify (bgp_peer_t * peer, int code, int subcode,
		      u_char *data, int len)
{
    u_char note[BGPMAXPACKETSIZE], *cp = note;

    assert (peer);

    BGP_PUT_NOTIFY (code, subcode, len, data, cp);

    if (bgp_send_peer (peer, BGP_NOTIFY, note, cp - note, 2) <= 0) {
	trace (TR_ERROR, peer->trace, "send %s failed\n",
	       bgpmessage2string (BGP_NOTIFY));
	return (-1);
    }

    if (len > 0) {
        trace (TR_WARN, peer->trace, 
	       "send %s %d/%d: %s with data %d bytes\n", 
	       bgpmessage2string (BGP_NOTIFY),
	       code, subcode, bgp_notify_to_string (code, subcode), len);
    }
    else {
        trace (TR_WARN, peer->trace, 
	       "send %s %d/%d: %s\n",
	       bgpmessage2string (BGP_NOTIFY),
	       code, subcode,
	       bgp_notify_to_string (code, subcode));
    }

    return (1);
}


int 
bgp_send_notification (bgp_peer_t * peer, int code, int subcode)
{
    return (bgp_send_notify (peer, code, subcode, NULL, 0));
}


int 
bgp_send_notify_byte (bgp_peer_t * peer, int code, int subcode, int opt)
{
    u_char data[1];

    data[0] = opt;
    return (bgp_send_notify (peer, code, subcode, data, sizeof data));
}


int 
bgp_send_notify_word (bgp_peer_t * peer, int code, int subcode, int opt)
{
    u_char data[2];

    data[0] = (opt >> 8) & 0xff;
    data[1] = opt & 0xff;
    return (bgp_send_notify (peer, code, subcode, data, sizeof data));
}


/*-----------------------------------------------------------
 *  Name: 	bgp_send_update
 *  Created:	Tue Jan 24 09:59:38 1995
 *  Author: 	Craig Labovitz   <labovit@snoopy.merit.net>
 *  DESCR:  	
 */

int 
bgp_send_update (bgp_peer_t * peer, int len, u_char * data)
{
    int ret;

    ret = bgp_send_peer (peer, BGP_UPDATE, data, len, 0);
    Timer_Reset_Time (peer->timer_KeepAlive);

    if (BGP->send_update_call_fn)
      return (BGP->send_update_call_fn (peer, data, len));

    return (ret);
}

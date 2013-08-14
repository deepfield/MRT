/* 
 * $Id: bgp_util.c,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#include <config.h>
#include <mrt.h>
#include <config_file.h>
#include <bgp.h>
#ifdef NT
#include <winsock2.h>
#ifdef HAVE_IPV6
#include <ws2ip6.h>
#endif /* HAVE_IPV6 */
#include <ws2tcpip.h>
#endif /* NT */

u_int aspath_hash_fn (aspath_t * aspath, u_int size);
void bgp_schedule_timer (mtimer_t * timer, bgp_peer_t * peer);
static void stop_bgp_peer (bgp_peer_t *peer, int lockf);
static void bgp_dump_view (uii_connection_t *uii, int viewno, int family,
	       as_regexp_code_t *code, bgp_peer_t *peer, condition_t *cond);

int
peer_set_gateway (bgp_peer_t *peer, int as, u_long id)
{
    prefix_t *local_prefix = NULL;
    prefix_t *remote_prefix = NULL;
    interface_t *interface;

    /* to see if the socket is still connected */
    
    if (get_socket_addr (peer->sockfd, 0 /* local */, &local_prefix) < 0) {
	Deref_Prefix (local_prefix);
	return (-1);
    }

    if (get_socket_addr (peer->sockfd, 1 /* remote */, &remote_prefix) < 0) {
	Deref_Prefix (local_prefix);
	Deref_Prefix (remote_prefix);
	return (-1);
    }

    if (peer->local_addr)
	Deref_Prefix (peer->local_addr);
    peer->local_addr = Ref_Prefix (local_prefix);

    if ((interface = find_interface_local (remote_prefix)) != NULL) {
        BIT_SET (peer->options, BGP_PEER_SELF);
    }
    else {
	interface = find_interface (remote_prefix);
    }
    peer->gateway = add_bgp_gateway (remote_prefix, as, id, interface);
    peer->interface = interface;
    Deref_Prefix (local_prefix);
    Deref_Prefix (remote_prefix);

    if ((INTERFACE_MASTER && peer->gateway->interface &&
	 !is_prefix_on (peer->gateway->prefix, peer->gateway->interface)) ||
        (INTERFACE_MASTER && peer->gateway->interface == NULL &&
	 find_interface_local (peer->local_addr))) {
	nexthop_t *nexthop = NULL;

	if (peer->gateway->interface == NULL) {
	    /* delete the gateway XXX */
	    peer->gateway = add_bgp_gateway (peer->gateway->prefix, 
				peer->gateway->AS, 
			     	peer->gateway->routerid, 
			     	find_interface_local (peer->local_addr));
	}

	if (MRT->rib_find_best_route) {
		//printf ("PREFIX %s\n", prefix_toax (peer->gateway->prefix));
	    nexthop = MRT->rib_find_best_route (peer->gateway->prefix, 
					        SAFI_UNICAST);
		//printf ("NEXTHOP %s\n", prefix_toax (nexthop->prefix));
	    if (nexthop && nexthop->prefix && 
			prefix_is_unspecified (nexthop->prefix)) {
		/* OK -- found the direct route. this happens with linux sit
		   which doesn't have the destination adddress of p2p */
    		peer->interface = nexthop->interface;
		return (1);
	    }
	}

	if (nexthop) {
	    if (!BIT_TEST (peer->options, BGP_INTERNAL))
	        BIT_SET (peer->options, BGP_EBGP_MULTIHOP);
	    if (peer->nexthop)
		deref_nexthop (peer->nexthop);
	    peer->nexthop = ref_nexthop (nexthop);
    	    peer->interface = peer->nexthop->interface;
	    trace (TR_INFO, peer->trace, 
		   "Multihop! immediate nexthop will be %a\n", nexthop->prefix);
	}
	else {
	    trace (TR_ERROR, peer->trace, 
	    	   "Multihop! immediate nexthop unknown\n");
	    return (0);
	}
    }
    return (1);
}


static void
bgp_connect_ready (bgp_peer_t * peer, int async)
{
    sockunion_t name;
    int namelen = sizeof (name);

    if (async) {
        if (peer->sockfd < 0) {
	    trace (TR_WARN, peer->trace,
	           "connect to %a succeeded but sockfd has been closed\n",
	           peer->peer_addr);
	    /* no event */
	    return;
        }

        if (peer->state != BGPSTATE_CONNECT) {
	    trace (TR_WARN, peer->trace,
	           "connect to %a succeeded but too late\n", peer->peer_addr);
	    /* no event */
	    return;
	}
        select_delete_fd2 (peer->sockfd);
    }

    /* see if we are really connected */
    if (getpeername (peer->sockfd, (struct sockaddr *)&name, &namelen) < 0) {
	trace (TR_INFO, peer->trace,
	       "connect to %a failed (%m)\n", peer->peer_addr);
	close (peer->sockfd);
	peer->sockfd = -1;
	if (async)
	    bgp_sm_process_event (peer, BGPEVENT_OPENFAIL);
	else
	    schedule_event2 ("bgp_sm_process_event",
			     peer->schedule, bgp_sm_process_event,
			     2, peer, BGPEVENT_OPENFAIL);
	return;
    }

    trace (TR_INFO, peer->trace, "Outgoing connection SUCCEEDED\n");

#ifdef HAVE_LIBPTHREAD
    socket_set_nonblocking (peer->sockfd, 0);
#endif /* HAVE_LIBPTHREAD */
    if (async)
        bgp_sm_process_event (peer, BGPEVENT_OPEN);
    else
        schedule_event2 ("bgp_sm_process_event",
		         peer->schedule, bgp_sm_process_event,
		         2, peer, BGPEVENT_OPEN);
}


/*
 * Starts tcp connection to peer. Returns 1 on sucess, -1 oltherwise
 */
int 
bgp_start_transport_connection (bgp_peer_t * peer)
{
    int ret;
    int family, len;
    struct sockaddr_in sin;
    struct sockaddr *s;
#ifdef HAVE_IPV6
    struct sockaddr_in6 sin6;
#endif /* HAVE_IPV6 */

    /* okay, start a TCP connection */

    if ((family = peer->peer_addr->family) == AF_INET) {
	memset (&sin, 0, sizeof (sin));
	sin.sin_family = family;
	sin.sin_port = htons (peer->peer_port);
	memcpy (&sin.sin_addr, prefix_tochar (peer->peer_addr), 4);
	s = (struct sockaddr *) &sin;
	len = sizeof (sin);
    }

#ifdef HAVE_IPV6
    else if (family == AF_INET6) {
	memset (&sin6, 0, sizeof (sin6));
	sin6.sin6_family = family;
	sin6.sin6_port = htons (peer->peer_port);
	memcpy (&sin6.sin6_addr, prefix_tochar (peer->peer_addr), 16);
	s = (struct sockaddr *) &sin6;
	len = sizeof (sin6);
    }
#endif /* HAVE_IPV6 */
    else {
        return (-1);
    }

    if (peer->sockfd >= 0) {
	select_delete_fdx (peer->sockfd);
    }

    if ((peer->sockfd = socket (family, SOCK_STREAM, 0)) < 0) {
	trace (TR_ERROR, peer->trace, "socket open failed (%m)\n");
	return (-1);
    }

    socket_reuse (peer->sockfd, 1);

#ifdef SO_BINDTODEVICE
    if (peer->bind_if) {
	struct ifreq ifr;
	safestrncpy ((char *)&ifr.ifr_ifrn.ifrn_name, peer->bind_if->name, 
		     sizeof (ifr.ifr_ifrn.ifrn_name));
	if (setsockopt (peer->sockfd, SOL_SOCKET, SO_BINDTODEVICE,
				  &ifr, sizeof (ifr)) < 0)
	    trace (TR_ERROR, peer->trace, "SO_BINDTODEVICE %s (%m)\n",
				   peer->bind_if->name);
    }
#endif /* SO_BINDTODEVICE */

    if (peer->bind_addr) {
	    int llen;
	    struct sockaddr_in l_sin;
	    struct sockaddr *l_s;
#ifdef HAVE_IPV6
	    struct sockaddr_in6 l_sin6;
#endif /* HAVE_IPV6 */

	    if (family  == AF_INET) {
		    memset (&l_sin, 0, sizeof (l_sin));
		    l_sin.sin_family = family;
		    memcpy (&l_sin.sin_addr, prefix_tochar (peer->bind_addr), 
			    4);
		    l_s = (struct sockaddr *) &l_sin;
		    llen = sizeof (sin);
	    }
#ifdef HAVE_IPV6
	    else if (family == AF_INET6) {
		    memset (&l_sin6, 0, sizeof (l_sin6));
		    l_sin6.sin6_family = family;
		    memcpy (&l_sin6.sin6_addr, prefix_tochar (peer->bind_addr),
			    16);
		    l_s = (struct sockaddr *) &l_sin6;
		    llen = sizeof (sin6);
	    }
#endif /* HAVE_IPV6 */
	    else {
		assert (0);
		return (-1);
	    }
	    if (bind (peer->sockfd, l_s, len) < 0) {
		    trace (TR_ERROR, peer->trace, "socket bind (%m)\n");
		    return (-1);
	    }
    }

    /* always non-blocking. 
      if connect doesn't return, there is no way to resume it. */
    socket_set_nonblocking (peer->sockfd, 1);

    ret = connect (peer->sockfd, s, len);
    if (ret < 0) {
	/* EWOULDBLOCK occurs on NT */
	if (socket_errno () != EINPROGRESS && 
		socket_errno () != EWOULDBLOCK) {
	    close (peer->sockfd);
	    peer->sockfd = -1;
	    return (-1);
	}
	trace (TR_PACKET, peer->trace, "waiting on %d for write\n",
	       peer->sockfd);
	select_add_fd_event ("bgp_connect_ready", peer->sockfd, SELECT_WRITE, 
			     TRUE, 
			     peer->schedule, bgp_connect_ready, 2, peer, TRUE);
	return (0);
    }
    bgp_connect_ready (peer, FALSE);
    return (1);
}


int
bgp_in_recv_open (bgp_peer_t *peer)
{
    int remain;
    u_char *cp;
    int type, length;

    assert (peer->accept_socket);

    /* switch the inputs */
    peer->sockfd = peer->accept_socket->sockfd;

    /* copy the packet */
    remain = peer->accept_socket->read_ptr_in - 
	     peer->accept_socket->buffer_in;
    if (remain > 0) {
	memcpy (peer->buffer, peer->accept_socket->buffer_in, remain);
	peer->read_ptr = peer->buffer + remain;
    }

    cp = peer->buffer;
    BGP_GET_HDRTYPE (type, cp);
    BGP_GET_HDRLEN (length, cp);
    assert (type == BGP_OPEN);
    /* assert (length >= remain); */
    peer->packet = peer->buffer;
    peer->start_ptr = peer->buffer + length;

    Deref_Prefix (peer->accept_socket->remote_prefix);
    Deref_Prefix (peer->accept_socket->local_prefix);
    Delete (peer->accept_socket);
    peer->accept_socket = NULL;

    if (get_socket_addr (peer->sockfd, 1 /* remote */, NULL) < 0) {
	close (peer->sockfd);
	peer->sockfd = -1;
	return (-1);
    }

    if (bgp_process_open (peer) > 0) {
        select_add_fd_event ("bgp_get_pdu", peer->sockfd, SELECT_READ,
                             1 /* on */, peer->schedule, 
			     (event_fn_t) bgp_get_pdu, 1, peer);
        select_add_fd_event ("bgp_flush_queue", peer->sockfd, SELECT_WRITE,
                             0 /* off */, peer->schedule, 
			     (event_fn_t) bgp_flush_queue, 1, peer);
	/* no hold timer for this open since open has been received */
	if (bgp_send_open (peer) >= 0) {
	    bgp_change_state (peer, BGPSTATE_OPENSENT, BGPEVENT_OPEN);
	    Timer_Turn_ON (peer->timer_KeepAlive);
	    if (bgp_send_keepalive (peer) >= 0) {
		if (peer->HoldTime_Interval > 0)
	            Timer_Reset_Time (peer->timer_HoldTime);
	        bgp_change_state (peer, BGPSTATE_OPENCONFIRM, 
				  BGPEVENT_RECVOPEN);
		return (1);
	    }
	}
    }
    /* OPEN was bad */
    /* notification already sent */
    /* outgoing connection has been closed. no way. */
    bgp_change_state (peer, BGPSTATE_IDLE, BGPEVENT_RECVOPEN);
    bgp_peer_dead (peer);
    Timer_Turn_ON (peer->timer_Start);
    return (0);
}


static void     
bgp_schedule_recv_in (bgp_peer_t * peer)
{
    sockunion_t name;
    int namelen = sizeof (name);

    if (peer->accept_socket == NULL)
	return;

    if (getpeername (peer->accept_socket->sockfd, (struct sockaddr *)&name, 
		&namelen) < 0) {
	trace (TR_INFO, peer->trace,
	       "accept_socket for %a has been closed (%m)\n", 
	       peer->accept_socket->remote_prefix);
	close (peer->accept_socket->sockfd);
        Deref_Prefix (peer->accept_socket->remote_prefix);
        Deref_Prefix (peer->accept_socket->local_prefix);
        Delete (peer->accept_socket);
        peer->accept_socket = NULL;
	return;
    }

    if (peer->state == BGPSTATE_ESTABLISHED
	    /* send it anyway because it may proceed from idle later */
            /* || peer->state == BGPSTATE_IDLE */) {
	trace (TR_INFO, peer->trace, "reject the incoming connection (%s)\n",
	       sbgp_states[peer->state]);
        goto cease;
    }

    else if (peer->state == BGPSTATE_IDLE) {
#if 0
	bgp_change_state (peer, BGPSTATE_ACTIVE, BGPEVENT_OPEN);
        Timer_Turn_OFF (peer->timer_Start);
#endif
	trace (TR_INFO, peer->trace, "suspend incoming from %a\n",
	       peer->accept_socket->remote_prefix);
	return;
    }

    else if (peer->state == BGPSTATE_ESTABLISHED) {

	trace (TR_INFO, peer->trace,
	    "rejecting the incoming connection (state is %s)\n",
	       sbgp_states[peer->state]);
        goto cease;
    }

    else if (peer->state == BGPSTATE_OPENSENT ||
	     peer->state == BGPSTATE_OPENCONFIRM) {

        int version;
        int as;
        u_long holdtime;
        int authcode;
        u_long id;
        u_char *cp;
	u_long myid = (peer->local_bgp->this_id)?
                       peer->local_bgp->this_id: MRT->default_id;

	char his[MAXLINE], mine[MAXLINE];

        cp = peer->accept_socket->buffer_in;
    	BGP_SKIP_HEADER (cp);
    	BGP_GET_OPEN (version, as, holdtime, id, authcode, cp);

	trace (TR_INFO, peer->trace,
	       "routerid comparison (in %s <=> out %s)\n", 
		inet_ntop (AF_INET, &id, his, sizeof (his)),
		inet_ntop (AF_INET, &myid, mine, sizeof (mine)));
	if (ntohl (id) <= ntohl (myid)) {
	    trace (TR_INFO, peer->trace,
	        "rejecting the incoming connection (router id)\n");
	    goto cease;
	}
        bgp_peer_dead (peer); /* this may clear schedule queue */
    }
    else if (peer->state == BGPSTATE_CONNECT) {
        bgp_peer_dead (peer); /* this may clear schedule queue */
    }
    else {
        assert (peer->state == BGPSTATE_ACTIVE);
	/* at least, retry timer is running */
        Timer_Turn_OFF (peer->timer_ConnectRetry);
    }

    trace (TR_INFO, peer->trace,
	   "accepting incoming connection (state was %s)\n",
	   sbgp_states[peer->state]);

    bgp_in_recv_open (peer);
    return;

  cease:
    bgp_send_notification2 (peer->accept_socket->sockfd, 
			    peer->accept_socket->remote_prefix,
			    peer->accept_socket->remote_port, BGP_CEASE, 0);
    close (peer->accept_socket->sockfd);

    Deref_Prefix (peer->accept_socket->remote_prefix);
    Deref_Prefix (peer->accept_socket->local_prefix);
    Delete (peer->accept_socket);
    peer->accept_socket = NULL;
}


static void
bgp_direct_in_recv_open (accept_socket_t *accept_socket)
{
    int type, length;
    int version;
    int as;
    u_long holdtime;
    int authcode;
    u_long id;
    bgp_peer_t *peer;
    bgp_local_t *local_bgp;
    int len;
    int sockfd;
    u_char *cp;
    char tmpx[64];

    assert (accept_socket);
    sockfd = accept_socket->sockfd;
    assert (sockfd >= 0);
    len = bgp_read (NULL, sockfd, accept_socket->read_ptr_in, 
		  	accept_socket->buffer_in + 
			sizeof (accept_socket->buffer_in) - 
			accept_socket->read_ptr_in);
    if (len < 0) {
error:
	trace (TR_INFO, BGP->trace, 
		"Give up the accept from %a at %a on fd %d (error)\n", 
		accept_socket->remote_prefix, accept_socket->local_prefix,
		accept_socket->sockfd);
    	select_delete_fdx (sockfd);
        pthread_mutex_lock (&accept_socket->listen_socket->mutex_lock);
	LL_Remove (accept_socket->listen_socket->ll_accept_sockets, 
		   accept_socket);
        pthread_mutex_unlock (&accept_socket->listen_socket->mutex_lock);
	Deref_Prefix (accept_socket->remote_prefix);
	Deref_Prefix (accept_socket->local_prefix);
	Delete (accept_socket);
        return;
    }

    accept_socket->read_ptr_in += len;

    if (accept_socket->read_ptr_in - accept_socket->buffer_in < 
		BGP_HEADER_LEN) {
        select_enable_fd_mask (sockfd, SELECT_READ);
	return;
    }

    trace (TR_INFO, BGP->trace, "incoming from %a at %a (len %d)\n", 
	   accept_socket->remote_prefix, accept_socket->local_prefix, len);

    cp = accept_socket->buffer_in;
    BGP_GET_HDRTYPE (type, cp);
    BGP_GET_HDRLEN (length, cp);

    if (length < BGP_HEADER_LEN || length > BGPMAXPACKETSIZE) {
	trace (TR_ERROR, BGP->trace,
	    "rejecting incoming from %a at %a (bad length %d)\n", 
	     accept_socket->remote_prefix, accept_socket->local_prefix, length);
        goto error;
    }

    if (type >= BGP_OPEN && type < BGP_PACKET_MAX) {
        trace (TR_PACKET, BGP->trace, "recv %s (%d bytes) [incoming]\n",
               sbgp_pdus[type], length);
    }
    else {
	trace (TR_ERROR, BGP->trace,
	    "rejecting incoming from %a at %a (unknown type code %d)\n", 
	    accept_socket->remote_prefix, accept_socket->local_prefix, type);
	goto error;
    }

    if (type != BGP_OPEN) {
	trace (TR_ERROR, BGP->trace,
	       "rejecting incoming from %a at %a (%s: type is not OPEN)\n",
	       sbgp_pdus[type]);
	goto error;
    }

    if (accept_socket->read_ptr_in - accept_socket->buffer_in < length) {
        select_enable_fd_mask (sockfd, SELECT_READ);
	return;
    }

    /* this happens only once */
    select_delete_fd2 (sockfd);
    /* without closing */

    pthread_mutex_lock (&accept_socket->listen_socket->mutex_lock);
    LL_Remove (accept_socket->listen_socket->ll_accept_sockets, accept_socket);
    pthread_mutex_unlock (&accept_socket->listen_socket->mutex_lock);

    BGP_SKIP_HEADER (cp);
    BGP_GET_OPEN (version, as, holdtime, id, authcode, cp);

    if (id == 0L || id == ~0L) {
        trace (TR_ERROR, BGP->trace, "invalid router id: %s\n",
               inet_ntop (AF_INET, &id, tmpx, sizeof (tmpx)));
	bgp_send_notification2 (sockfd, accept_socket->remote_prefix, 
				accept_socket->remote_port,
			        BGP_ERR_OPEN, BGP_ERROPN_BGPID);
        goto reject;
    }

    trace (TR_PACKET, BGP->trace,
           "Looking for peer with AS %d and ID %s\n",
           as, inet_ntop (AF_INET, &id, tmpx, sizeof (tmpx)));

    pthread_mutex_lock (&BGP->locals_mutex_lock);
    LL_Iterate (BGP->ll_bgp_locals, local_bgp) {
	pthread_mutex_lock (&local_bgp->peers_mutex_lock);
        LL_Iterate (local_bgp->ll_bgp_peers, peer) {
	    if (peer->peer_addr == NULL)
		continue;
	    if (prefix_compare_wolen (peer->peer_addr, 
			accept_socket->remote_prefix) != 0)
		continue;
	    if (peer->peer_as > 0 && peer->peer_as != as)
		continue;
	    if (peer->peer_id > 0 && peer->peer_id != id)
		continue;
	    /* the peer may be initiated throught socket for another peer */
	    if (peer->listen_socket && 
		    peer->listen_socket != accept_socket->listen_socket)
		continue;

	    /* found */

	    if (peer->peer_addr) {
                trace (TR_INFO, peer->trace, 
	               "Valid incoming connection detected at %a\n", 
		       accept_socket->local_prefix);
	    }
	    else {
	        bgp_peer_t *child;
		int i;
	        child = Add_BGP_Peer (peer->local_bgp, NULL, 
				      accept_socket->remote_prefix, 
				      as, id, peer->trace);
		/* register the peer in all applicable views */
		for (i = 0; i < MAX_BGP_VIEWS; i++) {
		    if (BITX_TEST (&local_bgp->view_mask, i))
			BITX_SET (&child->view_mask, i);
		}
	        child->options = peer->options;
                BIT_SET (child->options, BGP_CONNECT_PASSIVE);
	        child->parent = peer;
	        if (peer->children == NULL)
		    peer->children = LL_Create (0);
	        LL_Add (peer->children, child);
	        trace (TR_INFO, peer->trace, 
		       "Child from %a created at %a (but remains passive)\n", 
		       accept_socket->remote_prefix, 
		       accept_socket->local_prefix);
	        /* force to change BGP state */
	        bgp_change_state (child, BGPSTATE_ACTIVE, BGPEVENT_START);
	    }
	    if (peer->accept_socket) {
	        trace (TR_INFO, peer->trace,
	           "rejecting the incoming connection "
		   "(state is %s but input pending)\n",
	           sbgp_states[peer->state]);
		pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
    		pthread_mutex_unlock (&BGP->locals_mutex_lock);
	        goto cease;
	    }
	    else {
	        peer->accept_socket = accept_socket;
    	    	schedule_event2 ("bgp_schedule_recv_in", peer->schedule, 
				 bgp_schedule_recv_in, 1, peer);
		pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
    		pthread_mutex_unlock (&BGP->locals_mutex_lock);
		return;
	    }
	}
	pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
    }
    pthread_mutex_unlock (&BGP->locals_mutex_lock);

	if (BGP->accept_all_peers) {
	    /* at this point, as is unknown */
	    /* modifying BGP structure should be safe */
	    peer = Add_BGP_Peer (NULL, NULL, accept_socket->remote_prefix, 
				 as, id, BGP->trace);
	    /* safer way */
            BIT_SET (peer->options, BGP_CONNECT_PASSIVE);
	    trace (TR_INFO, peer->trace, 
		   "Anonymous peer created at %a (but remains passive)\n", 
		   accept_socket->local_prefix);
	    /* force to change BGP state */
	    bgp_change_state (peer, BGPSTATE_ACTIVE, BGPEVENT_START);
	    peer->accept_socket = accept_socket;
    	    schedule_event2 ("bgp_schedule_recv_in", peer->schedule, 
			      bgp_schedule_recv_in, 1, peer);
    	    pthread_mutex_unlock (&BGP->locals_mutex_lock);
	    return;
	}
	else {
	    /* as number -> 0 */
    	    peer = Find_BGP_Peer (NULL, accept_socket->remote_prefix, 0, id);
	    if (peer) {
	        assert (peer->peer_as != as);
	        trace (TR_INFO, BGP->trace, 
		       "Unconfigured peer %a with as %d at %a\n",
		       accept_socket->remote_prefix, as, 
			accept_socket->local_prefix);
	        bgp_send_notification2 (sockfd, accept_socket->remote_prefix, 
					accept_socket->remote_port,
				        BGP_ERR_OPEN, BGP_ERROPN_AS);
	    }
	    else {
	        /* router-id -> 0 */
    	        peer = Find_BGP_Peer (NULL, accept_socket->remote_prefix, 
				      as, 0);
	        if (peer) {
	            assert (peer->peer_id != id);
	            trace (TR_INFO, BGP->trace, 
		           "Unconfigured peer %a with id %s at %a\n",
		           accept_socket->remote_prefix,
               		   inet_ntop (AF_INET, &id, tmpx, sizeof (tmpx)),
			   accept_socket->local_prefix);
		}
		else {
	            trace (TR_INFO, BGP->trace, "Unconfigured peer %a at %a\n",
		       accept_socket->remote_prefix, 
		       accept_socket->local_prefix);
		}
	        bgp_send_notification2 (sockfd, accept_socket->remote_prefix, 
					accept_socket->remote_port,
				        BGP_ERR_OPEN, BGP_ERROPN_AUTH);
	    }
	}
  reject:
    trace (TR_INFO, BGP->trace, 
	    "Give up the accept from %a at %a on fd %d (reject)\n", 
	    accept_socket->remote_prefix, accept_socket->local_prefix,
	    accept_socket->sockfd);
    Deref_Prefix (accept_socket->remote_prefix);
    Deref_Prefix (accept_socket->local_prefix);
    Delete (accept_socket);
    close (sockfd);
    return;

  cease:
    bgp_send_notification2 (sockfd, accept_socket->remote_prefix,
			    accept_socket->remote_port, BGP_CEASE, 0);
    goto reject;
}


static void
bgp_accept_timeout (void)
{
    listen_socket_t *listen_socket;
    accept_socket_t *accept_socket;
    time_t now;

    time (&now);
    pthread_mutex_lock (&BGP->mutex_lock);
    LL_Iterate (BGP->ll_listen_sockets, listen_socket) {
        pthread_mutex_lock (&listen_socket->mutex_lock);
	LL_Iterate (listen_socket->ll_accept_sockets, accept_socket) {
	    if (accept_socket->start_time + BGP_OPEN_TIMEOUT < now) {
		accept_socket_t *prev;
	        assert (accept_socket->sockfd >= 0);
    		trace (TR_INFO, BGP->trace, 
	    	    "Give up the accept from %a at %a on fd %d (timeout)\n", 
	    	    accept_socket->remote_prefix, accept_socket->local_prefix,
	    	    accept_socket->sockfd);
    		select_delete_fdx (accept_socket->sockfd);
		Deref_Prefix (accept_socket->remote_prefix);
		Deref_Prefix (accept_socket->local_prefix);
		prev = LL_GetPrev (listen_socket->ll_accept_sockets, 
				   accept_socket);
		LL_Remove (listen_socket->ll_accept_sockets, accept_socket);
		Delete (accept_socket);
		accept_socket = prev;
	    }
	}
        pthread_mutex_unlock (&listen_socket->mutex_lock);
    }
    pthread_mutex_unlock (&BGP->mutex_lock);
}


static void
bgp_house_keeping_timeout (void)
{
    bgp_accept_timeout ();
    view_eval_nexthop (-1);

#ifdef notdef
    int afi, safi;
    for (afi = 0; afi < AFI_MAX; afi++) {
        for (safi = 0; safi < SAFI_MAX; safi++) {
    	    if (MRT->rib_update_nexthop)
        	MRT->rib_update_nexthop (afi, safi);
	}
    }
#endif
}


static void
bgp_in_accept_connection (listen_socket_t *listen_socket)
{
    int sockfd, len;
    sockunion_t remote, local;
    prefix_t *local_prefix, *remote_prefix;
    accept_socket_t *accept_socket;

    len = sizeof (remote);
    if ((sockfd = accept (listen_socket->sockfd, 
	    (struct sockaddr *) &remote, &len)) < 0) {
	trace (TR_ERROR, MRT->trace, "accept (%m)\n");
	select_enable_fd_mask (listen_socket->sockfd, SELECT_READ);
	return;
    }

    len = sizeof (local);
    if (getsockname (sockfd, (struct sockaddr *) &local, &len) < 0) {
        trace (TR_ERROR, MRT->trace, "getsockname (%m)\n");
        select_enable_fd_mask (listen_socket->sockfd, SELECT_READ);
	close (sockfd);
        return;
    }

    remote_prefix = sockaddr_toprefix ((struct sockaddr *) &remote);
    local_prefix = sockaddr_toprefix ((struct sockaddr *) &local);

    accept_socket = New (accept_socket_t);
    accept_socket->read_ptr_in = accept_socket->buffer_in;
    time (&accept_socket->start_time);
    accept_socket->sockfd = sockfd;
    accept_socket->remote_prefix = Ref_Prefix (remote_prefix);
    accept_socket->local_prefix = Ref_Prefix (local_prefix);
    accept_socket->listen_socket = listen_socket;
    accept_socket->remote_port = ntohs (remote.sin.sin_port);
    pthread_mutex_lock (&listen_socket->mutex_lock);
    LL_Add (listen_socket->ll_accept_sockets, accept_socket);
    pthread_mutex_unlock (&listen_socket->mutex_lock);
    socket_set_nonblocking (sockfd, 1);

    select_add_fd_event ("bgp_direct_in_recv_open", sockfd, 
			 SELECT_READ, TRUE, NULL, 
			 bgp_direct_in_recv_open, 1, accept_socket);

    trace (TR_INFO, BGP->trace, 
	        "incoming connection detected from %a at %a\n", 
		remote_prefix, local_prefix);
    select_enable_fd_mask (listen_socket->sockfd, SELECT_READ);
    Deref_Prefix (remote_prefix);
    Deref_Prefix (local_prefix);
}


int 
aspath_lookup_fn (aspath_t * tmp1, aspath_t * tmp2)
{
    u_int tmpx;

    if ((tmp1 == NULL) || (tmp2 == NULL)) {
	return (-1);
    }

    tmpx = compare_aspaths (tmp1, tmp2);
    return (tmpx);
}


bgp_local_t *
init_bgp_local (int as, u_long id)
{
    bgp_local_t *local_bgp = New (bgp_local_t);

    pthread_mutex_init (&local_bgp->mutex_lock, NULL);
    local_bgp->trace = trace_copy (BGP->trace);
    local_bgp->this_as = as;
    local_bgp->this_id = id;
    /* local_bgp->cluster_id = id; */
    memset (&local_bgp->view_mask, 0, sizeof (local_bgp->view_mask));
    local_bgp->bind_interface_only = 0;
    pthread_mutex_init (&local_bgp->peers_mutex_lock, NULL);
    local_bgp->ll_bgp_peers = LL_Create (0);
    local_bgp->num_interfaces = 0;
    memset (&local_bgp->view_mask, 0, sizeof (local_bgp->view_mask));
    local_bgp->num_peers = 0;
    local_bgp->num_ipv4_peers = 0;
    pthread_mutex_lock (&BGP->locals_mutex_lock);
    LL_Add (BGP->ll_bgp_locals, local_bgp);
    pthread_mutex_unlock (&BGP->locals_mutex_lock);
    if (LL_GetCount (BGP->ll_bgp_locals) == 1) {
        /* probably OK without locking */
        pthread_mutex_lock (&MRT->mutex_lock);
        BGP4_BIT_SET (MRT->protocols, PROTO_BGP);
        pthread_mutex_unlock (&MRT->mutex_lock);
    }
    return (local_bgp);
} 


void
remove_bgp_local (bgp_local_t *local_bgp)
{
    assert (local_bgp);
    pthread_mutex_lock (&BGP->locals_mutex_lock);
    LL_Remove (BGP->ll_bgp_locals, local_bgp);
    pthread_mutex_unlock (&BGP->locals_mutex_lock);
    pthread_mutex_destroy (&local_bgp->mutex_lock);
    Destroy_Trace (local_bgp->trace);
    LL_Destroy (local_bgp->ll_bgp_peers);
    if (LL_GetCount (BGP->ll_bgp_locals) == 0) {
        /* probably OK without locking */
        pthread_mutex_lock (&MRT->mutex_lock);
        BGP4_BIT_RESET (MRT->protocols, PROTO_BGP);
        pthread_mutex_unlock (&MRT->mutex_lock);
    }
} 


static void 
bgp_if_call_fn (int cmd, interface_t *interface, ll_addr_t *if_addr)
{
    bgp_local_t *local_bgp;
    bgp_peer_t *peer;
    
    /* if down only */
    if (if_addr != NULL)
	return;
    if (cmd != 'D') 
	return;

    pthread_mutex_lock (&BGP->locals_mutex_lock);
    LL_Iterate (BGP->ll_bgp_locals, local_bgp) {
	pthread_mutex_lock (&local_bgp->peers_mutex_lock);
        /* scan through peers */
        LL_Iterate (local_bgp->ll_bgp_peers, peer) {

	    if (peer->gateway == NULL ||
	        peer->gateway->interface != interface)
	        continue;

    	    schedule_event2 ("bgp_sm_process_event",
                      peer->schedule, bgp_sm_process_event,
                      2, peer, BGPEVENT_CLOSED);
	}
	pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
    }
    pthread_mutex_unlock (&BGP->locals_mutex_lock);
}


void 
init_BGP (trace_t * ltrace)
{
#ifdef notdef
    bgp_attr_t attr;
#endif
    BGP = New (bgp_t);
    pthread_mutex_init (&BGP->locals_mutex_lock, NULL);

    /* BGP->ll_bgp_peers = LL_Create (0); */

    BGP->lport = BGP_PORT;
    BGP->cport = BGP_PORT;
    BGP->ll_listen_sockets = LL_Create (0);
    BGP->ll_bgp_locals = LL_Create (0);

/*
    BGP->sockfd = -1;
    BGP->sockfd_count = 0;
*/
    BGP->accept_all_peers = 0;
    BGP->trace = trace_copy (ltrace);
    set_trace (BGP->trace, TRACE_PREPEND_STRING, "BGP", 0);
    BGP->views[0] = New_View (ltrace, 0, AFI_IP, SAFI_UNICAST);
    BITX_SET (&BGP->view_mask, 0);
    BGP->views[2] = New_View (ltrace, 2, AFI_IP, SAFI_MULTICAST);
    BITX_SET (&BGP->view_mask, 2);
    BGP->views[1] = New_View (ltrace, 1, AFI_IP6, SAFI_UNICAST);
    BITX_SET (&BGP->view_mask, 1);
    BGP->views[3] = New_View (ltrace, 3, AFI_IP6, SAFI_MULTICAST);
    BITX_SET (&BGP->view_mask, 3);
    BGP->default_local_pref = DEFAULT_LOCAL_PREF;
    BGP->Default_Start_Interval = DEFAULT_START_INTERVAL;
    BGP->Default_ConnectRetry_Interval = DEFAULT_CONNET_RETRY_INTERVAL;
    BGP->Default_KeepAlive_Interval = DEFAULT_KEEPALIVE_INTERVAL;
    BGP->Default_HoldTime_Interval = DEFAULT_HOLDTIME_INTERVAL;

    pthread_mutex_init (&BGP->mutex_lock, NULL);

#ifdef notdef
    BGP->attr_hash =
	HASH_Create (100, HASH_KeyOffset, HASH_Offset (&attr, &attr.aspath),
		     HASH_LookupFunction, aspath_lookup_fn,
		     HASH_HashFunction, aspath_hash_fn, NULL);
#endif

    BGP->schedule = New_Schedule ("BGP", BGP->trace);
    MRT->proto_update_route[PROTO_BGP] = bgp_update_route;
    BGP->update_call_fn = process_bgp_update;
    BGP->dump_direction = DUMP_DIR_RECV;
    mrt_thread_create2 ("BGP", BGP->schedule, NULL, NULL);
#define BGP_HOUSE_KEEPING_INTERVAL 15
    BGP->timer_house_keeping = New_Timer2 ("BGP house keeping timer",
                                BGP_HOUSE_KEEPING_INTERVAL, 0,
                                BGP->schedule, bgp_house_keeping_timeout, 0);
    if (INTERFACE_MASTER)
        LL_Add (INTERFACE_MASTER->ll_call_fns, bgp_if_call_fn);
}


/* 
 * Start BGP listening on port (usually 179)
 */
/* XXX bind_if may not work on some implemenations */
listen_socket_t * 
init_BGP_listen (prefix_t *bind_addr, interface_t *bind_if)
{
    struct sockaddr *sa;
    int sockfd, len;
    listen_socket_t *listen_socket;

    struct sockaddr_in serv_addr;
#ifdef HAVE_IPV6
    struct sockaddr_in6 serv_addr6;
#endif /* HAVE_IPV6 */

    pthread_mutex_lock (&BGP->mutex_lock);
    LL_Iterate (BGP->ll_listen_sockets, listen_socket) {
	/* skip if only one is null */
	if ((bind_addr == NULL || listen_socket->prefix == NULL) &&
		bind_addr != listen_socket->prefix)
	    continue;
	if ((bind_addr == listen_socket->prefix /* the both is null */||
		prefix_compare_wolen (bind_addr, listen_socket->prefix) == 0) &&
	        bind_if == listen_socket->interface)
	    break;
    }
    pthread_mutex_unlock (&BGP->mutex_lock);
    if (listen_socket) {
        pthread_mutex_lock (&listen_socket->mutex_lock);
	listen_socket->ref_count++;
        pthread_mutex_unlock (&listen_socket->mutex_lock);
	return (listen_socket);
    }

    /* check that NOT listening to portmaster! */

    memset (&serv_addr, 0, sizeof (serv_addr));
    serv_addr.sin_port = htons (BGP->lport);
    serv_addr.sin_family = AF_INET;
    if (bind_addr && bind_addr->family == AF_INET)
        memcpy (&serv_addr.sin_addr, prefix_tochar (bind_addr), 4);

    sa = (struct sockaddr *) &serv_addr;
    len = sizeof (serv_addr);
#ifdef HAVE_IPV6
    if (bind_addr == NULL || bind_addr->family == AF_INET6) {
        memset (&serv_addr6, 0, sizeof (serv_addr6));
        serv_addr6.sin6_port = htons (BGP->lport);
        serv_addr6.sin6_family = AF_INET6;
        if (bind_addr && bind_addr->family == AF_INET6)
            memcpy (&serv_addr6.sin6_addr, prefix_tochar (bind_addr), 16);
        sa = (struct sockaddr *) &serv_addr6;
        len = sizeof (serv_addr6);
    }
#endif /* HAVE_IPV6 */

    if ((sockfd = socket (sa->sa_family, SOCK_STREAM, 0)) < 0) {
#ifdef HAVE_IPV6
	if (sa->sa_family == AF_INET)
	    goto error;
	sa = (struct sockaddr *) &serv_addr;
	len = sizeof (serv_addr);
        if ((sockfd = socket (sa->sa_family, SOCK_STREAM, 0)) < 0) {
error:
#endif /* HAVE_IPV6 */
	    trace (TR_ERROR, BGP->trace, 
		   "Could not get socket (%m)\n");
	    return (NULL);
#ifdef HAVE_IPV6
	}
#endif /* HAVE_IPV6 */
    }

    /* allow the reuse this port */
    socket_reuse (sockfd, 1);

#ifdef SO_BINDTODEVICE
    if (bind_if) {
            struct ifreq ifr;
            safestrncpy (ifr.ifr_ifrn.ifrn_name, bind_if->name, 
			 sizeof (ifr.ifr_ifrn.ifrn_name));
            if (setsockopt (sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                                  &ifr, sizeof (ifr)) < 0)
                 trace (TR_ERROR, BGP->trace, "BINDTODEVICE %s (%m)\n",
                                   bind_if->name);
	    else
                 trace (TR_INFO, BGP->trace, "binding to interface %s\n",
			bind_if->name);
    }
#endif /* SO_BINDTODEVICE */

    if (bind (sockfd, sa, len) < 0) {
	trace (TR_ERROR, BGP->trace, 
	       "Could not bind to port %d (%m), aborting\n", BGP->lport);
	close (sockfd);
	return (NULL);
    }

    listen (sockfd, 5);

    listen_socket = New (listen_socket_t);
    listen_socket->sockfd = sockfd;
    listen_socket->ref_count = 1;
    pthread_mutex_init (&listen_socket->mutex_lock, NULL);
    listen_socket->prefix = Ref_Prefix (bind_addr);
    listen_socket->interface = bind_if;
    listen_socket->ll_accept_sockets = LL_Create (0);
    pthread_mutex_lock (&BGP->mutex_lock);
    LL_Add (BGP->ll_listen_sockets, listen_socket);
    pthread_mutex_unlock (&BGP->mutex_lock);

    select_add_fd_event ("bgp_in_accept_connection", sockfd, SELECT_READ, 
			 TRUE, NULL, 
			 bgp_in_accept_connection, 1, listen_socket);

    if (bind_addr)
        trace (TR_INFO, BGP->trace, 
	       "listening for connections on port %d at %a\n",
	       BGP->lport, bind_addr);
    else
        trace (TR_INFO, BGP->trace, "listening for connections on port %d\n",
	       BGP->lport);

    return (listen_socket);
}


bgp_peer_t *
Find_BGP_Peer (bgp_local_t *local_bgp, prefix_t * prefix, int as, u_long id)
{
    bgp_peer_t *peer;
    
    if (local_bgp == NULL) {
        pthread_mutex_lock (&BGP->locals_mutex_lock);
	LL_Iterate (BGP->ll_bgp_locals, local_bgp) {
	    pthread_mutex_lock (&local_bgp->peers_mutex_lock);
	    if ((peer = Find_BGP_Peer (local_bgp, prefix, as, id)) != NULL) {
	        pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
        	pthread_mutex_unlock (&BGP->locals_mutex_lock);
		return (peer);
	    }
	    pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
	}
       	pthread_mutex_unlock (&BGP->locals_mutex_lock);
	return (NULL);
    }

    /* scan through peers */
    LL_Iterate (local_bgp->ll_bgp_peers, peer) {

	if (peer->peer_as < 0)
	    continue;

	if (peer->peer_addr == NULL && peer->neighbor_list >= 0) {
	    if (apply_access_list (peer->neighbor_list, prefix)) {
		return (peer);
	    }
	}
	else if (prefix_compare_wolen (peer->peer_addr, prefix) == 0 &&
		(as == 0 || peer->peer_as == 0 || as == peer->peer_as) &&
		(id == 0 || peer->peer_id == 0 || id == peer->peer_id))
		return (peer);

	if (peer->aliases) {
	    prefix_t *alias;

	    LL_Iterate (peer->aliases, alias) {
		if (prefix_compare_wolen (alias, prefix) == 0 &&
		       (as == 0 || as == peer->peer_as) &&
		       (id == 0 || id == peer->peer_id))
		    return (peer);
	    }
	}
	continue;
    }
    return (NULL);
}


bgp_peer_t *
Find_BGP_Peer_ByID (bgp_local_t *local_bgp, char *name)
{
    bgp_peer_t *peer = NULL;

    if (local_bgp == NULL) {
        pthread_mutex_lock (&BGP->locals_mutex_lock);
	LL_Iterate (BGP->ll_bgp_locals, local_bgp) {
	    pthread_mutex_lock (&local_bgp->peers_mutex_lock);
	    if ((peer = Find_BGP_Peer_ByID (local_bgp, name)) != NULL) {
	        pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
        	pthread_mutex_unlock (&BGP->locals_mutex_lock);
		return (peer);
	    }
	    pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
	}
       	pthread_mutex_unlock (&BGP->locals_mutex_lock);
	return (NULL);
    }

    /* scan through peers */
    LL_Iterate (local_bgp->ll_bgp_peers, peer) {
	    if (peer->name && strcasecmp (peer->name, name) == 0)
		    break;
    }
    return (peer);
}


static int
bgp_obtain_index (bgp_local_t *local_bgp)
{
    int i;

    assert (local_bgp);
    /* reserve zero for the future use */
    for (i = 1 ; i < MAX_BGP_PEERS; i++) {
	if (!BITX_TEST (&local_bgp->bits_assigned, i)) {
	    BITX_SET (&local_bgp->bits_assigned, i);
	    return (i);
        }
    }
    return (-1);
}

static void
bgp_return_index (bgp_local_t *local_bgp, int index)
{
    assert (local_bgp);
    assert (BITX_TEST(&local_bgp->bits_assigned, index));
    BITX_RESET (&local_bgp->bits_assigned, index);
}


/* 
 * Initialize BGP peer and add to list of peers
 */
bgp_peer_t *
Add_BGP_Peer (bgp_local_t *local_bgp, char *name, prefix_t * prefix, 
	      int as, u_long id, trace_t * tr)
{
    char str[MAXLINE];
    bgp_peer_t *peer;
    int viewno;

    assert (name != NULL || prefix != NULL);

    if (local_bgp == NULL) {
	local_bgp = LL_GetHead (BGP->ll_bgp_locals);
    }
    assert (local_bgp);
    if (name) {
        if ((peer = Find_BGP_Peer_ByID (local_bgp, name)) != NULL) {
	    return (NULL);
        }
    }
    if (prefix) {
        if ((peer = Find_BGP_Peer (local_bgp, prefix, 
				   as, id)) != NULL) {
	    return (NULL);
        }
    }
#ifdef HAVE_IPV6
    if (prefix && prefix->family == AF_INET6)
        sprintf (str, "BGP4+ %s", (name)? name: prefix_toa (prefix));
    else
#endif /* HAVE_IPV6 */
    sprintf (str, "BGP %s", (name)? name: prefix_toa (prefix));

    peer = New (bgp_peer_t);
    peer->name = (name)? strdup (name): NULL;
    peer->peer_addr = (prefix)? Ref_Prefix (prefix): NULL;
    peer->peer_as = as;
    peer->peer_id = id;
    peer->peer_port = BGP->cport;
    peer->trace = trace_copy (tr);
    set_trace (peer->trace, TRACE_PREPEND_STRING, str, 0);
    peer->local_bgp = local_bgp;

    peer->index = bgp_obtain_index (local_bgp);
    local_bgp->num_peers++;

    peer->gateway = NULL;
    peer->bind_addr = NULL;
    peer->bind_if = NULL;
    peer->options = 0;
    if (as == peer->local_bgp->this_as)
	BIT_SET (peer->options, BGP_INTERNAL);

    peer->aliases = NULL;
    peer->sockfd = -1;
    peer->listen_socket = NULL;

    peer->neighbor_list = -1;
  for (viewno = 0; viewno < MAX_BGP_VIEWS; viewno++) {
      peer->filters[viewno].dlist_in = peer->filters[viewno].dlist_out = -1;
      peer->filters[viewno].flist_in = peer->filters[viewno].flist_out = -1;
      peer->filters[viewno].clist_in = peer->filters[viewno].clist_out = -1;
      peer->filters[viewno].route_map_in = -1;
      peer->filters[viewno].route_map_out = -1;                                 
      peer->default_weight[viewno] = -1;              
  } 

    peer->read_ptr = peer->buffer;
    peer->start_ptr = peer->buffer;
    peer->packet = NULL;

    peer->state = BGPSTATE_IDLE;

    peer->maximum_prefix = 0;
    peer->accept_socket = NULL;

    peer->Start_Interval = -1;
    peer->ConnectRetry_Interval = -1;
    peer->KeepAlive_Interval = -1;
    peer->HoldTime_Interval = -1;

    BIT_SET (peer->options, BGP_BGP4PLUS_DEFAULT);

    if (peer->peer_addr) {
        /* create timers */
        peer->timer_ConnectRetry = New_Timer (bgp_schedule_timer,
					 BGP->Default_ConnectRetry_Interval,
					 "ConnectRetry", peer);
        peer->timer_KeepAlive = New_Timer (bgp_schedule_timer,
				      BGP->Default_KeepAlive_Interval,
				      "KeepALive", peer);
        peer->timer_HoldTime = New_Timer (bgp_schedule_timer,
				     BGP->Default_HoldTime_Interval,
				     "HoldTime", peer);
        peer->timer_Start = New_Timer (bgp_schedule_timer, 
				   BGP->Default_Start_Interval,
				  "StartTime", peer);
        timer_set_flags (peer->timer_ConnectRetry, TIMER_ONE_SHOT);
	timer_set_flags (peer->timer_Start, TIMER_JITTER2, -25, 0);
        /* timer_set_jitter2 (peer->timer_KeepAlive, -25, 0); */
        timer_set_flags (peer->timer_HoldTime, TIMER_ONE_SHOT);
        timer_set_flags (peer->timer_Start, TIMER_ONE_SHOT);
        timer_set_flags (peer->timer_Start, TIMER_EXPONENT);
#define BGP_TIMER_START_MAX 4
	timer_set_flags (peer->timer_Start, TIMER_EXPONENT_MAX, 
					    BGP_TIMER_START_MAX);

        peer->send_queue = LL_Create (LL_DestroyFunction, bgp_packet_del, 0);
        pthread_mutex_init (&peer->send_mutex_lock, NULL);

        peer->ll_update_out = LL_Create (LL_DestroyFunction, 
					 delete_update_bucket, 0);
        pthread_mutex_init (&peer->update_mutex_lock, NULL);

    }
    pthread_mutex_init (&peer->mutex_lock, NULL);
    peer->schedule = New_Schedule ((name)? name: prefix_toa (peer->peer_addr), 
				    peer->trace);

    LL_Add (local_bgp->ll_bgp_peers, peer);
    mrt_thread_create2 (str, peer->schedule, NULL, NULL);
    return (peer);
}


static void
bgp_del_route_in (bgp_route_in_t *route_in)
{
    bgp_deref_attr (route_in->attr);
    Delete (route_in);
}


static void
delete_peer_route_in (bgp_peer_t *peer)
{
    int afi, safi;
    for (afi = 0; afi < AFI_MAX; afi++) {
	for (safi = 0; safi < SAFI_MAX; safi++) {
	    if (peer->routes_in[afi][safi]) {
		Destroy_Radix (peer->routes_in[afi][safi], bgp_del_route_in);
		peer->routes_in[afi][safi] = NULL;
	    }
	}
    }
}


static void
bgp_remove_me (bgp_peer_t *peer, bgp_peer_t *child)
{
    assert (peer->children);
    LL_Remove (peer->children, child);
    if (peer->state == BGPSTATE_DESTROYED &&
	    LL_GetCount (peer->children) <= 0) {
	LL_Destroy (peer->children);
        delete_schedule (peer->schedule);
        if (peer->name) Delete (peer->name);
        Destroy_Trace (peer->trace);
        pthread_mutex_destroy (&peer->mutex_lock);
	delete_peer_route_in (peer);
	Delete (peer);
        mrt_thread_exit ();
    }
}


static void
bgp_destroy_peer (bgp_peer_t *peer, int fast)
{
    assert (peer);
    assert (peer->local_bgp);
    if (peer->sockfd >= 0)
	select_delete_fdx (peer->sockfd);
    peer->local_bgp->num_peers--;
    bgp_return_index (peer->local_bgp, peer->index);

    if (peer->peer_addr) {
        /* peer is not on the list now, but the routunes should not care */
	if (!fast) {
	    if (peer->state == BGPSTATE_ESTABLISHED)
	        bgp_peer_down (peer);
            bgp_peer_dead (peer);
	}

        Destroy_Timer (peer->timer_ConnectRetry);
        Destroy_Timer (peer->timer_KeepAlive);
        Destroy_Timer (peer->timer_HoldTime);
        Destroy_Timer (peer->timer_Start);

        LL_Destroy (peer->send_queue);
        pthread_mutex_destroy (&peer->send_mutex_lock);
        LL_Destroy (peer->ll_update_out);
        pthread_mutex_destroy (&peer->update_mutex_lock);

	assert (peer->children == NULL);
	if (!fast && peer->parent) {
    	    schedule_event2 ("bgp_remove_me",
		      	     peer->parent->schedule, bgp_remove_me, 2, 
			     peer->parent, peer);
	}
    }
    else if (!fast) {
        clear_schedule (peer->schedule);
	if (peer->children && LL_GetCount (peer->children) > 0) {
	    bgp_peer_t *child;
	    LL_Iterate (peer->children, child) {
		stop_bgp_peer (child, 1);
        	pthread_mutex_lock (&peer->local_bgp->peers_mutex_lock);
		Destroy_BGP_Peer (child, 0);
        	pthread_mutex_unlock (&peer->local_bgp->peers_mutex_lock);
	    }
	    /* waiting all children are destroyed */
	    peer->state = BGPSTATE_DESTROYED;
	    return;
	}
    }
    /* delete now */
    if (peer->children)
	LL_Destroy (peer->children);

    delete_schedule (peer->schedule);
    if (peer->name) Delete (peer->name);
    Destroy_Trace (peer->trace);
    pthread_mutex_destroy (&peer->mutex_lock);
    delete_peer_route_in (peer);
    Delete (peer);
    mrt_thread_exit ();
}


void
Destroy_BGP_Peer (bgp_peer_t *peer, int fast)
{
    bgp_local_t *local_bgp;

    assert (peer);
    local_bgp = peer->local_bgp;
    /* pthread_mutex_lock (&local_bgp->peers_mutex_lock); */
    LL_RemoveFn (local_bgp->ll_bgp_peers, peer, NULL);
    /* pthread_mutex_unlock (&local_bgp->peers_mutex_lock); */
    schedule_event2 ("bgp_destroy_peer",
		      peer->schedule, bgp_destroy_peer, 2, peer, fast);
}


void
bgp_peer_down (bgp_peer_t * peer)
{
        int i;
	/* withdraw all routes associated with the peer */
        for (i = 0; i < MAX_BGP_VIEWS; i++) {
	    if (BITX_TEST (&peer->local_bgp->view_mask, i))
	        view_delete_peer (BGP->views[i], peer);
        }
        if (BGP->peer_down_call_fn)
	    BGP->peer_down_call_fn (peer);
}


/*
 * if peer is leaving established state, withdraw routes and free resources
 * close both sockets, reset inputs, stop timers, and clear schedule queue.
 */
void 
bgp_peer_dead (bgp_peer_t * peer)
{
    trace (TR_INFO, peer->trace, "shutdown the connection\n");

    if (peer->sockfd >= 0) {
        /* delete sockfd stuff */
	select_delete_fdx (peer->sockfd);
	trace (TR_INFO, peer->trace, "outgoing connection (fd %d) closed\n",
	       peer->sockfd);
	peer->sockfd = -1;
    }
    peer->gateway = NULL;
    /* keep incoming socket open */

    if (peer->peer_addr) {
        /* stop all timers except start */
        Timer_Turn_OFF (peer->timer_ConnectRetry);
        Timer_Turn_OFF (peer->timer_KeepAlive);
        Timer_Turn_OFF (peer->timer_HoldTime);
        /* Timer_Turn_OFF (peer->timer_Start); */
	/* delete output */
	pthread_mutex_lock (&peer->send_mutex_lock);
        LL_Clear (peer->send_queue);
	pthread_mutex_unlock (&peer->send_mutex_lock);
	pthread_mutex_lock (&peer->update_mutex_lock);
        LL_Clear (peer->ll_update_out);
	pthread_mutex_unlock (&peer->update_mutex_lock);
        if (peer->attr) {
            bgp_deref_attr (peer->attr);
	    peer->attr = NULL;
	}
        if (peer->ll_withdraw) {
            LL_Destroy (peer->ll_withdraw);
	    peer->ll_withdraw = NULL;
	}
        if (peer->ll_announce) {
            LL_Destroy (peer->ll_announce);
	    peer->ll_announce = NULL;
	}
	delete_peer_route_in (peer);
    }
    else {
	if (peer->children && LL_GetCount (peer->children) > 0) {
	    bgp_peer_t *child;
	    LL_Iterate (peer->children, child)
                bgp_stop_peer (child);
	}
    }

    /* should flush input buffer here */
    peer->read_ptr = peer->buffer;
    peer->start_ptr = peer->buffer;
    peer->packet = NULL;
    clear_schedule (peer->schedule);
    if (peer->peer_addr) {
	int as = peer->peer_as;
	u_long id = peer->peer_id;

        if (peer->new_as > 0) {
            as = peer->new_as;
	    peer->new_as = 0;
	}
        if (peer->new_id != 0) {
            id = peer->new_id;
	    peer->new_id = 0;
	}
	if (peer->peer_as != as) {
	    trace (TR_INFO, peer->trace, "AS number changed from %d to %d\n",
	       peer->peer_as, as);
	    peer->gateway = NULL;
	}
	if (peer->peer_id != id) {
	    trace (TR_INFO, peer->trace, "Router ID changed from %x to %x\n",
	       peer->peer_id, id);
	    peer->gateway = NULL;
	}
	BIT_RESET (peer->options, BGP_INTERNAL);
        if (as == peer->local_bgp->this_as)
	    BIT_SET (peer->options, BGP_INTERNAL);
    }
}


#ifdef notdef
int
bgp_kill_peer (gateway_t *gateway)
{
    bgp_peer_t *peer;

    if ((peer = find_bgp_peer (gateway)) != NULL) {
	bgp_sm_process_event (peer, BGPEVENT_STOP);
	return (1);
    }
    return (-1);
}
#endif


void
bgp_start_peer (bgp_peer_t *peer)
{
    assert (peer);
    schedule_event2 ("bgp_sm_process_event",
		      peer->schedule, bgp_sm_process_event,
		      2, peer, BGPEVENT_START);
}


void
bgp_start_all (bgp_local_t *local_bgp)
{
    bgp_peer_t *peer;

    if (local_bgp == NULL) {
        pthread_mutex_lock (&BGP->locals_mutex_lock);
        LL_Iterate (BGP->ll_bgp_locals, local_bgp) {
	    bgp_start_all (local_bgp);
	}
        pthread_mutex_unlock (&BGP->locals_mutex_lock);
	return;
    }

    pthread_mutex_lock (&local_bgp->peers_mutex_lock);
    LL_Iterate (local_bgp->ll_bgp_peers, peer) {
	/* children will be kicked by the parent */
	if (peer->parent == NULL)
            bgp_start_peer (peer);
    }
    pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
}


void
bgp_stop_peer (bgp_peer_t *peer)
{
    assert (peer);
    schedule_event2 ("bgp_sm_process_event",
		      peer->schedule, bgp_sm_process_event,
		      2, peer, BGPEVENT_STOP);
}


void
bgp_kill_all (bgp_local_t *local_bgp)
{
    bgp_peer_t *peer;

    if (local_bgp == NULL) {
        pthread_mutex_lock (&BGP->locals_mutex_lock);
        LL_Iterate (BGP->ll_bgp_locals, local_bgp) {
	    bgp_kill_all (local_bgp);
	}
        pthread_mutex_unlock (&BGP->locals_mutex_lock);
	return;
    }

    pthread_mutex_lock (&local_bgp->peers_mutex_lock);
    LL_Iterate (local_bgp->ll_bgp_peers, peer) {
	/* children will be signaled by the parent */
	if (peer->parent == NULL)
            bgp_stop_peer (peer);
    }
    pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
}


int 
set_BGP (int first, ...)
{
    va_list ap;
    enum BGP_ATTR attr;
    int id;

    pthread_mutex_lock (&BGP->mutex_lock);
    /* Process the Arguments */
    va_start (ap, first);
    for (attr = (enum BGP_ATTR) first; attr; 
				       attr = va_arg (ap, enum BGP_ATTR)) {
	switch (attr) {
#ifdef notdef
	case BGP_MY_AS:
	    local_bgp->this_as = va_arg (ap, int);
	    break;
	case BGP_MY_ID:
	    local_bgp->this_id = va_arg (ap, u_long);
	    if (!local_bgp->cluster_id)
		local_bgp->cluster_id = local_bgp->this_id;
	    break;
	case BGP_CURRENT_BGP:
	    BGP->current_bgp = va_arg (ap, bgp_local_t *);
	    break;
#endif
	case BGP_PEER_DOWN_FN:
	    BGP->peer_down_call_fn = va_arg (ap, void_fn_t);
	    break;
	case BGP_PEER_ESTABLISHED_FN:
	    BGP->peer_established_call_fn = va_arg (ap, void_fn_t);
	    break;
	case BGP_RECV_UPDATE_FN:
	    BGP->update_call_fn = va_arg (ap, int_fn_t);
	    break;
	case BGP_SEND_UPDATE_FN:
	    BGP->send_update_call_fn = va_arg (ap, int_fn_t);
	    break;
/*
	case BGP_RT_UPDATE_FN:
	    BGP->rt_update_call_fn = va_arg (ap, rib_update_route_t);
	    break;
*/
	case BGP_STATE_CHANGE_FN:
	    BGP->state_change_fn = va_arg (ap, void_fn_t);
	    break;
	case BGP_ACCEPT_ALL_PEERS:
	    BGP->accept_all_peers = va_arg (ap, int);
	    break;
	case BGP_LPORT:
	    BGP->lport = va_arg (ap, int);
	    break;
	case BGP_CPORT:
	    BGP->cport = va_arg (ap, int);
	    break;
	case BGP_TRACE_STRUCT:
	    BGP->trace = va_arg (ap, trace_t *);
	    break;
	case BGP_DUMP_ROUTE_FORM:
	    id = va_arg (ap, int);
	    assert (id >= 0 && id < MAX_BGP_VIEWS);
	    if (BGP->dump_route_form[id])
		free (BGP->dump_route_form[id]);
	    BGP->dump_route_form[id] = va_arg (ap, char *);
	    if (BGP->dump_route_form[id]) {
		BGP->dump_route_form[id] = strdup (BGP->dump_route_form[id]);
	        BGP->dump_route_interval[id] = va_arg (ap, int);
	        BGP->dump_route_type[id] = va_arg (ap, int);
	        BGP->dump_route_time[id] = 0;
	    }
	    break;
	case BGP_DUMP_UPDATE_FORM:
	    if (BGP->dump_update_form)
		free (BGP->dump_update_form);
	    BGP->dump_update_form = va_arg (ap, char *);
	    if (BGP->dump_update_form) {
	        BGP->dump_update_form = strdup (BGP->dump_update_form);
	        BGP->dump_update_interval = va_arg (ap, int);
	        BGP->dump_update_time = 0;
	        BGP->dump_update_types = va_arg (ap, u_long);
	        BGP->dump_update_family = va_arg (ap, int);
	    }
	    break;
	/* 0 -- receiving, 1 -- sending, 2 - both */
	case BGP_DUMP_DIRECTION:
	    BGP->dump_direction = va_arg (ap, int);
	    break;
	default:
	    assert (0);
	    break;
	}
    }
    va_end (ap);
    pthread_mutex_unlock (&BGP->mutex_lock);

    return (1);
}



#ifdef notdef
/* find_bgp_peer
 * given a prefix, find the corresponding bgp peer
 * structure.
 */
bgp_peer_t *
find_bgp_peer (bgp_local_t *local_bgp, gateway_t * gateway)
{
    bgp_peer_t *peer;

    pthread_mutex_lock (&local_bgp->peers_mutex_lock);
    LL_Iterate (local_bgp->ll_bgp_peers, peer) {
	if (peer->gateway == gateway) {
    	    pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
	    return (peer);
	}
    }
    pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
    return (NULL);
}
#endif


void
bgp_start_listening (bgp_peer_t *peer)
{
    assert (peer->listen_socket == NULL);

    peer->listen_socket = init_BGP_listen (peer->bind_addr, peer->bind_if);
    if (peer->listen_socket == NULL && (peer->bind_addr || peer->bind_if)) {
        peer->listen_socket = init_BGP_listen (NULL, NULL);
    }
}


void
start_bgp_peer (bgp_peer_t *peer)
{
    static int first = 1;

    if (first) {
	start_bgp ();
	first = 0;
    }
    /* I can not start listening here since
       bind address may be supplied later */
    timer_set_flags (peer->timer_Start, TIMER_EXPONENT_SET, 0);
    Timer_Turn_ON (peer->timer_Start);
}


static void
stop_bgp_peer (bgp_peer_t *peer, int lockf)
{
    if (peer->accept_socket) {
	assert (peer->accept_socket->sockfd >= 0);
	close (peer->accept_socket->sockfd);
        trace (TR_INFO, peer->trace, "incoming connection (fd %d) closed\n",
               peer->accept_socket->sockfd);
        peer->accept_socket->sockfd = -1;
	Deref_Prefix (peer->accept_socket->remote_prefix);
	Deref_Prefix (peer->accept_socket->local_prefix);
        peer->accept_socket = NULL;
    }
    else if (peer->sockfd >= 0) {
        select_delete_fdx (peer->sockfd);
        peer->sockfd = -1;
    }

    if (peer->listen_socket) {
        pthread_mutex_lock (&peer->listen_socket->mutex_lock);
	peer->listen_socket->ref_count--;
        if (peer->listen_socket->ref_count <= 0) {
	    accept_socket_t *accept_socket;
            if (lockf) pthread_mutex_lock (&BGP->mutex_lock);
	    LL_Remove (BGP->ll_listen_sockets, peer->listen_socket);
            if (lockf) pthread_mutex_unlock (&BGP->mutex_lock);
	    Deref_Prefix (peer->listen_socket->prefix);
            select_delete_fdx (peer->listen_socket->sockfd);
	    LL_Iterate (peer->listen_socket->ll_accept_sockets, 
			accept_socket) {
		accept_socket_t *prev;
	        trace (TR_INFO, BGP->trace, 
		   "Give up the accept from %a at %a on fd %d (terminate)\n", 
		    accept_socket->remote_prefix, accept_socket->local_prefix,
		    accept_socket->sockfd);
		select_delete_fdx (accept_socket->sockfd);
		Deref_Prefix (accept_socket->remote_prefix);
		Deref_Prefix (accept_socket->local_prefix);
		prev = LL_GetPrev (peer->listen_socket->ll_accept_sockets, 
				   accept_socket);
		LL_Remove (peer->listen_socket->ll_accept_sockets, 
			   accept_socket);
		Delete (accept_socket);
		accept_socket = prev;
	    }
            pthread_mutex_destroy (&peer->listen_socket->mutex_lock);
	    Delete (peer->listen_socket);
	    peer->listen_socket = NULL;
	}
	else
            pthread_mutex_unlock (&peer->listen_socket->mutex_lock);
    }

    timer_set_flags (peer->timer_Start, TIMER_EXPONENT_SET, 0);
    Timer_Turn_ON (peer->timer_Start);
}


/*
 *  start listening on socket 
 */
void
start_bgp (void)
{
    /* move to init_BGP */
    /* mrt_thread_create2 ("BGP", BGP->schedule, NULL, NULL); */
    Timer_Turn_ON (BGP->timer_house_keeping);
}


#if 0
void 
stop_bgp (bgp_local_t *local_bgp)
{
    bgp_peer_t *peer;
    prefix_t *prefix;
    int i;

    pthread_mutex_lock (&local_bgp->peers_mutex_lock);
    LL_Iterate (local_bgp->ll_bgp_peers, peer) {
	if (peer->parent == NULL) {
	    bgp_peer_t *prev;
	    prev = LL_GetPrev (local_bgp->ll_bgp_peers, peer);
	    stop_bgp_peer (peer, 0);
	    Destroy_BGP_Peer (peer, 0);
	    peer = prev;
	}
    }
    pthread_mutex_unlock (&local_bgp->peers_mutex_lock);

    pthread_mutex_lock (&local_bgp->mutex_lock);
/*
    if (BGP->sockfd >= 0) {
        select_delete_fdx (BGP->sockfd);
	BGP->sockfd = -1;
	BGP->sockfd_count = 0;
    }
*/

    LL_Iterate (local_bgp->ll_networks, prefix) {
        if (MRT->rib_redistribute_network)
            MRT->rib_redistribute_network (PROTO_BGP, prefix, 0);
    }
    LL_Clear (local_bgp->ll_networks);

    for (i = 0; i <= PROTO_MAX; i++) {
        if (BGP4_BIT_TEST (local_bgp->redistribute_mask, i)) {
            if (MRT->rib_redistribute_request)
                MRT->rib_redistribute_request (PROTO_BGP, i, 0);
	}
    }
    local_bgp->redistribute_mask = 0;

    for (i = 0; i < MAX_BGP_VIEWS; i++) {
        /* delete aggregate */
    }
   /* just leave BGP main thread idling */
 /* schedule_event2 ("mrt_thread_exit", BGP->schedule, mrt_thread_exit, 0); */
    pthread_mutex_unlock (&local_bgp->mutex_lock);
    /* asynchronous return */
}
#endif


/* 
 * dump various BGP stats to a socket
 * usually called by UII (user interactive interface)
 */
int 
show_bgp_local (uii_connection_t * uii)
{
    bgp_local_t *local;
    char tmpx[MAXLINE];

    pthread_mutex_lock (&BGP->mutex_lock);
    uii_add_bulk_output (uii, "Routing Protocol is \"BGP4+\"\n");

    if (BGP->trace != NULL)
	uii_add_bulk_output (uii, "Trace flags 0x%x\n\n", BGP->trace->flags);
    pthread_mutex_unlock (&BGP->mutex_lock);

    pthread_mutex_lock (&BGP->locals_mutex_lock);
    LL_Iterate (BGP->ll_bgp_locals, local) {
	int i;
        pthread_mutex_lock (&local->mutex_lock);
	uii_add_bulk_output (uii, "Local Router BGP AS%d\n", local->this_as);
	uii_add_bulk_output (uii, "    AS Number: %d    Router ID: %s\n",
			     local->this_as, 
		inet_ntop (AF_INET, &local->this_id, tmpx, sizeof (tmpx)));
	uii_add_bulk_output (uii, "    Local View Number(s):");
	for (i = 0; i < MAX_BGP_VIEWS; i++) {
	    if (BITX_TEST (&local->view_mask, i))
		uii_add_bulk_output (uii, " %d", i);
	}
	uii_add_bulk_output (uii, "\n\n");
        pthread_mutex_unlock (&local->mutex_lock);
    }
    pthread_mutex_unlock (&BGP->locals_mutex_lock);
    return (1);
}


/* 
 * dump various BGP stats to a socket
 * usually called by UII (user interactive interface)
 */
int 
show_bgp_views (uii_connection_t * uii)
{
    int viewno;
    int first = 1;

    for (viewno = 0; viewno < MAX_BGP_VIEWS; viewno++) {
        char tmpx[64];
        bgp_route_head_t *route_head;
        int n_heads = 0;
        int n_nodes = 0;
	view_t *view = BGP->views[viewno];

	if (view == NULL || view->local_bgp == NULL)
	    continue;
	
	if (first) {
	    first = 0;
	    uii_add_bulk_output (uii, "%4s %2s %5s %15s %5s %5s\n",
			"VIEW", "VS", "AS", "ID", "HEADS", "NODES");
	}
        view_open (view);

    	VIEW_RADIX_WALK (view, route_head) {
	    if (!BIT_TEST (route_head->state_bits, VRTS_DELETE)) {
		int n, m;
		n = LL_GetCount (route_head->ll_imported);
		m = LL_GetCount (route_head->ll_routes);
		n_nodes += (n + m);
		if (n > 0 || m > 0)
		    n_heads++;
	    }
        } VIEW_RADIX_WALK_END;
        view_close (view);

	uii_add_bulk_output (uii, "%4d %c%c %5d %15s %5d %5d\n",
		view->viewno, (view->afi == AFI_IP6)?'6':'4', 
			(view->safi == SAFI_MULTICAST)?'M':'U',
		view->local_bgp->this_as,
		inet_ntop (AF_INET, (view->local_bgp->this_id)?
				&view->local_bgp->this_id: &MRT->default_id, 
			   tmpx, sizeof (tmpx)), n_heads, n_nodes);
    }
    return (1);
}


/* 
 * dump various BGP stats to a socket
 * usually called by UII (user interactive interface)
 */
int 
show_f_bgp (uii_connection_t * uii, int family)
{
    return (show_f_bgp_summary (uii, NULL, family, FALSE));
}


int 
show_f_bgp_summary (uii_connection_t * uii, bgp_local_t *local_bgp, 
		    int family, int summary)
{
    bgp_peer_t *peer;
    char tmpx[MAXLINE], date[MAXLINE], peername[MAXLINE];
    time_t now;
    int count = 0;

    if (local_bgp == NULL) {
        pthread_mutex_lock (&BGP->locals_mutex_lock);
	LL_Iterate (BGP->ll_bgp_locals, local_bgp) {
	    show_f_bgp_summary (uii, local_bgp, family, summary);
	}
        pthread_mutex_unlock (&BGP->locals_mutex_lock);
	return (1);
    }

    assert (local_bgp);
    pthread_mutex_lock (&local_bgp->mutex_lock);
    time (&now);
    uii_add_bulk_output (uii, "Routing Protocol is \"BGP4+\", ");
    uii_add_bulk_output (uii, "Local Router ID is %s, ", 
		         inet_ntop (AF_INET, (local_bgp->this_id)?
				    	&local_bgp->this_id: &MRT->default_id,
			     		tmpx, sizeof (tmpx)));
    uii_add_bulk_output (uii, "Local AS is %d\n", local_bgp->this_as);
if (!summary) {
    if (local_bgp->trace != NULL)
	uii_add_bulk_output (uii, "Trace flags 0x%x\n", 
	    local_bgp->trace->flags);
    /* uii_add_bulk_output (uii, "%d Attribute Blocks\n", 
	              HASH_GetCount (BGP->attr_hash)); */
#if 0
    if (local_bgp->bgp_num_active_route_head > 0)
        uii_add_bulk_output (uii, "bgp active route heads: %d\n",
		       local_bgp->bgp_num_active_route_head);
    if (local_bgp->bgp_num_active_route_node > 0)
        uii_add_bulk_output (uii, "bgp active route nodes: %d\n",
		       local_bgp->bgp_num_active_route_node);
#endif
}
    pthread_mutex_unlock (&local_bgp->mutex_lock);

if (summary) {
	if (count++ != 0) uii_add_bulk_output (uii, "\n");
	uii_add_bulk_output (uii, "%-25s %1s %5s %11s %7s %3s/%-3s %5s %s\n",
		"Neighbor", "V", "AS", "Update(R/S)", "Notify",
		"Up", "Dwn", "Hours", "State");
}
    pthread_mutex_lock (&local_bgp->peers_mutex_lock);
    LL_Iterate (local_bgp->ll_bgp_peers, peer) {
	char xxx[MAXLINE];
	int bgp4plus_version = 0;
	int elapsed = (peer->time > 0)?(now - peer->time):-1;

	/* skip template or group */
	if (peer->peer_addr == NULL)
	    continue;

	if (family != 0 && peer->peer_addr->family != family)
	    continue;

        pthread_mutex_lock (&peer->mutex_lock);

#ifdef HAVE_IPV6
	if (BIT_TEST (peer->options, BGP_BGP4PLUS_01))
	    bgp4plus_version = 1;
#endif /* HAVE_IPV6 */

        if (peer->name)
	    sprintf (peername, "%s (%s)", peer->name, 
		     prefix_toa (peer->peer_addr));
        else if (peer->description)
	    sprintf (peername, "%s (%s)", peer->description, 
		     prefix_toa (peer->peer_addr));
	else
	    sprintf (peername, "%s", prefix_toa (peer->peer_addr));

if (summary) {
	peername[25] = '\0';
	sprintf (date, "-----");
	if (elapsed >= 0) {
	    if (elapsed / 3600 > 99)
	        sprintf (date, "%5d", elapsed / 3600);
	    else
	        sprintf (date, "%d.%02d", elapsed / 3600,
                            (elapsed % 3600) * 100 / 3600);
	}

	uii_add_bulk_output (uii, 
		"%-25s %1s %5d %5d/%-5d %3d/%-3d %3d/%-3d %5s %s\n",
            peername,
	    (peer->peer_addr->family == AF_INET)?"4": 
	        (bgp4plus_version == 0)?"-": "+",
	    peer->peer_as, 
	    peer->num_updates_recv, peer->num_updates_sent,
	    peer->num_notifications_recv, peer->num_notifications_sent,
	    peer->num_connections_established, peer->num_connections_dropped,
	    date,
	    sbgp_states[peer->state]);
}
else {

        time2date (elapsed, date);
	strcpy (xxx, "BGP4");
#ifdef HAVE_IPV6
	if (peer->peer_addr->family == AF_INET6)
	    sprintf (xxx, "BGP4+ draft %d", bgp4plus_version);
#endif /* HAVE_IPV6 */

	uii_add_bulk_output (uii, "\n");
	uii_add_bulk_output (uii, "  peer %s AS%d on %s [%s] %s\n", peername,
		       (peer->gateway)? peer->gateway->AS: peer->peer_as, 
	    	       (peer->interface)? peer->interface->name: "???",
		       sbgp_states[peer->state], date);

	uii_add_bulk_output (uii, 
		 "    Router ID %s (index #%d)",
	    inet_ntop (AF_INET, (peer->gateway)? &peer->gateway->routerid:
			&peer->peer_id, tmpx, sizeof (tmpx)),
		 	peer->index);
#if 0
	if (peer->default_weight >= 0)
	    uii_add_bulk_output (uii, 
		 " weight %d", peer->default_weight);
#endif
	uii_add_bulk_output (uii, " %c%s%s%s%s%s\n",
		 BIT_TEST (peer->options, BGP_INTERNAL)? 'i': 'e', xxx,
		 BIT_TEST (peer->options, BGP_EBGP_MULTIHOP)? " multi-hop": "",
		 BIT_TEST (peer->options, BGP_PEER_CISCO)? " cisco": "",
		 BIT_TEST (peer->options, BGP_PEER_TEST)? " test": "",
		 BIT_TEST (peer->options, BGP_PEER_SELF)? " self": "");
	/* if (peer->state == BGPSTATE_OPENSENT ||
                peer->state == BGPSTATE_OPENCONFIRM ||
	        peer->state == BGPSTATE_ESTABLISHED) */
	if (peer->local_addr)
	    uii_add_bulk_output (uii, 
		 "    Local Address %s (socket %d)\n", 
		 prefix_toa (peer->local_addr), peer->sockfd);
        if (LL_GetCount (BGP->ll_bgp_locals) != 1) {
	    uii_add_bulk_output (uii, "    Local AS: %-5d  Local ID: %s\n",
				 peer->local_bgp->this_as,
		inet_ntop (AF_INET, (peer->local_bgp->this_id)?
			&peer->local_bgp->this_id: &MRT->default_id, 
			tmpx, sizeof (tmpx)));
	}
	if (peer->listen_socket && peer->listen_socket->prefix)
	    uii_add_bulk_output (uii, 
		 "    Listening at  %s (socket %d)\n",
		 peer->listen_socket->prefix?
		     prefix_toa (peer->listen_socket->prefix): "*",
		 peer->listen_socket->sockfd);
	if (peer->timer_KeepAlive->time_next_fire <= 0)
	    uii_add_bulk_output (uii, "    KeepAlive Off");
	else
	    uii_add_bulk_output (uii, "    KeepAlive %d",
			   peer->timer_KeepAlive->time_next_fire - now);
	if (peer->timer_Start->time_next_fire <= 0)
	    uii_add_bulk_output (uii, "  Starttimer Off");
	else
	    uii_add_bulk_output (uii, "  Starttimer %d",
			   peer->timer_Start->time_next_fire - now);
	if (peer->timer_HoldTime->time_next_fire <= 0)
	    uii_add_bulk_output (uii, "  Holdtime Off");
	else
	    uii_add_bulk_output (uii, "  Holdtime %d",
			   peer->timer_HoldTime->time_next_fire - now);
	if (peer->timer_ConnectRetry->time_next_fire <= 0)
	    uii_add_bulk_output (uii, "  ConnectRetry Off\n");
	else
	    uii_add_bulk_output (uii, "  ConnectRetry %d\n",
			   peer->timer_ConnectRetry->time_next_fire - now);
	uii_add_bulk_output (uii, 
		"    Packets Recv %d  Updates Recv %d  Notifications Recv %d\n",
		     peer->num_packets_recv, peer->num_updates_recv,
		     peer->num_notifications_recv);
	uii_add_bulk_output (uii, 
		"    Packets Sent %d  Updates Sent %d  Notifications Sent %d\n",
		     peer->num_packets_sent, peer->num_updates_sent,
		     peer->num_notifications_sent);
	uii_add_bulk_output (uii, 
		"    Connections Established %d  Connections dropped %d\n",
		     peer->num_connections_established, 
		     peer->num_connections_dropped);

}
        pthread_mutex_unlock (&peer->mutex_lock);
    }
    pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
    return (1);
}


/* bgp_debug
 * set the debug flags or file for BGP
 * called by config routines
 */
int 
bgp_debug (uii_connection_t * uii, int opt_num, char *s)
{
    char *token, *arg = s;

    pthread_mutex_lock (&BGP->mutex_lock);
    /* get flag */
    if (opt_num == 0 || (token = uii_parse_line (&s)) == NULL) {
        set_trace (BGP->trace, TRACE_FLAGS, TR_ALL, NULL);
    }
    else {
        u_long flag;

        if ((flag = trace_flag (token)) == 0) {
            config_notice (TR_ERROR, uii, "unknown debug option\n");
	    Delete (arg);
	    return (-1);
	}
        set_trace (BGP->trace, TRACE_FLAGS, flag, NULL);

        /* get file name (OPTIONAL) */
        if ((token = uii_parse_line (&s)) == NULL) {
	    Delete (arg);
	    return (1);
        }
        set_trace (BGP->trace, TRACE_LOGFILE, token, NULL);
    }
    pthread_mutex_unlock (&BGP->mutex_lock);
    return (1);
}


int 
trace_bgp (uii_connection_t * uii)
{
    pthread_mutex_lock (&BGP->mutex_lock);
    if (uii->negative)
        set_trace (BGP->trace, TRACE_DEL_FLAGS, TR_ALL, NULL);
    else
        set_trace (BGP->trace, TRACE_ADD_FLAGS, TR_ALL, NULL);
    pthread_mutex_unlock (&BGP->mutex_lock);
    return (1);
}


static buffer_t *
bgp_make_tail (uii_connection_t *uii, bgp_attr_t *attr, buffer_t *buffer)
{
/* I need to change ipma stuff that depends on route format */
#if 0
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_METRIC)) {
	buffer_printf (buffer, "%6ld", attr->multiexit);
    }
    else {
	buffer_printf (buffer, "%6s", "");
    }
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_LOCALPREF)) {
	buffer_printf (buffer, " %6ld", attr->local_pref);
    }
    else {
	buffer_printf (buffer, " %6s", "");
    }
    buffer_printf (buffer, " %6d ", weight); /* XXX */
#endif
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH)) {
	char *data = buffer->data;
	int l;

	buffer_printf (buffer, "%A", attr->aspath);
	if ((l = strlen (data)) > 0) {
	    /* check to see if it's null as path */
	    buffer_putc (' ', buffer);
	}
    }
    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGIN)) {
	buffer_putc (origin2char (attr->origin), buffer);
    }
    buffer_putc ('\0', buffer);
    return (buffer);
}


static void
bgp_put_a_line (uii_connection_t *uii, bgp_route_t *route, time_t now)
{
    buffer_t *buffer = New_Buffer (0);
    int c1, c2;

    c1 = (route == route->head->active) ? '>' : '*';
    c1 = BIT_TEST (route->head->state_bits, VRTS_SUPPRESS)? 's': c1;
    c1 = bgp_nexthop_avail (route->attr)? c1: 'x';
    c1 = BIT_TEST (route->head->state_bits, VRTS_DELETE)? 'D': c1;

    bgp_make_tail (uii, route->attr, buffer);

    c2 = BIT_TEST (route->attr->options, BGP_PEER_SELF)? 'l': c2;
    c2 = BIT_TEST (route->attr->options, BGP_EBGP_MULTIHOP)? 'm': c2;
    c2 = BIT_TEST (route->flags, BGP_RT_AGGREGATED)? 'a': c2;

    rib_show_route_line (uii, c1, c2, route->attr->type, 
			 0, now - route->time,
			 route->head->prefix, 
			 route->attr->nexthop->prefix,
/* (route->attr->link_local)? route->attr->link_local: route->attr->nexthop, */
			 (route->attr->gateway)? 
				route->attr->gateway->interface: NULL, 
			  buffer->data);
    Delete_Buffer (buffer);
}


/* 
 * dump BGP routes to socket. usually called by UII
 */
static void
bgp_dump_view_int (uii_connection_t *uii, view_t *view, int family,
	           as_regexp_code_t *code, bgp_peer_t *peer, condition_t *cond)
{
    bgp_route_head_t *route_head;
    bgp_route_t *route;
    time_t now;
    int pass;
    int num_route_heads = 0;
    int num_route_nodes = 0;

    if (view == NULL)
	return;
    if (peer && !BITX_TEST (&peer->view_mask, view->viewno))
	return;
    if (family > 0 && family != afi2family (view->afi))
	return;

    /* pass 1 counts the number, pass 2 displays */
    for (pass = 1; pass <= 2; pass++) {

	if (pass == 2) {

	    if (num_route_heads == 0 && num_route_nodes == 0)
		continue;

    	    uii_add_bulk_output (uii, "\n");
            if (peer) {
                uii_add_bulk_output (uii, 
			"Peer %a View #%d heads %d nodes %d\n", 
		         peer->peer_addr, view->viewno,
			 num_route_heads, num_route_nodes);
    	    }
    	    else {
        	uii_add_bulk_output (uii, "View #%d %s %s heads %d nodes %d\n",
		   	view->viewno, afi2string (view->afi), 
		   	safi2string (view->safi),
		   	num_route_heads, num_route_nodes);
	    }
    	    uii_add_bulk_output (uii, "Status code: "
		    "s suppressed, * valid, > best, i - internal, "
		    "a - aggregate, x - no next-hop\n");
    	    uii_add_bulk_output (uii, "Origin codes: "
		    "i - IGP, e - EGP, ? - incomplete, a - aggregate\n");
    	    uii_add_bulk_output (uii, "\n");
#if 0
    	    rib_show_route_head (uii, "Metric LocPrf Weight Path");
#else
    	    rib_show_route_head (uii, "Path");
#endif

    	    time (&now);
	}

    	VIEW_RADIX_WALK (view, route_head) {

	    /* can not use continue in RADIX_WALK macro */
	    if (BIT_TEST (route_head->state_bits, VRTS_DELETE))
	    	goto skip;

	    if (peer) {
	    	/* show only active one */
		if ((route = route_head->active) != NULL &&
	    	    (cond == NULL || 
			apply_condition (cond, route_head->prefix) > 0)) {

		    if (BITX_TEST (&route_head->peer_mask, peer->index)) {
			if (pass == 1) {
			    num_route_heads++;
			    num_route_nodes++;
			}
			else {
			    bgp_put_a_line (uii, route, now);
			    if (cond) {
		    	        bgp_uii_attr (uii, route->attr);
			    }
			}
		    }
		}
	    }
	    else {
    		if (cond == NULL || 
		        apply_condition (cond, route_head->prefix) > 0) {
		    int match = 0;

		    LL_Iterate (route_head->ll_imported, route) {

	    		if (code && as_regexp_exec (code, NULL) < 0)
			    continue;

			if (pass == 1) {
			    if (match++ == 0)
			        num_route_heads++;
			    num_route_nodes++;
			}
			else {
	    		    bgp_put_a_line (uii, route, now);
			}
		    }

		    LL_Iterate (route_head->ll_routes, route) {

	    	        if (BGP4_BIT_TEST (route->attr->attribs, 
					   PA4_TYPE_ASPATH)) {
			    if (code && as_regexp_exec (code, 
					route->attr->aspath) < 0)
		    		continue;
	    		}
	    	        else {
			    if (code && as_regexp_exec (code, NULL) < 0)
		    	    	continue;
	    	    	}
			if (pass == 1) {
			    if (match++ == 0)
			        num_route_heads++;
			    num_route_nodes++;
			}
			else {
	    	    	    bgp_put_a_line (uii, route, now);
	    	    	    if (cond) {
				bgp_uii_attr (uii, route->attr);
	    	    	    }
			}
		    }
   		}
	    }
      skip: while (0);
        } VIEW_RADIX_WALK_END;
    }
}


static void
bgp_dump_view (uii_connection_t *uii, int viewno, int family,
	       as_regexp_code_t *code, bgp_peer_t *peer, condition_t *cond)
{
    view_t *view;

    if (viewno < 0) {
        for (viewno = 0; viewno < MAX_BGP_VIEWS; viewno++) {
            if ((view = BGP->views[viewno]) == NULL)
		continue;
	    if (peer && !BITX_TEST (&peer->view_mask, viewno))
		continue;
	    if (family > 0 && family != afi2family (view->afi))
		continue;
	    bgp_dump_view (uii, viewno, family, code, peer, cond);
	}
	return;
    }

    view = BGP->views[viewno];
    if (view == NULL)
	return;
    if (peer && !BITX_TEST (&peer->view_mask, viewno))
	return;
    if (family > 0 && family != afi2family (view->afi))
	return;
    view_open (view);
    bgp_dump_view_int (uii, view, family, code, peer, cond);
    view_close (view);
}


void
dump_text_bgp_view (uii_connection_t *uii, view_t *view)
{
    bgp_dump_view_int (uii, view, 0, NULL, NULL, NULL);
}


char *
mask2bitmap (bgp_bitset_t *ptr, int num, char *buf)
{
    int i;
    char *s = buf;

    for (i = 0; i < num; i++) {
        *s++ = (BITX_TEST (ptr, i))? '1': '0';
    }
    *s = '\0';
    return (buf);
}


/* 
 * dump BGP routes stored in route_in
 */
static void
bgp_dump_rtin (uii_connection_t *uii, int viewno, int family,
	       as_regexp_code_t *code, bgp_peer_t *peer, condition_t *cond)
{
    time_t now;
    int afi, safi;
    int pass;
    bgp_local_t *local_bgp;

    if (peer == NULL) {
        pthread_mutex_lock (&BGP->locals_mutex_lock);
        LL_Iterate (BGP->ll_bgp_locals, local_bgp) {
            pthread_mutex_lock (&local_bgp->peers_mutex_lock);
            LL_Iterate (local_bgp->ll_bgp_peers, peer) {
		bgp_dump_rtin (uii, viewno, family, code, peer, cond);
	    }
            pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
	}
        pthread_mutex_unlock (&BGP->locals_mutex_lock);
	return;
    }

    time (&now);
    assert (peer);

    for (afi = 0; afi < AFI_MAX; afi++) {

	if (family && afi != family2afi (family))
	    continue;

	for (safi = 0; safi < SAFI_MAX; safi++) {
            bgp_route_in_t *route_in;
            radix_tree_t *radix_tree;
            radix_node_t *radix_node;
	    int count = 0;

	    radix_tree = peer->routes_in[afi][safi];
	    if (radix_tree == NULL)
		continue;

	for (pass = 1; pass <= 2; pass++) {

	    if (pass == 2) {
		if (count <= 0)
		    continue;
		uii_add_bulk_output (uii, "\n");
                uii_add_bulk_output (uii, 
			"Peer %a %s %s %d routes\n", 
		         peer->peer_addr, afi2string (afi),
                         safi2string (safi), count);
		if (viewno >= 0)
    	            rib_show_route_head (uii, "Path");
		else
    	            rib_show_route_head (uii, "Views (0..16)");
	    }

            RADIX_WALK (radix_tree->head, radix_node) {

    		if (cond != NULL &&
		        apply_condition (cond, radix_node->prefix) <= 0) {
		    goto skip;
		}

                route_in = RADIX_DATA_GET (radix_node, bgp_route_in_t);
	    	if (BGP4_BIT_TEST (route_in->attr->attribs, PA4_TYPE_ASPATH)) {
		    if (code && as_regexp_exec (code, 
					route_in->attr->aspath) < 0)
		    	goto skip;
	    	    else {
		        if (code && as_regexp_exec (code, NULL) < 0)
		    	    goto skip;
		    }
		}
		if (viewno >= 0) {
		    /* skip if accepted */
		    if (BITX_TEST (&route_in->view_mask, viewno))
			goto skip;
		}

		if (pass == 1) {
		    count++;
		}
		else {
		    if (viewno >= 0) {
			buffer_t *buffer = New_Buffer (0);

			bgp_make_tail (uii, route_in->attr, buffer);
    		        rib_show_route_line (uii, ' ', ' ', 
					     route_in->attr->type, 
			 		     0, now - route_in->time,
			 		     radix_node->prefix, 
			 		     route_in->attr->nexthop->prefix,
			 		     (route_in->attr->gateway)? 
				         route_in->attr->gateway->interface: 
					     NULL, buffer->data);
			Delete_Buffer (buffer);
		    }
		    else {
		        char buf[MAX_BGP_VIEWS + 1];
		        mask2bitmap (&route_in->view_mask, 
			             16 /* MAX_BGP_VIEWS */, buf);
    		        rib_show_route_line (uii, ' ', ' ', 
					     route_in->attr->type, 
			 		     0, now - route_in->time,
			 		     radix_node->prefix, 
			 		     route_in->attr->nexthop->prefix,
			 		     (route_in->attr->gateway)? 
				         route_in->attr->gateway->interface: 
					     NULL, buf);
		    }
	       	    if (cond) {
		        bgp_uii_attr (uii, route_in->attr);
	       	    }
		}
	skip: while (0);
            } RADIX_WALK_END;
	}
	}
    }
}


/* show_bgp_routing table
 * dump BGP routes to socket. usually called by UII
 */
int 
show_f_bgp_rt_view_regexp (uii_connection_t * uii, int family, int viewno, 
			   char *expr, char *filtered)
{
    as_regexp_code_t *code = NULL;
    int pos = 0;

    if (viewno > MAX_BGP_VIEWS) {
	Delete (expr);
	Delete (filtered);
	return (-1);
    }

    if (expr) {
	if ((code = as_regexp_comp (expr, &pos)) == NULL) {
    	    uii_add_bulk_output (uii, "%s\n", expr);
    	    uii_add_bulk_output (uii, "%*c\n", pos, '^');
	    Delete (expr);
	    Delete (filtered);
	    return (-1);
	}
        Delete (expr);
    }

    if (filtered)
        bgp_dump_rtin (uii, viewno, family, code, NULL, NULL);
    else
        bgp_dump_view (uii, viewno, family, code, NULL, NULL);

    Delete (filtered);
    Delete (code);
    uii_send_bulk_data (uii);
    return (1);
}


int 
get_first_view (int afi, int safi)
{
    int viewno;

    for (viewno = 0; viewno < MAX_BGP_VIEWS; viewno++) {
	if (BGP->views[viewno] == NULL)
	    continue;
	if (afi > 0 && BGP->views[viewno]->afi != afi)
	    continue;
	if (safi > 0 && BGP->views[viewno]->safi != safi)
	    continue;
	return (viewno);
    }
    return (-1);
}


/* 
 * show BGP routes to match
 */
int 
show_bgp_rt_view_prefix (uii_connection_t * uii, int viewno, prefix_t *prefix, 
		         char *options, char *filtered)
{
    condition_t *condition;
    int permit = 1, refine = 0, exact = 0;
    prefix_t *wildcard = NULL;
    int family = 0;

    if (viewno > MAX_BGP_VIEWS) {
	Deref_Prefix (prefix);
	Delete (options);
	Delete (filtered);
	return (-1);
    }
    if (options) {
	get_alist_options (options, &wildcard, &refine, &exact);
        Delete (options);
    }
    condition = New (condition_t);
    condition->permit = permit;
    /* expects Ref_Prefix can handle even a case of prefix == NULL */
    condition->prefix = prefix;
    condition->wildcard = wildcard;
    condition->exact = exact;
    condition->refine = refine;

    if (prefix)
	family = prefix->family;

    if (filtered)
        bgp_dump_rtin (uii, viewno, family, NULL, NULL, condition);
    else
        bgp_dump_view (uii, viewno, family, NULL, NULL, condition);

    Deref_Prefix (prefix);
    Deref_Prefix (wildcard);
    Delete (condition);
    Delete (filtered);
    uii_send_bulk_data (uii);
    return (1);
}


#ifdef notdef
/* bgp_get_attr
 * attribute are stored in global hash. This 
 * 1) fetches attr if exists 
 * 2) or creates new attr
 */
bgp_attr_t *
bgp_get_attr (bgp_attr_t * attr)
{
    bgp_attr_t *tmpx;

    tmpx = HASH_Lookup (BGP->attr_hash, attr);

    if (tmpx == NULL) {
	HASH_Insert (BGP->attr_hash, bgp_ref_attr (attr));
	tmpx = attr;
    }

    return (tmpx);
}
#endif


int
show_f_bgp_neighbors_errors (uii_connection_t * uii, int family, 
			     char *peer_or_star)
{
    bgp_local_t *local_bgp;
    bgp_peer_t *peer;

    if (strcmp (peer_or_star, "*") != 0) {
	prefix_t *prefix = ascii2prefix (0, peer_or_star);
	/* XXX this happens due to a bug */
	if (prefix == NULL) {
	    if ((peer = Find_BGP_Peer_ByID (NULL, peer_or_star)) != NULL) {
		print_error_list (uii, peer->trace);
	    }
	    else {
                config_notice (TR_ERROR, uii, "Peer %s does not exist\n",
			       peer_or_star);
	        Delete (peer_or_star);
	        return (-1);
	    }
	}
        else if ((peer = Find_BGP_Peer (NULL, prefix, 0, 0)) == NULL) {
            config_notice (TR_ERROR, uii, "Peer %s does not exist\n",
		prefix_toa (prefix));
            Deref_Prefix (prefix);
	    Delete (peer_or_star);
            return (-1);
        }
	else {
	    print_error_list (uii, peer->trace);
            Deref_Prefix (prefix);
	}
    }
    else {
        pthread_mutex_lock (&BGP->locals_mutex_lock);
        LL_Iterate (BGP->ll_bgp_locals, local_bgp) {
	    pthread_mutex_lock (&local_bgp->peers_mutex_lock);
            LL_Iterate (local_bgp->ll_bgp_peers, peer) {
	        if (peer->peer_addr == NULL)
		    continue;
	        if (family != 0 && peer->peer_addr->family != family)
		    continue;
	        print_error_list (uii, peer->trace);
	    }
	    pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
	}
        pthread_mutex_unlock (&BGP->locals_mutex_lock);
    }

    Delete (peer_or_star);
    return (1);
}


int
show_f_bgp_neighbors_routes (uii_connection_t * uii, int family, 
			     int viewno, char *peer_or_star, char *option)
{
    bgp_peer_t *peer;
    bgp_local_t *local_bgp = NULL;

    if (viewno > MAX_BGP_VIEWS) {
	Delete (peer_or_star);
	Delete (option);
	return (-1);
    }

    if (viewno >= 0) {
        view_t *view = BGP->views[viewno];
        if (view == NULL)
	    return (0);
	local_bgp = view->local_bgp;
    }

    if (strcmp (peer_or_star, "*") != 0) {
	prefix_t *prefix = ascii2prefix (0, peer_or_star);
	/* XXX this happens due to a bug */
        if (local_bgp)
            pthread_mutex_lock (&local_bgp->peers_mutex_lock);

	if (prefix == NULL) {
	    if ((peer = Find_BGP_Peer_ByID (local_bgp, peer_or_star)) != NULL) {
	        if (option)
	            bgp_dump_rtin (uii, viewno, family, NULL, peer, NULL);
	        else
	            bgp_dump_view (uii, viewno, family, NULL, peer, NULL);
	    }
	    else {
                config_notice (TR_ERROR, uii, "Peer %s does not exist\n",
			       peer_or_star);
	        Delete (peer_or_star);
    		if (local_bgp)
		    pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
    		Delete (option);
	        return (-1);
	    }
	}
        else if ((peer = Find_BGP_Peer (local_bgp, prefix, 0, 0)) == NULL) {
            config_notice (TR_ERROR, uii, "Peer %a does not exist\n", prefix);
	    Deref_Prefix (prefix);
	    Delete (peer_or_star);
  	    if (local_bgp)
		pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
    	    Delete (option);
            return (-1);
	}
	else {
	    if (option)
	        bgp_dump_rtin (uii, viewno, family, NULL, peer, NULL);
	    else
	        bgp_dump_view (uii, viewno, family, NULL, peer, NULL);
            Deref_Prefix (prefix);
	}
  	if (local_bgp)
	    pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
    }
    else if (local_bgp) {
	pthread_mutex_lock (&local_bgp->peers_mutex_lock);
        LL_Iterate (local_bgp->ll_bgp_peers, peer) {
	    if (peer->peer_addr == NULL)
		continue;
	    /* XXX DEADLOCK MAY HAPPEN */
	    if (option)
	        bgp_dump_rtin (uii, viewno, family, NULL, peer, NULL);
	    else
	        bgp_dump_view (uii, viewno, family, NULL, peer, NULL);
	}
	pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
    }
    else {
        pthread_mutex_lock (&BGP->locals_mutex_lock);
        LL_Iterate (BGP->ll_bgp_locals, local_bgp) {
	    pthread_mutex_lock (&local_bgp->peers_mutex_lock);
            LL_Iterate (local_bgp->ll_bgp_peers, peer) {
	        if (peer->peer_addr == NULL)
		    continue;
	        /* XXX DEADLOCK MAY HAPPEN */
	        if (option)
	            bgp_dump_rtin (uii, viewno, family, NULL, peer, NULL);
		else
	            bgp_dump_view (uii, viewno, family, NULL, peer, NULL);
	    }
	    pthread_mutex_unlock (&local_bgp->peers_mutex_lock);
	}
        pthread_mutex_unlock (&BGP->locals_mutex_lock);
    }
    Delete (option);
    Delete (peer_or_star);
    return (1);
}


int
bgp_check_attr (bgp_peer_t * peer, bgp_attr_t * attr, int as)
{
    int peer_as;

    if (attr == NULL)
	return (0);

    assert (peer);

    if (!BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP)) {
/* XXX */
/* This is not sufficient because there could be both IPv4 and IPv6 info */
	trace (TR_ERROR, peer->trace, "attribute: nexthop missing\n");
	bgp_send_notify_byte (peer, BGP_ERR_UPDATE, BGP_ERRUPD_MISSING, 
			      PA4_TYPE_NEXTHOP);
	return (-1);
	
    }
    else {
	/* XXX should check nexthop well */

#ifdef HAVE_IPV6
	if (attr->nexthop->prefix->family == AF_INET6 && attr->link_local &&
	        peer && peer->gateway && peer->gateway->interface &&
	       (BIT_TEST (peer->gateway->interface->flags, IFF_POINTOPOINT) &&
                peer->gateway->interface->primary6 &&
                peer->gateway->interface->primary6->prefix->bitlen == 128)) {
	    trace (TR_PACKET, peer->trace, 
		   "attribute: dropping link_local of unshared link: %a\n",
		   attr->link_local->prefix);
	    deref_nexthop (attr->link_local);
	    attr->link_local = NULL;
	}
#endif /* HAVE_IPV6 */
    }

    if (!BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH)) {
	trace (TR_ERROR, peer->trace, "attribute: aspath missing\n");
	bgp_send_notify_byte (peer, BGP_ERR_UPDATE, BGP_ERRUPD_MISSING, 
			      PA4_TYPE_ASPATH);
	return (-1);
    }
    else {
	assert (peer->gateway);
        if (as != peer->gateway->AS /* eBGP */ &&
	    !BGPSIM_TRANSPARENT && /* bgpsim doesn't get thru here, though */
	    !BIT_TEST (peer->options, BGP_TRANSPARENT_AS)) {
	    if ((peer_as = bgp_get_home_AS (attr->aspath)) <= 0) {
		trace (TR_ERROR, peer->trace,
		       "attribute: no home for eBGP\n");
	        bgp_send_notification (peer, BGP_ERR_UPDATE, 
				      BGP_ERRUPD_ATTRLIST);
		return (-1);
	    }
	    else if (peer->gateway->AS != peer_as) {
		trace (TR_ERROR, peer->trace,
		       "attribute: strange home in aspath %s as %d\n",
		       aspath_toa (attr->aspath), peer->gateway->AS);
	        bgp_send_notification (peer, BGP_ERR_UPDATE, 
				      BGP_ERRUPD_ATTRLIST);
		return (-1);
	    }
	}
	if (as > 0 && bgp_check_aspath_loop (attr->aspath, as)) {
	    trace (TR_WARN, peer->trace,
		   "attribute: my own as %d in aspath %s\n",
		   as, aspath_toa (attr->aspath));
	    /* just discard */
	    return (-1);
	}
    }

    if (!BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGIN)) {
	trace (TR_ERROR, peer->trace, "attribute: origin missing\n");
	bgp_send_notify_byte (peer, BGP_ERR_UPDATE, BGP_ERRUPD_MISSING, 
			      PA4_TYPE_ORIGIN);
	return (-1);
    }

    if (BIT_TEST (peer->options, BGP_INTERNAL) &&
	    !BGP4_BIT_TEST (attr->attribs, PA4_TYPE_LOCALPREF)) {
	trace (TR_ERROR, peer->trace, "attribute: localpref missing\n");
	bgp_send_notify_byte (peer, BGP_ERR_UPDATE, BGP_ERRUPD_MISSING, 
			      PA4_TYPE_LOCALPREF);
	return (-1);
    }

    if (!BIT_TEST (peer->options, BGP_INTERNAL) && (
	    BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGINATOR_ID) ||
	    BGP4_BIT_TEST (attr->attribs, PA4_TYPE_CLUSTER_LIST))) {
	char *str;
	str = BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGINATOR_ID)?
		bgptype2string (PA4_TYPE_ORIGINATOR_ID):
		bgptype2string (PA4_TYPE_CLUSTER_LIST);
        trace (TR_ERROR, peer->trace,
               "strange attribute %s from eBGP\n", str);
    }

    if (/* BIT_TEST (peer->options, BGP_INTERNAL) && */
	    BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGINATOR_ID)) {
	u_long my_id;
    	my_id = (peer->local_bgp->this_id)? peer->local_bgp->this_id: 
					    MRT->default_id;
	if (my_id == prefix_tolong (attr->originator)) {
            char atext[64];
	    /* just ignore. don't need to send a notification */
            trace (TR_ERROR, peer->trace,
                   "originator id %a is the same as mine %s\n",
		    attr->originator,
                   inet_ntop (AF_INET, &my_id, atext, sizeof (atext)));
	    return (-1);
	}
    }

    if (/* BIT_TEST (peer->options, BGP_INTERNAL) && */
	    BGP4_BIT_TEST (attr->attribs, PA4_TYPE_CLUSTER_LIST)) {
	u_long my_cluster_id;
	DATA_PTR ptr;
    	my_cluster_id = (peer->local_bgp->cluster_id)?
				peer->local_bgp->cluster_id: MRT->default_id;
	assert (attr->cluster_list);
        LL_Iterate (attr->cluster_list, ptr) {
            char atext[64];
	    u_long id = (u_long) ptr;
            if (id == my_cluster_id) {
                trace (TR_ERROR, peer->trace,
                    "Duplicate my cluster id %s in %s",
                    inet_ntop (AF_INET, &id, atext, sizeof (atext)),
                     cluster_list_toa (attr->cluster_list));
	        /* just ignore. don't need to send a notification */
                return (-1);
	    }
        }
    }
    return (1);
}


int       
check_bgp_networks (prefix_t *prefix, int viewno)
{
    prefix_t *network;
    view_t *view = BGP->views[viewno];

    assert (view);
    assert (view->ll_networks);
    LL_Iterate (view->ll_networks, network) {
        if (a_include_b (network, prefix))
            return (1);
    }
    return (0);
}

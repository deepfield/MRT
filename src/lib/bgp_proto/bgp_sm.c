/*
 *  $Id: bgp_sm.c,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#include <mrt.h>
#include <bgp.h>


/*
 * A convenience routine that does tracing on state
 * transition.
 */
void 
bgp_change_state (bgp_peer_t * peer, int state, int event)
{
    /* this happens in case incoming overwrites outgoing */
    /* assert (peer->state != state); */

    trace (TR_STATE, peer->trace, "%s -> %s (event %s)\n",
	   sbgp_states[peer->state], sbgp_states[state], sbgp_events[event]);

    if (peer->state == BGPSTATE_ESTABLISHED)
        trace (TR_WARN, peer->trace, "Leaving Established\n");

    bgp_write_status_change (peer, state);

    if (BGP->state_change_fn)
        BGP->state_change_fn (peer, state);

    peer->state = state;
    time (&peer->time);

    if (state == BGPSTATE_ESTABLISHED) {
        trace (TR_WARN, peer->trace, "Established\n");
	if (peer->accept_socket) {
            trace (TR_STATE, peer->trace, "closing the incoming socket %d\n",
		   peer->accept_socket->sockfd);
	    close (peer->accept_socket->sockfd);
	    Deref_Prefix (peer->accept_socket->remote_prefix);
	    Deref_Prefix (peer->accept_socket->local_prefix);
	    Delete (peer->accept_socket);
	    peer->accept_socket = NULL;
	}
	/* reset exponential increase in start timer */
	timer_set_flags (peer->timer_Start, TIMER_EXPONENT_SET, 0);

	peer->num_connections_established++;


        if (BGP->peer_established_call_fn)
	    BGP->peer_established_call_fn (peer);
    }
}


static void 
bgp_sm_state_idle (bgp_peer_t * peer, int event)
{
    /* ignore all events but START event */
    if (event != BGPEVENT_START) {
	if (event == BGPEVENT_STOP)
	    return;
        trace (TR_ERROR, peer->trace, 
	       "event %s should not happen at state %s\n",
	       sbgp_events[event], sbgp_states[peer->state]);
	return;
    }

    /* set a capability to send */
    bgp_reset_cap_opt (peer);

    /* first START initiates listening */
    if (peer->listen_socket == NULL)
	bgp_start_listening (peer);

    if (peer->accept_socket) {
	/* leave from idle to accept an open */
	bgp_change_state (peer, BGPSTATE_ACTIVE, event);
	if (bgp_in_recv_open (peer) >= 0)
	    return;
    }
    if (BIT_TEST (BGP_CONNECT_PASSIVE, peer->options)) {
	/* this happens if receiving an open failed */
	if (peer->state != BGPSTATE_ACTIVE)
	    bgp_change_state (peer, BGPSTATE_ACTIVE, event);
	return;
    }

    trace (TR_STATE, peer->trace, "Attempting connection\n");
    Timer_Turn_ON (peer->timer_ConnectRetry);
    bgp_change_state (peer, BGPSTATE_CONNECT, event);
    if (bgp_start_transport_connection (peer) >= 0)
	return;
    bgp_change_state (peer, BGPSTATE_ACTIVE, BGPEVENT_OPENFAIL);
}


static void 
bgp_sm_state_connect (bgp_peer_t * peer, int event)
{
    switch (event) {
    case BGPEVENT_OPEN:
	if (!BIT_TEST (BGP_CONNECT_PASSIVE, peer->options))
	    Timer_Turn_OFF (peer->timer_ConnectRetry);
        select_add_fd_event ("bgp_get_pdu", peer->sockfd, SELECT_READ,
                             1 /* on */, peer->schedule,
			     (event_fn_t) bgp_get_pdu, 1, peer);
        select_add_fd_event ("bgp_flush_queue", peer->sockfd, SELECT_WRITE,
                             0 /* off */, peer->schedule, 
			     (event_fn_t) bgp_flush_queue, 1, peer);
	if (bgp_send_open (peer) >= 0) {
	    bgp_change_state (peer, BGPSTATE_OPENSENT, event);
            Timer_Set_Time (peer->timer_HoldTime, BGP_OPEN_TIMEOUT);
            Timer_Turn_ON (peer->timer_HoldTime);
	    return;
	}
	break;
    case BGPEVENT_OPENFAIL:
	if (!BIT_TEST (BGP_CONNECT_PASSIVE, peer->options))
	    Timer_Reset_Time (peer->timer_ConnectRetry);
	bgp_change_state (peer, BGPSTATE_ACTIVE, event);
	return;
    case BGPEVENT_CONNRETRY:
	Timer_Reset_Time (peer->timer_ConnectRetry);
	if (bgp_start_transport_connection (peer) >= 0)
	    return;
	bgp_change_state (peer, BGPSTATE_ACTIVE, event);
	return;
    case BGPEVENT_START:
	return;			/* do nothing */
    default:
	break;
    }
    bgp_change_state (peer, BGPSTATE_IDLE, event);
    bgp_peer_dead (peer);
    Timer_Turn_ON (peer->timer_Start);
}


static void 
bgp_sm_state_active (bgp_peer_t * peer, int event)
{
    switch (event) {
    case BGPEVENT_OPEN:
	if (!BIT_TEST (BGP_CONNECT_PASSIVE, peer->options))
	    Timer_Turn_OFF (peer->timer_ConnectRetry);
        select_add_fd_event ("bgp_get_pdu", peer->sockfd, SELECT_READ,
                             1 /* on */, peer->schedule, 
			     (event_fn_t) bgp_get_pdu, 1, peer);
        select_add_fd_event ("bgp_flush_queue", peer->sockfd, SELECT_WRITE,
                             0 /* off */, peer->schedule, 
			     (event_fn_t) bgp_flush_queue, 1, peer);
	if (bgp_send_open (peer) >= 0) {
	    bgp_change_state (peer, BGPSTATE_OPENSENT, event);
            Timer_Set_Time (peer->timer_HoldTime, BGP_OPEN_TIMEOUT);
            Timer_Turn_ON (peer->timer_HoldTime);
	    return;
	}
	break;
    case BGPEVENT_OPENFAIL:
	if (!BIT_TEST (BGP_CONNECT_PASSIVE, peer->options))
	    Timer_Reset_Time (peer->timer_ConnectRetry);
	break;
    case BGPEVENT_CONNRETRY:
	Timer_Reset_Time (peer->timer_ConnectRetry);
        bgp_change_state (peer, BGPSTATE_CONNECT, event);
	if (bgp_start_transport_connection (peer) >= 0)
	    return;
	break;
    case BGPEVENT_START:
	return;			/* do nothing */
    default:
	break;
    }
    bgp_change_state (peer, BGPSTATE_IDLE, event);
    bgp_peer_dead (peer);
    Timer_Turn_ON (peer->timer_Start);
}


static void
bgp_update_peer_options (bgp_peer_t *peer)
{
    assert (peer);
    if (peer->code == BGP_ERR_OPEN) {
	if (peer->subcode == BGP_ERROPN_OPTPARAM) {
	    if (!BIT_TEST (peer->options, BGP_DONTSEND_CAPABILITY)) {
	        BIT_SET (peer->options, BGP_DONTSEND_CAPABILITY);
                trace (TR_INFO, peer->trace,
                       "will not send a capability again\n");
	    }
	}
	if (peer->subcode == BGP_ERROPN_CAPABILITY) {
	    /* XXX no fall-backs for now */
	    if (!BIT_TEST (peer->options, BGP_DONTSEND_CAPABILITY)) {
	        BIT_SET (peer->options, BGP_DONTSEND_CAPABILITY);
                trace (TR_INFO, peer->trace,
                       "will not send a capability again\n");
	    }
	}
    }
#ifdef HAVE_IPV6
    /* Once the new version of BGP4+ packet was received,
       it stays with the version */
    if (peer->code == BGP_ERR_UPDATE 
	    && peer->subcode == BGP_ERRUPD_OPTATTR) {
	if (BIT_TEST (peer->options, BGP_BGP4PLUS_AUTO)) {
           if (!BIT_TEST (peer->options, BGP_BGP4PLUS_01)) {
		BIT_SET (peer->options, BGP_BGP4PLUS_01);
            	trace (TR_INFO, peer->trace, 
		       "version changed from 0 to 1\n");
	    }
	    else if (!BIT_TEST (peer->options, BGP_BGP4PLUS_01_RCVD)) {
		BIT_RESET (peer->options, BGP_BGP4PLUS_01);
            	trace (TR_INFO, peer->trace, 
			"version changed from 1 to 0\n");
	    }
	}
    }
#endif /* HAVE_IPV6 */
}


static void 
bgp_sm_state_opensent (bgp_peer_t * peer, int event)
{
    switch (event) {
    case BGPEVENT_RECVOPEN:
	/* if OPEN is good */
	if (bgp_process_open (peer) >= 0) {
	    Timer_Turn_ON (peer->timer_KeepAlive);
	    if (bgp_send_keepalive (peer) >= 0) {
	        /* bgp_process_open set holdtime */
	        Timer_Reset_Time (peer->timer_HoldTime);
	        bgp_change_state (peer, BGPSTATE_OPENCONFIRM, event);
	        return;
	    }
	}
	/* OPEN was bad */
	/* notification already sent */
	break;
    case BGPEVENT_CLOSED:
	/* close transport connection */
	if (peer->sockfd >= 0) {
	    select_delete_fdx (peer->sockfd);
	    peer->sockfd = -1;
	}
	/* I think holdtimer is running */
	Timer_Turn_OFF (peer->timer_HoldTime);
	if (!BIT_TEST (BGP_CONNECT_PASSIVE, peer->options))
	    Timer_Reset_Time (peer->timer_ConnectRetry);
	bgp_change_state (peer, BGPSTATE_ACTIVE, event);
	return;
    case BGPEVENT_HOLDTIME:
	bgp_send_notification (peer, BGP_ERR_HOLDTIME, 0);
	break;
    /* I think BGPEVENT_RECVNOTIFY is needed (no in RFC) */
    case BGPEVENT_RECVNOTIFY:
	bgp_update_peer_options (peer);
	break;
    case BGPEVENT_STOP:
	bgp_send_notification (peer, BGP_CEASE, 0);
	break;
    case BGPEVENT_START:
	return;			/* do nothing */
    default:
	bgp_send_notification (peer, BGP_ERR_FSM, 0);
	break;
    }
    bgp_change_state (peer, BGPSTATE_IDLE, event);
    bgp_peer_dead (peer);
    Timer_Turn_ON (peer->timer_Start);
}


static void 
bgp_sm_state_openconfirm (bgp_peer_t * peer, int event)
{
    switch (event) {
    case BGPEVENT_RECVKEEPALIVE:
	/* holdtime has been updated on reception of open message */
	Timer_Reset_Time (peer->timer_HoldTime);
	bgp_change_state (peer, BGPSTATE_ESTABLISHED, event);
	bgp_establish_peer (peer, 1, -1); /* send initial routes */
	return;
    case BGPEVENT_HOLDTIME:
	bgp_send_notification (peer, BGP_ERR_HOLDTIME, 0);
	break;
    case BGPEVENT_RECVNOTIFY:
	bgp_update_peer_options (peer);
	break;
    case BGPEVENT_KEEPALIVE:
	if (bgp_send_keepalive (peer) >= 0)
	    return;
	break;
    case BGPEVENT_CLOSED:
	break;
    case BGPEVENT_STOP:
	bgp_send_notification (peer, BGP_CEASE, 0);
	break;
    case BGPEVENT_START:
	return;			/* do nothing */
    default:
	bgp_send_notification (peer, BGP_ERR_FSM, 0);
	break;
    }
    bgp_change_state (peer, BGPSTATE_IDLE, event);
    bgp_peer_dead (peer);
    Timer_Turn_ON (peer->timer_Start);
}


static void 
bgp_sm_state_established (bgp_peer_t * peer, int event)
{
    switch (event) {
    case BGPEVENT_RECVKEEPALIVE:
	/* zero timer never starts */
	Timer_Reset_Time (peer->timer_HoldTime);
	return;
    case BGPEVENT_RECVUPDATE:
	Timer_Reset_Time (peer->timer_HoldTime);
	if (bgp_process_update (peer) >= 0)
	    return;
	/* notification has been sent */
	break;
    case BGPEVENT_RECVNOTIFY:
	bgp_update_peer_options (peer);
	break;
    case BGPEVENT_CLOSED:
	break;
    case BGPEVENT_HOLDTIME:
	bgp_send_notification (peer, BGP_ERR_HOLDTIME, 0);
	break;
    case BGPEVENT_KEEPALIVE:
	if (bgp_send_keepalive (peer) >= 0)
	    return;
	break;
    case BGPEVENT_STOP:
	bgp_send_notification (peer, BGP_CEASE, 0);
	break;
    case BGPEVENT_START:
	return;			/* do nothing */
    default:
	break;
    }

    peer->num_connections_dropped++;

    bgp_change_state (peer, BGPSTATE_IDLE, event);
    bgp_peer_down (peer);
    bgp_peer_dead (peer);
    /* kick start timer here instead of inside bgp_change_state()
       because bgp_peer_dead() will clear the fire in the schedule queue 
       in case bgp_peer_down() takes long time */
    Timer_Turn_ON (peer->timer_Start);
}


void 
bgp_sm_process_event (bgp_peer_t * peer, int event)
{
    assert (peer);

    switch (peer->state) {
    case BGPSTATE_IDLE:
	bgp_sm_state_idle (peer, event);
	break;
    case BGPSTATE_ACTIVE:
	bgp_sm_state_active (peer, event);
	break;
    case BGPSTATE_CONNECT:
	bgp_sm_state_connect (peer, event);
	break;
    case BGPSTATE_OPENSENT:
	bgp_sm_state_opensent (peer, event);
	break;
    case BGPSTATE_OPENCONFIRM:
	bgp_sm_state_openconfirm (peer, event);
	break;
    case BGPSTATE_ESTABLISHED:
	bgp_sm_state_established (peer, event);
	break;
    default:
	assert (0);
	break;
    }
}

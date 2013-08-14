/*
 * $Id: srsvp.c,v 1.1.1.1 2000/08/14 18:46:14 labovit Exp $
 */

#include "ricd.h"
#include "config_file.h"

static void srsvp_neighbor_down (srsvp_t *srsvp, srsvp_neighbor_t *neighbor);
static void srsvp_neighbor_start (srsvp_t *srsvp, srsvp_neighbor_t *neighbor);
static int srsvp_process_pdu (srsvp_t *srsvp, srsvp_neighbor_t *neighbor);
static srsvp_neighbor_t *srsvp_create_neighbor2 (srsvp_t *srsvp, 
			prefix_t *prefix, interface_t *interface, int routerf);
static int srsvp_resolv_upstream (srsvp_t *srsvp, srsvp_flow_t *flow);
static int srsvp_i_am_sender (srsvp_t *srsvp, srsvp_flow_t *flow);
static void srsvp_destroy_flow (srsvp_t *srsvp, srsvp_flow_t *flow);
static void srsvp_destroy_leaf (srsvp_t *srsvp, srsvp_leaf_t *leaf);
static char *srsvp_error_spec_string (u_long errcode, char *text);
static srsvp_flow_t *srsvp_flow_find (srsvp_t *srsvp, srsvp_flow_t *flow);
static srsvp_flow_t *srsvp_flow_copy_add (srsvp_t *srsvp, srsvp_flow_t *flow);
static srsvp_neighbor_t *srsvp_get_upstream (srsvp_t *srsvp, prefix_t *sender, 
					     req_qos_t *req_qos,
		    			     u_long *errcode_p);


static char *srsvp_pdus[] = {
    "",
    "PATH",
    "RESV",
    "PATH_ERR",
    "RESV_ERR",
    "PATH_TEAR",
    "RESV_TEAR",
};



req_qos_t *
copy_req_qos (req_qos_t *src, req_qos_t *dst)
{
    assert (src);
    if (src == NULL)
	return (NULL);
    if (dst == NULL) {
	dst = New (req_qos_t);
    }
    *dst = *src;
    return (dst);
}


static void
srsvp_notify_hqlip (srsvp_t *srsvp, srsvp_flow_t *flow, srsvp_leaf_t *leaf,
		    int on)
{
   hqlip_t *hqlip = RICD->hqlip;
   srsvp_interface_t *vif;
   req_qos_t *req_qos;

#ifdef HAVE_IPV6
    if (srsvp->family == AF_INET6)
	hqlip = RICD6->hqlip;
#endif /* HAVE_IPV6 */

    assert (leaf->neighbor);
    vif = leaf->neighbor->vif;
    req_qos = copy_req_qos (leaf->req_qos, NULL);
    schedule_event2 ("hqlip_link_status",
                     hqlip->schedule,
                     (event_fn_t) hqlip_link_status,
                     4, hqlip, req_qos, vif->interface, on);
}


static void
trace_flow (u_long flags, trace_t *tr, srsvp_flow_t *flow, char *header)
{
    if (flow == NULL)
	return;
    trace (flags, tr,
	   "%s flow %a proto %d port %d sender %a sport %d\n", header,
	   flow->destin, flow->proto, flow->dport, flow->sender, 
	   flow->sport);
}


static void
trace_neighbor (u_long flags, trace_t *tr, srsvp_neighbor_t *neighbor, 
		char *header)
{
    if (neighbor == NULL)
	return;
    trace (flags, tr,
	   "%s %a lih %d on %s\n", header,
	    neighbor->prefix, neighbor->lih, neighbor->vif->interface->name);
}


static void
trace_req_qos (u_long flags, trace_t *tr, req_qos_t *req_qos, char *header)
{
    if (req_qos == NULL)
	return;
    trace (flags, tr, "  %s pri %u mtu %u pps %u "
	"sec %u cd %u cf %u rdly %u rfee %u\n", header,
	req_qos->pri, req_qos->mtu, req_qos->pps, req_qos->sec,
	req_qos->cd, req_qos->cf, req_qos->rdly, req_qos->rfee);
}


static int
srsvp_write (srsvp_neighbor_t *neighbor, u_char *data, int len)
{
    int ret;

    if (neighbor->sockfd < 0)
	return (-1);
    ret = write (neighbor->sockfd, data, len);
    if (ret < 0) {
	trace (TR_ERROR, neighbor->trace,
	       "write failed %m on fd %d\n", neighbor->sockfd);
    }
    else {
	trace (TR_PACKET, neighbor->trace, "write %d bytes\n", ret);
	neighbor->num_packets_sent++;
    }
    return (ret);
}


#ifndef HAVE_LIBPTHREAD
static void
destroy_packet (packet_t *packet)
{   
    Delete (packet->data);
    Delete (packet);
}   


static int
srsvp_flush_queue (srsvp_t *srsvp, srsvp_neighbor_t * neighbor)
{   
    packet_t *packet;
    int ret;
    
    for (;;) {
        pthread_mutex_lock (&neighbor->send_mutex_lock);
        packet = LL_GetHead (neighbor->send_queue);
        if (packet == NULL) {
	    /* end of queue */
            pthread_mutex_unlock (&neighbor->send_mutex_lock);
	    return (1);
        }
        LL_RemoveFn (neighbor->send_queue, packet, NULL);
        pthread_mutex_unlock (&neighbor->send_mutex_lock);

        ret = srsvp_write (neighbor, packet->data, packet->len);
    
        if (ret == 0) {
	    /* try again */
            pthread_mutex_lock (&neighbor->send_mutex_lock);
	    LL_Prepend (neighbor->send_queue, packet);
	    select_enable_fd_mask (neighbor->sockfd, SELECT_WRITE);
            pthread_mutex_unlock (&neighbor->send_mutex_lock);
	    return (0);
        }
    	destroy_packet (packet);
	if (ret < 0)
	    return (ret);
    }
    return (0);
}   
#endif /* HAVE_LIBPTHREAD */


static int 
srsvp_send_message (srsvp_t *srsvp, srsvp_neighbor_t *neighbor, 
		    int type, u_long srbit, int len, u_char *data)
{
    int flags = 0;
    int ttl = 255; /* XXX ? */
    assert (type >= SRSVP_MSG_PATH && type <= SRSVP_MSG_RESV_TEAR);
    assert (len >= 0 && len + SRSVP_MSG_HDR_SIZE < SRSVP_MSG_SIZE);

    if (neighbor->sockfd < 0)
	return (-1);
{
#ifdef HAVE_LIBPTHREAD
    u_char msgbuf[SRSVP_MSG_SIZE];
    u_char *cp = msgbuf;
#else
    u_char *cp = NewArray (u_char, len + SRSVP_MSG_HDR_SIZE);
    packet_t *packet = New (packet_t);
    packet->data = cp;
    packet->len = len + SRSVP_MSG_HDR_SIZE;
#endif /* HAVE_LIBPTHREAD */

    MRT_PUT_BYTE ((SRSVP_MSG_VERSION << 4) | (flags & 0x0f), cp);
    MRT_PUT_BYTE (type, cp);
    MRT_PUT_SHORT (0, cp);
    MRT_PUT_BYTE (ttl, cp);
    MRT_PUT_BYTE (srbit, cp);
    MRT_PUT_SHORT (len + SRSVP_MSG_HDR_SIZE, cp); /* includes common header */
    if (len > 0)
	memcpy (cp, data, len);

#ifdef HAVE_LIBPTHREAD
    /* send it directly since I am a thread */
    return (srsvp_write (neighbor, msgbuf, len + SRSVP_MSG_HDR_SIZE));
#else
    pthread_mutex_lock (&neighbor->send_mutex_lock);
    LL_Append (neighbor->send_queue, packet);
    if (LL_GetCount (neighbor->send_queue) == 1) {
	select_enable_fd_mask (neighbor->sockfd, SELECT_WRITE);
    }
    pthread_mutex_unlock (&neighbor->send_mutex_lock);
    trace (TR_PACKET, neighbor->trace, "send %s (%d bytes) queued\n",
           srsvp_pdus[type], len + SRSVP_MSG_HDR_SIZE);
    return (0);
#endif /* HAVE_LIBPTHREAD */
}
}


static int
srsvp_read (srsvp_neighbor_t *neighbor, u_char *ptr, int len)
{
    int n;

    if (neighbor->sockfd < 0)
	return (-1);
    n = read (neighbor->sockfd, ptr, len);

    if (n < 0) {

	switch (errno) {
        case EWOULDBLOCK:
#if     defined(EAGAIN) && EAGAIN != EWOULDBLOCK
        case EAGAIN:
#endif  /* EAGAIN */
        case EINTR:
        case ENETUNREACH:
        case EHOSTUNREACH:
	    trace (TR_INFO, neighbor->trace, 
		   "READ FAILED on %d (%m) -- OKAY TO IGNORE\n",
		   neighbor->sockfd);
	    return (0);
	default:
	    trace (TR_WARN, neighbor->trace, "READ FAILED on %d (%m)\n",
		   neighbor->sockfd);
	    return (-1);
	}
    }
    else if (n == 0) {
	trace (TR_WARN, neighbor->trace, "READ FAILED on %d EOF???\n",
	       neighbor->sockfd);
	return (-1);
    }

    trace (TR_PACKET, neighbor->trace, "read %d bytes\n", n);
    return (n);
}


static int
srsvp_fill_packet (srsvp_neighbor_t *neighbor)
{
    int len, n;

    assert (neighbor);
    assert (neighbor->read_ptr >= neighbor->buffer);
    assert (neighbor->read_ptr <= 
		neighbor->buffer + sizeof (neighbor->buffer));
    assert (neighbor->start_ptr >= neighbor->buffer);
    assert (neighbor->start_ptr <= 
		neighbor->buffer + sizeof (neighbor->buffer));

    if ((len = neighbor->read_ptr - neighbor->start_ptr) == 0) {
	/* reset the pointers */
	neighbor->start_ptr = neighbor->buffer;
	neighbor->read_ptr = neighbor->buffer;
    }

    if (neighbor->buffer + sizeof (neighbor->buffer) - neighbor->read_ptr 
		< SRSVP_MSG_SIZE) {
	/* need to move them to the start to get more */
	memcpy (neighbor->buffer, neighbor->start_ptr, len);
	neighbor->start_ptr = neighbor->buffer;
	neighbor->read_ptr = neighbor->buffer + len;
    }

    if ((n = srsvp_read (neighbor, neighbor->read_ptr, SRSVP_MSG_SIZE)) < 0) {
	return (-1);
    }
    else if (n == 0) {
	return (0);
    }

    neighbor->read_ptr += n;
    assert (neighbor->read_ptr <= 
		neighbor->buffer + sizeof (neighbor->buffer));
    return (len + n);
}


static int
srsvp_get_packet (srsvp_neighbor_t *neighbor)
{
    int pdu_len, len;
    u_char *cp;

    neighbor->packet = NULL;

    /* need to be filled at least a header in buffer */
    /* check if the requested length of data already in buffer */
    if ((len = neighbor->read_ptr - neighbor->start_ptr) 
		< SRSVP_MSG_HDR_SIZE) {
	return (0);
    }

    cp = neighbor->start_ptr;
    SRSVP_PEEK_HDRLEN (pdu_len, cp);
    if (pdu_len < SRSVP_MSG_HDR_SIZE || pdu_len > SRSVP_MSG_SIZE) {
        neighbor->start_ptr = neighbor->read_ptr; /* eat up the input */
	trace (TR_WARN, neighbor->trace, "wrong message size %d\n", pdu_len);
	return (-1);
    }

    /* see if the total length packet in buffer */
    /* check if the requested length of data already in buffer */
    if (len < pdu_len) {
	return (0);
    }

    neighbor->packet = neighbor->start_ptr;
    neighbor->start_ptr += pdu_len;
    return (1);
}


static int
srsvp_get_pdu (srsvp_t *srsvp, srsvp_neighbor_t * neighbor)
{
    int ret;

    /* I know that the return value will not be used, but leave as it was */

    if ((ret = srsvp_fill_packet (neighbor)) < 0) {
	srsvp_neighbor_down (srsvp, neighbor);
	return (-1);
    }
    else if (ret == 0) {
        assert (neighbor->sockfd >= 0);
	select_enable_fd_mask (neighbor->sockfd, SELECT_READ);
	return (ret);
    }

    for (;;) {

        if ((ret = srsvp_get_packet (neighbor)) < 0) {
	    srsvp_neighbor_down (srsvp, neighbor);
	    return (-1);
        }
        else if (ret == 0) {
	    break;
        }
   
        if ((ret = srsvp_process_pdu (srsvp, neighbor)) < 0) {
	    srsvp_neighbor_down (srsvp, neighbor);
	    return (-1);
        }
    }

    if (neighbor->sockfd >= 0)
	select_enable_fd_mask (neighbor->sockfd, SELECT_READ);
    return (1);
}


static void
srsvp_connect_ready (srsvp_t *srsvp, srsvp_neighbor_t *neighbor)
{
    sockunion_t name;
    int namelen = sizeof (name);

    if (BIT_TEST (neighbor->flags, SRSVP_OPEN_IN_PROGRESS)) {
	Timer_Turn_OFF (neighbor->open_timeout);
        BIT_RESET (neighbor->flags, SRSVP_OPEN_IN_PROGRESS);
    }

    if (neighbor->sockfd < 0) {
	trace (TR_WARN, neighbor->trace,
	       "connect to %a succeeded but sockfd %d has been closed\n",
	        neighbor->prefix, neighbor->sockfd);
	return;
    }

    /* see if we are really connected */
    if (getpeername (neighbor->sockfd, (struct sockaddr *) &name, 
			&namelen) < 0) {
	trace (TR_INFO, neighbor->trace,
	       "connect to %a failed (%m)\n", neighbor->prefix);
        srsvp_neighbor_down (srsvp, neighbor);
	return;
    }

    trace (TR_INFO, neighbor->trace, "outgoing connection succeeded on %d\n",
	   neighbor->sockfd);

#ifndef HAVE_LIBPTHREAD
    socket_set_nonblocking (neighbor->sockfd, 0);
#endif /* HAVE_LIBPTHREAD */
    timer_set_flags (neighbor->open_retry, TIMER_EXPONENT_SET, 0);
    srsvp_neighbor_start (srsvp, neighbor);
}


static int
srsvp_tcp_connect (srsvp_t *srsvp, srsvp_neighbor_t *neighbor)
{
    int ret, port = SRSVP_TCP_PORT;
    int family, len;
    sockunion_t anyaddr;
    prefix_t *local = neighbor->vif->prefix;

    memset (&anyaddr, 0, sizeof (anyaddr));
    /* initiate a TCP connection */
    family = neighbor->prefix->family;
#ifdef HAVE_IPV6
    if (family == AF_INET6) {
	anyaddr.sin6.sin6_family = family;
	anyaddr.sin6.sin6_port = htons (port);
	memcpy (&anyaddr.sin6.sin6_addr, prefix_tochar (neighbor->prefix), 16);
	len = sizeof (anyaddr.sin6);
    }
    else
#endif /* HAVE_IPV6 */
    {
	anyaddr.sin.sin_family = family;
	anyaddr.sin.sin_port = htons (port);
	memcpy (&anyaddr.sin.sin_addr, prefix_tochar (neighbor->prefix), 4);
	len = sizeof (anyaddr.sin);
    }

    if ((neighbor->sockfd = socket (family, SOCK_STREAM, 0)) < 0) {
	trace (TR_ERROR, srsvp->trace, "socket open failed (%m)\n");
	return (-1);
    }

    if (local) {
	/* port will not be bound */
	if (socket_bind_port (neighbor->sockfd, family, 
			      prefix_tochar (local), 0) < 0 ) {
	    return (-1);
	}
    }

#ifndef HAVE_LIBPTHREAD
    /* always non-blocking. 
      if connect doesn't return, there is no way to resume it. */
    socket_set_nonblocking (neighbor->sockfd, 1);
#endif /* HAVE_LIBPTHREAD */

    if (BIT_TEST (neighbor->flags, SRSVP_OPEN_RETRY)) {
        BIT_RESET (neighbor->flags, SRSVP_OPEN_RETRY);
    }
    BIT_SET (neighbor->flags, SRSVP_OPEN_IN_PROGRESS);
    trace (TR_TRACE, neighbor->trace,
           "initiating connect to %a on sockfd %d\n",                        
            neighbor->prefix, neighbor->sockfd);    
    ret = connect (neighbor->sockfd, (struct sockaddr *)& anyaddr, len);
    if (ret < 0) {
	if (errno != EINPROGRESS) {
	    /* wait open timeout to delete the neighbor */
	    return (-1);
	}
	trace (TR_PACKET, srsvp->trace, "waiting on %d for write\n",
	       neighbor->sockfd);
        BIT_SET (neighbor->flags, SRSVP_OPEN_IN_PROGRESS);
	Timer_Turn_ON (neighbor->open_timeout);
	select_add_fd_event ("srsvp_connect_ready", neighbor->sockfd, 
			     SELECT_WRITE, TRUE, 
			     neighbor->schedule, srsvp_connect_ready, 
			     2, srsvp, neighbor);
	return (0);
    }
    srsvp_connect_ready (srsvp, neighbor);
    return (1);
}


static void
srsvp_open_retry (srsvp_t *srsvp, srsvp_neighbor_t *neighbor)
{
    if (srsvp_tcp_connect (srsvp, neighbor) < 0)
	Timer_Turn_ON (neighbor->open_retry);
}


static void
srsvp_neighbor_down (srsvp_t *srsvp, srsvp_neighbor_t *neighbor)
{
    if (BIT_TEST (neighbor->flags, SRSVP_NEIGHBOR_DELETED))
	return;

    if (BIT_TEST (neighbor->flags, SRSVP_OPEN_IN_PROGRESS)) {
	Timer_Turn_OFF (neighbor->open_timeout);
        BIT_RESET (neighbor->flags, SRSVP_OPEN_IN_PROGRESS);
    }
    if (BIT_TEST (neighbor->flags, SRSVP_OPEN_RETRYING)) {
        Timer_Turn_OFF (neighbor->open_retry);
        BIT_RESET (neighbor->flags, SRSVP_OPEN_RETRYING);
    }
    if (BIT_TEST (neighbor->flags, SRSVP_NEIGHBOR_CONNECTED)) {
        Timer_Turn_OFF (neighbor->keep_alive);
        BIT_RESET (neighbor->flags, SRSVP_NEIGHBOR_CONNECTED);
    }

    trace (TR_WARN, neighbor->trace, 
	   "neighbor %a on %s going down\n", 
	    neighbor->prefix, neighbor->vif->interface->name);
    time (&neighbor->utime);
    if (neighbor->sockfd >= 0) {
	select_delete_fd (neighbor->sockfd);
/*
	if (select_delete_fd (neighbor->sockfd) < 0)
	    close (neighbor->sockfd);
*/
        neighbor->sockfd = -1;
    }
#ifndef HAVE_LIBPTHREAD
    LL_Clear (neighbor->send_queue);
#endif /* HAVE_LIBPTHREAD */
    neighbor->read_ptr = neighbor->buffer;
    neighbor->start_ptr = neighbor->buffer;
    if (BIT_TEST (neighbor->flags, SRSVP_NEIGHBOR_ROUTER)) {
        if (prefix_compare_wolen (neighbor->prefix, 
		neighbor->vif->prefix) > 0) {
            BIT_SET (neighbor->flags, SRSVP_OPEN_RETRYING);
            Timer_Turn_ON (neighbor->open_retry);
	}
    }
}


static void
srsvp_keep_alive (srsvp_t *srsvp, srsvp_neighbor_t *neighbor)
{
    if (!BIT_TEST (neighbor->flags, SRSVP_NEIGHBOR_CONNECTED))
	return;

    if (neighbor->sockfd < 0)
	return;

    if (get_socket_addr (neighbor->sockfd, 0, NULL) < 0) {
        trace (TR_WARN, neighbor->trace, "not connected (%m)\n");
        srsvp_neighbor_down (srsvp, neighbor);
        return;
    }
}


static void
srsvp_open_accept (srsvp_t *srsvp, srsvp_interface_t *vif)
{
    int new_sockfd, len;
    sockunion_t remote;
    prefix_t *local_prefix = NULL, *remote_prefix;
    srsvp_neighbor_t *neighbor;
    interface_t *interface = vif->interface;
    int sockfd = vif->tcp_sockfd;
   
    if (sockfd < 0)
	return;

    len = sizeof (remote);
    if ((new_sockfd = accept (sockfd,
            (struct sockaddr *) &remote, &len)) < 0) {
        trace (TR_ERROR, srsvp->trace, "accept (%m)\n");
        select_enable_fd_mask (sockfd, SELECT_READ);
        return; 
    }
    select_enable_fd_mask (sockfd, SELECT_READ);

    remote_prefix = sockaddr_toprefix ((struct sockaddr *) &remote);
    if (remote_prefix->family != srsvp->family) {
        trace (TR_WARN, srsvp->trace,
               "recv open from %a on %s but family must be %s\n",
               remote_prefix, vif->interface->name, 
	       family2string (srsvp->family));
	Deref_Prefix (remote_prefix);
        close (new_sockfd); 
	return;
    }

    if (!BITX_TEST (&srsvp->interface_mask, interface->index)) {
	/* must not happen */
        trace (TR_ERROR, srsvp->trace, 
	       "connection from %a on %s refused (interface disabled)\n",
	        remote_prefix, interface->name);
	Deref_Prefix (remote_prefix);
        close (new_sockfd); 
        return;
    }

    if (get_socket_addr (sockfd, 0, &local_prefix) < 0) {
        trace (TR_ERROR, srsvp->trace, "getsockname (%m)\n");
	Deref_Prefix (remote_prefix);
        close (new_sockfd); 
        return;
    }
    assert (local_prefix);

    if (local_prefix == NULL || prefix_is_unspecified (local_prefix)) {
	Deref_Prefix (local_prefix);
	local_prefix = Ref_Prefix (vif->prefix);
    }
    else {
        if (!address_equal (vif->prefix, local_prefix)) {
            trace (TR_ERROR, srsvp->trace, 
	           "connection from %a to %a on %s refused "
			"(local address unknown)\n",
		    remote_prefix, local_prefix, interface->name);
	    Deref_Prefix (local_prefix);
	    Deref_Prefix (remote_prefix);
            close (new_sockfd); 
            return;
	}
    }

    if (remote_prefix->family != local_prefix->family) {
        trace (TR_ERROR, srsvp->trace, 
	       "connection from %a to %a on %s refused (family mismatch)\n",
	        remote_prefix, local_prefix, interface->name);
	Deref_Prefix (local_prefix);
	Deref_Prefix (remote_prefix);
        close (new_sockfd); 
        return;
    }
    if (address_equal (remote_prefix, local_prefix)) {
        trace (TR_ERROR, srsvp->trace, 
	       "connection from %a to %a on %s refused (myself)\n",
		remote_prefix, local_prefix, interface->name);
	Deref_Prefix (local_prefix);
	Deref_Prefix (remote_prefix);
        close (new_sockfd); 
        return;
    }

    LL_Iterate (vif->ll_neighbors, neighbor) {
	if (address_equal (neighbor->prefix, remote_prefix))
	    break;
    }
    if (neighbor == NULL) {
        trace (TR_INFO, srsvp->trace, 
	       "connection from %a to %a on %s accepted (host)\n",
		remote_prefix, local_prefix, interface->name);
	neighbor = srsvp_create_neighbor2 (srsvp, 
			Ref_Prefix (remote_prefix), interface, 0);
    }
    else {
        if (neighbor->sockfd >= 0) {
            trace (TR_ERROR, srsvp->trace, 
	           "connection from %a to %a on %s refused "
		   "(already connected)\n",
		    remote_prefix, local_prefix, interface->name);
	    Deref_Prefix (local_prefix);
	    Deref_Prefix (remote_prefix);
            close (new_sockfd); 
#ifdef notdef
	    /* probably, the existing is dead (but this is weak to atack) */
	    srsvp_neighbor_down (srsvp, neighbor);
#endif
            return;
        }

        if (BIT_TEST (neighbor->flags, SRSVP_NEIGHBOR_ROUTER)) {
            /* tcp connection must initiate from small to big */
            if (prefix_compare_wolen (remote_prefix, local_prefix) >= 0) {
                trace (TR_ERROR, srsvp->trace, 
	               "connection from %a to %a on %s refused "
		       "(reverse direction)\n",
		        remote_prefix, local_prefix, interface->name);
	        Deref_Prefix (local_prefix);
	        Deref_Prefix (remote_prefix);
                close (new_sockfd); 
                return;
            }
	}
        trace (TR_INFO, srsvp->trace, 
	       "connection from %a to %a on %s accepted (%s)\n",
		remote_prefix, local_prefix, interface->name,
		BIT_TEST (neighbor->flags, SRSVP_NEIGHBOR_ROUTER)?
		"router": "host");
    }

    neighbor->sockfd = new_sockfd;
    Deref_Prefix (local_prefix);
    Deref_Prefix (remote_prefix);

    srsvp_neighbor_start (srsvp, neighbor);
}


static srsvp_neighbor_t *
srsvp_create_neighbor2 (srsvp_t *srsvp, prefix_t *prefix, 
		        interface_t *interface, int routerf)
{
    char name[MAXLINE];
    srsvp_interface_t *vif;
    srsvp_neighbor_t *neighbor;

    if (srsvp == NULL) {
        ricd_t *ricd = RICD;
#ifdef HAVE_IPV6
        if (prefix->family == AF_INET6)
	    ricd = RICD6;
#endif /* HAVE_IPV6 */
        schedule_event2 ("srsvp_create_neighbor2",
                         ricd->srsvp->schedule,
                         (event_fn_t) srsvp_create_neighbor2,
                         4, ricd->srsvp, prefix, interface, routerf);
	return (NULL);
    }

    vif = srsvp->srsvp_interfaces[interface->index];
    if (vif == NULL) {
	Deref_Prefix (prefix);
	return (NULL);
    }

    LL_Iterate (vif->ll_neighbors, neighbor) {
	if (address_equal (neighbor->prefix, prefix))
	    break;
    }

    if (neighbor == NULL) {
        neighbor = New (srsvp_neighbor_t);
        neighbor->prefix = Ref_Prefix (prefix);
        neighbor->trace = trace_copy (srsvp->trace);
        sprintf (name, "SRSVP %s", prefix_toa (prefix));
        set_trace (neighbor->trace, TRACE_PREPEND_STRING, name, 0);
        neighbor->sockfd = -1;
        neighbor->vif = vif;
#ifndef HAVE_LIBPTHREAD
        neighbor->send_queue = LL_Create (LL_DestroyFunction, 
					  destroy_packet, 0);
#endif /* HAVE_LIBPTHREAD */
        neighbor->read_ptr = neighbor->buffer;
        neighbor->start_ptr = neighbor->buffer;
        time (&neighbor->ctime);
        time (&neighbor->utime);
        neighbor->schedule = New_Schedule (name, neighbor->trace);
        mrt_thread_create2 (name, neighbor->schedule, NULL, NULL);
        LL_Add2 (vif->ll_neighbors, neighbor);
        if (vif->prefix) {
	    if (address_equal (prefix, vif->prefix)) {
	        /* loop back */
	        vif->myself = neighbor;
	    }
        }
        else if (is_prefix_local_on (prefix, interface)) {
	    /* loop back */
	    vif->myself = neighbor;
        }

        trace (TR_PACKET, neighbor->trace,
               "created on %s as %s\n", interface->name,
		routerf? "router": "host");

    }
    else if (routerf && !BIT_TEST (neighbor->flags, SRSVP_NEIGHBOR_ROUTER)) {
        trace (TR_PACKET, neighbor->trace,
               "updated on %s as %s\n", interface->name,
		routerf? "router": "host");
    }
    BIT_RESET (neighbor->flags, SRSVP_NEIGHBOR_DELETED);

    if (routerf && !BIT_TEST (neighbor->flags, SRSVP_NEIGHBOR_ROUTER)) {
	BIT_SET (neighbor->flags, SRSVP_NEIGHBOR_ROUTER);
	if (neighbor->open_retry == NULL) {
            neighbor->open_retry = New_Timer2 ("srsvp_connect_retry", 
			       		SRSVP_OPEN_RETRY, TIMER_ONE_SHOT, 
					neighbor->schedule, 
			       		(void_fn_t)srsvp_open_retry, 
			       		2, srsvp, neighbor);
	    timer_set_flags (neighbor->open_retry, TIMER_EXPONENT);
            timer_set_flags (neighbor->open_retry, TIMER_EXPONENT_MAX,
                                            SRSVP_OPEN_RETRY_MAX);
	}
	if (neighbor->open_timeout == NULL)
            neighbor->open_timeout = New_Timer2 ("srsvp_connect_timeout", 
			       		SRSVP_OPEN_TIMEOUT, TIMER_ONE_SHOT, 
					neighbor->schedule, 
			       		srsvp_neighbor_down, 
			       		2, srsvp, neighbor);
    }
    if (neighbor->keep_alive == NULL)
        /* need to check a tcp connection peridodically */
	/* this is not needed since select() wakes up on read
	   when the connection was lost */
        neighbor->keep_alive = New_Timer2 ("srsvp_keep_alive", 
			       		SRSVP_KEEP_ALIVE, 0, 
					neighbor->schedule, 
			       		srsvp_keep_alive, 
			       		2, srsvp, neighbor);

    if (neighbor->sockfd < 0 &&
		BIT_TEST (neighbor->flags, SRSVP_NEIGHBOR_ROUTER)) {
        /* I need to know my address to compare */
        if (vif->prefix == NULL) {
	    Deref_Prefix (prefix);
	    return (neighbor);
        }
        /* tcp connection must initiate from small to big */
        if (prefix_compare_wolen (prefix, vif->prefix) > 0) {
	    srsvp_tcp_connect (srsvp, neighbor);
        }
    }
    Deref_Prefix (prefix);
    return (neighbor);
}


void
srsvp_create_neighbor (srsvp_t *srsvp, prefix_t *prefix, 
		       interface_t *interface)
{
    srsvp_create_neighbor2 (srsvp, Ref_Prefix (prefix), 
			    interface, 1);
}


void
srsvp_delete_neighbor (srsvp_t *srsvp, prefix_t *prefix, 
		       interface_t *interface)
{
    srsvp_interface_t *vif;
    srsvp_neighbor_t *neighbor;

    if (srsvp == NULL) {
        ricd_t *ricd = RICD;
        if (prefix->family == AF_INET6)
	    ricd = RICD6;
        schedule_event2 ("srsvp_delete_neighbor",
                         ricd->srsvp->schedule,
                         (event_fn_t) srsvp_delete_neighbor,
                         3, ricd->srsvp, prefix, interface);
	return;
    }
    vif = srsvp->srsvp_interfaces[interface->index];
    if (vif == NULL)
	return;

    LL_Iterate (vif->ll_neighbors, neighbor) {
	if (address_equal (neighbor->prefix, prefix))
	    break;
    }

    if (neighbor == NULL)
	return;
    if (BIT_TEST (neighbor->flags, SRSVP_NEIGHBOR_DELETED))
	return;

    if (neighbor->sockfd >= 0) {
        select_delete_fd (neighbor->sockfd);
        neighbor->sockfd = -1;
    }
    BIT_SET (neighbor->flags, SRSVP_NEIGHBOR_DELETED);

    srsvp_neighbor_down (srsvp, neighbor);
}


void 
srsvp_start (srsvp_t *srsvp)
{
}


void
srsvp_init (ricd_t *ricd)
{
    char *name = "SRSVP";

#ifdef HAVE_IPV6
    if (ricd->family == AF_INET6) {
        name = "SRSVP6";
    }
#endif /* HAVE_IPV6 */

    ricd->srsvp = New (srsvp_t);
    ricd->srsvp->trace = trace_copy (ricd->trace);
    set_trace (ricd->srsvp->trace, TRACE_PREPEND_STRING, name, 0);
    ricd->srsvp->family = ricd->family;
    ricd->srsvp->ll_srsvp_interfaces = LL_Create (0);
    memset (&ricd->srsvp->interface_mask, 0, 
		sizeof (ricd->srsvp->interface_mask));
    ricd->srsvp->schedule  = New_Schedule (name, ricd->trace);
    mrt_thread_create2 (name, ricd->srsvp->schedule, NULL, NULL);
    qif_close ();
    qif_init ();
    /* XXX where i can close it? */
}


static int
srsvp_vif_tcp_init (srsvp_t *srsvp, srsvp_interface_t *vif)
{
    int sockfd;
    u_char *bind_addr = (vif->prefix)? prefix_tochar (vif->prefix): NULL;

    if (vif->tcp_sockfd >= 0) {
	select_delete_fd (vif->tcp_sockfd);
	vif->tcp_sockfd = -1;
    }
    sockfd = socket_open (srsvp->family, SOCK_STREAM, 0);
    if (sockfd < 0)
	return (sockfd);
    socket_reuse (sockfd, 1);
    socket_bind_port (sockfd, srsvp->family, bind_addr, SRSVP_TCP_PORT);
    listen (sockfd, 5);
    vif->tcp_sockfd = sockfd;
    select_add_fd_event ("srsvp_open_accept", sockfd, 
			  SELECT_READ, TRUE, srsvp->schedule, 
			  srsvp_open_accept, 2, srsvp, vif);
    return (sockfd);
}


static void
srsvp_set_vif_prefix (srsvp_t *srsvp, srsvp_interface_t *vif, prefix_t *prefix)
{
    Deref_Prefix (vif->prefix);
    if (prefix == NULL) {
#ifdef HAVE_IPV6
	if (srsvp->family == AF_INET6)
	    vif->prefix = vif->interface->primary6->prefix;
	else
#endif /* HAVE_IPV6 */
        vif->prefix = vif->interface->primary->prefix;
    }
    else {
        vif->prefix = Ref_Prefix (prefix);
    }
}


void
srsvp_activate_interface (srsvp_t *srsvp, interface_t *interface, 
			  prefix_t *local, int on)
{
    srsvp_interface_t *vif;

    vif = srsvp->srsvp_interfaces [interface->index];

    if (on > 0 && BITX_TEST (&srsvp->interface_mask, interface->index)) {
	/* updating network */
 	assert (vif);
	if (local && !address_equal (vif->prefix, local)) {
	    srsvp_set_vif_prefix (srsvp, vif, local);
	    srsvp_vif_tcp_init (srsvp, vif);
	}
    }

    else if (on > 0 && !BITX_TEST (&srsvp->interface_mask, interface->index)) {
	/* new */
	if (vif != NULL) {
	    Deref_Prefix (vif->prefix);
	    srsvp_set_vif_prefix (srsvp, vif, local);
	}
	else {
 	    vif = New (srsvp_interface_t);
            vif->interface = interface;
            vif->ll_neighbors = LL_Create (0);
	    vif->tcp_sockfd = -1;
	    vif->qalg = 0; /* XXX */
	    vif->qlimit = -1; /* XXX */
	    srsvp->srsvp_interfaces [interface->index] = vif;
	    srsvp_set_vif_prefix (srsvp, vif, local);
	    LL_Add2 (srsvp->ll_srsvp_interfaces, vif);
	    /* add qif needs vif->prefix set */
	    qif_add_qif (srsvp, vif);
	}
	BITX_SET (&srsvp->interface_mask, interface->index);
	assert (vif->tcp_sockfd < 0);
	srsvp_vif_tcp_init (srsvp, vif);
    }
    else if (on < 0 && BITX_TEST (&srsvp->interface_mask, interface->index)) {
	qif_del_qif (srsvp, vif);
	BITX_RESET (&srsvp->interface_mask, interface->index);
	vif = srsvp->srsvp_interfaces [interface->index];
	assert (vif);
	if (vif->tcp_sockfd >= 0) {
	/* interface_mask was off, hello timer off 
		so that gracefully stopping by protocol timeout */
	    select_delete_fd (vif->tcp_sockfd);
	    vif->tcp_sockfd = -1;
	}
	Deref_Prefix (vif->prefix);
	vif->prefix = NULL;
    }
}


/* XXX called from another thread */
int
srsvp_show_neighbors (uii_connection_t *uii, char *ip, char *ifname)
{
    srsvp_interface_t *vif;
    srsvp_neighbor_t *neighbor;
    time_t now;
    interface_t *interface = NULL;
    ricd_t *ricd = RICD;
    srsvp_t *srsvp;

    if (strcasecmp (ip, "ipv6") == 0)
	ricd = RICD6;
    Delete (ip);

    if (ricd == NULL || ricd->srsvp == NULL)
	return (0);
    srsvp = ricd->srsvp;

    if (ifname) {
        interface = find_interface_byname (ifname);
        Delete (ifname);
        if (interface == NULL) {
            return (-1);
        }                            
    }                                   

    time (&now);
    uii_add_bulk_output (uii, "%-35s %7s %8s %3s %3s %11s\n",
                "Neighbor Address", "If",  "Time", "UP", "R/H", "Sent/Rcvd");
    LL_Iterate (srsvp->ll_srsvp_interfaces, vif) {

	if (interface != NULL && interface != vif->interface)
	    continue;

	if (vif->ll_neighbors == NULL || LL_GetCount (vif->ll_neighbors) == 0)
	    continue;

	LL_Iterate (vif->ll_neighbors, neighbor) {
	    char buff[64], strbuf[64] = "";

	    if (vif->myself == neighbor)
	        sprintf (strbuf, " (self)");

	    else if (BIT_TEST (neighbor->flags, SRSVP_OPEN_IN_PROGRESS))
	        sprintf (strbuf, " (connecting)");

	    else if (BIT_TEST (neighbor->flags, SRSVP_OPEN_RETRYING))
	        sprintf (strbuf, " (retry wait)");

	    else if (BIT_TEST (neighbor->flags, SRSVP_NEIGHBOR_CONNECTED))
	        sprintf (strbuf, " (connected)");

	    if (!BITX_TEST (&srsvp->interface_mask, vif->interface->index))
	        sprintf (strbuf, " (deleted)");
	        
            uii_add_bulk_output (uii, 
		    "%-35a %7s %8s %3d %3s %5d/%-5d %s\n",
		    neighbor->prefix, neighbor->vif->interface->name,
		    time2date (now - neighbor->utime, buff),
		    neighbor->num_session_up,
		    BIT_TEST (neighbor->flags, SRSVP_NEIGHBOR_ROUTER)?
			" R ": " H ",
		    neighbor->num_packets_sent, neighbor->num_packets_recv,
		    strbuf);
	}
    }
    return (1);
}


static int
srsvp_forward_msg (srsvp_t *srsvp, int type, int srbit, srsvp_flow_t *flow,
		   srsvp_neighbor_t *neighbor)
{
    u_char msgbuf[SRSVP_MSG_SIZE], *cp = msgbuf;
    int afi = family2afi (srsvp->family);
    prefix_t *rsvp_hop;
    int lih;
    int truetype = type;

    if (type == SRSVP_MSG_RESV0 || type == SRSVP_MSG_RESV1)
	truetype = SRSVP_MSG_RESV;
    assert (truetype >= SRSVP_MSG_PATH && truetype <= SRSVP_MSG_RESV_TEAR);
    trace (TR_PACKET, neighbor->trace, 
	   "preparing %s srbit 0x%x\n", srsvp_pdus[truetype], srbit);

    trace (TR_PACKET, neighbor->trace, 
	   "  session %a proto %d port %d\n", flow->destin, flow->proto, 
	    flow->dport);
    /* session class */
    MRT_PUT_SHORT (SRSVP_OBJ_HDR_SIZE + afi2plen(afi) + 4, cp);
    MRT_PUT_BYTE (SRSVP_OBJ_SESSION, cp);
    MRT_PUT_BYTE (afi, cp);
    MRT_PUT_DATA (prefix_tochar (flow->destin), afi2plen (afi), cp);
    MRT_PUT_BYTE (flow->proto, cp);
    MRT_PUT_BYTE (flow->flags & 0xff, cp);
    MRT_PUT_SHORT (flow->dport, cp);

    if (type == SRSVP_MSG_PATH || type == SRSVP_MSG_PATH_TEAR) {
	rsvp_hop = neighbor->vif->prefix;
	lih = neighbor->lih;
    }
    else {
        rsvp_hop = neighbor->prefix;
	lih = neighbor->lih;
    }
    assert (rsvp_hop);
    assert (rsvp_hop->family == srsvp->family);
    trace (TR_PACKET, neighbor->trace, 
	   "  rsvp_hop %a lih %d\n", rsvp_hop, lih);
    MRT_PUT_SHORT (SRSVP_OBJ_HDR_SIZE + afi2plen(afi) + 4, cp);
    MRT_PUT_BYTE (SRSVP_OBJ_RSVP_HOP, cp);
    MRT_PUT_BYTE (afi, cp);
    MRT_PUT_DATA (prefix_tochar (rsvp_hop), afi2plen (afi), cp);
    MRT_PUT_LONG (lih, cp);

    assert (flow->sender->family == srsvp->family);
    trace (TR_PACKET, neighbor->trace, 
	    "  sender template %a port %d\n", 
	    flow->sender, flow->sport);
    MRT_PUT_SHORT (SRSVP_OBJ_HDR_SIZE + afi2plen(afi) + 4, cp);
    MRT_PUT_BYTE (SRSVP_OBJ_SENDERT, cp);
    MRT_PUT_BYTE (afi, cp);
    MRT_PUT_DATA (prefix_tochar (flow->sender), afi2plen (afi), cp);
    MRT_PUT_BYTE (0, cp);
    MRT_PUT_BYTE (0, cp); /* XXX */
    MRT_PUT_SHORT (flow->sport, cp);

    if (type == SRSVP_MSG_RESV1 || 
		(type == SRSVP_MSG_PATH && flow->sender_tspec)) {
	req_qos_t *req_qos;
	int class;

        if (type == SRSVP_MSG_RESV1) {
	    req_qos = flow->req_qos;
	    class = SRSVP_OBJ_FLOW_SPEC;
	    trace_req_qos (TR_PACKET, neighbor->trace, req_qos, "flow-spec");
	}
	else {
	    req_qos = flow->sender_tspec;
	    class = SRSVP_OBJ_SENDER_TSPEC;
	    trace_req_qos (TR_PACKET, neighbor->trace, req_qos, 
			   "sender-tspec");
	}

        assert (req_qos);
	MRT_PUT_SHORT (SRSVP_OBJ_HDR_SIZE + SRSVP_REQ_QOS_SIZE, cp);
	MRT_PUT_BYTE (class, cp);
	MRT_PUT_BYTE (3, cp);
        MRT_PUT_BYTE (req_qos->pri, cp);
        MRT_PUT_BYTE (req_qos->rsvd, cp);
        MRT_PUT_SHORT (req_qos->mtu, cp);
        MRT_PUT_LONG (req_qos->pps, cp);
        MRT_PUT_LONG (req_qos->sec, cp);
        MRT_PUT_LONG (req_qos->cd, cp);
        MRT_PUT_LONG (req_qos->cf, cp);
        MRT_PUT_LONG (req_qos->rdly, cp);
        MRT_PUT_LONG (req_qos->rfee, cp);
    }

    if (type == SRSVP_MSG_PATH_TEAR || type == SRSVP_MSG_RESV_TEAR) {
	char text[1024];
        /* ERROR SPEC */
	trace (TR_PACKET, neighbor->trace, "  error-spec %s (0x%x)\n",
		srsvp_error_spec_string (flow->errcode, text), flow->errcode);
	MRT_PUT_SHORT (SRSVP_OBJ_HDR_SIZE + 4, cp);
	MRT_PUT_BYTE (SRSVP_OBJ_ERR_SPEC, cp);
	MRT_PUT_BYTE (3, cp);
        MRT_PUT_LONG (flow->errcode, cp);
    }
    return (srsvp_send_message (srsvp, neighbor,  
                    truetype, srbit, cp - msgbuf, msgbuf));
}


typedef struct _error_specs_t {
    u_long errcode;
    char *text;
} error_specs_t;

static error_specs_t error_specs[] = {
    {SRSVP_MSG_ERR_UNREACH, "Unreachable Host"},
    {SRSVP_MSG_ERR_BANDWIDTH, "Unavailable Bandwidth"},
    {SRSVP_MSG_ERR_DELAY, "Unsatisfying Delay"},
    {SRSVP_MSG_ERR_CHARGE, "Unsatisfying Charge"},
    {0, NULL},
};


static char *
srsvp_error_spec_string (u_long errcode, char *text)
{
    static char stext[1024];
    char *cp;
    int sep = '\0';
    error_specs_t *table = error_specs;

    cp = (text)? text: stext;
    sprintf (cp, "Unknown code 0x%lx", errcode);
    if (errcode == 0) {
	strcpy (cp, "none");
    }
    else {
	while (table->errcode) {
            if (BIT_TEST (errcode, table->errcode)) {
	        if (sep)
	            *cp++ = sep;
	        strcpy (cp, table->text);
	        cp += strlen (cp);
	        sep = '/';
	    }
	    table++;
	}
    }
    if (text)
	return (text);
    return (strdup (stext));
}


static int
srsvp_i_am_sender (srsvp_t *srsvp, srsvp_flow_t *flow)
{
    srsvp_interface_t *vif;

    if (BIT_TEST (flow->flags, SRSVP_FLOWF_SENDER))
	return (TRUE);
    LL_Iterate (srsvp->ll_srsvp_interfaces, vif) {
	if (address_equal (flow->sender, vif->prefix)) {
            trace (TR_TRACE, srsvp->trace, 
			"flow %a port %d proto %d: "
			"I am the sender on %s at %a port %d\n", 
			 flow->destin, flow->dport, flow->proto,
			 vif->interface->name, vif->prefix, 
			 flow->sport);
	    BIT_SET (flow->flags, SRSVP_FLOWF_SENDER);
	    return (TRUE);
        }
    }
    return (FALSE);
}


static int
srsvp_accept_resv (srsvp_t *srsvp, int type, int srbit, 
		   srsvp_flow_t *flow, req_qos_t *req_qos,
		   prefix_t *ssource, int lih, 
		   u_char *cp, int hdrlen, srsvp_neighbor_t *neighbor)
{
    u_char *end = cp + hdrlen, *xp = cp;
    int len, class, afi;
    u_long errcode = 0;
    char text[1024];
    srsvp_leaf_t *leaf = NULL;
    int change = 0;
    srsvp_flow_t *flow2;

    /* XXX FAQ_INFO */
    while ((cp = xp) + SRSVP_OBJ_HDR_SIZE <= end) {
	MRT_GET_SHORT (len, cp);
	MRT_GET_BYTE (class, cp);
	MRT_GET_BYTE (afi, cp);
	if (class != SRSVP_OBJ_FAQ_INFO)
	    break;
	xp += len;
	if (xp > end) {
            trace (TR_ERROR, neighbor->trace, 
	           "wrong object len %d (exceeds %d) class %d type %d\n", 
		    len, xp - end, class, afi);
	    return (-1);
	}
    }
    /* XXX PQC_INFO */
    while ((cp = xp) + SRSVP_OBJ_HDR_SIZE <= end) {
	MRT_GET_SHORT (len, cp);
	MRT_GET_BYTE (class, cp);
	MRT_GET_BYTE (afi, cp);
	if (class != SRSVP_OBJ_PQC_INFO)
	    break;
	xp += len;
	if (xp > end) {
            trace (TR_ERROR, neighbor->trace, 
	           "wrong object len %d (exceeds %d) class %d type %d\n", 
		    len, xp - end, class, afi);
	    return (-1);
	}
    }
    /* ERROR SPEC */
    if ((cp = xp) + SRSVP_OBJ_HDR_SIZE <= end) {
	MRT_GET_SHORT (len, cp);
	MRT_GET_BYTE (class, cp);
	MRT_GET_BYTE (afi, cp);
    if (class == SRSVP_OBJ_ERR_SPEC) {
	xp += len;
	if (xp > end) {
            trace (TR_ERROR, neighbor->trace, 
	           "wrong object len %d (exceeds %d) class %d type %d\n", 
		    len, xp - end, class, afi);
	    return (-1);
	}
	if (type != SRSVP_MSG_RESV_TEAR) {
            trace (TR_ERROR, neighbor->trace, 
	           "error spec is not allowed in a resv message\n");
	    return (-1);
	}
        if (afi != 3) {
            trace (TR_ERROR, neighbor->trace, 
	           "unsupported type %d in error spec\n", afi);
	    return (-1);
        }
        if (len != SRSVP_OBJ_HDR_SIZE + 4) {
            trace (TR_ERROR, neighbor->trace, 
	           "wrong len %d in error spec (must be %d)\n", len, 4 + 4);
	    return (-1);
        }
        if (cp + 4 > xp) {
            trace (TR_ERROR, neighbor->trace, 
	           "inconsistency in length (%d short)\n", 
		    cp + 4 - xp);
	    return (-1);
        }
        MRT_GET_LONG (errcode, cp);
	trace (TR_PACKET, neighbor->trace, "  error-spec %s (0x%x)\n",
		srsvp_error_spec_string (errcode, text), errcode);
    }
    }
    if (xp != end) {
        trace (TR_ERROR, neighbor->trace, 
	       "wrong packet len (%d remains)\n", 
		end - xp);
	return (-1);
    }

    if (type == SRSVP_MSG_RESV)
        type = (req_qos)? SRSVP_MSG_RESV1: SRSVP_MSG_RESV0;

    if (type == SRSVP_MSG_RESV0 && srsvp_i_am_sender (srsvp, flow)) {
	srsvp_forward_msg (srsvp, SRSVP_MSG_PATH, srbit, flow, 
		           neighbor);
	return (1);
    }

    flow2 = flow;
    flow = srsvp_flow_find (srsvp, flow2);

    if (type == SRSVP_MSG_RESV_TEAR) {
	if (flow == NULL) {
	    trace_flow (TR_PACKET, neighbor->trace, flow, "no flow");
	    return (0);
	}
    }

    if (flow == NULL) {
	flow = srsvp_flow_copy_add (srsvp, flow2);
    }
    flow->errcode = errcode;

    if (type == SRSVP_MSG_RESV_TEAR && srsvp_i_am_sender (srsvp, flow2)) {
	srsvp_destroy_flow (srsvp, flow);
	qif_notify (srsvp, flow, -1);
	return (1);
    }

    if (flow->ll_downstreams) {
	LL_Iterate (flow->ll_downstreams, leaf) {
	    if (address_equal (leaf->neighbor->prefix, neighbor->prefix))
	        break;
	}
    }

    if (type == SRSVP_MSG_RESV_TEAR) {
	if (BIT_TEST (leaf->flags, SRSVP_LEAFF_READY)) {
	    srsvp_notify_hqlip (srsvp, flow, leaf, OFF);
	    qif_del_flow (srsvp, flow, leaf);
	}
	LL_Remove (flow->ll_downstreams, leaf);
	srsvp_destroy_leaf (srsvp, leaf);
        if (LL_GetCount (flow->ll_downstreams) <= 0) {
    	    srsvp_forward_msg (srsvp, SRSVP_MSG_RESV_TEAR, 0, 
				   flow, flow->upstream);
	    srsvp_destroy_flow (srsvp, flow);
	}
	/* XXX in case of reducing pps */
	return (0);
    }

    if (leaf == NULL) {
	leaf = New (srsvp_leaf_t);
	leaf->neighbor = neighbor;
	leaf->neighbor->lih = lih; /* XXX */
        trace_neighbor (TR_TRACE, neighbor->trace, leaf->neighbor, "add");
	if (req_qos) {
	    if (leaf->req_qos == NULL)
	        leaf->req_qos = copy_req_qos (req_qos, NULL);
            if (flow->req_qos == NULL) {
	        flow->req_qos = copy_req_qos (req_qos, NULL);
		change++;
	    }
	    else {
		/* merge req_qos in flow */
		if (flow->req_qos->pps < req_qos->pps) {
		    flow->req_qos->pps = req_qos->pps;
		    change++;
		}
	    }
	}
	LL_Add2 (flow->ll_downstreams, leaf);
    }
    else if (req_qos) {
	if (leaf->req_qos == NULL)
	    leaf->req_qos = copy_req_qos (req_qos, NULL);
	else if (memcmp (leaf->req_qos, req_qos, sizeof (*req_qos)) != 0) {
	    copy_req_qos (req_qos, leaf->req_qos);
	    /* merge req_qos in flow */
	    /* XXX in case of reducing pps */
	    if (flow->req_qos->pps < req_qos->pps) {
	        flow->req_qos->pps = req_qos->pps;
	        change++;
	    }
        }
    }

    if (!change) {
	/* short cut the resv message */
        if (type == SRSVP_MSG_RESV0) {
	    if (BIT_TEST (flow->flags, SRSVP_FLOWF_RESV0))
		return (0);
	    if (BIT_TEST (flow->flags, SRSVP_FLOWF_RESV1) ||
	        BIT_TEST (flow->flags, SRSVP_FLOWF_READY)) {
		srsvp_forward_msg (srsvp, SRSVP_MSG_PATH, srbit, 
				   flow, neighbor);
		return (1);
	    }
	}
        if (type == SRSVP_MSG_RESV1) {
	    if (BIT_TEST (flow->flags, SRSVP_FLOWF_RESV1))
		return (0);
	    if (BIT_TEST (flow->flags, SRSVP_FLOWF_READY)) {
		BIT_RESET (leaf->flags, SRSVP_LEAFF_RESV1);
		BIT_SET (leaf->flags, SRSVP_LEAFF_READY);
		trace_neighbor (TR_TRACE, neighbor->trace, 
				leaf->neighbor, "ready");
		srsvp_forward_msg (srsvp, SRSVP_MSG_PATH, srbit, 
				   flow, neighbor);
		srsvp_notify_hqlip (srsvp, flow, leaf, ON);
		qif_add_flow (srsvp, flow, leaf);
		return (1);
	    }
	}
    }

    if (type == SRSVP_MSG_RESV1 && srsvp_i_am_sender (srsvp, flow)) {
	BIT_RESET (leaf->flags, SRSVP_LEAFF_RESV1);
	BIT_SET (leaf->flags, SRSVP_LEAFF_READY);
	BIT_SET (flow->flags, SRSVP_FLOWF_READY);
	trace_neighbor (TR_TRACE, neighbor->trace, leaf->neighbor, "ready");
	srsvp_forward_msg (srsvp, SRSVP_MSG_PATH, srbit, flow, 
		           neighbor);
	qif_notify (srsvp, flow, 0);
	srsvp_notify_hqlip (srsvp, flow, leaf, ON);
	qif_add_flow (srsvp, flow, leaf);
	return (1);
    }

    if (flow->upstream == NULL) {
	if (srsvp_resolv_upstream (srsvp, flow) < 0) {
	    LL_Iterate (flow->ll_downstreams, leaf) {
    		srsvp_forward_msg (srsvp, SRSVP_MSG_PATH_TEAR, 0, 
				   flow, leaf->neighbor);
	    }
	    srsvp_destroy_flow (srsvp, flow);
	    return (0);
	}
    }

    switch (type) {
    case SRSVP_MSG_RESV0:
	trace_neighbor (TR_TRACE, neighbor->trace, leaf->neighbor, "resv0");
	srsvp_forward_msg (srsvp, SRSVP_MSG_RESV0, srbit, flow, 
			   flow->upstream);
	BIT_SET (leaf->flags, SRSVP_LEAFF_RESV0);
	BIT_SET (flow->flags, SRSVP_FLOWF_RESV0);
	break;
    case SRSVP_MSG_RESV1:
	trace_neighbor (TR_TRACE, neighbor->trace, leaf->neighbor, "resv1");
	srsvp_forward_msg (srsvp, SRSVP_MSG_RESV1, srbit, flow, 
			   flow->upstream);
	BIT_SET (leaf->flags, SRSVP_LEAFF_RESV1);
	BIT_SET (flow->flags, SRSVP_FLOWF_RESV1);
	break;
    }
    return (1);
}


static int
srsvp_i_am_receiver (srsvp_t *srsvp, srsvp_flow_t *flow)
{
    srsvp_interface_t *vif;

    if (BIT_TEST (flow->flags, SRSVP_FLOWF_RECVER))
	return (TRUE);
    LL_Iterate (srsvp->ll_srsvp_interfaces, vif) {
	if (address_equal (flow->destin, vif->prefix)) {
            trace (TR_TRACE, srsvp->trace, 
			"flow %a port %d proto %d: "
			"I am the receiver on %s at %a port %d\n", 
			 flow->destin, flow->dport, flow->proto,
			 vif->interface->name, vif->prefix, 
			 flow->dport);
	    BIT_SET (flow->flags, SRSVP_FLOWF_RECVER);
	    return (TRUE);
        }
    }
    return (FALSE);
}


static int
srsvp_accept_path (srsvp_t *srsvp, int type, int srbit, 
		   srsvp_flow_t *flow, req_qos_t *req_qos,
		   prefix_t *ssource, int lih, 
		   u_char *cp, int hdrlen, srsvp_neighbor_t *neighbor)
{
    u_char *end = cp + hdrlen, *xp = cp;
    int len, class, afi;
    char text[1024];
    srsvp_leaf_t *leaf;
    srsvp_flow_t *flow2;
    srsvp_neighbor_t *neighbor2;
    u_long errcode = 0;

    /* XXX POLICY_DATA */
    while ((cp = xp) + SRSVP_OBJ_HDR_SIZE <= end) {
	MRT_GET_SHORT (len, cp);
	MRT_GET_BYTE (class, cp);
	MRT_GET_BYTE (afi, cp);
	if (class != SRSVP_OBJ_POLICYD)
	    break;
	xp += len;
	if (xp > end) {
            trace (TR_ERROR, neighbor->trace, 
	           "wrong object len %d (exceeds %d) class %d type %d\n", 
		    len, xp - end, class, afi);
	    return (-1);
	}
    }
    /* XXX FAQ_INFO */
    while ((cp = xp) + SRSVP_OBJ_HDR_SIZE <= end) {
	MRT_GET_SHORT (len, cp);
	MRT_GET_BYTE (class, cp);
	MRT_GET_BYTE (afi, cp);
	if (class != SRSVP_OBJ_FAQ_INFO)
	    break;
	xp += len;
	if (xp > end) {
            trace (TR_ERROR, neighbor->trace, 
	           "wrong object len %d (exceeds %d) class %d type %d\n", 
		    len, xp - end, class, afi);
	    return (-1);
	}
    }
    /* XXX PQC_INFO */
    while ((cp = xp) + SRSVP_OBJ_HDR_SIZE <= end) {
	MRT_GET_SHORT (len, cp);
	MRT_GET_BYTE (class, cp);
	MRT_GET_BYTE (afi, cp);
	if (class != SRSVP_OBJ_PQC_INFO)
	    break;
	xp += len;
	if (xp > end) {
            trace (TR_ERROR, neighbor->trace, 
	           "wrong object len %d (exceeds %d) class %d type %d\n", 
		    len, xp - end, class, afi);
	    return (-1);
	}
    }
    /* ERROR SPEC */
    if ((cp = xp) + SRSVP_OBJ_HDR_SIZE <= end) {
	MRT_GET_SHORT (len, cp);
	MRT_GET_BYTE (class, cp);
	MRT_GET_BYTE (afi, cp);
    if (class == SRSVP_OBJ_ERR_SPEC) {
	xp += len;
	if (xp > end) {
            trace (TR_ERROR, neighbor->trace, 
	           "wrong object len %d (exceeds %d) class %d type %d\n", 
		    len, xp - end, class, afi);
	    return (-1);
	}
	if (type == SRSVP_MSG_PATH) {
            trace (TR_ERROR, neighbor->trace, 
	           "error spec is not allowed in a path message\n");
	    return (-1);
	}
        if (afi != 3) {
            trace (TR_ERROR, neighbor->trace, 
	           "unsupported type %d in error spec\n", afi);
	    return (-1);
        }
        if (len != SRSVP_OBJ_HDR_SIZE + 4) {
            trace (TR_ERROR, neighbor->trace, 
	           "wrong len %d in error spec (must be %d)\n", len, 4 + 4);
	    return (-1);
        }
        if (cp + 4 > xp) {
            trace (TR_ERROR, neighbor->trace, 
	           "inconsistency in length (%d short)\n", 
		    cp + 4 - xp);
	    return (-1);
        }
        MRT_GET_LONG (errcode, cp);
	trace (TR_PACKET, neighbor->trace, "  error-spec %s (0x%x)\n",
		srsvp_error_spec_string (errcode, text), errcode);
    }
    }
    if (xp != end) {
        trace (TR_ERROR, neighbor->trace, 
	       "wrong packet len (%d remains)\n", 
		end - xp);
	return (-1);
    }

    /* XXX req_qos is sender tspec -- optional */

    flow2 = flow;
    flow = srsvp_flow_find (srsvp, flow2);

    if (type == SRSVP_MSG_PATH_TEAR) {
	if (flow == NULL) {
	    trace_flow (TR_PACKET, neighbor->trace, flow2, "no flow");
	    return (0);
	}
        flow->errcode = errcode;
        if (BIT_TEST (flow->flags, SRSVP_FLOWF_RECVER)) {
	    qif_notify (srsvp, flow, -1);
	    srsvp_destroy_flow (srsvp, flow);
	    return (0);
        }
	/* XXX need to check who caused this */
	LL_Iterate (flow->ll_downstreams, leaf) {
	    srsvp_forward_msg (srsvp, SRSVP_MSG_PATH_TEAR, srbit, 
				     flow, leaf->neighbor);
	    if (BIT_TEST (leaf->flags, SRSVP_LEAFF_READY)) {
	        srsvp_notify_hqlip (srsvp, flow, leaf, OFF);
		qif_del_flow (srsvp, flow, leaf);
	    }
	}
	srsvp_destroy_flow (srsvp, flow);
	return (0);
    }

    if (flow == NULL) {
	if (srsvp_i_am_receiver (srsvp, flow2)) {

	    if (srsvp_resolv_upstream (srsvp, flow2) < 0) {
	        return (0);
	    }
	    if (flow2->sender_tspec == NULL) {
        	trace (TR_ERROR, neighbor->trace, "no sender-tspec\n");
	        return (0);
	    }
    	    flow = srsvp_flow_copy_add (srsvp, flow2);
	    flow->req_qos = flow->sender_tspec;
	    flow->sender_tspec = NULL;
	    trace_flow (TR_TRACE, neighbor->trace, flow, "resv1");
	    srsvp_forward_msg (srsvp, SRSVP_MSG_RESV1, 0, 
			       flow, flow->upstream);
	    BIT_SET (flow->flags, SRSVP_FLOWF_RESV1);
    	    return (1);
	}

    without_resv0:

	flow = flow2;
        trace (TR_TRACE, neighbor->trace, "going without resv0 (%s)\n",
		(flow)? "no downstreams": "no flow");
	neighbor2 = srsvp_get_upstream (srsvp, flow->destin, NULL, 
					&flow->errcode);
	if (neighbor2 != NULL) {
	    srsvp_forward_msg (srsvp, SRSVP_MSG_PATH, srbit, 
			       flow, neighbor2);
	}
	else {
	    srsvp_forward_msg (srsvp, SRSVP_MSG_RESV_TEAR, 0, 
			       flow, neighbor);
	}
	return (0);
    }

    if (flow->upstream != neighbor) {
	assert (flow->upstream);
        trace (TR_ERROR, neighbor->trace, 
	       "not upstream (must be %a)\n", flow->upstream->prefix);
	srsvp_forward_msg (srsvp, SRSVP_MSG_PATH_TEAR, 0, 
			   flow, neighbor);
	return (0);
    }

    if (BIT_TEST (flow->flags, SRSVP_FLOWF_RECVER)) {
	if (BIT_TEST (flow->flags, SRSVP_FLOWF_RESV1)) {
	    BIT_SET (flow->flags, SRSVP_FLOWF_READY);
	    qif_notify (srsvp, flow, 0);
	    trace_flow (TR_TRACE, neighbor->trace, flow, "ready");
	}
	else {
	    if (srsvp_resolv_upstream (srsvp, flow) < 0) {
	        srsvp_destroy_flow (srsvp, flow);
	        return (0);
	    }
	    trace_flow (TR_TRACE, neighbor->trace, flow, "resv1");
	    srsvp_forward_msg (srsvp, SRSVP_MSG_RESV1, 0, 
			       flow, flow->upstream);
	    BIT_SET (flow->flags, SRSVP_FLOWF_RESV1);
	}
	return (1);
    }

    if (flow->ll_downstreams == NULL ||
		LL_GetCount (flow->ll_downstreams) <= 0) {
	/* no down streams */
	goto without_resv0;
    }

    if (BIT_TEST (flow->flags, SRSVP_FLOWF_RESV1)) {
        BIT_SET (flow->flags, SRSVP_FLOWF_READY);
        BIT_RESET (flow->flags, SRSVP_FLOWF_RESV1);
    }
    LL_Iterate (flow->ll_downstreams, leaf) {
	if (BIT_TEST (leaf->flags, SRSVP_LEAFF_RESV1)) {
	    srsvp_forward_msg (srsvp, SRSVP_MSG_PATH, srbit, flow,
			       leaf->neighbor);
	    BIT_RESET (leaf->flags, SRSVP_LEAFF_RESV1);
	    if (BIT_TEST (leaf->flags, SRSVP_LEAFF_READY)) {
	        trace_neighbor (TR_TRACE, neighbor->trace, 
				leaf->neighbor, "change");
		/* XXX no way to update */
	        /* srsvp_notify_hqlip (srsvp, flow, leaf, OFF);
	        srsvp_notify_hqlip (srsvp, flow, leaf, ON); */
	    }
	    else {
	        BIT_SET (leaf->flags, SRSVP_LEAFF_READY);
	        trace_neighbor (TR_TRACE, neighbor->trace, 
				leaf->neighbor, "ready");
	        srsvp_notify_hqlip (srsvp, flow, leaf, ON);
	    }
	    qif_add_flow (srsvp, flow, leaf);
	}
	else {
	    srsvp_leaf_t *prev;
	    srsvp_forward_msg (srsvp, SRSVP_MSG_PATH, srbit, flow, 
			       leaf->neighbor);
	    prev = LL_GetPrev (flow->ll_downstreams, leaf);
	    LL_Remove (flow->ll_downstreams, leaf);
	    srsvp_destroy_leaf (srsvp, leaf);
	    leaf = prev;
            if (LL_GetCount (flow->ll_downstreams) <= 0) {
		srsvp_destroy_flow (srsvp, flow);
		/* must exit since it was destroyed */
		break;
	    }
	}
    }
    return (1);
}


static u_int
srsvp_flow_hash_fn (srsvp_flow_t *flow, u_int size)
{
    int val = 0;

    val += ip_hash_fn (flow->destin, size);
    val += flow->dport;
    val += flow->proto;
    val += ip_hash_fn (flow->sender, size);
    val += flow->sport;
    val = val % size;
    return (val);
}


static int
srsvp_flow_lookup_fn (srsvp_flow_t *a, srsvp_flow_t *b)
{
    if (a->dport != b->dport)
	return (FALSE);
    if (a->proto != b->proto)
	return (FALSE);
    if (!address_equal (a->destin, b->destin))
	return (FALSE);
    
    if (a->sport != b->sport)
	return (FALSE);
    if (!address_equal (a->sender, b->sender))
	return (FALSE);
    return (TRUE);
}


static srsvp_flow_t *
srsvp_flow_create (srsvp_t *srsvp, prefix_t *destin, int proto, int dport, 
		   prefix_t *sender, int sport, req_qos_t *req_qos, 
		   u_long flags, srsvp_flow_t *flow)
{
    if (flow == NULL) {
        flow = New (srsvp_flow_t);
        flow->destin = Ref_Prefix (destin);
        flow->sender = Ref_Prefix (sender);
        if (req_qos) {
	    flow->req_qos = copy_req_qos (req_qos, NULL);
	}
	else {
	    flow->req_qos = NULL;
	}
        flow->ll_downstreams = LL_Create (0);
    }
    else {
	/* assuming a static memory */
	memset (flow, 0, sizeof (*flow));
        flow->destin = destin;
        flow->sender = sender;
	flow->req_qos = req_qos;
        flow->ll_downstreams = NULL;
    }
    flow->dport = dport;
    flow->proto = proto;
    flow->flags = flags;
    flow->errcode = 0;
    flow->sport = sport;
    flow->upstream = NULL;

    return (flow);
}


static void
srsvp_destroy_flow2 (srsvp_t *srsvp, srsvp_flow_t *flow)
{
    pthread_mutex_lock (&srsvp->flows->mutex_lock);
    HASH_Remove (srsvp->flows->table, flow);
    pthread_mutex_unlock (&srsvp->flows->mutex_lock);
    trace_flow (TR_TRACE, srsvp->trace, flow, "del");
    Deref_Prefix (flow->destin);
    Deref_Prefix (flow->sender);
    if (flow->req_qos)
	Delete (flow->req_qos);
    if (flow->sender_tspec)
	Delete (flow->sender_tspec);
    if (flow->ll_downstreams) {
	srsvp_leaf_t *leaf;
	LL_Iterate (flow->ll_downstreams, leaf) {
	    srsvp_destroy_leaf (srsvp, leaf);
	}
	LL_Destroy (flow->ll_downstreams);
    }
    Delete (flow);
}


srsvp_flow_t *
srsvp_flow_find (srsvp_t *srsvp, srsvp_flow_t *flow)
{
    srsvp_flow_t *flow2;
    if (srsvp->flows == NULL)
	return (NULL);
    pthread_mutex_lock (&srsvp->flows->mutex_lock);
    flow2 = HASH_Lookup (srsvp->flows->table, flow);
    pthread_mutex_unlock (&srsvp->flows->mutex_lock);
    if (flow2 && BIT_TEST (flow2->flags, SRSVP_FLOWF_DELETED)) {
	/* the end was delayed to now */
	srsvp_destroy_flow2 (srsvp, flow2);
	flow2 = NULL;
    }
    return (flow2);
}
    

static srsvp_flow_t *
srsvp_flow_copy_add (srsvp_t *srsvp, srsvp_flow_t *flow)
{
    srsvp_flow_t *nflow;

    if (srsvp->flows == NULL) {
	srsvp->flows = New (mrt_hash_table_t);
        pthread_mutex_init (&srsvp->flows->mutex_lock, NULL);
    }
    nflow = srsvp_flow_create (srsvp, flow->destin, flow->proto, flow->dport, 
		   flow->sender, flow->sport, flow->req_qos, 
		   flow->flags, NULL);

    trace_flow (TR_TRACE, srsvp->trace, nflow, "add");
    if (nflow->req_qos)
        trace_req_qos (TR_TRACE, srsvp->trace, nflow->req_qos, "flow-spec");
    if (flow->sender_tspec) {
	nflow->sender_tspec = copy_req_qos (flow->sender_tspec, NULL);
        trace_req_qos (TR_TRACE, srsvp->trace, nflow->sender_tspec, 
		       "sender-tspec");
    }

    if (flow->ll_downstreams) {
        srsvp_leaf_t *leaf, *nleaf;
	LL_Iterate (flow->ll_downstreams, leaf) {
	    nleaf = New (srsvp_leaf_t);
	    nleaf->neighbor = leaf->neighbor;
	    nleaf->flags = leaf->flags;
	    trace_neighbor (TR_TRACE, srsvp->trace, leaf->neighbor, "add");
	    if (leaf->req_qos) {
	        nleaf->req_qos = copy_req_qos (leaf->req_qos, NULL);
	        trace_req_qos (TR_TRACE, srsvp->trace, leaf->req_qos, 
			       "flow-spec");
	    }
	    LL_Add2 (nflow->ll_downstreams, nleaf);
	}
    }
    nflow->upstream = flow->upstream;

    pthread_mutex_lock (&srsvp->flows->mutex_lock);
    if (srsvp->flows->table == NULL) {
        srsvp->flows->table = HASH_Create (SRSVP_FLOW_HASH_SIZE,
                 	 	 HASH_EmbeddedKey, True,
                    	 	 HASH_KeyOffset, 0,
                    	 	 HASH_LookupFunction, srsvp_flow_lookup_fn,
                    	 	 HASH_HashFunction, srsvp_flow_hash_fn, 0);
    }
    HASH_Insert (srsvp->flows->table, nflow);
    pthread_mutex_unlock (&srsvp->flows->mutex_lock);

    return (nflow);
}


static void
srsvp_destroy_leaf (srsvp_t *srsvp, srsvp_leaf_t *leaf)
{
    trace_neighbor (TR_TRACE, srsvp->trace, leaf->neighbor, "del");
    if (leaf->req_qos)
	Delete (leaf->req_qos);
    Delete (leaf);
}



static void
srsvp_destroy_flow (srsvp_t *srsvp, srsvp_flow_t *flow)
{
    BIT_SET (flow->flags, SRSVP_FLOWF_DELETED);
}


static int
srsvp_process_pdu (srsvp_t *srsvp, srsvp_neighbor_t *neighbor)
{
    int version, hdrflags, sessionf, senderf, type, ttl, srbit, hdrlen;
    u_char *cp, *end, *xp;
    int class, len, proto, dafi, safi, dport, lih, sport = 0;
    prefix_t sdestin, ssource, ssender, *sender = NULL;
    u_char addr[16];
    srsvp_flow_t sflow, *flow = NULL;
    req_qos_t rqos, *req_qos = NULL;
    int ret = 0;

    assert (neighbor);
    assert (neighbor->packet);
    neighbor->num_packets_recv++;

    cp = neighbor->packet;
    SRSVP_GET_HEADER (version, hdrflags, type, ttl, srbit, hdrlen, cp);
    end = neighbor->packet + hdrlen;
    xp = cp;

    if (type >= SRSVP_MSG_PATH && type <= SRSVP_MSG_RESV_TEAR) {
        trace (TR_PACKET, neighbor->trace, 
	       "recv %s version %d flags 0x%x ttl %d srbit 0x%x "
	       "(%d bytes)\n",
	        srsvp_pdus[type], version, hdrflags, ttl, srbit, hdrlen);
    }

    if (hdrlen < SRSVP_MSG_HDR_SIZE) {
        trace (TR_ERROR, neighbor->trace, 
	       "recv a message with too short length %d\n", hdrlen);
	return (-1);
    }

    if (version != SRSVP_MSG_VERSION) {
        trace (TR_ERROR, neighbor->trace, 
	       "recv a message with unsupported version %d\n", version);
	return (-1);
    }

    /* session class */
    if ((cp = xp) + SRSVP_OBJ_HDR_SIZE > end) {
        trace (TR_ERROR, neighbor->trace, 
	       "recv a message with too short len %d to get session\n", 
		hdrlen);
	return (-1);
    }

    MRT_GET_SHORT (len, cp);
    MRT_GET_BYTE (class, cp);
    MRT_GET_BYTE (dafi, cp);

    if (class != SRSVP_OBJ_SESSION) {
        trace (TR_ERROR, neighbor->trace, 
	       "session is missing (len %d class %d afi %d)\n", 
		len, class, dafi);
	return (-1);
    }
    xp += len;
    if (xp > end) {
        trace (TR_ERROR, neighbor->trace, 
	       "wrong object len %d (exceeds %d) class %d type %d\n", 
		len, xp - end, class, dafi);
	return (-1);
    }
#ifdef HAVE_IPV6
    if (dafi == AFI_IP6) {
	/* OK */
    }
    else
#endif /* HAVE_IPV6 */
    if (dafi == AFI_IP) {
	/* OK */
    }
    else {
        trace (TR_ERROR, neighbor->trace, 
	       "unsupported afi %d in session\n", dafi);
	return (-1);
    }
    if (len != SRSVP_OBJ_HDR_SIZE + afi2plen (dafi) + 4) {
        trace (TR_ERROR, neighbor->trace, 
	       "wrong len %d in session (must be %d)\n", 
		len, afi2plen (dafi) + 4);
	return (-1);
    }
    if (cp + afi2plen (dafi) + 4 > xp) {
        trace (TR_ERROR, neighbor->trace, 
	       "inconsistency in length (%d short)\n", 
		cp + afi2plen (dafi) + 4 - xp);
	return (-1);
    }

    MRT_GET_DATA (addr, afi2plen (dafi), cp);
    MRT_GET_BYTE (proto, cp);
    MRT_GET_BYTE (sessionf, cp);
    MRT_GET_SHORT (dport, cp);
    New_Prefix2 (afi2family (dafi), addr, -1, &sdestin);
    trace (TR_PACKET, neighbor->trace, 
	   "  session %a proto %d port %d\n", &sdestin, proto, dport);

    /* session rsvp_hop */
    if ((cp = xp) + SRSVP_OBJ_HDR_SIZE > end) {
        trace (TR_ERROR, neighbor->trace, 
	       "recv a message with too short len %d to get rsvp_hop\n", 
		hdrlen);
	return (-1);
    }
    MRT_GET_SHORT (len, cp);
    MRT_GET_BYTE (class, cp);
    MRT_GET_BYTE (safi, cp);

    if (class != SRSVP_OBJ_RSVP_HOP) {
        trace (TR_ERROR, neighbor->trace, 
	       "rsvp_hop is missing (len %d class %d afi %d)\n", 
		len, class, safi);
	return (-1);
    }
    xp += len;
    if (xp > end) {
        trace (TR_ERROR, neighbor->trace, 
	       "wrong object len %d (exceeds %d) class %d type %d\n", 
		len, xp - end, class, safi);
	return (-1);
    }
#ifdef HAVE_IPV6
    if (safi == AFI_IP6) {
	/* OK */
    }
    else
#endif /* HAVE_IPV6 */
    if (safi == AFI_IP) {
	/* OK */
    }
    else {
        trace (TR_ERROR, neighbor->trace, 
	       "unsupported afi %d in rsvp_hop\n", safi);
	return (-1);
    }
    if (len != SRSVP_OBJ_HDR_SIZE + afi2plen (safi) + 4) {
        trace (TR_ERROR, neighbor->trace, 
	       "wrong len %d in rsvp_hop (must be %d)\n", 
		len, afi2plen (safi) + 4);
	return (-1);
    }
    if (cp + afi2plen (safi) + 4 > xp) {
        trace (TR_ERROR, neighbor->trace, 
	       "inconsistency in length (%d short)\n", 
		cp + afi2plen (safi) + 4 - xp);
	return (-1);
    }

    if (dafi != safi) {
        trace (TR_ERROR, neighbor->trace, 
	       "inconsistency in afi of session %d and rsvp_hop %d\n", 
		dafi, safi);
	return (-1);
    }
    MRT_GET_DATA (addr, afi2plen (safi), cp);
    MRT_GET_LONG (lih, cp);
    New_Prefix2 (afi2family (safi), addr, -1, &ssource);

    trace (TR_PACKET, neighbor->trace, 
	   "  rsvp_hop %a lih %d\n", &ssource, lih);

    while ((cp = xp) + SRSVP_OBJ_HDR_SIZE <= end) {
	int afi;

	MRT_GET_SHORT (len, cp);
	MRT_GET_BYTE (class, cp);
	MRT_GET_BYTE (afi, cp);
	if (class != SRSVP_OBJ_SENDERT) {
	    break;
	}
        xp += len;
        if (xp > end) {
            trace (TR_ERROR, neighbor->trace, 
	           "wrong object len %d (exceeds %d) class %d type %d\n", 
		    len, xp - end, class, dafi);
	    return (-1);
        }
#ifdef HAVE_IPV6
        if (afi == AFI_IP6) {
	    /* OK */
        }
        else
#endif /* HAVE_IPV6 */
        if (afi == AFI_IP) {
	    /* OK */
        }
        else {
            trace (TR_ERROR, neighbor->trace, 
	           "unsupported afi %d in sender tamplate\n", afi);
	    return (-1);
        }
        if (len != SRSVP_OBJ_HDR_SIZE + afi2plen (afi) + 4) {
            trace (TR_ERROR, neighbor->trace, 
	           "wrong len %d in sender tamplate (must be %d)\n", 
		    len, afi2plen (afi) + 4);
	    return (-1);
        }
        if (cp + afi2plen (afi) + 4 > xp) {
            trace (TR_ERROR, neighbor->trace, 
	           "inconsistency in length (%d short)\n", 
		    cp + afi2plen (afi) + 4 - xp);
	    return (-1);
        }
	if (sender != NULL) {
            trace (TR_WARN, neighbor->trace, 
	           "only one sender allowed in this version\n");
	    cp = cp + afi2plen (afi) + 4;
 	}
	else {
            MRT_GET_DATA (addr, afi2plen (afi), cp);
	    cp += 1;
            MRT_GET_BYTE (senderf, cp);
            MRT_GET_SHORT (sport, cp);
	    New_Prefix2 (afi2family (afi), addr, -1, &ssender);
	    sender = &ssender;
            trace (TR_PACKET, neighbor->trace, 
	            "  sender template %a flags 0x%x port %d\n", 
		    sender, senderf, sport);
	}
    }

    if (sender == NULL) {
        trace (TR_ERROR, neighbor->trace, 
	       "at least one sender must be specified in a message\n");
	return (-1);
    }

    flow = srsvp_flow_create (srsvp, &sdestin, proto, dport, 
		       &ssender, sport, NULL, 0, &sflow);

    if ((cp = xp) + SRSVP_OBJ_HDR_SIZE <= end) {
	int afi;
	char *text = "????";

	MRT_GET_SHORT (len, cp);
	MRT_GET_BYTE (class, cp);
	MRT_GET_BYTE (afi, cp);

        if (class == SRSVP_OBJ_FLOW_SPEC || class == SRSVP_OBJ_SENDER_TSPEC) {
	    xp += len;
	    if (xp > end) {
                trace (TR_ERROR, neighbor->trace, 
	               "wrong object len %d (exceeds %d) class %d type %d\n", 
		    len, xp - end, class, afi);
	        return (-1);
	    }
    
	    req_qos = &rqos;

	    switch (type) {
	    case SRSVP_MSG_PATH:
            case SRSVP_MSG_PATH_TEAR:
		flow->sender_tspec = req_qos;
		text = "sender-tspec";
		if (class == SRSVP_OBJ_FLOW_SPEC) {
            	    trace (TR_ERROR, neighbor->trace, 
	           	    "flow spec is not allowed in a path message\n");
	    	    return (-1);
		}
		break;
            case SRSVP_MSG_RESV:
            case SRSVP_MSG_RESV_TEAR:
		flow->req_qos = req_qos;
		text = "flow-spec";
		if (class == SRSVP_OBJ_SENDER_TSPEC) {
            	    trace (TR_ERROR, neighbor->trace, 
	           	    "sender tspec is not allowed in a resv message\n");
	    	    return (-1);
		}
		break;
	    }

            if (afi != 3) {
                trace (TR_ERROR, neighbor->trace, 
	               "unsupported type %d in flow spec or sender tspec\n", 
			afi);
	        return (-1);
            }
            if (len != SRSVP_OBJ_HDR_SIZE + SRSVP_REQ_QOS_SIZE) {
                trace (TR_ERROR, neighbor->trace, 
	               "wrong len %d in flow spec or sender tspec "
		       "(must be %d)\n", 
		        len, SRSVP_OBJ_HDR_SIZE + SRSVP_REQ_QOS_SIZE);
	        return (-1);
            }
            if (cp + SRSVP_REQ_QOS_SIZE > xp) {
                trace (TR_ERROR, neighbor->trace, 
	               "inconsistency in length (%d short)\n", 
		        cp + SRSVP_REQ_QOS_SIZE - xp);
	        return (-1);
            }
            MRT_GET_BYTE (req_qos->pri, cp);
            MRT_GET_BYTE (req_qos->rsvd, cp);
            MRT_GET_SHORT (req_qos->mtu, cp);
            MRT_GET_LONG (req_qos->pps, cp);
            MRT_GET_LONG (req_qos->sec, cp);
            MRT_GET_LONG (req_qos->cd, cp);
            MRT_GET_LONG (req_qos->cf, cp);
            MRT_GET_LONG (req_qos->rdly, cp);
            MRT_GET_LONG (req_qos->rfee, cp);
	    trace_req_qos (TR_PACKET, neighbor->trace, req_qos, text);
        }
    }

    switch (type) {
    case SRSVP_MSG_PATH_TEAR:
    case SRSVP_MSG_PATH:
	    ret = srsvp_accept_path (srsvp, type, srbit, flow, req_qos,
			       &ssource, lih, xp, end - xp, neighbor);
	    break;
    case SRSVP_MSG_RESV_TEAR:
    case SRSVP_MSG_RESV:
	    ret = srsvp_accept_resv (srsvp, type, srbit, flow, req_qos,
			       &ssource, lih, xp, end - xp, neighbor);
	    break;
    default:
            trace (TR_ERROR, neighbor->trace, 
		"recv unknown message type %d (%d bytes)\n", type, len);
	    ret = -1;
    }
    return (ret);
}


static void
srsvp_neighbor_start (srsvp_t *srsvp, srsvp_neighbor_t *neighbor)
{
    time (&neighbor->utime);
    select_add_fd_event ("srsvp_get_pdu", neighbor->sockfd, SELECT_READ,
                         1 /* on */, neighbor->schedule,
                         (event_fn_t) srsvp_get_pdu, 2, srsvp, neighbor);
#ifndef HAVE_LIBPTHREAD
    select_add_fd_event ("srsvp_flush_queue", neighbor->sockfd, SELECT_WRITE,
                         0 /* off */, neighbor->schedule,
                         (event_fn_t) srsvp_flush_queue, 2, srsvp, neighbor);
#endif /* HAVE_LIBPTHREAD */
    neighbor->num_packets_sent = 0;
    neighbor->num_packets_recv = 0;
    neighbor->num_session_up++;
    BIT_SET (neighbor->flags, SRSVP_NEIGHBOR_CONNECTED);
    Timer_Turn_ON (neighbor->keep_alive);
}


static srsvp_neighbor_t *
srsvp_get_upstream (srsvp_t *srsvp, prefix_t *sender, req_qos_t *req_qos,
		    u_long *errcode_p)
{
    hqlip_t *hqlip = RICD->hqlip;
    link_qos_t lqos;
    int metric;
    srsvp_interface_t *vif;
    srsvp_neighbor_t *neighbor;
    hqlip_neighbor_t *hqlip_neighbor;

    assert (errcode_p);
#ifdef HAVE_IPV6
    if (sender->family == AF_INET6)
	hqlip = RICD6->hqlip;
#endif /* HAVE_IPV6 */
    hqlip_neighbor = hqlip_find_nexthop (hqlip, hqlip->root, sender, 
					 req_qos, &lqos, &metric, errcode_p);
    if (hqlip_neighbor == NULL) {
	char text[1024];
        trace (TR_TRACE, srsvp->trace, 
		"hqlip neighbor not found for sender %a (%s)\n", 
		sender, srsvp_error_spec_string (*errcode_p, text));
	return (NULL);
    }

    LL_Iterate (srsvp->ll_srsvp_interfaces, vif) {
        LL_Iterate (vif->ll_neighbors, neighbor) {
	    if (BIT_TEST (neighbor->flags, SRSVP_NEIGHBOR_DELETED))   
                continue;
	    if (address_equal (hqlip_neighbor->prefix, neighbor->prefix)) {
        	trace (TR_TRACE, srsvp->trace, 
		       "srsvp neighbor %a found on %s for sender %a\n", 
		       neighbor->prefix, neighbor->vif->interface->name,
		       sender);
	        return (neighbor);
	    }
        }
    }
    trace (TR_TRACE, srsvp->trace, 
	   "neighbor not found for sender %a (no srsvp neighbor for %a)\n", 
	   sender, hqlip_neighbor->prefix);
    *errcode_p = SRSVP_MSG_ERR_UNREACH;
    return (NULL);
}


static int
srsvp_resolv_upstream (srsvp_t *srsvp, srsvp_flow_t *flow)
{
    srsvp_neighbor_t *neighbor;

    neighbor = srsvp_get_upstream (srsvp, flow->sender, flow->req_qos,
                    		       &flow->errcode);
    if (neighbor == NULL) {
	char text[1024];
        trace (TR_TRACE, srsvp->trace, 
		"flow %a port %d proto %d: upstream not found (%s)\n", 
		flow->destin, flow->dport, flow->proto,
		srsvp_error_spec_string (flow->errcode, text));
	flow->upstream = NULL;
	return (-1);
    }
    trace (TR_TRACE, srsvp->trace, 
	   "flow %a port %d proto %d: upstream %a found on %s (%s)\n", 
	   flow->destin, flow->dport, flow->proto, neighbor->prefix,
	   neighbor->vif->interface->name,
    	   (flow->upstream == NULL)? "new": (flow->upstream != neighbor)?
		"change": "same");
    flow->upstream = neighbor;
    return (1);
}


/* called from routing socket receiver */
void
srsvp_flow_request_by_app (srsvp_t *srsvp, srsvp_flow_t *flow, int cmd)
{
    prefix_t *nexthop;
    u_long errcode;
    srsvp_neighbor_t *neighbor;
    char text[256] = "app-req recv";
    prefix_t *rvp = NULL;

    assert (cmd == 'S' || cmd == 'R');
    assert (flow);
    nexthop = flow->sender;
    if (cmd == 'S') {
	nexthop = flow->destin;
 	strcpy (text, "app-req send");
    }

    trace_flow (TR_TRACE, srsvp->trace, flow, text);
    trace_req_qos (TR_TRACE, srsvp->trace, flow->req_qos, "app-req");

    if (flow->req_qos->pps == 0) {

        if ((flow = srsvp_flow_find (srsvp, flow)) == NULL) {
	    trace (TR_ERROR, srsvp->trace, "no flow\n");
	    return;
        }

        if (BIT_TEST (flow->flags, SRSVP_FLOWF_SENDER)) {
	    srsvp_leaf_t *leaf;
	    if (flow->ll_downstreams) {
	        LL_Iterate (flow->ll_downstreams, leaf) {
		    if (!BIT_TEST (leaf->neighbor->vif->interface->flags, 
				  IFF_LOOPBACK)) {
        	        srsvp_forward_msg (srsvp, SRSVP_MSG_PATH_TEAR, 0, 
					   flow, leaf->neighbor);
		    }
		    if (BIT_TEST (leaf->flags, SRSVP_LEAFF_READY)) {
			srsvp_notify_hqlip (srsvp, flow, leaf, OFF);
    		        qif_del_flow (srsvp, flow, leaf);
		    }
	        }
	    }
        }
        else {
            if (flow->upstream)
                srsvp_forward_msg (srsvp, SRSVP_MSG_RESV_TEAR, 0, flow, 
			           flow->upstream);
        }
        srsvp_destroy_flow (srsvp, flow);
    	return;
    }

    if (prefix_is_multicast (flow->destin)) {
        if (cmd == 'S') {
	    trace (TR_ERROR, srsvp->trace, "no send multicast\n");
	    qif_notify (srsvp, flow, -1);
	    return;
	}
	if ((rvp = ricd_get_rvp (flow->destin)) == NULL) {
	    trace (TR_ERROR, srsvp->trace, "rvp for %a not found\n", 
		   flow->destin);
	    qif_notify (srsvp, flow, -1);
	    return;
	}
	trace (TR_TRACE, srsvp->trace, "rvp for %a is %a\n", flow->destin,
		rvp);
        flow->sender = rvp;
	nexthop = rvp;
    }

    neighbor = srsvp_get_upstream (srsvp, nexthop, flow->req_qos, &errcode);
    if (neighbor == NULL) {
	char text[1024];
	trace (TR_ERROR, srsvp->trace, "next-hop for %a not found (%s)\n",
		    nexthop, srsvp_error_spec_string (errcode, text));
	qif_notify (srsvp, flow, -1);
	return;
    }

    if (srsvp_flow_find (srsvp, flow) != NULL) {
	trace (TR_ERROR, srsvp->trace, "flow exist\n");
	qif_notify (srsvp, flow, -1);
	return;
    }

    flow = srsvp_flow_copy_add (srsvp, flow);
    if (cmd == 'S') {
        srsvp_leaf_t *leaf;
	leaf = New (srsvp_leaf_t);
	leaf->neighbor = neighbor;
	leaf->neighbor->lih = 0; /* XXX */
	LL_Add2 (flow->ll_downstreams, leaf);
        trace_neighbor (TR_TRACE, neighbor->trace, leaf->neighbor, "add");
	flow->flags = SRSVP_FLOWF_SENDER;
	if (BIT_TEST (neighbor->vif->interface->flags, IFF_LOOPBACK)) {
	    BIT_SET (flow->flags, SRSVP_FLOWF_READY);
	    BIT_SET (leaf->flags, SRSVP_LEAFF_READY);
	    leaf->req_qos = copy_req_qos (flow->req_qos, NULL);
	    srsvp_notify_hqlip (srsvp, flow, leaf, ON);
    	    qif_add_flow (srsvp, flow, leaf);
	    qif_notify (srsvp, flow, 0);
	}
	else {
	    leaf->req_qos = NULL;
	    flow->sender_tspec = flow->req_qos;
	    flow->req_qos = NULL;
            srsvp_forward_msg (srsvp, SRSVP_MSG_PATH, 0, flow, neighbor);
	}
    }
    else {
        flow->upstream = neighbor;
	flow->flags = SRSVP_FLOWF_RECVER;
	if (BIT_TEST (neighbor->vif->interface->flags, IFF_LOOPBACK)) {
            srsvp_leaf_t *leaf;
	    leaf = New (srsvp_leaf_t);
	    leaf->neighbor = neighbor;
	    leaf->neighbor->lih = 0; /* XXX */
	    LL_Add2 (flow->ll_downstreams, leaf);
            trace_neighbor (TR_TRACE, neighbor->trace, leaf->neighbor, "add");
	    BIT_SET (flow->flags, SRSVP_FLOWF_READY);
	    BIT_SET (leaf->flags, SRSVP_LEAFF_READY);
	    leaf->req_qos = copy_req_qos (flow->req_qos, NULL);
	    srsvp_notify_hqlip (srsvp, flow, leaf, ON);
    	    qif_add_flow (srsvp, flow, leaf);
	    qif_notify (srsvp, flow, 0);
	}
	else {
            srsvp_forward_msg (srsvp, SRSVP_MSG_RESV0, 0, flow, neighbor);
	}
    }
}


/* "flow (send|recv) %a port %d (udp|tcp) %sreq-qos" */
int 
srsvp_flow_request_by_user (uii_connection_t *uii, char *send_s,
			    prefix_t *destin, 
			    int dport, char *proto_s, char *req_qos_s)
{
    int proto = IPPROTO_TCP;
    config_req_qos_t *config_req_qos;
    req_qos_t *req_qos = NULL;
    u_long errcode;
    srsvp_flow_t sflow, *flow;
    srsvp_neighbor_t *neighbor;
    srsvp_t *srsvp = RICD->srsvp;
    prefix_t sprefix;
    prefix_t *rvp = NULL;

#ifdef HAVE_IPV6
    if (destin->family == AF_INET6)
	srsvp = RICD6->srsvp;
#endif /* HAVE_IPV6 */

    if (strcasecmp (proto_s, "udp") == 0)
	proto = IPPROTO_UDP;
    else if (strcasecmp (proto_s, "tcp") == 0)
	proto = IPPROTO_TCP;

    LL_Iterate (CONFIG_RICD->ll_config_req_qoses, config_req_qos) {
	if (BIT_TEST (config_req_qos->flags, CONFIG_QOS_DELETED))
	    break;
	if (strcasecmp (config_req_qos->name, req_qos_s) == 0) {
	    req_qos = config_req_qos->req_qos;
	    break;
	}
    }
    if (req_qos == NULL) {
	config_notice (TR_ERROR, uii, "req-qos %s not found\n", req_qos_s);
	Deref_Prefix (destin);
	Delete (send_s);
	Delete (proto_s);
	Delete (req_qos_s);
	return (-1);
    }

    if (prefix_is_multicast (destin)) {
        if (strcasecmp (send_s, "send") == 0) {
	    config_notice (TR_ERROR, uii, "no send multicast\n");
	    Deref_Prefix (destin);
	    Delete (send_s);
	    Delete (proto_s);
	    Delete (req_qos_s);
	    return (-1);
	}
	if ((rvp = ricd_get_rvp (destin)) == NULL) {
	    config_notice (TR_ERROR, uii, "rvp for %a not found\n", destin);
	    Deref_Prefix (destin);
	    Delete (send_s);
	    Delete (proto_s);
	    Delete (req_qos_s);
	    return (-1);
	}
	config_notice (TR_TRACE, uii, "rvp for %a is %a\n", destin, rvp);
    }

    neighbor = srsvp_get_upstream (srsvp, (rvp)? rvp: destin, req_qos, 
				   &errcode);
    if (neighbor == NULL) {
	char text[1024];
	config_notice (TR_ERROR, uii, "%s %a not found (%s)\n", 
			(rvp)? "rvp": "detination", (rvp)? rvp: destin,
			srsvp_error_spec_string (errcode, text));
	Deref_Prefix (destin);
	Delete (send_s);
	Delete (proto_s);
	Delete (req_qos_s);
	return (-1);
    }

    /* hash function looks at prefix length, too */
    New_Prefix2 (neighbor->vif->prefix->family, 
		 prefix_tochar (neighbor->vif->prefix), 
		 -1, &sprefix);

    if (strcasecmp (send_s, "send") == 0) {
        srsvp_flow_create (srsvp, destin, proto, dport, 
			      &sprefix, dport /* XXX */,
			      req_qos, SRSVP_FLOWF_SENDER, &sflow);
    }
    else if (rvp) {
        srsvp_flow_create (srsvp, destin, proto, dport, 
			      rvp, dport /* XXX */,
			      req_qos, SRSVP_FLOWF_RECVER, &sflow);
    }
    else {
        srsvp_flow_create (srsvp, &sprefix, proto, dport, 
			      destin, dport /* XXX */,
			      req_qos, SRSVP_FLOWF_RECVER, &sflow);
    }
    if ((flow = srsvp_flow_find (srsvp, &sflow)) != NULL) {
	config_notice (TR_ERROR, uii, 
		"you can not change an existing one\n");
	Deref_Prefix (destin);
	Delete (send_s);
	Delete (proto_s);
	Delete (req_qos_s);
	return (-1);
    }

    flow = srsvp_flow_copy_add (srsvp, &sflow);
    if (strcasecmp (send_s, "send") == 0) {
        srsvp_leaf_t *leaf;
	leaf = New (srsvp_leaf_t);
	leaf->neighbor = neighbor;
	leaf->neighbor->lih = 0; /* XXX */
	leaf->req_qos = NULL;
	flow->sender_tspec = flow->req_qos;
	flow->req_qos = NULL;
	LL_Add2 (flow->ll_downstreams, leaf);
        trace_neighbor (TR_TRACE, neighbor->trace, leaf->neighbor, "add");
        srsvp_forward_msg (srsvp, SRSVP_MSG_PATH, 0, flow, neighbor);
        srsvp_destroy_flow (srsvp, flow);
    }
    else {
        flow->upstream = neighbor;
        srsvp_forward_msg (srsvp, SRSVP_MSG_RESV0, 0, flow, neighbor);
    }
    Deref_Prefix (destin);
    Delete (send_s);
    Delete (proto_s);
    Delete (req_qos_s);
    return (1);
}


int 
srsvp_no_flow_request_by_user (uii_connection_t *uii, char *ip, int num)
{
    srsvp_t *srsvp = RICD->srsvp;
    srsvp_flow_t *flow;
    int count = 1;

#ifdef HAVE_IPV6
    if (strcasecmp (ip, "ipv6") == 0)
	srsvp = RICD6->srsvp;
#endif /* HAVE_IPV6 */
    Delete (ip);

    if (srsvp->flows == NULL)
	return (0);
    pthread_mutex_lock (&srsvp->flows->mutex_lock);
    HASH_Iterate (srsvp->flows->table, flow) {
	if (count == num)
	    break;
    }
    pthread_mutex_unlock (&srsvp->flows->mutex_lock);
    if (flow == 0) {
	config_notice (TR_ERROR, uii, "no such flow: %d\n", num);
	return (0);
    }
    if (BIT_TEST (flow->flags, SRSVP_FLOWF_SENDER)) {
	srsvp_leaf_t *leaf;
	if (flow->ll_downstreams) {
	    LL_Iterate (flow->ll_downstreams, leaf) {
        	srsvp_forward_msg (srsvp, SRSVP_MSG_PATH_TEAR, 0, flow, 
				   leaf->neighbor);
		if (BIT_TEST (leaf->flags, SRSVP_LEAFF_READY)) {
		    srsvp_notify_hqlip (srsvp, flow, leaf, OFF);
    		    qif_del_flow (srsvp, flow, leaf);
		}
	    }
	}
    }
    else {
        if (flow->upstream)
            srsvp_forward_msg (srsvp, SRSVP_MSG_RESV_TEAR, 0, flow, 
			       flow->upstream);
    }
    srsvp_destroy_flow (srsvp, flow);
    return (1);
}


int 
srsvp_show_flows (uii_connection_t *uii, char *ip)
{
    srsvp_t *srsvp = RICD->srsvp;
    srsvp_flow_t *flow;
    int count = 1;

#ifdef HAVE_IPV6
    if (strcasecmp (ip, "ipv6") == 0)
	srsvp = RICD6->srsvp;
#endif /* HAVE_IPV6 */
    Delete (ip);

    if (srsvp->flows == NULL)
	return (0);
    pthread_mutex_lock (&srsvp->flows->mutex_lock);
    HASH_Iterate (srsvp->flows->table, flow) {
	if (count == 1) {
            uii_add_bulk_output (uii, 
		"%2s %4s %5s %15s %5s %5s %15s %5s %15s %3s "
		"%1s %4s %4s %3s %2s %2s %2s %2s\n",
		"NO", "S/R", "STAT", "DESTINATION", "PROTO", "DPORT",
		"SENDER", "SPORT", "UPSTREAM", "IF", 
		"P", "MTU", "PPS", "SEC", "CD", "CF", "RD", "RF");
	}
        uii_add_bulk_output (uii, "%2d", count++);
        uii_add_bulk_output (uii, " %4s",
	    BIT_TEST (flow->flags, SRSVP_FLOWF_SENDER)? "SEND":
	    BIT_TEST (flow->flags, SRSVP_FLOWF_RECVER)? "RECV": "FWRD");
        uii_add_bulk_output (uii, " %5s",
	    BIT_TEST (flow->flags, SRSVP_FLOWF_DELETED)? "DELED":
	    BIT_TEST (flow->flags, SRSVP_FLOWF_READY)? "READY":
	    BIT_TEST (flow->flags, SRSVP_FLOWF_RESV1)? "RESV1": 
	    BIT_TEST (flow->flags, SRSVP_FLOWF_RESV1)? "RESV0": "     ");
        uii_add_bulk_output (uii, " %15a %5d %5d %15a %5d",
	   flow->destin, flow->proto, flow->dport, flow->sender, flow->sport);
	if (flow->upstream) {
            uii_add_bulk_output (uii, " %15a %3s", 
		flow->upstream->prefix,
		flow->upstream->vif->interface->name);
	}
	else {
            uii_add_bulk_output (uii, " %15s %3s", "", "");
	}
        if (flow->req_qos) {
            uii_add_bulk_output (uii, 
		" %1u %4u %4u %3u %2u %2u %2u %2u",
		flow->req_qos->pri, flow->req_qos->mtu, 
		flow->req_qos->pps, flow->req_qos->sec,
		flow->req_qos->cd, flow->req_qos->cf, 
		flow->req_qos->rdly, flow->req_qos->rfee);
	}
	if (flow->errcode) {
	    char text[256];
	    srsvp_error_spec_string (flow->errcode, text);
            uii_add_bulk_output (uii, " %s", text);
	}

        uii_add_bulk_output (uii, "\n");

	if (flow->ll_downstreams) {
	    srsvp_leaf_t *leaf;
	    LL_Iterate (flow->ll_downstreams, leaf) {
                uii_add_bulk_output (uii, "%2s", "");
                uii_add_bulk_output (uii, " %4s", "LEAF");
        	uii_add_bulk_output (uii, " %5s",
	    	    BIT_TEST (flow->flags, SRSVP_FLOWF_DELETED)? "DELED":
		    BIT_TEST (leaf->flags, SRSVP_LEAFF_READY)? "READY":
		    BIT_TEST (leaf->flags, SRSVP_LEAFF_RESV1)? "RESV1": 
		    BIT_TEST (leaf->flags, SRSVP_LEAFF_RESV0)? "RESV0": 
			"     ");
                uii_add_bulk_output (uii, " %15a %49s %3s",
			leaf->neighbor->prefix, "",
			leaf->neighbor->vif->interface->name);
                if (leaf->req_qos) {
                uii_add_bulk_output (uii, 
			" %1u %4u %4u %3u %2u %2u %2u %2u",
		    leaf->req_qos->pri, leaf->req_qos->mtu, 
		    leaf->req_qos->pps, leaf->req_qos->sec,
		    leaf->req_qos->cd, leaf->req_qos->cf, 
		    leaf->req_qos->rdly, leaf->req_qos->rfee);
	        }
                uii_add_bulk_output (uii, "\n");
	    }
	}
    }
    pthread_mutex_unlock (&srsvp->flows->mutex_lock);
    return (1);
}

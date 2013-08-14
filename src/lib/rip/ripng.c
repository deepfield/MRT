/*
 * $Id: ripng.c,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
 */

#ifdef NT
#include <ntconfig.h>
#include <winsock2.h>
#ifdef HAVE_IPV6
#include <ws2ip6.h>
#endif /* HAVE_IPV6 */
#include <ws2tcpip.h>
#else
#include <config.h>
#endif /* NT */

#ifdef HAVE_IPV6
#ifdef NT
#else
#include <sys/fcntl.h>
#include <sys/uio.h>
#endif /* NT */

#include "mrt.h"
#include "api6.h"
#include "rip.h"


/* 
 * Given 1) the gateway we received the packet from, 
 *       2) a pointer to the packet, and
 *       3) the length (num bytes) of the packet, 
 * munge the packet making a linked list of prefix and attribute tuples
 */

LINKED_LIST *
ripng_process_packet_response (gateway_t * gateway, u_char * update, int bytes,
			       int pref)
{
    u_char *cp;
    prefix_t *prefix;
    nexthop_t *nexthop = ref_nexthop (gateway);
    rip_attr_t *attr;
    time_t now;
    LINKED_LIST *ll_rip_ann_rt = NULL;

#define RIPNG_RTELEN 20

    if ((bytes % RIPNG_RTELEN) != 0) {
	trace (TR_WARN, RIPNG->trace, "invalid RTE size %d\n", bytes);
    }

    time (&now);
    cp = update;

    while (cp < update + bytes) {
	struct in6_addr *addr6;
	char tmp6[INET6_ADDRSTRLEN];
	int tag, prefixlen, metric;
	rip_ann_rt_t *rip_ann_rt;

	if ((update + bytes) - cp < RIPNG_RTELEN)
	    break;
	addr6 = (struct in6_addr *) cp;
	cp += 16;

/* UTIL_GET_XXX requires type of argument is equal to XXX */

	BGP_GET_SHORT (tag, cp);
	BGP_GET_BYTE (prefixlen, cp);
	BGP_GET_BYTE (metric, cp);

#define RIPNG_NEXT_HOP 0xff
	if (metric == RIPNG_NEXT_HOP) {
	    if (IN6_IS_ADDR_UNSPECIFIED (addr6)) {
		trace (TR_PACKET, RIPNG->trace,
		       "nexthop is the originator itself %a\n",
		       gateway->prefix);
		continue;
	    }
	    if (!IN6_IS_ADDR_LINKLOCAL (addr6)) {
		trace (TR_WARN, RIPNG->trace,
		       "nexthop %s but not link-local address from %a\n",
		       inet_ntop (AF_INET6, addr6, tmp6, sizeof tmp6),
		       gateway->prefix);
		continue;
	    }
	    trace (TR_PACKET, RIPNG->trace,
		   "  nexthop %s\n",
		   inet_ntop (AF_INET6, addr6, tmp6, sizeof tmp6));
	    if (prefixlen != 0 && tag != 0)
		trace (TR_WARN, RIPNG->trace,
		       "non-zero prefixlen (%d) or tag (%d) "
		       "in specifying nexthop %s from %a\n",
		       prefixlen, tag,
		       inet_ntop (AF_INET6, addr6, tmp6, sizeof tmp6),
		       gateway->prefix);
	    deref_nexthop (nexthop);
	    prefix = New_Prefix (AF_INET6, addr6, 128);
	    nexthop = add_nexthop (prefix, gateway->interface);
	    Deref_Prefix (prefix);
	}
	else {
	    if (prefixlen > 128) {
	        trace (TR_WARN, RIPNG->trace,
		       "too large prefixlen %d\n", prefixlen);
		continue;
	    }
	    prefix = New_Prefix (AF_INET6, addr6, prefixlen);
	    attr = rip_new_attr (RIPNG, metric);
	    attr->gateway = gateway;
	    attr->nexthop = ref_nexthop (nexthop);
	    attr->metric = metric;
	    attr->tag = tag;
	    attr->utime = now;
	    attr->pref = pref;
            if (ll_rip_ann_rt == NULL)
                ll_rip_ann_rt = LL_Create (LL_DestroyFunction, rip_delete_rip_ann_rt, 
				       0);
	    rip_ann_rt = New (rip_ann_rt_t);
            rip_ann_rt->prefix = prefix;
            rip_ann_rt->attr = attr; 
            LL_Add (ll_rip_ann_rt, rip_ann_rt);
	}
    }
    deref_nexthop (nexthop);
    return (ll_rip_ann_rt);
}


LINKED_LIST *
ripng_process_packet_request (u_char * update, int bytes)
{
    u_char *cp = update;
    LINKED_LIST *ll_rip_ann_rt = NULL;

    while (cp < update + bytes) {
	int tag, prefixlen, metric;
        prefix_t *prefix;
        struct in6_addr *addr6;
	rip_ann_rt_t *rip_ann_rt;

	assert ((update + bytes) - cp >= RIPNG_RTELEN);
	addr6 = (struct in6_addr *) cp;
	cp += 16;

	BGP_GET_SHORT (tag, cp);
	BGP_GET_BYTE (prefixlen, cp);
	BGP_GET_BYTE (metric, cp);

	if (cp == update + bytes && metric == RIP_METRIC_INFINITY &&
	    prefixlen == 0 &&	/* tag == 0 && */
	    IN6_IS_ADDR_UNSPECIFIED (addr6)) {
	    trace (TR_PACKET, RIPNG->trace,
		   "  whole-table request, responding\n");
	    return (NULL);
	}

        prefix = New_Prefix (AF_INET6, &addr6, prefixlen);
        rip_ann_rt = New (rip_ann_rt_t);
        rip_ann_rt->prefix = prefix;
        rip_ann_rt->attr = NULL;
        rip_ann_rt->metric = metric;
        if (ll_rip_ann_rt == NULL)
            ll_rip_ann_rt = LL_Create (LL_DestroyFunction, rip_delete_rip_ann_rt, 0);
    }
    return (ll_rip_ann_rt);
}


/* 
 * start listening for broadcast ripng updates and request
 */
int
ripng_init_listen (interface_t *interface)
{
    struct sockaddr_in6 ripng;
    int sockfd;

    if ((sockfd = socket_open (AF_INET6, SOCK_DGRAM, 0)) < 0)
	return (-1);

    socket_reuse (sockfd, 1);
    socket_rcvbuf (sockfd, RIPNG_MIN_BUFSIZE);
#ifndef NT
    ipv6_multicast_loop (sockfd, 0);
    ipv6_pktinfo (sockfd, 1);
    ipv6_recvhops (sockfd, 1);
    ipv6_multicast_hops (sockfd, 255);
    ipv6_unicast_hops (sockfd, 255);
#endif /* NT */

    memset (&ripng, 0, sizeof (ripng));
    ripng.sin6_port = htons (RIPNG->port);
    ripng.sin6_family = AF_INET6;
    ripng.sin6_flowinfo = htonl (RIPNG_IPV6_PRIORITY);
    
#ifdef SIN6_LEN
    ripng.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
    if (interface) {
		assert (interface->link_local);
        memcpy (&ripng.sin6_addr, 
		prefix_toaddr6 (interface->link_local->prefix), 16);
#ifdef __KAME__
		ripng.sin6_addr.s6_addr[2] = (interface->index >> 8) & 0xff;
		ripng.sin6_addr.s6_addr[3] = interface->index & 0xff;
#endif /* __KAME__ */
    }

    if (bind (sockfd, (struct sockaddr *) &ripng, sizeof (ripng)) < 0) {
	trace (TR_ERROR, RIPNG->trace, "bind to port %d: %m\n",
		RIPNG->port);
	close (sockfd);
	return (-1);
    }

#ifdef NT
	ipv6_multicast_loop (sockfd, 0);
    ipv6_pktinfo (sockfd, 1);
    ipv6_recvhops (sockfd, 1);
    ipv6_multicast_hops (sockfd, 255);
    ipv6_unicast_hops (sockfd, 255);
#endif /* NT */

    trace (TR_TRACE, RIPNG->trace, "listening socket %d port %d at %s on %s\n",
	   sockfd, ntohs (ripng.sin6_port), 
	   (interface)? prefix_toa (interface->link_local->prefix): "*",
	   (interface)? interface->name: "?");
    return (sockfd);
}


static int
ripng_sendmsgto (rip_interface_t *rip_interface,
                 u_char * buffer, int buflen, u_long flag,
                 prefix_t *host, int port)
{
    interface_t *interface = rip_interface->interface;
    int sockfd = (rip_interface->sockfd >= 0)?
                    rip_interface->sockfd: RIPNG->sockfd;

    if (host == NULL) {
        host = RIPNG->all_routers;
        port = RIPNG->port;
    }

    return (send_packet (sockfd, buffer, buflen, 0, host, port, interface, 
			 RIPNG_IPV6_PRIORITY));
}


/* 
 * use multicast for multicast-capable interfaces 
 * use unicast for p-to-p non-multicast-capable interfaces (non standard way)
 * if ll_prefixes is NULL, send a request for complete routing table 
 *    ll_prefixes ... not implemented yet and usual daemon doesn't need it
 */
int
ripng_send_request (rip_interface_t *rip_interface, LINKED_LIST * ll_prefixes)
{
#define RIPNG_HDRLEN 4
#define RIPNG_RTELEN 20
    u_char buffer[RIPNG_HDRLEN + RIPNG_RTELEN];
    u_char *cp;
    int ret;

    assert (ll_prefixes == NULL);	/* XXX not yet implemented */
    cp = buffer;
    memset (buffer, 0, sizeof (buffer));

    BGP_PUT_BYTE (RIPNG_REQUEST, cp);
    BGP_PUT_BYTE (RIPNG_VERSION, cp);

    BGP_PUT_SHORT (0, cp);	/* must be 0 */
    memset (cp, 0, 16);
    cp += 16;

    BGP_PUT_SHORT (0, cp);	/* must be 0 */
    BGP_PUT_BYTE (0, cp);	/* length 0 or 16?? spec is not clear */
    BGP_PUT_BYTE (RIP_METRIC_INFINITY, cp);	/* infinity metric */

    if ((ret = ripng_sendmsgto (rip_interface, buffer, cp - buffer, 0,  
                       RIPNG->all_routers, RIPNG->port)) >= 0)
        trace (TR_TRACE, RIPNG->trace, "send request on %s\n",
               rip_interface->interface->name);
    return (ret);
}


/*
 * turn on the interface
 */
int
ripng_interface (rip_interface_t *rip_interface, int on)
{
    int ret = 0;
    interface_t *interface = rip_interface->interface;

    if (!BIT_TEST (interface->flags, IFF_MULTICAST) &&
		!BIT_TEST (interface->flags, IFF_POINTOPOINT)) {
		trace (TR_ERROR, RIPNG->trace,
               "on interface %s ignored due to NBMA\n",
               interface->name);
		return (-1);
    }
    if (BIT_TEST (interface->flags, IFF_MULTICAST))
        ret = join_leave_group (RIPNG->sockfd, interface, RIPNG->all_routers, on);
    if (ret >= 0 && on)
		ripng_send_request (rip_interface, NULL);
    return (ret);
}

/*
 * given an interface, broadcast ripng routes (according to policy)
 * we do this every RIPNG_UPDATE_INTERVAL
 * if change flag is set (==1) then only send routes marked as
 * changed
 */
int
ripng_send_update (LINKED_LIST *ll_rip_ann_rt,
		   rip_interface_t *rip_interface, prefix_t *host, int port)
{
    u_char *data, *cp;
    int count = 0; /* total */
    int routes = 0;		/* count of routes */
    int pdulen;
    LINKED_LIST *ll_tuple;
    tuple_t *tuple;
    rip_ann_rt_t *rip_ann_rt;
    interface_t *interface = rip_interface->interface;

    assert (interface);

#define IPV6_HDRLEN 40
#define UDP_HDRLEN 8
    pdulen = interface->mtu - IPV6_HDRLEN - UDP_HDRLEN;
    assert (pdulen >= RIPNG_HDRLEN + RIPNG_RTELEN);
    data = NewArray (u_char, pdulen);

    cp = data;
    memset (data, 0, pdulen);

    BGP_PUT_BYTE (RIPNG_RESPONSE, cp);
    BGP_PUT_BYTE (RIPNG_VERSION, cp);
    BGP_PUT_SHORT (0, cp);

    if (host)
        trace (TR_TRACE, RIPNG->trace, "send response to %a on %s\n",
	       host, interface->name);
    else
        trace (TR_TRACE, RIPNG->trace, "send response on %s\n",
	       interface->name);

    /* make a list first and then send them to avoid waiting on sendto() 
       with locking the route table */
    ll_tuple = LL_Create (0);

    /* on flashing update, locking should be done outer side
       because of keeping change flags and reset them after sending out */

    LL_Iterate (ll_rip_ann_rt, rip_ann_rt) {

	prefix_t *prefix = rip_ann_rt->prefix;
	rip_attr_t *attr = rip_ann_rt->attr;
	int metric = rip_ann_rt->metric;

	routes++;

	BGP_PUT_ADDR6 (prefix_tochar (prefix), cp);
	BGP_PUT_SHORT (attr->tag, cp);
	BGP_PUT_BYTE (prefix->bitlen, cp);
	BGP_PUT_BYTE (metric, cp);

	/* 
	 * see if we have filled up the buffer. If so, send packet and 
	 * create new buffer 
	 */
	if (cp - data > pdulen - RIPNG_RTELEN) {
	    tuple = New (tuple_t);
	    tuple->len = cp - data;
	    tuple->data = data;
	    LL_Add (ll_tuple, tuple);
	    data = NewArray (u_char, pdulen);
	    cp = data;
	    memset (data, 0, pdulen);
	    BGP_PUT_BYTE (RIPNG_RESPONSE, cp);
	    BGP_PUT_BYTE (RIPNG_VERSION, cp);
	    BGP_PUT_SHORT (0, cp);
	    count += routes;
	    routes = 0;
	}
    }

    /* okay, send packet (assuming we have one) */
    if (routes > 0) {
	tuple = New (tuple_t);
	tuple->len = cp - data;
	tuple->data = data;
	LL_Add (ll_tuple, tuple);
	count += routes;
    }
    else {
	/* delete the last buffer created but no routes */
	Delete (data);
    }

    LL_Iterate (ll_tuple, tuple) {
	ripng_sendmsgto (rip_interface, tuple->data, tuple->len, 0, host, port);
	Delete (tuple->data);
	Delete (tuple);
    }

    LL_Destroy (ll_tuple);
/*  Delete (tuple); */
    return (count);
}


/* 
 * read and process and RIPNG update packet recieved on our interface
 */
int
ripng_receive_update (rip_interface_t *rip_interface)
{
    u_char *buffer, *cp = buffer;
    int n, port;
    int command, version, zero;
    prefix_t *prefix = NULL;
    gateway_t *gateway = NULL;
    interface_t *interface;
    int sockfd;
    int hop_count = 255;

    sockfd = (rip_interface && rip_interface->sockfd >= 0)? 
		rip_interface->sockfd: RIPNG->sockfd;
    cp = buffer = NewArray (u_char, RIPNG_MIN_BUFSIZE);
#ifdef NT
	n = recvmsgfrom (sockfd, buffer, RIPNG_MIN_BUFSIZE, FIONBIO, 
                     &prefix, &port, &interface, NULL, &hop_count);
#else
    n = recvmsgfrom (sockfd, buffer, RIPNG_MIN_BUFSIZE, O_NONBLOCK, 
                     &prefix, &port, &interface, NULL, &hop_count);
   #endif /* NT */
 select_enable_fd (sockfd);
    if (n < 0)
	goto ignore;

    assert (interface);

    /*
     * get command first for later check
     */
    BGP_GET_BYTE (command, cp);
    BGP_GET_BYTE (version, cp);
    BGP_GET_SHORT (zero, cp);

    if (rip_interface == NULL) {
	trace (TR_TRACE, RIPNG->trace,
               "packet from %a at RIPNG socket %d\n", prefix, sockfd);
        rip_interface = RIPNG->rip_interfaces[interface->index];
	assert (rip_interface);
    }
    else if (rip_interface != RIPNG->rip_interfaces[interface->index]) {
	trace (TR_ERROR, RIPNG->trace,
               "confusion: from %a on %s but must be on %s\n",
               prefix, interface->name, rip_interface->interface->name);
        interface = rip_interface->interface;
    }

    if (!BITX_TEST (&RIPNG->interface_mask, interface->index)) {
	trace (TR_PACKET, RIPNG->trace,
	       "packet from %a on disabled interface %s\n",
	       prefix, interface->name);
	goto ignore;
    }
    if (RIPNG->alist >= 0 && apply_access_list (RIPNG->alist, prefix) == 0) {
        trace (TR_TRACE, RIPNG->trace,  
               "discard update from %a (a-list %d)\n", prefix, RIPNG->alist);
        goto ignore;
    }

    /*
     * common check for all commands
     */
    if (version != RIPNG_VERSION) {
	trace (TR_WARN, RIPNG->trace,
	       "unsupported version %d from %a on %s\n",
	       version, prefix, interface->name);
/* XXX  goto ignore; */
    }

    if (zero) {
	trace (TR_WARN, RIPNG->trace,
	       "non-zero pad field (value 0x%x) from %a on %s\n",
	       zero, prefix, interface->name);
/* XXX  goto ignore; */
    }

    if (command != RIPNG_RESPONSE && command != RIPNG_REQUEST) {
	trace (TR_WARN, RIPNG->trace,
	       "unsupported command %d from %a on %s, ignore!\n",
	       command, prefix, interface->name);
	goto ignore;
    }

    if (command == RIPNG_RESPONSE) {

	/* register the gateway */
	gateway = add_gateway (prefix, 0, interface);

	/* don't listen to things broadcast from our own interface */
	if (find_interface_local (prefix)) {
	    trace (TR_PACKET, RIPNG->trace,
		   "recv ignore own response from %a on %s, ignore!\n",
		   prefix, interface->name);
	    goto ignore;
	}

	if (IN6_IS_ADDR_V4MAPPED (prefix_toaddr6 (prefix))) {
	    trace (TR_WARN, RIPNG->trace, "received response "
		   "with ipv4 source from %a on %s, ignore!\n",
		   prefix, interface->name);
	    goto ignore;
	}

	if (!IN6_IS_ADDR_LINKLOCAL (prefix_toaddr6 (prefix))) {
	    trace (TR_WARN, RIPNG->trace,
		   "received response with non link-local source "
		   "from %a on %s, but continue\n", prefix, interface->name);
	}

	/* check if this interface is configured for RIPNG */
	if (!BITX_TEST (&RIPNG->interface_mask, interface->index)) {
	    trace (TR_PACKET, RIPNG->trace, "received response "
		   "from %a on unconfigured interface %s, ignore!\n",
		   gateway->prefix, interface->name);
	    goto ignore;
	}

	if (port != RIPNG->port) {
	    trace (TR_INFO, RIPNG->trace,
		   "non-standard source port %d from %a on %s, "
		   "ignored!\n", port,
		   gateway->prefix, interface->name);
	    goto ignore;
	}

	/*
	 * ID also suggests to check if the hop count is 255
	 */
	if (hop_count != 255) {
#ifdef notdef
	    trace (TR_INFO, RIPNG->trace,
		   "hop count %d from %a on %s, "
		   "ignored!\n", hop_count,
		   gateway->prefix, interface->name);
	    /* up to the recent versions, 
	       MRT RIPng sends updates with hop count 1 */
	    goto ignore;
#else
	    trace (TR_INFO, RIPNG->trace,
		   "hop count %d from %a on %s\n",
		   hop_count,
		   gateway->prefix, interface->name);
#endif
	}

	if (interface->mtu < n + IPV6_HDRLEN + UDP_HDRLEN) {
	    trace (TR_WARN, RIPNG->trace,
		   "received packet size %d (+%d hdrs) exceeds mtu %d, "
		   "from %a on %s\n",
		   n, IPV6_HDRLEN + UDP_HDRLEN, interface->mtu,
		   gateway->prefix, interface->name);
	}
	else {
	    trace (TR_TRACE, RIPNG->trace,
		   "recv response %d bytes from %a on %s\n",
		   n, gateway->prefix, interface->name);
	}

	if (n - (cp - buffer)) {
	    LINKED_LIST *ll_rip_ann_rt;

	    /* munge the ripng packet 
	       and return list of prefixes and attributes */

	    ll_rip_ann_rt = ripng_process_packet_response (gateway, cp, 
					n - (cp - buffer),
		(rip_interface->default_pref >= 0)?
                        rip_interface->default_pref: RIPNG_PREF);

	    if (ll_rip_ann_rt) {
	        /* update our tables */
	        if (RIPNG->process_update_fn)
	            RIPNG->process_update_fn (ll_rip_ann_rt);

	        LL_Destroy (ll_rip_ann_rt);
	    }
	}
    }
    else if (command == RIPNG_REQUEST) {

	/* register the gateway */
	if (port == RIPNG->port)
	    gateway = add_gateway (prefix, 0, interface);

	/* don't listen to things broadcast from our own interface
	   except for a query */
	if (find_interface_local (prefix) && port == RIPNG->port)
	    goto ignore;

	trace (TR_TRACE, RIPNG->trace,
	       "recv request %d bytes port %d from %a on %s\n",
	       n, port, prefix, interface->name);

#ifdef notdef
	/* request from over a router will be rejected for now */
	if (!IN6_IS_ADDR_LINKLOCAL (prefix_toaddr6 (prefix))) {
	    trace (TR_WARN, RIPNG->trace,
		   "received request "
		   "with non link-local source from %a on %s, ignore!\n",
		   prefix, interface->name);
	    goto ignore;
	}
#endif

	if (n - (cp - buffer) > 0) {
	    LINKED_LIST *ll_rip_ann_rt;

	    /* more than 1 entry */
	    ll_rip_ann_rt = ripng_process_packet_request (cp, n - (cp - buffer));
            rip_process_requst (RIPNG, ll_rip_ann_rt, rip_interface, prefix, port);
	    trace (TR_PACKET, RIPNG->trace,
		   "recv request answered to %a port %d on %s\n",
		   prefix, port, interface->name);
	}
	else {
	    trace (TR_WARN, RIPNG->trace,
		   "recv request no entry from %a on %s, discard it!\n",
		   prefix, interface->name);
	}
    }
    if (prefix)
	Deref_Prefix (prefix);
    Delete (buffer);
    return (1);

  ignore:
    if (prefix)
	Deref_Prefix (prefix);
    Delete (buffer);
    return (0);
}


int
ripng_process_update (LINKED_LIST *ll_rip_ann_rt)
{
    return (rip_process_update (RIPNG, ll_rip_ann_rt));
}


void
ripng_update_route (prefix_t * prefix, generic_attr_t * new,
                    generic_attr_t * old, int pref, int viewno)
{
    assert (viewno == 0);
    rip_update_route (RIPNG, prefix, new, old, pref);
}


int
ripng_start (int port)
{
    RIPNG->port = port;
    if ((RIPNG->sockfd = ripng_init_listen (NULL)) < 0) {
        trace (TR_ERROR, RIPNG->trace, "aborted due to error(s)\n");
        return (-1);
    }
    rip_start (RIPNG);
    select_add_fd_event ("ripng_receive_update", RIPNG->sockfd, SELECT_READ,
                         1, RIPNG->schedule, (event_fn_t) ripng_receive_update,
			 1, NULL);
    return (0);
}


void
ripng_stop (void)
{
    rip_stop (RIPNG);
}


void
ripng_init (trace_t *tr)
{
    assert (RIPNG == NULL);
    RIPNG = New (rip_t);
    RIPNG->trace = trace_copy (tr);
    RIPNG->proto = PROTO_RIPNG;
    RIPNG->port = RIPNG_DEFAULT_PORT;
    RIPNG->send_update_fn = ripng_send_update;
    RIPNG->process_update_fn = ripng_process_update;
    RIPNG->interface_fn = ripng_interface;
    RIPNG->all_routers = ascii2prefix (AF_INET6, "ff02::09");
    RIPNG->alist = -1;
    MRT->proto_update_route[PROTO_RIPNG] = ripng_update_route;
    set_trace (RIPNG->trace, TRACE_PREPEND_STRING, "RIPNG", 0);
    rip_init (RIPNG);
}


int
ripng_show (uii_connection_t * uii)           
{
    return (rip_show (RIPNG, uii));
}  


int
ripng_show_routing_table (uii_connection_t * uii, int optnum, char *ifname)
{
    int ret;

    if (optnum > 0) {
        ret = rip_show_routing_table (RIPNG, uii, ifname);
	Delete (ifname);
    }
    else
        ret = rip_show_routing_table (RIPNG, uii, NULL);
    return (ret);
}   


void
ripng_set (int first, ...)
{
    va_list ap;

    /* Process the Arguments */
    va_start (ap, first);
    rip_set (RIP, ap);
    va_end (ap);
}

#endif /* HAVE_IPV6 */

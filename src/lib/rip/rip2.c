/*
 * $Id: rip2.c,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
 */

#ifdef NT
#include <ntconfig.h>
#include <winsock2.h>
#ifdef HAVE_IPV6
#include <ws2ip6.h>
#endif /* HAVE_IPV6 */
#include <ws2tcpip.h>
#else
#include <sys/fcntl.h>
#endif /* NT */ 
#include <mrt.h>
#include <api6.h>
#include <rip.h>


LINKED_LIST *
rip2_process_packet_response (gateway_t * gateway, u_char * update, int bytes,
			      int pref)
{
    u_char *cp;
    time_t now;
    LINKED_LIST *ll_rip_ann_rt = NULL;

#define RIP_RTELEN 20

    if ((bytes % RIP_RTELEN) != 0) {
	trace (TR_WARN, RIP->trace, "invalid RTE size %d\n", bytes);
    }

    time (&now);
    cp = update;

    while (cp < update + bytes) {
	int afi, tag, prefixlen, metric;
	struct in_addr addr, mask, nhop;
        prefix_t *prefix;
        rip_attr_t *attr;
	rip_ann_rt_t *rip_ann_rt;

	BGP_GET_SHORT (afi, cp);
	BGP_GET_SHORT (tag, cp);
	BGP_GET_ADDR (&addr, cp);
	BGP_GET_ADDR (&mask, cp);
	BGP_GET_ADDR (&nhop, cp);
	BGP_GET_LONG (metric, cp);

	if (afi == 0xffff /* Authentication */ ) {
	    trace (TR_ERROR, RIP->trace,
		   "Authentication not supported (type %d)\n", tag);
	    continue;
	}
	/* IP = 1, IP6 = 2 defined in RFC 1700 p.91 but RIP RFC says 2 for IP */
	if (afi != 2 /* IP AFI */ ) {
	    trace (TR_ERROR, RIP->trace, "unknown afi = %d\n", afi);
	    continue;
	}

	prefixlen = mask2len (&mask, 4);
	prefix = New_Prefix (AF_INET, &addr, prefixlen);

	attr = rip_new_attr (RIP, metric);
	attr->gateway = gateway;
	if (nhop.s_addr == INADDR_ANY) {
	    attr->nexthop = ref_nexthop (gateway);
	}
	else {
	    prefix_t *prefix = New_Prefix (AF_INET, &nhop, 32);
	    attr->nexthop = add_nexthop (prefix, gateway->interface);
	    Deref_Prefix (prefix);
	}
	attr->metric = metric;
	attr->tag = tag;
	attr->utime = now;
	attr->pref = pref;
	if (ll_rip_ann_rt == NULL)
	    ll_rip_ann_rt = LL_Create (LL_DestroyFunction, rip_delete_rip_ann_rt, 0);
	rip_ann_rt = New (rip_ann_rt_t);
	rip_ann_rt->prefix = prefix;
	rip_ann_rt->attr = attr;
	LL_Add (ll_rip_ann_rt, rip_ann_rt);
    }
    return (ll_rip_ann_rt);
}


LINKED_LIST *
rip2_process_packet_request (u_char * update, int bytes)
{
    u_char *cp = update;
    LINKED_LIST *ll_rip_ann_rt = NULL;

    if ((bytes % RIP_RTELEN) != 0) {
	trace (TR_WARN, RIP->trace, "invalid RTE size %d\n", bytes);
    }

    while (cp < update + bytes) {
	int afi, tag, prefixlen, metric;
	struct in_addr addr, mask, nhop;
        prefix_t *prefix;
	rip_ann_rt_t *rip_ann_rt;

	if ((update + bytes) - cp < RIP_RTELEN)
	    break;

	BGP_GET_SHORT (afi, cp);
	BGP_GET_SHORT (tag, cp);
	BGP_GET_ADDR (&addr, cp);
	BGP_GET_ADDR (&mask, cp);
	BGP_GET_ADDR (&nhop, cp);
	BGP_GET_LONG (metric, cp);

	prefixlen = mask2len (&mask, 4);

	/* Address family field in RIP REQUEST must be zero. (RFC1058 3.4.1) 
		"Vladimir V. Ivanov" <vlad@elis.tusur.ru> */
	if (cp == update + bytes && afi == 0 &&
	    metric == RIP_METRIC_INFINITY /* &&
	    prefixlen == 0 && tag == 0 && 
	    addr.s_addr == INADDR_ANY && mask.s_addr == INADDR_ANY &&
	    nhop.s_addr == INADDR_ANY */) {
	    trace (TR_PACKET, RIP->trace,
		   "  whole-table request, responding\n");
	    return (NULL);
	}

	if (afi != 2 /* IP AFI */) {
	    trace (TR_WARN, RIP->trace, "unknown afi = %d\n", afi);
	    continue;
	}

	prefix = New_Prefix (AF_INET, &addr, prefixlen);
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
 * start listening for broadcast rip updates
 */
int
rip2_init_listen (interface_t *interface)
{
    struct sockaddr_in serv_addr;
    int sockfd;

    if ((sockfd = socket_open (AF_INET, SOCK_DGRAM, 0)) < 0)
	return (-1);

    socket_reuse (sockfd, 1);
    socket_broadcast (sockfd, 1); /* in case of fall back */
    ip_multicast_loop (sockfd, 0);
    ip_recvttl (sockfd, 1);
    ip_pktinfo (sockfd, 1);

    memset (&serv_addr, 0, sizeof (serv_addr));
    /* check that NOT listening to portmaster! */
    serv_addr.sin_port = htons (RIP->port);
    serv_addr.sin_family = AF_INET;
    if (interface) {
        assert (interface->primary);
        assert (interface->primary->prefix->family == AF_INET);
        serv_addr.sin_addr.s_addr = prefix_tolong (interface->primary->prefix);
    }
    else {
        serv_addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind (sockfd,
	      (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0) {
	trace (TR_ERROR, RIP->trace, "bind to port %d: %m\n", RIP->port);
	close (sockfd);
	return (-1);
    }
    trace (TR_TRACE, RIP->trace, "listening port %d at %s on %s\n",
           ntohs (serv_addr.sin_port),
	   (interface)? prefix_toa (interface->primary->prefix): "*",
           (interface)? interface->name: "?");
    return (sockfd);
}


static int
rip2_sendmsgto (rip_interface_t *rip_interface,
		u_char * buffer, int buflen, u_long flag,
		prefix_t *host, int port)
{
    interface_t *interface = rip_interface->interface;
    int sockfd = (rip_interface->sockfd >= 0)?
		    rip_interface->sockfd: RIP->sockfd;

    if (host == NULL) {
	host = RIP->all_routers;
	port = RIP->port;
    }

    return (send_packet (sockfd, buffer, buflen, 0, host, port, interface, 0));
}


/*
 * broadcast request for list of prefixes
 * if NULL, send a request for complete routing table 
 */
int
rip2_send_request (rip_interface_t *rip_interface, LINKED_LIST * ll_prefixes)
{
    u_char buffer[RIP_MAX_PDU], *cp = buffer;
    int ret;

    assert (ll_prefixes == NULL);	/* XXX not yet implemented */

    BGP_PUT_BYTE (RIP_REQUEST, cp);
    BGP_PUT_BYTE (RIP_VERSION, cp);
    BGP_PUT_SHORT (0, cp);	/* unused */
    BGP_PUT_SHORT (0, cp);     /* AF_UNSPEC */
    BGP_PUT_SHORT (0, cp);	/* tag */
    BGP_PUT_NETLONG (0, cp);	/* ip address */
    BGP_PUT_NETLONG (0, cp);	/* subnet mask */
    BGP_PUT_NETLONG (0, cp);	/* next hop */
    BGP_PUT_LONG (RIP_METRIC_INFINITY, cp);

    if ((ret = rip2_sendmsgto (rip_interface, buffer, cp - buffer, 0, 
		       RIP->all_routers, RIP->port)) >= 0)
	    trace (TR_TRACE, RIP->trace, "send request on %s\n",
		   rip_interface->interface->name);
    return (ret);
}


/*
 * turn on the interface
 */
int
rip2_interface (rip_interface_t *rip_interface, int on)
{
    int ret = 0;
    interface_t *interface = rip_interface->interface;

    if ((!BIT_TEST (interface->flags, IFF_BROADCAST) ||
         !BIT_TEST (interface->flags, IFF_MULTICAST)) &&
	!BIT_TEST (interface->flags, IFF_POINTOPOINT)) {
	trace (TR_ERROR, RIP->trace,
               "on interface %s ignored due to NBMA\n",
               interface->name);
	return (-1);
    }
    if (BIT_TEST (interface->flags, IFF_MULTICAST))
        ret = join_leave_group (RIP->sockfd, interface, RIP->all_routers, on);
    if (ret >= 0 && on)
	rip2_send_request (rip_interface, NULL);
    return (ret);
}


/*
 * given an interface, broadcast rip routes (according to policy) 
 * we do this every RIP_UPDATE_INTERVAL
 */
int
rip2_send_update (LINKED_LIST *ll_rip_ann_rt,
		  rip_interface_t *rip_interface, prefix_t *host, int port)
{
    u_char buffer[RIP_MAX_PDU], *cp = buffer;
    int count = 0; /* total */
    int routes = 0;
    rip_ann_rt_t *rip_ann_rt;

    BGP_PUT_BYTE (RIP_RESPONSE, cp);
    BGP_PUT_BYTE (RIP_VERSION, cp);
    BGP_PUT_SHORT (0, cp);	/* unused */

    /* on flashing update, locking should be done outer side
       because of keeping change flags and reset them after sending out */

    LL_Iterate (ll_rip_ann_rt, rip_ann_rt) {
        prefix_t *prefix = rip_ann_rt->prefix;
        rip_attr_t *attr = rip_ann_rt->attr;
	int metric = rip_ann_rt->metric;
	struct in_addr addr;

	BGP_PUT_SHORT (2, cp);	/* afi */
	BGP_PUT_SHORT (attr->tag, cp);	/* tag */
	BGP_PUT_ADDR (prefix_tochar (prefix), cp);	/* ip address */
	len2mask (prefix->bitlen, &addr, sizeof addr);
	BGP_PUT_ADDR (&addr, cp);	/* subnet mask */
	BGP_PUT_NETLONG (0, cp);	/* next hop, itself only XXX */
	BGP_PUT_LONG (metric, cp);
	routes++;

	/* see if we have filled up the buffer */
	if (cp - buffer > RIP_MAX_PDU - RIP_RTELEN) {
	    if (rip2_sendmsgto (rip_interface, buffer, cp - buffer, 0,
				host, port) < 0)
		return (-1);

	    if (host) {
		trace (TR_TRACE, RIP->trace, "send %d routes to %s\n",
		       routes, host);
	    }
	    else if (rip_interface)
		trace (TR_TRACE, RIP->trace, "send %d routes on %s\n",
		       routes, rip_interface->interface->name);
	    else
		assert (0);
	    cp = buffer;
	    BGP_PUT_BYTE (RIP_RESPONSE, cp);
	    BGP_PUT_BYTE (RIP_VERSION, cp);
	    BGP_PUT_SHORT (0, cp);	/* unused */
	    count += routes;
	    routes = 0;
	}

    }

    if (routes > 0) {
	count += routes;
	if (rip2_sendmsgto (rip_interface, buffer, cp - buffer, 0,
			    host, port) < 0)
	    return (-1);

	    if (host) {
		trace (TR_TRACE, RIP->trace, "send %d routes to %s\n",
		       routes, host);
	    }
	    else if (rip_interface)
		trace (TR_TRACE, RIP->trace, "send %d routes on %s\n",
		       routes, rip_interface->interface->name);
	    else
		assert (0);
    }
    return (count);
}


/* rip_receive_update
 * read and process and RIP update packet recieved on
 * our interface
 */
int
rip2_receive_update (rip_interface_t *rip_interface)
{
#define RIP_MAX_PDU 512
    u_char buffer[RIP_MAX_PDU], *cp = buffer;
    int n, port;
    int command, version, zero;
    prefix_t *prefix;
    gateway_t *gateway;
    interface_t *interface;
    int sockfd;

    sockfd = (rip_interface && rip_interface->sockfd)? 
		rip_interface->sockfd: RIP->sockfd;
#ifdef NT
	n = recvmsgfrom (sockfd, buffer, sizeof (buffer), FIONBIO,
                     &prefix, &port, &interface, NULL, NULL);
#else
    n = recvmsgfrom (sockfd, buffer, sizeof (buffer), O_NONBLOCK,
                     &prefix, &port, &interface, NULL, NULL);
    #endif /* NT */


select_enable_fd (sockfd);
    if (n <= 0)
	return (0);
    assert (prefix);

    if (interface == NULL) {
	trace (TR_WARN, RIP->trace,
	       "discard packet from %a (interface unknown)\n", prefix);
	goto ignore;
    }
    if (rip_interface == NULL) {
        trace (TR_TRACE, RIP->trace,
               "packet from %a at RIP socket %d\n", prefix, sockfd);
        rip_interface = RIP->rip_interfaces[interface->index];
        assert (rip_interface);
    }
    else if (rip_interface != RIP->rip_interfaces[interface->index]) {
        trace (TR_ERROR, RIP->trace,
               "confusion: from %a on %s but must be on %s\n", prefix,
               interface->name, rip_interface->interface->name);
        interface = rip_interface->interface;
    }
    if (RIP->alist >= 0 && apply_access_list (RIP->alist, prefix) == 0) {
	trace (TR_TRACE, RIP->trace,
	       "discard update from %a (a-list %d)\n", prefix, RIP->alist);
	goto ignore;
    }

    if (!BITX_TEST (&RIP->interface_mask, interface->index)) {
        trace (TR_PACKET, RIP->trace,
               "packet from %a on disabled interface %s\n",                     
               prefix, interface->name);         
        goto ignore;
    }

    assert (rip_interface);

    /*
     * get command first for later check
     */
    BGP_GET_BYTE (command, cp);
    BGP_GET_BYTE (version, cp);
    BGP_GET_SHORT (zero, cp);

    if (version != RIP_VERSION) {
	trace (TR_WARN, RIP->trace,
	       "unsupported version %d from %a on %s\n",
	       version, prefix, interface->name);
	goto ignore;
    }

    if (zero) {
	trace (TR_WARN, RIP->trace,
	       "non-zero pad field (value 0x%x) from %a on %s\n",
	       zero, prefix, interface->name);
/* XXX  goto ignore; */
    }

    if (command != RIP_RESPONSE && command != RIP_REQUEST) {
	trace (TR_WARN, RIP->trace,
	       "unsupported command %d from %a on %s, ignore!\n",
	       command, prefix, interface->name);
	goto ignore;
    }

    if (command == RIP_RESPONSE) {

	/* register the gateway */
	gateway = add_gateway (prefix, 0, interface);

	/* don't listen to things broadcast from our own interface */
	if (find_interface_local (prefix)) {
	    trace (TR_PACKET, RIP->trace,
		   "recv ignore own response from %a on %s, ignore!\n",
		   prefix, interface->name);
	    goto ignore;
	}

	/* check if this interface is configured for RIP */
	if (!BITX_TEST (&RIP->interface_mask, interface->index)) {
	    trace (TR_PACKET, RIP->trace, "received response "
		   "from %a on unconfigured interface %s, ignore!\n",
		   gateway->prefix, interface->name);
	    goto ignore;
	}

	if (port != RIP->port) {
	    trace (TR_INFO, RIP->trace,
		   "non-standard source port %d from %a on %s, "
		   "ignored!\n", port,
		   gateway->prefix, interface->name);
	    goto ignore;
	}

	trace (TR_TRACE, RIP->trace,
	       "recv response %d bytes from %a on %s\n",
	       n, gateway->prefix, interface->name);

	if (n - (cp - buffer)) {
	    LINKED_LIST *ll_rip_ann_rt;

	    ll_rip_ann_rt = rip2_process_packet_response (gateway, cp, 
				n - (cp - buffer),
		(rip_interface->default_pref >= 0)? 
			rip_interface->default_pref: RIP_PREF);

	    if (ll_rip_ann_rt) {
                /* update our tables */
                if (RIP->process_update_fn)
                    RIP->process_update_fn (ll_rip_ann_rt);

                LL_Destroy (ll_rip_ann_rt);
	    }
	}
    }
    else if (command == RIP_REQUEST) {

	/* register the gateway */
	if (port == RIP->port)
	    gateway = add_gateway (prefix, 0, interface);

	/* don't listen to things broadcast from our own interface
	   except for a query */
	if (find_interface_local (prefix) && port == RIP->port) {
	    goto ignore;
	}

	trace (TR_TRACE, RIP->trace,
	       "recv request %d bytes port %d from %a on %s\n",
	       n, port, prefix, interface->name);

	if (n - (cp - buffer) > 0) {
	    LINKED_LIST *ll_rip_ann_rt;

	    /* more than 1 entry */
	    ll_rip_ann_rt = rip2_process_packet_request (cp, n - (cp - buffer));
	    rip_process_requst (RIP, ll_rip_ann_rt, rip_interface, prefix, port);
	    trace (TR_PACKET, RIP->trace,
		   "recv request answered to %a port %d on %s\n",
		   prefix, port, interface->name);
	}
	else {
	    trace (TR_WARN, RIP->trace,
		   "recv request no entry from %a on %s, discard it!\n",
		   prefix, interface->name);
	    goto ignore;
	}
    }
    if (prefix)
	Deref_Prefix (prefix);
    return (1);
  ignore:
    if (prefix)
	Deref_Prefix (prefix);
    return (0);
}


int 
rip2_process_update (LINKED_LIST *ll_rip_ann_rt)
{
    return (rip_process_update (RIP, ll_rip_ann_rt));
}


void
rip2_update_route (prefix_t * prefix, generic_attr_t * new,
                   generic_attr_t * old, int pref, int viewno)
{
    assert (viewno == 0);
    rip_update_route (RIP, prefix, new, old, pref);
}


int
rip2_start (int port)
{
    RIP->port = port;
    if ((RIP->sockfd = rip2_init_listen (NULL)) < 0) {
        trace (TR_ERROR, RIP->trace, "aborted due to error(s)\n");
        return (-1);
    }
    rip_start (RIP);
    select_add_fd_event ("rip2_receive_update", RIP->sockfd, SELECT_READ,
                         1, RIP->schedule, (event_fn_t) rip2_receive_update, 
			 1, NULL);
    return (0);
}


void 
rip2_stop (void)
{
    rip_stop (RIP);
}


void
rip2_init (trace_t *tr)
{
    assert (RIP == NULL);
    RIP = New (rip_t);
    RIP->trace = trace_copy (tr);
    RIP->proto = PROTO_RIP;
    RIP->port = RIP_DEFAULT_PORT;
    RIP->send_update_fn = rip2_send_update;
    RIP->process_update_fn = rip2_process_update;
    RIP->interface_fn = rip2_interface;
    RIP->all_routers = ascii2prefix (AF_INET, "224.0.0.9");
    RIP->alist = -1;
    MRT->proto_update_route[PROTO_RIP] = rip2_update_route;
    set_trace (RIP->trace, TRACE_PREPEND_STRING, "RIP", 0);
    rip_init (RIP);
}


int     
rip2_show (uii_connection_t * uii)
{
    return (rip_show (RIP, uii));
}


int
rip2_show_routing_table (uii_connection_t * uii, int optnum, char *ifname)
{
    int ret;

    if (optnum > 0) {
        ret = rip_show_routing_table (RIP, uii, ifname);
        Delete (ifname);
    }
    else
        ret = rip_show_routing_table (RIP, uii, NULL);
    return (ret);
}


void
rip2_set (int first, ...)
{
    va_list ap;

    /* Process the Arguments */
    va_start (ap, first);
    rip_set (RIP, ap);
    va_end (ap);
}

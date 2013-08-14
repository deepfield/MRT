/*
 * $Id: common.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>
#include <api6.h>
#include <interface.h>
#include <ctype.h>


#ifdef NT
#include <winsock2.h>
#ifdef HAVE_IPV6
#include <ws2ip6.h>
#endif /* HAVE_IPV6 */
#include <ws2tcpip.h>
#endif /* NT */

static void 
call_change_fns (int cmd, interface_t *interface, ll_addr_t *if_addr)
{
    interface_call_fn_t fn;
    assert (cmd == 'A' || cmd == 'D');

    LL_Iterate (INTERFACE_MASTER->ll_call_fns, fn) {
	fn (cmd, interface, if_addr);
    }
}


interface_t *
new_interface (char *name, u_long flags, int mtu, int index)
{
    interface_t *interface;
    char tmpx[MAXLINE];

    assert (INTERFACE_MASTER);

    if (name != NULL) {
        interface = find_interface_byname (name);
        if (interface == NULL) {
            INTERFACE_MASTER->number++;
#ifndef NT
			if (index <= 0)
				index = INTERFACE_MASTER->number;
            if (index > MAX_INTERFACES || INTERFACE_MASTER->index2if[index]) {
                trace (TR_FATAL, INTERFACE_MASTER->trace,
	           "Too many interfaces %d (should be <= %d)\n", 
	           INTERFACE_MASTER->number, MAX_INTERFACES);
				return (NULL);
            }
#endif /* NT */
			
            interface = New (interface_t);
            interface->flags = 0; /* value 0 never appears */
            interface->mtu = 0;
            interface->ll_addr = LL_Create (0);
    #if 0
            memset (interface->dlist_in, 0, sizeof (interface->dlist_in));
            memset (interface->dlist_out, 0, sizeof (interface->dlist_out));
            interface->metric_in = 1;
            interface->metric_out = 0;
            interface->default_pref = -1;
#ifdef HAVE_IPV6
            interface->default_pref6 = -1;
#endif /* HAVE_IPV6 */
#endif
            safestrncpy (interface->name, name, sizeof (interface->name));

            interface->index = index;
#ifdef HAVE_MROUTING
            interface->vif_index = -1;
#endif /* HAVE_MROUTING */
#if defined(HAVE_MROUTING) || defined(HAVE_MROUTING6)
            interface->threshold = 1;
            interface->rate_limit = 0;
#endif /* HAVE_MROUTING || HAVE_MROUTING6 */
            INTERFACE_MASTER->index2if[index] = interface;
	    pthread_mutex_lock (&INTERFACE_MASTER->mutex_lock);
            LL_Add (INTERFACE_MASTER->ll_interfaces, interface);
	    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
        }
    }
    else {
	interface = find_interface_byindex (index);
    }

    if (interface->flags != flags || interface->mtu != mtu) {
        interface->flags = flags;
        interface->mtu = mtu;

        if (INTERFACE_MASTER->max_mtu < mtu)
	    INTERFACE_MASTER->max_mtu = mtu;

        trace (TR_INFO, INTERFACE_MASTER->trace,
	       "Interface %s flags %s mtu %d index %d\n", interface->name, 
		print_iflags (tmpx, sizeof (tmpx), flags), mtu, index);

        call_change_fns ((flags & IFF_UP)?'A': 'D', interface, NULL);
    }
    return (interface);
}


ll_addr_t *
New_Addr (int family, void *addr, int bitlen, void *broadcast)
{

    ll_addr_t *if_addr;

    if_addr = New (ll_addr_t);
    assert (addr);
    if_addr->prefix = New_Prefix (family, addr, bitlen);
    if (broadcast)
	if_addr->broadcast = New_Prefix (family, broadcast, bitlen);
    else
	if_addr->broadcast = NULL;

    return (if_addr);
}


static int 
compare_interface (interface_t *a, interface_t *b)
{
	if (BIT_TEST (a->flags, IFF_LOOPBACK) !=
	         BIT_TEST (b->flags, IFF_LOOPBACK)) {
	    return (BIT_TEST (a->flags, IFF_LOOPBACK)? 1: -1);
	}
	if (BIT_TEST (a->flags, IFF_TUNNEL) !=
	         BIT_TEST (b->flags, IFF_TUNNEL)) {
	    return (BIT_TEST (a->flags, IFF_TUNNEL)? 1: -1);
	}
	if (BIT_TEST (a->flags, IFF_VIF_TUNNEL) !=
	         BIT_TEST (b->flags, IFF_VIF_TUNNEL)) {
	    return (BIT_TEST (a->flags, IFF_VIF_TUNNEL)? 1: -1);
	}
	if (BIT_TEST (a->flags, IFF_UP) !=
	         BIT_TEST (b->flags, IFF_UP)) {
	    return (BIT_TEST (a->flags, IFF_UP)? -1: 1);
	}

	if (BIT_TEST (a->flags, IFF_POINTOPOINT) !=
	         BIT_TEST (b->flags, IFF_POINTOPOINT)) {
	    return (BIT_TEST (a->flags, IFF_POINTOPOINT)? 1: -1);
	}

    /* choose the largest ip number */
    if (a->primary && b->primary) {
	if (ntohl (prefix_tolong (b->primary->prefix)) !=
	    ntohl (prefix_tolong (a->primary->prefix))) {
	    return ((ntohl (prefix_tolong (a->primary->prefix)) >
		     ntohl (prefix_tolong (b->primary->prefix)))? -1: 1);
	}
    }
    return (0);
}


static void
update_default_interface (void)
{
    interface_t *interface;
#ifdef HAVE_IPV6
    interface_t *candidate = NULL;
#endif /* HAVE_IPV6 */

    pthread_mutex_lock (&INTERFACE_MASTER->mutex_lock);
    LL_SortFn (INTERFACE_MASTER->ll_interfaces, 
	       (LL_CompareProc) compare_interface);

    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
	if (interface->primary)
	    break;
    }
    INTERFACE_MASTER->default_interface = interface;
    if (interface) {
        trace (TR_INFO, INTERFACE_MASTER->trace,
	           "DEFAULT Interface %s\n", interface->name);
	MRT->default_id = prefix_tolong (interface->primary->prefix);
    }
#ifdef HAVE_IPV6
    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
	if (interface->primary6) {
	    if (candidate == NULL) {
		candidate = interface;
	    }
	    else if (!IN6_IS_ADDR_UC_GLOBAL 
		(prefix_toaddr6 (candidate->primary6->prefix)) &&
	      IN6_IS_ADDR_UC_GLOBAL 
		(prefix_toaddr6 (interface->primary6->prefix))) {
	        candidate = interface;
	    }
	}
    }
    INTERFACE_MASTER->default_interface6 = candidate;
    if (candidate)
        trace (TR_INFO, INTERFACE_MASTER->trace,
	           "DEFAULT V6 Interface %s\n", candidate->name);
#endif /* HAVE_IPV6*/
    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
}


static void
update_primary (interface_t *interface)
{
    ll_addr_t *if_addr;

    LL_Iterate (interface->ll_addr, if_addr) {
        if (interface->primary == NULL && 
		if_addr->prefix->family == AF_INET) {
	    interface->primary = if_addr;
        }
#ifdef HAVE_IPV6
	if (if_addr->prefix->family != AF_INET6)
	    continue;
	if (!IN6_IS_ADDR_LOOPBACK (prefix_toaddr6 (if_addr->prefix)) &&
	    (IN6_IS_ADDR_V4MAPPED (prefix_toaddr6 (if_addr->prefix)) ||
	     IN6_IS_ADDR_V4COMPAT (prefix_toaddr6 (if_addr->prefix)))) {
	    continue;
	}
	if (interface->primary6 == NULL || (!IN6_IS_ADDR_UC_GLOBAL (
		    prefix_toaddr6 (interface->primary6->prefix)) &&
		IN6_IS_ADDR_UC_GLOBAL (prefix_toaddr6 (if_addr->prefix)))) {
	    interface->primary6 = if_addr;
	}
	if (interface->link_local == NULL &&
	    IN6_IS_ADDR_LINKLOCAL (prefix_toaddr6 (if_addr->prefix))) {
	    interface->link_local = if_addr;
	}
#endif /* HAVE_IPV6 */
    }
}


/*
 * I know I need to introduce a mutex lock since it may be called from 
 * kernel asynchronously
 */
interface_t *
update_addr_of_interface (int cmd,
			  interface_t * interface, int family,
		          void *addr, int bitlen, void *broadcast)
{
    ll_addr_t *if_addr;
    char ifa[256];
    char tmp6[64];
    char tmp7[64];

    assert (interface);
    assert (INTERFACE_MASTER);

#ifdef HAVE_IPV6
    assert (family == AF_INET || family == AF_INET6);
#else
    assert (family == AF_INET);
#endif /* HAVE_IPV6 */

#ifndef NT
    if (broadcast)
        sprintf (ifa, "%s %s %s/%d %s %s", interface->name,
	         (family == AF_INET)? "inet": "inet6",
	         inet_ntop (family, addr, tmp6, sizeof tmp6), bitlen,
	         BIT_TEST (interface->flags, IFF_POINTOPOINT) ?
	         "dest" : "broadcast",
	         inet_ntop (family, broadcast, tmp7, sizeof tmp7));
    else
#endif /* NT */ 
        sprintf (ifa, "%s %s %s/%d", interface->name,
	         (family == AF_INET)? "inet": "inet6",
	         inet_ntop (family, addr, tmp6, sizeof tmp6), bitlen);

#ifdef HAVE_IPV6
    /* we don't accept these ones */
    if (family == AF_INET6) {

        /* IN6_IS_ADDR_LOOPBACK is required since IN6_IS_ADDR_V4COMPAT
	   on some implementations includes ::1 */
	if (!IN6_IS_ADDR_LOOPBACK ((struct in6_addr *) addr) && (
	       IN6_IS_ADDR_UNSPECIFIED ((struct in6_addr *) addr) ||
	       IN6_IS_ADDR_V4MAPPED ((struct in6_addr *) addr) ||
	       IN6_IS_ADDR_V4COMPAT ((struct in6_addr *) addr))) {
	    trace (TR_TRACE, INTERFACE_MASTER->trace,
	           "Interface %s skipped\n", ifa);
	    return (NULL);
	}
	if (broadcast && !IN6_IS_ADDR_LOOPBACK ((struct in6_addr *) addr) && (
	      IN6_IS_ADDR_UNSPECIFIED ((struct in6_addr *) broadcast) ||
	      IN6_IS_ADDR_V4MAPPED ((struct in6_addr *) broadcast) ||
	      IN6_IS_ADDR_V4COMPAT ((struct in6_addr *) broadcast))) {
	    trace (TR_TRACE, INTERFACE_MASTER->trace,
	           "Interface %s skipped\n", ifa);
	    return (NULL);
	}
    }
#endif

    LL_Iterate (interface->ll_addr, if_addr) {
	int plen = (family == AF_INET)? 4: 16;
	if (if_addr->prefix->family != family)
	    continue;
	if (memcmp (prefix_tochar (if_addr->prefix), addr, plen) == 0 &&
	        if_addr->prefix->bitlen == bitlen)
	    break;
    }

    if (cmd == 'D') {
	if (if_addr == NULL) {
	    trace (TR_WARN, INTERFACE_MASTER->trace,
	           "Interface %s not found for deletion\n", ifa);
	    return (NULL);
	}
        LL_Remove (interface->ll_addr, if_addr);
	/* after removed, call them so find_interface can't find it */
        if (BIT_TEST (interface->flags, IFF_UP))
	    call_change_fns ('D', interface, if_addr);
	if (if_addr->prefix)
	    Deref_Prefix (if_addr->prefix);
	if (if_addr->broadcast)
	    Deref_Prefix (if_addr->broadcast);
	if (if_addr == interface->primary) {
	    interface->primary = NULL;
	    update_primary (interface);
	}
#ifdef HAVE_IPV6
	if (if_addr == interface->primary6) {
	    interface->primary6 = NULL;
	    update_primary (interface);
	}
	if (if_addr == interface->link_local) {
	    interface->link_local = NULL;
	    update_primary (interface);
	}
#endif /* HAVE_IPV6 */
	Delete (if_addr);
	trace (TR_WARN, INTERFACE_MASTER->trace,
	       "Interface %s deleted\n", ifa);
	return (NULL);
    }
    assert (cmd == 'A');

    if (if_addr == NULL) {
        if_addr = New_Addr (family, addr, bitlen, broadcast);
        LL_Add (interface->ll_addr, if_addr);
    }

    update_primary (interface);
    trace (TR_INFO, INTERFACE_MASTER->trace, "Interface %s\n", ifa);
    /* interface may not be up */
    if (BIT_TEST (interface->flags, IFF_UP))
        call_change_fns ('A', interface, if_addr);
    return (interface);
}


interface_t *
add_addr_to_interface (interface_t * interface, int family,
                       void *addr, int len, void *broadcast)
{
    return (update_addr_of_interface ('A', interface, family, addr, len,
				      broadcast));
}


int
init_interfaces (trace_t * ltrace)
{
    assert (INTERFACE_MASTER == NULL);
    INTERFACE_MASTER = New (interface_master_t);
    INTERFACE_MASTER->ll_interfaces = LL_Create (0);
    INTERFACE_MASTER->trace = trace_copy (ltrace);
    set_trace (INTERFACE_MASTER->trace, TRACE_PREPEND_STRING, "IF", 0);
    INTERFACE_MASTER->number = 0;
    INTERFACE_MASTER->max_mtu = 576;
    INTERFACE_MASTER->default_interface = NULL;
    INTERFACE_MASTER->ll_call_fns = LL_Create (0);
    pthread_mutex_init (&INTERFACE_MASTER->mutex_lock, NULL);
#ifndef NT
    if ((INTERFACE_MASTER->sockfd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
        trace (TR_FATAL, INTERFACE_MASTER->trace, "socket for AF_INET (%m)\n");
    }
#ifdef HAVE_IPV6
    if ((INTERFACE_MASTER->sockfd6 = socket (AF_INET6, SOCK_DGRAM, 0)) < 0) {
        trace (TR_WARN, INTERFACE_MASTER->trace, "socket for AF_INET6 (%m)\n");
    }
#endif /* HAVE_IPV6 */
#endif /* NT */

    read_interfaces ();
    /* it's better to update default interface 
	whenever interfaces change, though */
    update_default_interface ();


	// NT is not dual stack. We can have an IPv6 only machine
/* original by Craig -- #if !defined(HAVE_IPV6) && defined(NT) */
/* I'm not sure but I need to change here for other platforms */
#if !defined(NT) || (!defined(HAVE_IPV6) && defined(NT))
    if (INTERFACE_MASTER->default_interface == NULL) {
        trace (TR_FATAL, INTERFACE_MASTER->trace, 
	       "Interface initialization Failed, Aborting\n");
		return (-1);
    }
#endif /* NT */
#ifdef HAVE_IPV6
	if (INTERFACE_MASTER->default_interface6 == NULL) {
        trace (TR_FATAL, INTERFACE_MASTER->trace, 
	       "Interface initialization Failed, Aborting\n");
		return (-1);
    }
#endif /* HAVE_IPV6 */

    return (1);
}


/* 
 * Given a prefix, find an interface that prefix is on
 */
interface_t *
find_interface (prefix_t * prefix)
{
    return (find_interface_flags (prefix, 0));
}


/* 
 * Given a prefix, find an interface with the specified flags 
 * that prefix is on if flags == 0, then see everything
 */
interface_t *
find_interface_flags (prefix_t * prefix, u_long flags)
{
    interface_t *interface;
    int llocal = 0;
    int p2p;

    /* bgpsim doesn't initialize ifs */
    if (INTERFACE_MASTER == NULL)
	return (NULL);

#ifdef HAVE_IPV6
    if (prefix_is_linklocal (prefix)) {
	llocal++;
    }
#endif /* HAVE_IPV6 */


#ifdef NT
#ifdef HAVE_IPV6
	if (prefix->family == AF_INET6)
		return (NT_find_interface (prefix, flags));
#endif /* HAVE_IPV6 */
#endif /* NT */
    pthread_mutex_lock (&INTERFACE_MASTER->mutex_lock);

/* p2p interface's destination first */
for (p2p = 1; p2p >= 0; p2p--) {
    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {

	if (p2p == 1 && !BIT_TEST (interface->flags, IFF_POINTOPOINT))
	    continue;
	if (p2p == 0 && BIT_TEST (interface->flags, IFF_POINTOPOINT))
	    continue;

	if (flags && !BIT_TEST (interface->flags, flags))
	    continue;

	if (llocal && interface->ll_addr) {
    	    ll_addr_t *ll_addr;
	    LL_Iterate (interface->ll_addr, ll_addr) {
		if (ll_addr->prefix == NULL)
		    continue;
		if (ll_addr->prefix->family != prefix->family)
		    continue;
		if (address_equal (prefix, ll_addr->prefix)) {
   	    	    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
	    	    return (interface);
		}
	    }
	}
	else if (is_prefix_on (prefix, interface)) {
   	    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
	    return (interface);
	}
#ifdef HAVE_MROUTING
	if (interface->flags & IFF_VIF_TUNNEL) {
    	    if (interface->tunnel_destination &&
		    prefix->family == interface->tunnel_destination->family) {
		if (a_include_b (interface->tunnel_destination, prefix)) {
    		    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
		    return (interface);
		}
	    }
	}
#endif /* HAVE_MROUTING */
    }
}

    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
    return (NULL);
}


/* 
 * Given a prefix, find a tunnel with the prefix as destination
 */
interface_t *
find_tunnel_interface (prefix_t * prefix)
{
    interface_t *interface = NULL;

    /* bgpsim doesn't initialize ifs */
    if (INTERFACE_MASTER == NULL)
	return (NULL);

#ifdef HAVE_MROUTING
    pthread_mutex_lock (&INTERFACE_MASTER->mutex_lock);
    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
	if (!BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
	    continue;
	if (interface->tunnel_destination == NULL)
	    continue;
	if (address_equal (interface->tunnel_destination, prefix))
	    break;
    }
    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
#endif /* HAVE_MROUTING */
    return (interface);
}


/*
 * Given a prefix, find interfaces on that prefix's network
 *   matches exactly or includes
 */
LINKED_LIST *
find_network (prefix_t * prefix)
{
    interface_t *interface;
    ll_addr_t *ll_addr;
    LINKED_LIST *ll = NULL;

    if (INTERFACE_MASTER == NULL) return (NULL);

    pthread_mutex_lock (&INTERFACE_MASTER->mutex_lock);
    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {

	if (interface->ll_addr) {
	    LL_Iterate (interface->ll_addr, ll_addr) {
		prefix_t *addr = ll_addr->prefix;
		if (addr == NULL)
		    continue;
		if (addr->family != prefix->family)
		    continue;
		if (addr->bitlen < prefix->bitlen)
		    continue;
		if (BIT_TEST (interface->flags, IFF_POINTOPOINT) &&
			ll_addr->broadcast != NULL)
		    addr = ll_addr->broadcast;

		if (a_include_b (prefix, addr)) {
		    if (ll == NULL)
			ll = LL_Create (0);
		    LL_Add (ll, interface);
		}
	    }
	}
    }
    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
    return (ll);
}


/* 
 * Given a name, find an interface that has the name
 */
interface_t *
find_interface_byname (char *name)
{
    interface_t *interface;

    if (INTERFACE_MASTER == NULL) return (NULL);

    pthread_mutex_lock (&INTERFACE_MASTER->mutex_lock);
    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
	if (strcasecmp (name, interface->name) == 0) {
    	    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
	    return (interface);
	}
    }
    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
    return (NULL);
}


/* if a digit doesn't follow the name, all interfaces starting with the name
   will be returned */
LINKED_LIST *
find_interface_byname_all (char *name)
{
    LINKED_LIST *ll = NULL;
    int all = 0;
    int len = strlen (name);
    interface_t *interface;

    if (INTERFACE_MASTER == NULL) return (ll);

    if (!isdigit (name[len - 1]))
	all++;

    pthread_mutex_lock (&INTERFACE_MASTER->mutex_lock);

    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
	int match = 0;

	if (all == 0) {
	    if (strcasecmp (name, interface->name) == 0)
	        match++;
	}
	else {
	    if (strncasecmp (name, interface->name, len) == 0 &&
		   (strlen (interface->name) == len ||
		    isdigit (interface->name [len])))
	        match++;
	}
	if (match) {
	    if (ll == NULL)
		ll = LL_Create (0);
	    LL_Add (ll, interface);
	}
    }
    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
    return (ll);
}


/* 
 * if it belongs to a local interface, its pointer returned
 * this is used to detect when we have received a broadcast packet from 
 * ourselves in rip, and ripng
 */
interface_t *
find_interface_local (prefix_t * prefix)
{
    interface_t *interface;
    int p2p;

    if (INTERFACE_MASTER == NULL) return (NULL);

#ifndef HAVE_IPV6
    assert (prefix->family == AF_INET);
#else
    assert (prefix->family == AF_INET || prefix->family == AF_INET6);
#endif /* HAVE_IPV6 */

    pthread_mutex_lock (&INTERFACE_MASTER->mutex_lock);
/* network interface's destination first */
for (p2p = 0; p2p <= 1; p2p++) {
    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
	if (p2p == 1 && !BIT_TEST (interface->flags, IFF_POINTOPOINT))
	    continue;
	if (p2p == 0 && BIT_TEST (interface->flags, IFF_POINTOPOINT))
	    continue;
	if (is_prefix_local_on (prefix, interface)) {
    	    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
    	    return (interface);
	}
    }
}
    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
    return (interface);
}


/* 
 * if it belongs to a local interface, its pointer returned
 */
interface_t *
find_interface_direct (prefix_t * prefix)
{
    interface_t *interface;
    int p2p;

    if (INTERFACE_MASTER == NULL) return (NULL);

#ifndef HAVE_IPV6
    assert (prefix->family == AF_INET);
#else
    assert (prefix->family == AF_INET || prefix->family == AF_INET6);
#endif /* HAVE_IPV6 */

    pthread_mutex_lock (&INTERFACE_MASTER->mutex_lock);
/* p2p interface's destination first */
for (p2p = 1; p2p >= 0; p2p--) {
    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
	if (p2p == 1 && !BIT_TEST (interface->flags, IFF_POINTOPOINT))
	    continue;
	if (p2p == 0 && BIT_TEST (interface->flags, IFF_POINTOPOINT))
	    continue;
	if (is_prefix_on (prefix, interface)) {
    	    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
    	    return (interface);
	}
    }
}
    pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
    return (interface);
}


/* 
 * compatible purpose
 */
interface_t *
local_interface (int family, void *cp)
{
    prefix_t ptmp, *prefix = &ptmp;

    if (INTERFACE_MASTER == NULL) return (NULL);

    if ((prefix->family = family) == AF_INET) {
	prefix->bitlen = 32;
	memcpy (&prefix->add.sin, cp, 4);
    }
#ifdef HAVE_IPV6
    else if (family == AF_INET6) {
	prefix->bitlen = 128;
	memcpy (&prefix->add.sin6, cp, 16);
    }
#endif /* HAVE_IPV6 */

    return (find_interface_local (prefix));
}


typedef struct {
    u_int bit;
    char *name;
} bits;
static bits iflags[] =
{
    {IFF_UP, "UP"},
#ifdef IFF_BROADCAST
    {IFF_BROADCAST, "BROADCAST"},
#endif /* IFF_BROADCAST */
#ifdef IFF_DEBUG
    {IFF_DEBUG, "DEBUG"},
#endif /* IFF_DEBUG */
#ifdef IFF_LOOPBACK
    {IFF_LOOPBACK, "LOOPBACK"},
#endif /* IFF_LOOPBACK */
#ifdef IFF_POINTOPOINT
    {IFF_POINTOPOINT, "POINTOPOINT"},
#endif /* IFF_POINTOPOINT */
#ifdef IFF_NOTRAILERS
    {IFF_NOTRAILERS, "NOTRAILERS"},
#endif /* IFF_NOTRAILERS */
#ifdef IFF_RUNNING
    {IFF_RUNNING, "RUNNING"},
#endif /* IFF_RUNNING */
#ifdef IFF_NOARP
    {IFF_NOARP, "NOARP"},
#endif /* IFF_NOARP */
#ifdef IFF_PROMISC
    {IFF_PROMISC, "PROMISC"},
#endif /* IFF_PROMISC */
#ifdef IFF_ALLMULTI
    {IFF_ALLMULTI, "ALLMULTI"},
#endif /* IFF_ALLMULTI */
#ifdef IFF_OACTIVE
    {IFF_OACTIVE, "OACTIVE"},
#endif /* IFF_OACTIVE */
#ifdef IFF_SIMPLEX
    {IFF_SIMPLEX, "SIMPLEX"},
#endif /* IFF_SIMPLEX */
#ifdef IFF_LINK0
    {IFF_LINK0, "LINK0"},
    {IFF_LINK1, "LINK1"},
    {IFF_LINK2, "LINK2"},
#endif /* IFF_LINK0 */
#ifdef IFF_MULTICAST
    {IFF_MULTICAST, "MULTICAST"},
#endif /* IFF_MULTICAST */
#ifdef IFF_USERDEF
    {IFF_USERDEF, "USERDEF"},
#endif /* IFF_USERDEF */
#ifdef IFF_TUNNEL
    {IFF_TUNNEL, "TUNNEL"},
#endif /* IFF_TUNNEL */
#ifdef IFF_VIF_TUNNEL
    {IFF_TUNNEL, "VIF_TUNNEL"},
#endif /* IFF_VIF_TUNNEL */
    {0, NULL}
};


char *
print_iflags (char *tmpx, int len, u_long flags)
{
    int i, l, n = 0;

    assert (len >= 3);
    tmpx[n++] = '<';
    for (i = 0; iflags[i].bit; i++) {
	if (!BIT_TEST (flags, iflags[i].bit))
	    continue;
	if (n > 1)
	    tmpx[n++] = ',';
	l = strlen (iflags[i].name);
	if (n + l + 1 > len - 1)
	    break;
	strcpy (tmpx + n, iflags[i].name);
	n += l;
    }
    tmpx[n++] = '>';
    tmpx[n] = '\0';
    return (tmpx);
}


int 
mask2len (void *vmask, int bytes)
{
    int i, j, bitlen = 0;
    u_char *mask = vmask;

    if (bytes == 0 || mask == NULL)
	return (bitlen);
    for (i = 0; i < bytes; i++, bitlen += 8) {
	if (mask[i] != 0xff)
	    break;
    }
    if (i != bytes && mask[i]) {
	for (j = 7; j > 0; j--, bitlen++) {
	    if ((mask[i] & (1 << j)) == 0)
		break;
	}
    }
    /* this doesn't check if the rest of bits are all 0 or not */
    /* test in another place if contiguous or not */

#if 0
    if (bitlen == 0)
	bitlen = bytes * 8;
#endif
    return (bitlen);
}


u_char *
len2mask (int bitlen, void *vmask, int bytes)
{
    int i;
    u_char *mask = vmask;

    assert (bytes * 8 >= bitlen);
    if (bitlen == 0) {
		memset (mask, 0, bytes);
		return (mask);
    }
    if (mask == NULL || bytes == 0)
		return (NULL);
    for (i = 0; i < (bitlen / 8); i++)
		mask[i] = 0xff;
    if (bitlen < (bytes * 8))
		mask[i++] = 0xff << (8 - (bitlen & 7));
    for (; i < bytes; i++)
		mask[i] = 0;
    return (mask);
}


interface_t *
find_interface_byindex (int index)
{
    if (INTERFACE_MASTER == NULL) return (NULL);

#ifdef notdef
    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
	if (interface->index == index)
	    return (interface);
    }
    return (NULL);
#else
    if (index < 0 || index >= MAX_INTERFACES)
	return (NULL);
    return (INTERFACE_MASTER->index2if[index]);
#endif
}


/* with proto and add/delete -- called from the kernel */
int 
update_kernel_route (int cmd,
		     int family, void *dest, void *nhop, int masklen, int index,
		     int proto)
{
    prefix_t *prefix, *nexthop;
    int len = 32;
    interface_t *interface = NULL;
    generic_attr_t *attr;
    u_long flags = MRT_RTOPT_KERNEL;

#ifdef HAVE_IPV6
    assert (family == AF_INET || family == AF_INET6);
#else
    assert (family == AF_INET);
#endif /* HAVE_IPV6 */

    if (family == AF_INET) {
	if (*(u_long *) nhop == INADDR_ANY) {
	    /* proto = PROTO_CONNECTED; */
	    /* proto = PROTO_KERNEL; */
	    /* return (0); */
	}
	if (IN_MULTICAST (ntohl (*(u_long *)dest)))
	    return (0);
    }
#ifdef HAVE_IPV6
    else {
        struct in6_addr zero6;

	memset (&zero6, 0, sizeof (zero6));
	/* linux way of direct connected route */
	if (memcmp (nhop, &zero6, 16) == 0) {
	    /* proto = PROTO_CONNECTED; */
	    /* proto = PROTO_KERNEL; */
	    /* return (0); */
	}
	/*
	 * I'm not sure but for now these prefixs are ignored
	 */
	if (((!IN6_IS_ADDR_UNSPECIFIED ((struct in6_addr *) dest)
		    || masklen > 0) &&
	        !IN6_IS_ADDR_LOOPBACK ((struct in6_addr *) dest) &&
	        IN6_IS_ADDR_V4COMPAT ((struct in6_addr *) dest)) ||
	    IN6_IS_ADDR_LINKLOCAL ((struct in6_addr *) dest) ||
	    IN6_IS_ADDR_MULTICAST ((struct in6_addr *) dest))
	    return (0);
	len = 128;
    }
#endif /* HAVE_IPV6 */

    if (index > 0) {
	interface = find_interface_byindex (index);
    }

    nexthop = New_Prefix (family, nhop, len);
    prefix = New_Prefix (family, dest, masklen);
    trace (TR_INFO, MRT->trace, "KERNEL READ(%c) %p %a index %d proto %s\n",
	   cmd, prefix, nexthop, index, proto2string (proto));
    assert (proto == PROTO_KERNEL || proto == PROTO_STATIC
				  || proto == PROTO_CONNECTED); /* XXX */
    attr = New_Generic_Attr (proto);
    attr->nexthop = add_nexthop (nexthop, interface);
    attr->gateway = add_gateway (nexthop, 0, interface);

    /* XXX This is a hack. Sometimes, kernel has unavailable routes with
       connected status which will not be removed by MRT. So, change it to
       kernel route that will be later removed */
    if (!nexthop_available (attr->nexthop))
	attr->type = PROTO_KERNEL;

    /* don't announce a route for loopback and ::/xx */
    if (prefix_is_loopback (prefix) ||
        prefix_is_unspecified (prefix))
	flags |= MRT_RTOPT_SUPPRESS;

    if (MRT->rib_update_route) {
	/* kernel routes go to unicast routing table only */
	assert (cmd == 'A' || cmd == 'D');
	if (cmd == 'A')
            MRT->rib_update_route (prefix, attr, NULL, KERNEL_PREF, 
				   flags, 0);
	else if (cmd == 'D')
            MRT->rib_update_route (prefix, NULL, attr, KERNEL_PREF, 
				   flags, 0);
    }
    Deref_Generic_Attr (attr);
    Deref_Prefix (prefix);
    Deref_Prefix (nexthop);
    return (1);
}


int 
add_kernel_route (int family, void *dest, void *nhop, int masklen, int index)
{
    return (update_kernel_route ('A',
			         family, dest, nhop, masklen, index, 
			         PROTO_KERNEL));
}

static mtimer_t *timeout;

static void
kernel_route_timeout (void)
{
    if (MRT->rib_flush_route) {
        MRT->rib_flush_route (PROTO_KERNEL, AFI_IP, SAFI_UNICAST);
#ifdef HAVE_IPV6
        MRT->rib_flush_route (PROTO_KERNEL, AFI_IP6, SAFI_UNICAST);
#endif /* HAVE_IPV6 */
    }
}


void
kernel_read_rt_table (int seconds)
{
    if (MRT->rib_update_route) {
	sys_kernel_read_rt_table ();
        if (seconds > 0) {
            timeout = New_Timer2 ("kernel routes timeout timer",
			          seconds, TIMER_AUTO_DELETE|TIMER_ONE_SHOT,
				  NULL, kernel_route_timeout, 0);
            Timer_Turn_ON (timeout);
	}

    }
}


/*
 * add all of the interface routes to the appropriate ribs
 */
void
add_interfaces_to_rib (int cmd, interface_t *interface, ll_addr_t *if_addr)
{
    prefix_t *network, *nexthop = NULL;
    generic_attr_t *attr;
    u_long flags = 0;
    prefix_t *pointopoint = NULL;
    int pplen = 32;
    interface_t *interface2 = interface;

    assert (cmd == 'I' || cmd == 'A' || cmd == 'D');

    /* initialization */
    if (cmd == 'I') {
	assert (interface == NULL);
	assert (if_addr == NULL);

	/* I can't lock here since find_interface is used inside */
	/* pthread_mutex_lock (&INTERFACE_MASTER->mutex_lock); */
        LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
	    /* skip inactive ones */
	    if (!BIT_TEST (interface->flags, IFF_UP))
		continue;
	    if (interface->ll_addr == NULL)
	        return;
            LL_Iterate (interface->ll_addr, if_addr) {
	        add_interfaces_to_rib ('A', interface, if_addr);
	    }
	}
	pthread_mutex_lock (&INTERFACE_MASTER->mutex_lock);
	LL_Add (INTERFACE_MASTER->ll_call_fns, add_interfaces_to_rib);
	pthread_mutex_unlock (&INTERFACE_MASTER->mutex_lock);
	return;
    }

    /* interface up/down */
    if (if_addr == NULL) {
	if (interface->ll_addr == NULL)
	    return;
        LL_Iterate (interface->ll_addr, if_addr) {
	    add_interfaces_to_rib (cmd, interface, if_addr);
	}
	return;
    }

    if (BIT_TEST (interface->flags, IFF_POINTOPOINT))
	pointopoint = if_addr->broadcast;

    if (BIT_TEST (interface->flags, IFF_LOOPBACK))
	flags |= MRT_RTOPT_SUPPRESS;

    network = if_addr->prefix;

    if (network->family == AF_INET) {
	/* OK */
        if (BIT_TEST (interface->flags, IFF_POINTOPOINT)) {
            /* ipv4 dummy nexthop for p2p local side */
            nexthop = ascii2prefix (AF_INET, "127.0.0.1/32");
	    interface2 = find_interface (nexthop);
	}
	else {
            /* ipv4 dummy nexthop for direct connected route */
            nexthop = ascii2prefix (AF_INET, "0.0.0.0/32");
	}
    }
#ifdef HAVE_IPV6
    else if (network->family == AF_INET6) {

	if (!prefix_is_loopback (network) && !prefix_is_unspecified (network)
		&& !prefix_is_global (network))
	    return;

        if (BIT_TEST (interface->flags, IFF_POINTOPOINT)) {
            /* ipv6 dummy nexthop for p2p local side */
            nexthop = ascii2prefix (AF_INET6, "::1/128");
	    interface2 = find_interface (nexthop);
        }
        else {
            /* ipv6 dummy nexthop for direct connected route */
            nexthop = ascii2prefix (AF_INET6, "::/128");
	}
	pplen = 128;
    }
#endif /* HAVE_IPV6 */
    else {
	/* skip others */
	return;
    }

    assert (nexthop);
    /* create new one for masking */
    network = New_Prefix (network->family, prefix_tochar (network),
			  pointopoint ? pplen: network->bitlen);
    /* masking may not be needed */
    netmasking (network->family, prefix_tochar (network),
		network->bitlen);

    trace (TR_INFO, MRT->trace, "%s an interface route for %s\n",
	   (cmd == 'A')?  "Adding": "Deleting", interface->name);
    attr = New_Generic_Attr (PROTO_CONNECTED);
    attr->nexthop = add_nexthop (nexthop, interface2);
    attr->gateway = add_gateway (nexthop, 0, interface2);

    if (MRT->rib_update_route) {
        MRT->rib_update_route (network, 
			(cmd == 'A')? attr: NULL, (cmd == 'D')? attr: NULL, 
			CONNECTED_PREF, flags, SAFI_UNICAST);
        MRT->rib_update_route (network, 
			(cmd == 'A')? attr: NULL, (cmd == 'D')? attr: NULL,
			CONNECTED_PREF, flags, SAFI_MULTICAST);
    }
    Deref_Generic_Attr (attr);
    Deref_Prefix (network);

    if (pointopoint) {
	/* create new one for masking */
	pointopoint = New_Prefix (pointopoint->family,
				  prefix_tochar (pointopoint),
				  pplen);
	/* masking may not be needed */
	netmasking (pointopoint->family, prefix_tochar (pointopoint),
		    pointopoint->bitlen);

	trace (TR_INFO, MRT->trace, 
	       "%s an interface route for %s\n", 
		(cmd == 'A')? "Adding": "Deleting", interface->name);
	Deref_Prefix (nexthop);
	/* use the local side of the p2p interface */
	nexthop = New_Prefix (if_addr->prefix->family, 
			      prefix_tochar (if_addr->prefix), pplen);
        attr = New_Generic_Attr (PROTO_CONNECTED);
        attr->nexthop = add_nexthop (nexthop, interface);
        attr->gateway = add_gateway (nexthop, 0, interface);
        if (MRT->rib_update_route) {
       	    MRT->rib_update_route (pointopoint,
			    (cmd == 'A')? attr: NULL, (cmd == 'D')? attr: NULL,
			    CONNECTED_PREF, flags, SAFI_UNICAST);
       	    MRT->rib_update_route (pointopoint, 
			    (cmd == 'A')? attr: NULL, (cmd == 'D')? attr: NULL,
			    CONNECTED_PREF, flags, SAFI_MULTICAST);
	}
        Deref_Generic_Attr (attr);
	Deref_Prefix (pointopoint);
    }
    Deref_Prefix (nexthop);
}


void
kernel_update_route (prefix_t * dest, generic_attr_t * new, 
		     generic_attr_t * old, int pref)
/* pref is not used */
{
    int newindex = 0, oldindex = 0, rc;
    prefix_t *newhop = NULL, *oldhop = NULL;

    if (dest->family == AF_INET && !MRT->kernel_install_flag4)
		return;
#ifdef HAVE_IPV6
    if (dest->family == AF_INET6 && !MRT->kernel_install_flag6)
	return;
#endif /* HAVE_IPV6 */

    if (new) {
	assert (new->nexthop);
        newindex = (new->nexthop->interface)?
			new->nexthop->interface->index: 0;
        newhop = new->nexthop->prefix;
    }
    if (old) {
	assert (old->nexthop);
        oldindex = (old->nexthop->interface)?
			old->nexthop->interface->index: 0;
        oldhop = old->nexthop->prefix;
    }
    rc = sys_kernel_update_route (dest, newhop, oldhop, newindex, oldindex);

    trace (TR_TRACE, MRT->trace, "KERNEL %s %s nexthop %s index %d %s\n",
	   (newhop && oldhop == NULL) ? "ADD" : 
	   (newhop == NULL && oldhop) ? "DEL" :
	   (newhop && oldhop) ? "CHG" : "???",
	   prefix_toax (dest),
	   prefix_toa (newhop? newhop: oldhop), newindex,
	   (rc < 0) ? "FAILED" : "OK");
}


static char n2b[256] = {
0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 
1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8, 
};

int 
how_many_bits (interface_bitset_t *bitset)
{
    int n = 0;
    int i;
    u_char *ubits = (u_char *) bitset->bits;

    for (i = 0; i < sizeof (bitset->bits); i++) {
	n += n2b [ubits [i]];
    }
    return (n);
}

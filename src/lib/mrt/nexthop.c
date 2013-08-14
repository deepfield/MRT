/* 
 * $Id: nexthop.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>
#ifdef NT
#include <ntconfig.h>
#include <winsock2.h>
#ifdef HAVE_IPV6
#include <ws2ip6.h>
#endif /* HAVE_IPV6 */
#include <ws2tcpip.h>
#endif /* NT */


static u_int
nexthop_hash_fn (nexthop_t *nexthop, u_int size)
{
    if (BIT_TEST (nexthop->flags, GATEWAY_UNSPEC)) {
		int val = 0;
		if (nexthop->interface)
			val += nexthop->interface->index;
		val += nexthop->routerid;
		val += nexthop->AS;
		val = val % size;
		return (val);
    }
	
#ifdef HAVE_IPV6
    if (nexthop->prefix->family == AF_INET6) {
		u_int val, buff[4];
		memcpy (buff, prefix_tochar (nexthop->prefix), 16);
		val = buff[0] ^ buff[1] ^ buff[2] ^ buff[3];
		val ^= (val >> 16);
		if (nexthop->interface)
			val += nexthop->interface->index;
		val += nexthop->routerid;
		val += nexthop->AS;
		val = val % size;
		return (val);
    }
    else
#endif /* HAVE_IPV6 */
		if (nexthop->prefix->family == AF_INET) {
			u_int val;
			u_char dest[4];
			memcpy (dest, prefix_tochar (nexthop->prefix), 4);
			val = dest[0] + dest[1] + dest[2] + dest[3];
			if (nexthop->interface)
				val += nexthop->interface->index;
			val += nexthop->routerid;
			val += nexthop->AS;
			val = val % size;
			return (val);
		}
		else {
			assert (0);
		}
		/* NEVER REACHES */
		return (0);
}


static int
nexthop_lookup_fn (nexthop_t *a, nexthop_t *b)
{
    return (address_equal (a->prefix, b->prefix) &&
		(a->AS == b->AS) && (a->routerid == b->routerid) &&
		(a->interface == b->interface));
}


nexthop_t *
ref_nexthop (nexthop_t *nexthop)
{
    if (nexthop) {
        pthread_mutex_lock (&nexthop->mutex_lock);
        assert (nexthop->ref_count > 0);
        nexthop->ref_count++;
        pthread_mutex_unlock (&nexthop->mutex_lock);
    }
    return (nexthop);
}


static void
nexthop_evaluate (nexthop_t *nexthop)
{
    u_long oflags = nexthop->flags;
	
    if (nexthop->interface == NULL)
		return;
    if (BIT_TEST (nexthop->flags, GATEWAY_UNSPEC|GATEWAY_LLOCAL))
		return;
	
    if (BIT_TEST (nexthop->flags, GATEWAY_LOCAL)) {
		if (!is_prefix_local_on (nexthop->prefix, nexthop->interface)) {
			nexthop->flags &= ~GATEWAY_LOCAL;
		}
    }
    else if (BIT_TEST (nexthop->flags, GATEWAY_DIRECT)) {
		if (!is_prefix_on (nexthop->prefix, nexthop->interface)) {
			nexthop->flags &= ~GATEWAY_DIRECT;
		}
    }
	
    if (!BIT_TEST (nexthop->flags, GATEWAY_LOCAL|GATEWAY_DIRECT)) {
        if (!BIT_TEST (oflags, GATEWAY_LOCAL) &&
			is_prefix_local_on (nexthop->prefix, nexthop->interface)) {
            nexthop->flags |= GATEWAY_LOCAL;
        }
        else if (!BIT_TEST (oflags, GATEWAY_DIRECT) &&
			is_prefix_on (nexthop->prefix, nexthop->interface)) {
            nexthop->flags |= GATEWAY_DIRECT;
		}
    }
}


/* called when there is a change in an interface */
static void
nexthop_call_fn (int cmd, interface_t *interface, ll_addr_t *if_addr)
{
    mrt_hash_table_t *hash = &MRT->hash_table;
    nexthop_t *nexthop;
	
    /* don't process if's up-downs */
    if (if_addr == NULL)
		return;
	
    assert (if_addr->prefix);
#ifdef HAVE_IPV6
    if (if_addr->prefix->family == AF_INET6)
		hash = &MRT->hash_table6;
#endif /* HAVE_IPV6 */
	
    pthread_mutex_lock (&hash->mutex_lock);
    HASH_Iterate (hash->table, nexthop) {
	int before = nexthop_available (nexthop);
	int after;

	if (nexthop->interface == NULL || nexthop->interface != interface)
	    continue;
	if (BIT_TEST (nexthop->flags, GATEWAY_UNSPEC|GATEWAY_LLOCAL))
	    continue;

	/* XXX if there is overlap or radical change, this is not enough */
	nexthop_evaluate (nexthop);

	after = nexthop_available (nexthop);
	if (before != after) {
            trace (TR_TRACE, MRT->trace,
	           "nexthop_evaluate: %a on %s (%s -> %s)\n",
                   nexthop->prefix, 
	           nexthop->interface?nexthop->interface->name: "?",
	           before? "o": "x", after? "o": "x");
	}
    }
    pthread_mutex_unlock (&hash->mutex_lock);
}


#define NEXTHOP_HASH_SIZE 1023
/* 
* find nexthop or create a new one if it does not exit
*/
/* if interface supplied, it never changes. with the same prefix, 
but different interface results in registering another nexthop */
nexthop_t *
add_bgp_nexthop (prefix_t *prefix, int as, u_long id, interface_t *interface)
{
    nexthop_t nh, *nexthop;
    mrt_hash_table_t *hash = &MRT->hash_table;
    char sbuf[128];
	
    if (prefix == NULL)
		return (NULL);
	
#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6)
		hash = &MRT->hash_table6;
#endif /* HAVE_IPV6 */
	
    pthread_mutex_lock (&hash->mutex_lock);
	
    if (hash->table == NULL) {
	if (INTERFACE_MASTER) {
	    /* since this is important */
            LL_Prepend (INTERFACE_MASTER->ll_call_fns, nexthop_call_fn);
	}
        hash->table = HASH_Create (NEXTHOP_HASH_SIZE, 
			HASH_EmbeddedKey, True,
			HASH_KeyOffset, 0,
			HASH_LookupFunction, nexthop_lookup_fn,
			HASH_HashFunction, nexthop_hash_fn, NULL);
    }
	
    nh.prefix = prefix;
    nh.interface = interface;
    nh.flags = 0;
    nh.ref_count = 1;
    nh.AS = as;
    nh.routerid = id;
    if (prefix_is_unspecified (prefix))
		nh.flags |= GATEWAY_UNSPEC;
#ifdef HAVE_IPV6
    else if (prefix_is_linklocal (prefix))
		nh.flags |= GATEWAY_LLOCAL;
#endif /* HAVE_IPV6 */
	
    if ((nexthop = HASH_Lookup (hash->table, &nh))) {
        pthread_mutex_unlock (&hash->mutex_lock);
		nexthop = ref_nexthop (nexthop);
		return (nexthop);
    }
	
    nexthop = New (nexthop_t);
    nexthop->prefix = Ref_Prefix (prefix);
    nexthop->AS = as;
    nexthop->routerid = id;
    nexthop->interface = interface;
    nexthop->flags = 0;
    if (prefix_is_unspecified (prefix))
		nexthop->flags |= GATEWAY_UNSPEC;
#ifdef HAVE_IPV6
    else if (prefix_is_linklocal (prefix))
		nexthop->flags |= GATEWAY_LLOCAL;
#endif /* HAVE_IPV6 */
	
/* fprintf (stderr, "nexthop=%x, prefix=%s as=%d interface=%s key=%x\n",
	nexthop, prefix_toax (prefix), as, interface?interface->name:"",
	nexthop_hash_fn (nexthop, 1023)); */

    nexthop_evaluate (nexthop);
	
#ifdef NT
	//printf ("%s\n", prefix_toax (nexthop->prefix));
	if (prefix_is_v4compat (nexthop->prefix))
		nexthop->flags |= GATEWAY_LLOCAL;
#endif /* nt */

    if (BIT_TEST (nexthop->flags, GATEWAY_LOCAL|GATEWAY_DIRECT|
		GATEWAY_UNSPEC|GATEWAY_LLOCAL)) {
		sprintf (sbuf, " on %s", (interface)? interface->name: "?");
    }
    else {
		sprintf (sbuf, " via %s", (interface)? interface->name: "?");
    }
    nexthop->ref_count = 1;
    pthread_mutex_init (&nexthop->mutex_lock, NULL);
    HASH_Insert (hash->table, nexthop);
    pthread_mutex_unlock (&hash->mutex_lock);
    if (as != 0 || id != 0)
        trace (TR_STATE, MRT->trace, "add_nexthop: %a as %d id %x%s\n",
		nexthop->prefix, as, id, sbuf);
    else
        trace (TR_STATE, MRT->trace, "add_nexthop: %a%s\n",
		nexthop->prefix, sbuf);
    return (nexthop);
}


nexthop_t *
add_nexthop (prefix_t *prefix, interface_t *interface)
{
    return (add_bgp_nexthop (prefix, 0, 0, interface));
}


#ifdef notdef
nexthop_t *
find_bgp_nexthop (prefix_t *prefix, int as, u_long id, interface_t *interface)
{
    nexthop_t nh, *nexthop = &nh;
    mrt_hash_table_t *hash = &MRT->hash_table;
	
    if (prefix == NULL)
		return (NULL);
	
#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6)
		hash = &MRT->hash_table6;
#endif /* HAVE_IPV6 */
	
    if (hash->table == NULL)
		return (NULL);
	
    pthread_mutex_lock (&hash->mutex_lock);
	
    nexthop->prefix = prefix;
    nexthop->interface = interface;
    nexthop->AS = as;
    nexthop->routerid = id;
	
    if ((nexthop = HASH_Lookup (hash->table, nexthop))) {
        pthread_mutex_unlock (&hash->mutex_lock);
		return (nexthop);
    }
    return (NULL);
}


nexthop_t *
find_nexthop (prefix_t *prefix, interface_t *interface)
{
    return (find_nexthop (prefix, 0, 0, interface));
}
#endif


void
deref_nexthop (nexthop_t *nexthop)
{
    if (nexthop == NULL)
		return;
    pthread_mutex_lock (&nexthop->mutex_lock);
    assert (nexthop->ref_count > 0);
    if (nexthop->ref_count <= 1) {
		mrt_hash_table_t *hash = &MRT->hash_table;
#ifdef HAVE_IPV6
		if (nexthop->prefix->family == AF_INET6)
			hash = &MRT->hash_table6;
#endif /* HAVE_IPV6 */
        pthread_mutex_lock (&hash->mutex_lock);
        /* someone may be searching in the table 
	       and found this at the same time */
		if (nexthop->ref_count <= 1) {
			HASH_Remove (hash->table, nexthop);
            pthread_mutex_unlock (&hash->mutex_lock);
			pthread_mutex_destroy (&nexthop->mutex_lock);
			Deref_Prefix (nexthop->prefix);
			Delete (nexthop);
			return;
		}
        pthread_mutex_unlock (&hash->mutex_lock);
    }
    nexthop->ref_count--;
    pthread_mutex_unlock (&nexthop->mutex_lock);
    return;
}


gateway_t *
find_bgp_gateway (prefix_t *prefix, int as, u_long id)
{
    nexthop_t *nexthop, *found = NULL;
    mrt_hash_table_t *hash = &MRT->hash_table;
	
    if (prefix == NULL)
		return (NULL);
	
#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6)
		hash = &MRT->hash_table6;
#endif /* HAVE_IPV6 */
	
    if (hash->table == NULL)
		return (NULL);
	
    pthread_mutex_lock (&hash->mutex_lock);
    HASH_Iterate (hash->table, nexthop) {
		if (address_equal (nexthop->prefix, prefix) &&
			(nexthop->AS == as) && (nexthop->routerid == id)) {
			if (found) {
				trace (TR_WARN, MRT->trace, 
					"duplicated nexthop detected: %s on %s and %s\n", 
					prefix_toa (prefix),
					(nexthop->interface)?nexthop->interface->name:"?",
					(found->interface)?found->interface->name:"?");
				pthread_mutex_unlock (&hash->mutex_lock);
				return (NULL);
			}
			found = nexthop;
		}
    }
    pthread_mutex_unlock (&hash->mutex_lock);
    return (found);
}


gateway_t *
find_gateway (prefix_t *prefix)
{
    return (find_bgp_gateway (prefix, 0, 0));
}


int
is_prefix_local_on (prefix_t * prefix, interface_t *interface)
{
    ll_addr_t *ll_addr;
    u_char *addr;
	struct in6_addr *sin6_addr;

    assert (prefix);
    assert (interface);
	
    if (interface->ll_addr) {
        LL_Iterate (interface->ll_addr, ll_addr) {
			if (ll_addr->prefix == NULL)
				continue;
			if (ll_addr->prefix->family != prefix->family)
				continue;
			
			/*
			 * The local side addresses are checked even in case of p-to-p
			 */			
#ifdef HAVE_IPV6
			if ((prefix->family == AF_INET6) && 
				(memcmp ((u_char *) prefix_toaddr6 (prefix), (u_char *) prefix_toaddr6(ll_addr->prefix), 16) == 0)) {
				return (TRUE);
			}
#endif /* HAVE_IPV6 */
			addr = prefix_touchar (ll_addr->prefix);
			if (memcmp (prefix_touchar (prefix), addr, 
				(prefix->family == AF_INET) ? 4 : 16) == 0) {
				return (TRUE);
			}
		}
    }
	
#ifdef HAVE_MROUTING
    if (interface->tunnel_source) {
		addr = prefix_touchar (interface->tunnel_source);
		if (memcmp (prefix_touchar (prefix), addr, 
			(prefix->family == AF_INET) ? 4 : 16) == 0) {
			return (TRUE);
        }
    }
#endif /* HAVE_MROUTING */
	
    return (FALSE);
}


/* if the prefix is directly connected even itself */
int
is_prefix_on (prefix_t *prefix, interface_t *interface)
{
    ll_addr_t *ll_addr;
    u_char *addr, *dest;
    int bitlen;
	
    assert (prefix);
    assert (interface);
	
    if (interface->ll_addr == NULL)
		return (0);
	
    addr = prefix_touchar (prefix);
	
    LL_Iterate (interface->ll_addr, ll_addr) {
		if (ll_addr->prefix == NULL)
			continue;
		if (ll_addr->prefix->family != prefix->family)
			continue;
			/*
			if (ll_addr->prefix->bitlen > prefix->bitlen)
			continue;
		*/
		dest = prefix_touchar (ll_addr->prefix);
		bitlen = ll_addr->prefix->bitlen;
		
		if (BIT_TEST (interface->flags, IFF_POINTOPOINT)) {
			bitlen = 32;
#ifdef HAVE_IPV6
			if (ll_addr->prefix->family == AF_INET6)
				bitlen = 128;
#endif /* HAVE_IPV6 */
		}
		
		if (comp_with_mask (addr, dest, bitlen))
			return (1);
		
		if (BIT_TEST (interface->flags, IFF_POINTOPOINT)) {
			/* there is no destionation addr for sit on Linux */
			if (ll_addr->broadcast == NULL) {
#ifdef notdef
				/* XXX -- any address can be on */
				return (1);
#else
				continue;
#endif
			}
			dest = prefix_touchar (ll_addr->broadcast);
			if (comp_with_mask (addr, dest, bitlen))
				return (1);
		}
    }
    return (0);
}


int
nexthop_available (nexthop_t *nexthop)
{
    if (nexthop == NULL)
        return (FALSE);

    return (BIT_TEST (nexthop->flags, GATEWAY_LOCAL|GATEWAY_DIRECT|
		GATEWAY_LLOCAL|GATEWAY_UNSPEC) &&
		nexthop->interface != NULL && 
		BIT_TEST (nexthop->interface->flags, IFF_UP));
}


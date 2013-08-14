/* 
 * $Id: hashfn.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include "mrt.h"

int
ip_hash_fn (prefix_t * prefix, int size)
{
#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6) {
	u_long val, buff[4];
	memcpy (buff, prefix_tochar (prefix), 16);
	netmasking (prefix->family, (char *) buff, prefix->bitlen);
	/* Pedro's suggestion */
	val = buff[0] ^ buff[1] ^ buff[2] ^ buff[3];
	val ^= (val >> 16);
	val = val % size;
	return (val);
    }
    else
#endif /* HAVE_IPV6 */
    if (prefix->family == AF_INET) {
	u_int val;
	u_char dest[4];
	memcpy (dest, prefix_tochar (prefix), 4);
	netmasking (prefix->family, dest, prefix->bitlen);
	val = dest[0] + dest[1] + dest[2] + dest[3];
	val = val % size;
	return (val);
    }
    else {
	assert (0);
    }
    /* NEVER REACHES */
    return (0);
}


int
ip_lookup_fn (prefix_t * a, prefix_t * b)
{
    return (prefix_compare (a, b));
}


int
ip_pair_hash_fn (prefix_pair_t * prefix_pair, int size)
{
    u_long val = 0;

    val |= ip_hash_fn (prefix_pair->prefix1, size);
    val |= ip_hash_fn (prefix_pair->prefix2, size);
    val = val % size;
    return (val);
}


int
ip_pair_lookup_fn (prefix_pair_t * a, prefix_pair_t * b)
{
    return (prefix_compare (a->prefix1, b->prefix1) &&
            prefix_compare (a->prefix2, b->prefix2));
}

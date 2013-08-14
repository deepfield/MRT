/*
 * $Id: kernel_uii.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>
#include <interface.h>
#ifdef NT
#include <ntconfig.h>
#include <winsock2.h>
#ifdef HAVE_IPV6
#include <ws2ip6.h>
#endif /* HAVE_IPV6 */
#include <ws2tcpip.h>
#endif /* NT */

/* show_interfaces
 * Dump various interface stats/info to a socket
 */
int
show_interfaces (uii_connection_t * uii)
{
    interface_t *interface;
    ll_addr_t *ll_addr;
    char tmpx[MAXLINE];

    if (INTERFACE_MASTER == NULL) return (0);

    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {

#ifdef HAVE_MROUTING
	if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL)) {
	    uii_add_bulk_output (uii, "Interface %s %s %s -> %s index %d\n",
		interface->name,
		print_iflags (tmpx, MAXLINE, interface->flags),
		interface->tunnel_source? 
		    prefix_toa (interface->tunnel_source): "",
		interface->tunnel_destination? 
		    prefix_toa (interface->tunnel_destination): "",
		interface->index);
	    continue;
	}
#endif /* HAVE_MROUTING */

	uii_add_bulk_output (uii, "Interface %s %s mtu %d index %d\n",
		       interface->name,
		       print_iflags (tmpx, MAXLINE, interface->flags),
		       interface->mtu, interface->index);

#ifdef notdef
	if (interface->prefix != NULL) {
	    uii_add_bulk_output (uii, "  inet4 %s\n", 
				 prefix_toa (interface->prefix));
	}
#ifdef HAVE_IPV6
	if (interface->prefix6 != NULL) {
	    uii_add_bulk_output (uii, "  inet6 %s\n", 
				 prefix_toa (interface->prefix6));
	}
#endif /* HAVE_IPV6 */
#endif
	LL_Iterate (interface->ll_addr, ll_addr) {
	    assert (ll_addr->prefix);

	    tmpx[0] = '\0';
	    if (ll_addr->broadcast)
		sprintf (tmpx, " %s %s", 
			BIT_TEST (interface->flags, IFF_POINTOPOINT) ?
		      "-->" : "broadcast", prefix_toa (ll_addr->broadcast));

	    uii_add_bulk_output (uii, "  %s %s/%d%s\n",
			   (ll_addr->prefix->family == AF_INET) ? "inet" :
#ifdef HAVE_IPV6
			   (ll_addr->prefix->family == AF_INET6) ? "inet6" :
#endif /* HAVE_IPV6 */
			   "???",
		prefix_toa (ll_addr->prefix), ll_addr->prefix->bitlen, tmpx);
	}
	uii_add_bulk_output (uii, "\n");
    }
    return (1);
}


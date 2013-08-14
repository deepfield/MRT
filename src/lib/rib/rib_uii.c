/*
 * $Id: rib_uii.c,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
 */

#include <ctype.h>
#include <mrt.h>
#include <rib.h>
#include <array.h>

extern u_int num_active_generic_attr;
extern u_int num_active_route_head;
extern u_int num_active_route_node;
extern u_int num_active_prefixes;


static void 
show_gateway_table (uii_connection_t *uii, int family, mrt_hash_table_t *hash)
{
   gateway_t *gateway;

   pthread_mutex_lock (&hash->mutex_lock);
   uii_add_bulk_output (uii, "%d %s gateway(s)/nexthop(s) registered\n",
      		  HASH_GetCount (hash->table),
		  family2string (family));
   HASH_Iterate (hash->table, gateway) {
      uii_add_bulk_output (uii, "    %s\ton %s flags 0x%x (count %d)\n",
	 prefix_toa (gateway->prefix),
	 gateway->interface?gateway->interface->name:"???",
	 gateway->flags,
	 gateway->ref_count);
   }
   pthread_mutex_unlock (&hash->mutex_lock);
}


static void
show_gateway (uii_connection_t *uii)
{
/*    if (IPV4) */
        show_gateway_table (uii, AF_INET, &MRT->hash_table);
#ifdef HAVE_IPV6
/*    if (IPV6) */
        show_gateway_table (uii, AF_INET6, &MRT->hash_table6);
#endif /* HAVE_IPV6 */
}


int 
show_rib_status (uii_connection_t *uii)
{
    uii_add_bulk_output (uii, "%d active prefixes\n", num_active_prefixes);
    uii_add_bulk_output (uii, "%d active generic attributes\n", 
		num_active_generic_attr);
    uii_add_bulk_output (uii, "%d active route heads\n", num_active_route_head);
    uii_add_bulk_output (uii, "%d active route nodes\n", num_active_route_node);
    show_gateway (uii);
    return (1);
}


static char *format1 = "%c%c%c %4s %-8s %-26s %-24s %-7s %s\n";
static char *format2 = "%c%c%c %4d %-8s %-26s %-24s %-7s %s\n";

void 
rib_show_route_head (uii_connection_t *uii, char *append)
{
    uii_add_bulk_output (uii, format1,
	' ', ' ', 'P', "Pref", "Time", "Destination", "Next Hop", "If", 
	(append)? append: "");
}


void 
rib_show_route_line (uii_connection_t *uii, int c1, int c2, int type, int pref,
        	     int elapsed, prefix_t *prefix, prefix_t *nexthop, 
		     interface_t *interface, char *append)
{
    char tmp1[128], date[64];

    prefix_toa2x (prefix, tmp1, 1);
    time2date (elapsed, date);

    uii_add_bulk_output (uii, format2,
		     c1, c2, 
		     (type >= 0)? toupper (proto2string (type)[0]): ' ',
		     pref, date, tmp1,
		     nexthop? prefix_toa (nexthop): "*unknown*",
		     (interface)? interface->name : "???",
		     (append)? append: "");
}


int 
show_rib_routes (uii_connection_t *uii, rib_t *rib)
{
    route_head_t *route_head;
    route_node_t *route_node;
    time_t now;

    /* rib may not be used (bgpsim) */
    if (rib == NULL)
	return (0);

    time (&now);
    rib_open (rib);

    uii_add_bulk_output (uii, 
	"Number of Unique Destinations: %d, Number of Entries: %d\n", 
		         rib->num_active_routes, rib->num_active_nodes);
    uii_add_bulk_output (uii, "Status code: "
        "> best, * valid, i - internal, x - no next-hop, X - no install\n");
    rib_show_route_head (uii, "Kernel");
    RIB_RADIX_WALK (rib, route_head) {
	LL_Iterate (route_head->ll_route_nodes, route_node) {
	    int c1 = ' ', c2 = ' ';
            time_t elapse = now - route_node->time;
	    char *opt = NULL;
	    nexthop_t *nexthop;
	    interface_t *interface = NULL;

	    nexthop = route_node->attr->nexthop;
	    if (nexthop)
		interface = nexthop->interface;

	    if (route_head->active == route_node)
		c1 = '>';
	    if (!nexthop_available (nexthop))
		c1 = 'x';
	    if (BIT_TEST (route_node->flags, MRT_RTOPT_NOINSTALL))
		c2 = 'X';
	    if (BIT_TEST (route_node->flags, MRT_RTOPT_SUPPRESS))
		c2 = 'i';
	    if (BIT_TEST (route_node->flags, MRT_RTOPT_KERNEL))
		opt = "K";

	    if (nexthop == NULL)
		nexthop = route_node->attr->parent;

	    rib_show_route_line (uii, c1, c2,
		route_node->attr->type,
		route_node->pref, elapse, 
		route_head->prefix, 
		(nexthop)? nexthop->prefix: NULL,
		interface, opt);
	}
    } RIB_RADIX_WALK_END;
    rib_close (rib);
    uii_send_bulk_data (uii);
    return (1);
}


int
show_ip_routes (uii_connection_t * uii, char *cmd)
{
    rib_t *rib = RIB;
    if ((cmd != NULL) && strcasecmp (cmd, "mroutes") == 0)
		rib = RIBm;
    return (show_rib_routes (uii, rib));
}


#ifdef HAVE_IPV6
int
show_ipv6_routes (uii_connection_t * uii, char *cmd)
{
    rib_t *rib = RIBv6;
    if ((cmd != NULL) && strcasecmp (cmd, "mroutes") == 0)
	rib = RIBv6m;
    return (show_rib_routes (uii, rib));
}
#endif /* HAVE_IPV6 */


static int 
trace_bgp_rib_op (uii_connection_t * uii, char *s, int op)
{
    /* rib may not be used (bgpsim) */
    if (RIB == NULL)
	return (0);

    if (strcasecmp (s, "*") == 0) {
        rib_open (RIB);
       	set_trace (RIB->trace, op, TR_ALL, NULL);
        rib_close (RIB);
#ifdef HAVE_IPV6
        rib_open (RIBv6);
       	set_trace (RIBv6->trace, op, TR_ALL, NULL);
        rib_close (RIBv6);
#endif /* HAVE_IPV6 */
	
    }
    else if (strcasecmp (s, "inet") == 0) {
        rib_open (RIB);
       	set_trace (RIB->trace, op, TR_ALL, NULL);
        rib_close (RIB);
    }
#ifdef HAVE_IPV6
    else if (strcasecmp (s, "inet6") == 0) {
        rib_open (RIBv6);
       	set_trace (RIBv6->trace, op, TR_ALL, NULL);
        rib_close (RIBv6);
    }
#endif /* HAVE_IPV6 */
    else {
	user_notice (TR_ERROR, MRT->trace, uii,
		       "invalid or unconfigured rib %s\n", s);
        Delete (s);
        return (-1);
    }
    Delete (s);
    return (1);
}


static int 
trace_f_rib (uii_connection_t * uii, int family)
{
    int op = TRACE_ADD_FLAGS;

    if (RIB == NULL)
	return (0);

    if (uii->negative)
	op = TRACE_DEL_FLAGS;

    if (family == 0) {
        rib_open (RIB);
       	set_trace (RIB->trace, op, TR_ALL, NULL);
        rib_close (RIB);
#ifdef HAVE_IPV6
        rib_open (RIBv6);
       	set_trace (RIBv6->trace, op, TR_ALL, NULL);
        rib_close (RIBv6);
#endif /* HAVE_IPV6 */
    }
    else if (family == AF_INET) {
        rib_open (RIB);
       	set_trace (RIB->trace, op, TR_ALL, NULL);
        rib_close (RIB);
    }
#ifdef HAVE_IPV6
    else if (family == AF_INET6) {
        rib_open (RIBv6);
       	set_trace (RIBv6->trace, op, TR_ALL, NULL);
        rib_close (RIBv6);
    }
#endif /* HAVE_IPV6 */
    else {
	user_notice (TR_ERROR, MRT->trace, uii,
		       "invalid or unconfigured rib family = %d\n", family);
        return (-1);
    }
    return (1);
}


int 
trace_ip_rib (uii_connection_t *uii)
{
     return (trace_f_rib (uii, AF_INET));
}


#ifdef HAVE_IPV6
int 
trace_ipv6_rib (uii_connection_t *uii)
{
     return (trace_f_rib (uii, AF_INET6));
}
#endif /* HAVE_IPV6 */


int 
trace_rib (uii_connection_t * uii, char *s)
{
    return (trace_bgp_rib_op (uii, s, TRACE_ADD_FLAGS));
}


int 
no_trace_rib (uii_connection_t * uii, char *s)
{
    return (trace_bgp_rib_op (uii, s, TRACE_DEL_FLAGS));
}


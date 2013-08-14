/* 
 * $Id: gateway.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>


/*
 * convert gateway info into a ascii string
 * this should really use thread-specific data!! FIXME!
 */
char *gateway_toa (char *tmp, gateway_t *gateway) {

  if (gateway->AS > 0)
    sprintf (tmp, "%s AS%d", prefix_toa (gateway->prefix), gateway->AS);
  else
    sprintf (tmp, "%s", prefix_toa (gateway->prefix));

  return (tmp);
}


/* gateway_toa2
 * convert gateway info into a ascii string
 */
char *
gateway_toa2 (gateway_t *gateway) {

  char *stmp;
  THREAD_SPECIFIC_STORAGE (stmp);

  if (gateway->AS > 0)
    sprintf (stmp, "%s AS%d", prefix_toa (gateway->prefix), gateway->AS);
  else
    sprintf (stmp, "%s", prefix_toa (gateway->prefix));

  return (stmp);
}


/* 
 * find gateway or create a new one if it does not exit
 */
gateway_t *
add_bgp_gateway (prefix_t *prefix, int as, u_long id, interface_t *interface)
{
    return (add_bgp_nexthop (prefix, as, id, interface));
}


gateway_t *
add_gateway (prefix_t *prefix, int as, interface_t *interface)
{
    return (add_bgp_nexthop (prefix, as, 0, interface));
}

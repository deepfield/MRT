/*
 * $Id: vars.c,v 1.1.1.1 2000/08/14 18:46:12 labovit Exp $
 */

#include <mrt.h>
#include <rip.h>
#include <bgp.h>
#include <rib.h>
#include <interface.h>

rip_t *RIP = NULL;
rip_t *RIPNG = NULL;
bgp_t *BGP = NULL;
int IPV4 = 0;
int IPV6 = 0;
rib_t *RIB = NULL;
rib_t *RIBS[AFI_MAX][SAFI_MAX];
rib_t *RIBm = NULL;
rib_t *RIBv6 = NULL;
rib_t *RIBv6m = NULL;
interface_master_t *INTERFACE_MASTER = NULL;

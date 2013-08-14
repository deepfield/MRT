/*
 * $Id: ripng.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _RIPNG_H
#define _RIPNG_H

#include <config.h>
#ifdef HAVE_IPV6
#include <linked_list.h>
#include <trace.h>
#include <timer.h>
#include <schedule.h>
#include <hash.h>

#include <mrt.h>
#include <proto.h>
#include <interface.h>
#include <rib.h>

#define RIPNG_DEFAULT_PORT	521
#define RIPNG_IPV6_PRIORITY	(7<<24)

#define RIPNG_MIN_BUFSIZE ((INTERFACE_MASTER->max_mtu > 8 * 1024) ? \
                            INTERFACE_MASTER->max_mtu : 8 * 1024)

#define RIPNG_REQUEST     1
#define RIPNG_RESPONSE    2

#define RIPNG_VERSION	1

LINKED_LIST *ripng_process_packet_response (gateway_t * gateway, 
		u_char * update, int bytes, int pref);
LINKED_LIST *ripng_process_packet_request (u_char * update, int bytes);
int ripng_interface (rip_interface_t *rip_interface, int on);
int ripng_send_update (LINKED_LIST *ll_rip_ann_rt,
                  rip_interface_t *rip_interface, prefix_t *host, int port);
int ripng_send_request (rip_interface_t *rip_interface,
                       LINKED_LIST * ll_prefixes);
int ripng_receive_update (rip_interface_t *rip_interface);
void ripng_update_route (prefix_t * prefix, generic_attr_t * new,
                         generic_attr_t * old, int pref, int viewno);
int ripng_init_listen (interface_t *interface);
void ripng_init (trace_t *tr);
void ripng_stop (void);
int ripng_start (int port);
int ripng_show (uii_connection_t * uii);
int ripng_show_routing_table (uii_connection_t * uii, int optnum, char *ifname);
void ripng_set (int first, ...);

extern rip_t *RIPNG;

#endif /* HAVE_IPV6 */
#endif /* _RIPNG_H */

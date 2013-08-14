/*
 * $Id: rip.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _RIP_H
#define _RIP_H

#include <config.h>
#include <linked_list.h>
#include <trace.h>
#include <timer.h>
#include <schedule.h>
#include <hash.h>

#include <mrt.h>
#include <proto.h>
#include <interface.h>
#include <rib.h>

#define RIP_DEFAULT_PORT	520
#define RIP_MAX_PDU		512

#define RIP_REQUEST	1
#define RIP_RESPONSE	2

/* #define RIP_VERSION  1 */
#define RIP_VERSION     2       /* support RIP-2 only (no compatible mode) */

#undef RIP_POISONED_REVERSE	/* define if poisoned reverse */

#if 0				/* test */
#define RIP_TIMEOUT_INTERVAL	60
#define RIP_GARBAGE_INTERVAL	40
#define RIP_UPDATE_INTERVAL	15
#else
#define RIP_TIMEOUT_INTERVAL	180
#define RIP_GARBAGE_INTERVAL	120	/* after timeout */
#define RIP_UPDATE_INTERVAL	30
#endif
#define RIP_START_DELAY		5	/* delay after enabled */
#define RIP_TABLE_HASH_SIZE	1023	/* hash size of the routing table */
#define RIP_METRIC_INFINITY	16

/* These values come from gated */
#define RIP_FLASH_DELAY_MIN 1
#define RIP_FLASH_DELAY_MAX 5

typedef struct _rip_interface_t {
    interface_t *interface;
    int dlist_in;    /* list num for input filtering */
    int dlist_out;   /* list num for output filtering */
    int metric_in;              /* input metric */
    int metric_out;             /* output metric */
    int default_pref;
    int sockfd;
} rip_interface_t;


typedef int (*send_update_fn_t) (LINKED_LIST *, rip_interface_t *, prefix_t *,
                                 int);
typedef int (*process_update_fn_t) (LINKED_LIST *);
typedef int (*interface_fn_t) (rip_interface_t *, int);

typedef struct _rip_t {
    int proto;			/* PROTO_RIP or PROTO_RIPNG */
    interface_bitset_t interface_mask;	/* mask of interfaces ripng is configed for */
    HASH_TABLE *hash;		/* hash of prefixes */
    trace_t *trace;

    /* rib_update_route_t update_call_fn; */
    u_long redistribute_mask;
    schedule_t *schedule;
    mtimer_t *timer;		/* timer used for sending update */
    mtimer_t *age;		/* aging routes */
    mtimer_t *flash;		/* flash update */

    LINKED_LIST *ll_networks;	/* prefix */
    LINKED_LIST *ll_networks2;	/* interface name */
    LINKED_LIST *ll_dlists;	/* distribute-list */
    LINKED_LIST *ll_rip_interfaces;	/* enabled rip interface */
    rip_interface_t *rip_interfaces[MAX_INTERFACES];
    int flash_update_waiting;
    int changed;
    send_update_fn_t send_update_fn;
    process_update_fn_t process_update_fn;
    interface_fn_t interface_fn;
    prefix_t *all_routers;

    int sockfd;
    int port; /* host byte order */
    int alist;
} rip_t;

typedef struct _rip_attr_t {
    int type;
    u_long ref_count;
    nexthop_t *nexthop;
    gateway_t *gateway;
    u_long tag;

    int metric;
    int pref;
    time_t ctime;		/* time created */
    time_t utime;		/* time updated */
    time_t dtime;		/* time started deletion process */
} rip_attr_t;

typedef struct _rip_route_t {
    u_long flags;
    prefix_t *prefix;
    rip_attr_t *active;
    rip_attr_t *current;
    LINKED_LIST *received;
    LINKED_LIST *imported;
} rip_route_t;

/* route flags */
#define RT_RIP_CHANGE	0x1
#define RT_RIP_DELETE	0x2


/* user settable attributes */
enum RIP_ATTR {
    RIP_NULL = 0,
    RIP_TRACE_STRUCT,
    RIP_RT_UPDATE_FN,		/* function to call when ripng routes change */
    RIP_USE_PORTSERVER		/* use portserver library for listening */
};


typedef struct _rip_ann_rt_t {
    prefix_t *prefix;
    rip_attr_t *attr;
    int metric;
} rip_ann_rt_t;


/* public functions */

void rip_process_requst (rip_t *rip, LINKED_LIST *ll_rip_ann_rt,
                    rip_interface_t *rip_interface, prefix_t *from, int port);
void rip_delete_rip_ann_rt (rip_ann_rt_t *rip_ann_rt);
void rip_advertise_route (rip_t *rip, int all);
void rip_init (rip_t *rip);
void rip_start (rip_t *rip);
void rip_stop (rip_t *rip);
int rip_policy (rip_t * rip, prefix_t * prefix, rip_attr_t * attr,
		rip_interface_t * out);
void rip_set (rip_t *rip, va_list ap);
void rip_interface_recheck (rip_t *rip);
void rip_distribute_list_recheck (rip_t *rip);
rip_attr_t *rip_new_attr (rip_t * rip, int metric);
void rip_del_attr (rip_attr_t * attr);
int rip_process_update (rip_t * rip, LINKED_LIST * ll_rip_ann_rt);
void rip_update_route (rip_t *rip, prefix_t * prefix, generic_attr_t * new,
		       generic_attr_t * old, int pref);
int rip_show (rip_t *rip, uii_connection_t * uii);
int rip_show_routing_table (rip_t *rip, uii_connection_t * uii, char *ifname);

/* from rip2.c */
LINKED_LIST *rip2_process_packet_response (gateway_t * gateway, 
			u_char * update, int bytes, int pref);
int rip2_interface (rip_interface_t *rip_interface, int on);
int rip2_send_update (LINKED_LIST *ll_rip_ann_rt, 
                  rip_interface_t *rip_interface, prefix_t *host, int port);
int rip2_send_request (rip_interface_t *rip_interface, 
		       LINKED_LIST * ll_prefixes);
LINKED_LIST *rip2_process_packet_request (u_char * update, int bytes);
int rip2_receive_update (rip_interface_t *rip_interface);
void rip2_update_route (prefix_t * prefix, generic_attr_t * new,
		        generic_attr_t * old, int pref, int viewno);
int rip2_init_listen (interface_t *interface);
void rip2_init (trace_t *tr);
void rip2_stop (void);
int rip2_start (int port);
int rip2_show (uii_connection_t * uii);
int rip2_show_routing_table (uii_connection_t * uii, int optnum, char *ifname);
void rip2_set (int first, ...);

extern rip_t *RIP;

#ifdef HAVE_IPV6
#include "ripng.h"
#endif /* HAVE_IPV6 */

#endif /* _RIP_H */

/*
 * $Id: protoconf.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _CONFIG_MRTD_H
#define _CONFIG_MRTD_H

#include <mrt.h>

typedef struct _config_mrtd_t {
#ifdef notdef
    int line;			/* when parsing file, current lineno */
/* I'm not sure the following are used */
    int sockfd;			/* socket if being configured by user */
    /* int state; */		/* router, interface, etc */
    int instance;		/* protocol, or interface number */
    int negate;			/* command prefeced by a "no" */
#endif /* notdef */
    route_map_t *route_map;
    interface_t *interface;	/* umm, not interface number ... */
    LINKED_LIST *ll_interfaces;
    pthread_mutex_t static_routes_lock;
    pthread_mutex_t static_mroutes_lock;
    HASH_TABLE *static_routes;
    HASH_TABLE *static_mroutes;	/* for multicast */
    time_t dump_route_time;
    time_t dump_route_last;
    char *dump_route_form;
    time_t dump_update_time;
    time_t dump_update_last;
    char *dump_update_form;
    int protocol;
    int viewno;	/* only for BGP */
} config_mrtd_t;

typedef struct _static_route_t {
    prefix_t *prefix;
    prefix_t *nexthop;
    interface_t *interface;
    int pref;
    int safi;
    generic_attr_t *attr;
#define STATIC_ROUTE_UP 0x01
    u_long flags;
} static_route_t;

extern config_mrtd_t *CONFIG_MRTD;       /* from config.c */
extern int BGPSIM_TRANSPARENT;

void check_passwd ();
int show_rib_routes ();
int show_rib_status ();
int show_rip_routing_table ();
#ifdef HAVE_IPV6
void show_ripng ();
int show_ripng_routing_table ();
#endif /* HAVE_IPV6 */

int show_threads ();
int show_view ();
int process_bgp_update ();

int init_mrtd_config (trace_t * trace);
void config_create_default ();

int rip_debug (uii_connection_t * uii);
int bgp_debug (uii_connection_t * uii);
#ifdef notdef
#ifdef HAVE_IPV6
int ripng_debug (uii_connection_t * uii);
#endif /* HAVE_IPV6 */
#endif
void get_config_interface (interface_t * interface);

int config_router_network_prefix (uii_connection_t * uii, prefix_t *prefix);
int config_router_network_name (uii_connection_t * uii, char *name);
int config_router_network_interface (uii_connection_t * uii, char *name);
int config_redistribute (uii_connection_t * uii, char *proto);
int no_config_redistribute (uii_connection_t * uii, char *proto_string);

void config_bgp_init (void);
void config_bgp_init2(int include_dump_commands);
void config_rtmap_init (void);
void config_rip_init (void);
int string2proto (char *proto_string);

int load_rib_from_disk (char *filename);
int load_f_bgp_routes (char *filename, int this_family_only);

void config_multicast_init (void);
void config_dvmrp_init (void);
void config_pim_init (void);

#endif /* _CONFIG_MRTD_H */


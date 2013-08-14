/*
 * $Id: ricd.h,v 1.1.1.1 2000/08/14 18:46:14 labovit Exp $
 */

#ifndef _RICD_H_
#define _RICD_H_

#include "mrt.h"
#include "sspec.h"
#include "hqlip.h"
#include "srsvp.h"


#define RICD_VERSION "1.0.0a [12/15/99]"
#define PROTO_RICD 13
#define UII_CONFIG_ROUTER_RIC 16


typedef struct _packet_t {
    void *data;
    int len;
} packet_t;


typedef struct _config_aggregate_t {
    char *name;
    prefix_t *prefix;
} config_aggregate_t;


#define CONFIG_QOS_DELETED 0x01

typedef struct _config_if_qos_t {
    char *name;
    if_qos_t *if_qos;
    u_long flags;
} config_if_qos_t;


typedef struct _config_link_qos_t {
    char *name;
    link_qos_t *link_qos;
    u_long flags;
} config_link_qos_t;


typedef struct _config_area_qos_t {
    char *name;
    area_qos_t *area_qos;
    u_long flags;
} config_area_qos_t;


#define HQLIP_AREA_DELETED 0x01
typedef struct _config_area_t {
    char *name;
    my_area_t *my_area;
    u_long flags;
    LINKED_LIST *ll_aggregates;
} config_area_t;


#define HQLIP_NETWORK_DELETED 0x01
typedef struct _hqlip_config_network_t {
    interface_t *interface;
    config_if_qos_t *config_if_qos;
    config_link_qos_t *config_link_qos;
    prefix_t *prefix;
    int keep_alive_interval;
    int metric;
    u_long flags;
    config_area_t *config_area0;
    config_area_t *config_area1;
} hqlip_config_network_t;       

    
typedef struct _config_req_qos_t {
    char *name;
    req_qos_t *req_qos;
    u_long flags;
} config_req_qos_t;


typedef struct _ricd_t {
    int family;
    int running;
    trace_t *trace;
    hqlip_t *hqlip;
    srsvp_t *srsvp;
} ricd_t;

typedef struct _config_ricd_t {
    ricd_t *ricd;
    LINKED_LIST *ll_config_if_qoses;
    LINKED_LIST *ll_config_link_qoses;
    LINKED_LIST *ll_config_area_qoses;
    LINKED_LIST *ll_config_req_qoses;
    LINKED_LIST *ll_rvps;
} config_ricd_t;


typedef struct _ricd_rvps_t {
    prefix_t *prefix;
    prefix_t *address;
} ricd_rvp_t;


extern config_ricd_t *CONFIG_RICD;
extern ricd_t *RICD;
extern ricd_t *RICD6; 

void ricd_init_config (void);
prefix_t *ricd_get_rvp (prefix_t *prefix);

/* hqlip.c */
void hqlip_init (ricd_t *ricd);
void hqlip_start (hqlip_t *hqlip);
void hqlip_activate_interface (hqlip_t *hqlip,
                               hqlip_config_network_t *network, int on,
			       my_area_t *my_area);
area_t *add_area (int level, prefix_t *id);
int hqlip_show_neighbors (uii_connection_t *uii, char *ip, char *ifname);
int hqlip_show_areas (uii_connection_t *uii, char *ip);
int hqlip_update_area_center (hqlip_t *hqlip, my_area_t *my_area,
                          spath_area_center_t *spath_area_center);
int hqlip_show_path (uii_connection_t *uii, char *ip, 
		     prefix_t *p1, prefix_t *p2);
hqlip_neighbor_t *hqlip_find_nexthop (hqlip_t *hqlip, my_area_t *my_area, 
				prefix_t *destin, req_qos_t *req_qos, 
				link_qos_t *link_qos, int *metric,
                    		u_long *errcode);
void hqlip_link_status (hqlip_t *hqlip, req_qos_t *req_qos, 
			interface_t *interface, int on);

/* srsvp.c */
void srsvp_init (ricd_t *ricd);
void srsvp_start (srsvp_t *srsvp);
void srsvp_activate_interface (srsvp_t *srsvp, interface_t *interface,
                               prefix_t *local, int on);
void srsvp_create_neighbor (srsvp_t *srsvp, prefix_t *prefix, 
			    interface_t *interface);
void srsvp_delete_neighbor (srsvp_t *srsvp, prefix_t *prefix, 
			    interface_t *interface);
int srsvp_show_neighbors (uii_connection_t *uii, char *ip, char *ifname);
int srsvp_show_flows (uii_connection_t *uii, char *ip);
int srsvp_flow_request_by_user (uii_connection_t *uii, char *send_s,
		prefix_t *sender, int dport, char *proto_s, char *req_qos_s);
int srsvp_no_flow_request_by_user (uii_connection_t *uii, char *ip, int num);
void srsvp_flow_request_by_app (srsvp_t *srsvp, srsvp_flow_t *flow, int cmd);

req_qos_t *copy_req_qos (req_qos_t *src, req_qos_t *dst);

#define afi2plen(afi) (((afi) == AFI_IP6)? 16: ((afi) == AFI_IP)? 4: 0)

/* qif.c */
int qif_init (void);
int qif_close (void);
int qif_add_qif (srsvp_t *srsvp, srsvp_interface_t *vif);
int qif_del_qif (srsvp_t *srsvp, srsvp_interface_t *vif);
int qif_add_flow (srsvp_t *srsvp, srsvp_flow_t *flow, srsvp_leaf_t *leaf);
int qif_del_flow (srsvp_t *srsvp, srsvp_flow_t *flow, srsvp_leaf_t *leaf);
int qif_notify (srsvp_t *srsvp, srsvp_flow_t *flow, int eno);

#endif _RICD_H_

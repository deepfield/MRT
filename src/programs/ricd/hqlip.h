/*
 * $Id: hqlip.h,v 1.1.1.1 2000/08/14 18:46:14 labovit Exp $
 */

#ifndef _HQLIP_H
#define _HQLIP_H

#define HQLIP_UDP_PORT 7094
#define HQLIP_TCP_PORT 7094
#define HQLIP_HELLO_INTERVAL 25
#define HQLIP_HELLO_JITTER    5
#define HQLIP_HELLO_TTL       1
#define HQLIP_KEEPALIVE_INTERVAL 10
#define HQLIP_KEEPALIVE_TIMEOUT(x) ((x)*3+(x)/2)
#define HQLIP_LINK_QOS_INTERVAL 30

#define HQLIP_MSGF_NOTSYNCED 0x01
#define HQLIP_MSGF_EXTERNAL  0x02

#define HQLIP_MSG_KEEP_ALIVE  1
#define HQLIP_MSG_LINK_QOS    2
#define HQLIP_MSG_AREA_CENTER 3
#define HQLIP_MSG_AREA_ADDR   4
#define HQLIP_MSG_AREA_QOS    5
#define HQLIP_MSG_SYNC        6

#define HQLIP_MSG_HDR_SIZE   12
#define HQLIP_MSG_SIZE    65535
#define HQLIP_UDP_SIZE      512

#define HQLIP_GET_HEADER(flags, type, level, len, tstamp, cp) \
    do { \
        MRT_GET_BYTE((flags), (cp)); \
        MRT_GET_BYTE((type), (cp)); \
        MRT_GET_BYTE((level), (cp)); \
	cp += 1; \
	cp += 2; \
        MRT_GET_SHORT((len), (cp)); \
        MRT_GET_LONG((tstamp), (cp)); \
    } while (0)

#define HQLIP_PEEK_HDRLEN(len, cp) \
    do { \
        int Xlen; \
        Xlen = ((int)*(u_char *)((cp) + 6)) << 8; \
        Xlen |= (int)*(u_char *)((cp) + 7); \
        (len) = Xlen; \
    } while (0)
  
#define HQLIP_PEEK_HDRTYPE(type, cp)       ((type) = *(u_char *)((cp) + 1))
#define HQLIP_PEEK_HDRLEVEL(level, cp)       ((level) = *(u_char *)((cp) + 2))

typedef struct _hqlip_interface_t {
    prefix_t *prefix;
    interface_t *interface;
    u_long flags;
    LINKED_LIST *ll_neighbors;
    mtimer_t *probe;		/* neighbor probe (hello) */
    int keep_alive_interval;
    struct _hqlip_neighbor_t *myself;
    int udp_sockfd;
    int tcp_sockfd;
    if_qos_t *if_qos;
    link_qos_t *link_qos;
    int metric;
    struct _my_area_t *my_area0;
} hqlip_interface_t;


#define HQLIP_NEIGHBOR_DELETED 0x01
#define HQLIP_OPEN_IN_PROGRESS 0x02
#define HQLIP_NEIGHBOR_CONNECTED 0x04

typedef struct _hqlip_neighbor_t {
    prefix_t *prefix;
    hqlip_interface_t *vif;
    time_t ctime;
    time_t utime;
    u_long flags;
    mtimer_t *timeout;          /* neighbor timeout */
    mtimer_t *keep_alive;       /* keep alive timer */
    int sockfd;
    trace_t *trace;
    schedule_t *schedule;
#ifndef HAVE_LIBPTHREAD
    pthread_mutex_t send_mutex_lock; /* it's for non-thread, through */
    LINKED_LIST *send_queue;	/* for non-blocking send */
#endif /* HAVE_LIBPTHREAD */
    u_char buffer[HQLIP_MSG_SIZE * 2];
    u_char *start_ptr, *read_ptr;
    u_char *packet;
    int num_packets_recv;
    int num_packets_sent;
    int num_session_up;
    struct _spath_link_qos_t *spath_link_qos;

    u_long synced_level_bitset;
    LINKED_LIST *ll_packets;
} hqlip_neighbor_t;


typedef struct _area_t {
    int level;		/* area level */
    prefix_t *id;	/* area id */
    pthread_mutex_t mutex_lock;
    int ref_count;
    struct _my_area_t *my_area;	/* local area */
} area_t;


typedef struct _my_area_t {
    char *name;
    area_t *area;
    struct _spath_area_center_t *winner;  /* a center who won */
    struct _spath_area_center_t *exwinner;  /* a previous center */
    struct _spath_area_center_t *center;  /* a candidate by me */
    int pps;			  /* if i am a candidate */
    struct _my_area_t *parent;
    hqlip_interface_t *vif;	/* at leval 0 only */
    LINKED_LIST *ll_neighbors; /* neighbors at this level with this area */
    LINKED_LIST *ll_children; /* level >= 1, my_areas */
    LINKED_LIST *ll_prefixes; /* level >= 1, prefixes */

    LINKED_LIST *ll_spath_link_qoses;
    LINKED_LIST *ll_spath_area_centers;
    LINKED_LIST *ll_spath_area_addrs;
    LINKED_LIST *ll_spath_area_qoses;

    trace_t *trace;
    schedule_t *schedule;     

#define HQLIP_MY_AREA_DELETED 0x01
#define HQLIP_MY_AREA_SYNCING 0x02
    u_long flags;
    int udp_recv_socket;
} my_area_t;


typedef struct _hqlip_t {
    int family;
    interface_bitset_t interface_mask;	/* mask of interfaces configed for */
    trace_t *trace;

    schedule_t *schedule;
    my_area_t *root;		/* internet area */
    LINKED_LIST *ll_networks;   /* configured networks */
    LINKED_LIST *ll_areas;      /* configured areas */
    LINKED_LIST *ll_hqlip_interfaces;	/* enabled hqlip interfaces */
    hqlip_interface_t *hqlip_interfaces[MAX_INTERFACES];

    prefix_t *all_hosts;
    int keep_alive_interval;
    u_long router_id;

    int udp_count;	/* counter for how many receivers share */
    int udp_sockfd;	/* a socket for receiving a udp hello */
    int running;
} hqlip_t;

#define HQLIP_AREA_LEVEL_INTERNET 16

#define SSPEC_NUM_LINKQOS 8
typedef struct _spath_link_qos_t {
    area_t *area1;
    area_t *area2;
    u_long metric;
    LINKED_LIST *ll_link_qoses; /* max 8 */
    time_t tstamp;
    time_t ctime;
    time_t utime;
    LINKED_LIST *ll_bad_updates;
    time_t ktime;
#define LINK_QOS_CHANGED  0x01
#define LINK_QOS_EXTERNAL 0x02
#define LINK_QOS_DELETED  0x04
    u_long flags;
    hqlip_neighbor_t *neighbor;	/* who sent this */
    struct _spath_link_qos_t *delayed_link_qos;
} spath_link_qos_t;


#define SSPEC_NUM_AREAQOS 4
typedef struct _spath_area_qos_t {           
    area_t *area;                 
    area_t *in;
    area_t *out;
    LINKED_LIST *ll_area_qoses; /* max 4 */
    time_t tstamp;
    time_t ctime;
    time_t utime;
#define AREA_QOS_CHANGED  0x01
#define AREA_QOS_DELETED  0x02
    u_long flags;
    hqlip_neighbor_t *neighbor;	/* who sent this */
} spath_area_qos_t;

typedef struct _spath_area_center_t {           
    area_t *area;
    /* u_long router_id; */
    int pri;
    time_t tstamp;
    time_t ctime;
    time_t utime;
#define AREA_CENTER_CHANGED  0x01
#define AREA_CENTER_DELETED  0x02
    u_long flags;
    hqlip_neighbor_t *neighbor;	/* who sent this */
} spath_area_center_t;

typedef struct _spath_area_addr_t {           
    area_t *area;
    LINKED_LIST *ll_prefixes;
    time_t tstamp;
    time_t ctime;
    time_t utime;
#define AREA_ADDR_CHANGED  0x01
#define AREA_ADDR_DELETED  0x02
    u_long flags;
    hqlip_neighbor_t *neighbor;	/* who sent this */
} spath_area_addr_t;

#endif /* _HQLIP_H */

/*
 * $Id: bgp.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _BGP_H
#define _BGP_H

#include <mrt.h>
#include <timer.h>
#include <trace.h>
#include <io.h>
#include <schedule.h>
#include <hash.h>

#include <rib.h>
#include <bgp_proto.h>

struct _bgp_attr_t;
#define bgp_attr_t struct _bgp_attr_t

/* various settable attributes */
#define DEFAULT_PEER_NAME	"glasshouse.merit.edu"
#define DEFAULT_PEER_AS		185
#ifdef notdef
#define DEFAULT_MY_AS		6503
#define DEFAULT_MY_ID		0xc66c3cb0
#endif
#define DEFAULT_LOCAL_AS        6503
#define DEFAULT_ROUTER_ID       0xc66c3cb0

#define MAX_AS_NUMBER           65535

#define DEFAULT_DATAFILE	"/tmp/bgp.data"

#define DEFAULT_BGP_VERSION	4
#define DEFAULT_BGP4PLUS_VERSION 1	/* 0, 1, 2 -- auto */

#define DEFAULT_CONNET_RETRY_INTERVAL	120 /* was 60 */
#define DEFAULT_START_INTERVAL		10 /* RFC suggests 60 */
#define DEFAULT_KEEPALIVE_INTERVAL	30
#define DEFAULT_HOLDTIME_INTERVAL	90 /* was 180 */
#define BGP_OPEN_TIMEOUT		240

#define BGP_MIN_HOLDTIME        20      /* What we'll accept */

/* pdu types */
#define BGP_OPEN		1
#define BGP_UPDATE		2
#define BGP_NOTIFICATION	3
#define BGP_KEEPALIVE		4

/* saving routing table to disk (mrtd) */
#define DUMP_ASCII		1
#define DUMP_BINARY		2

#define DUMP_DIR_RECV	0x01
#define DUMP_DIR_SEND	0x02
#define DUMP_DIR_BOTH   (DUMP_DIR_RECV|DUMP_DIR_SEND)

extern char *sbgp_states[];
extern char *sbgp_pdus[];
extern char *sbgp_events[];
extern char *s_bgp_error[];
extern char *s_bgp_error_header[];
extern char *s_bgp_error_open[];
extern char *s_bgp_error_update[];


#define BGP_TRANSPARENT_AS			0x00001
#define BGP_TRANSPARENT_NEXTHOP		0x00002
#define BGP_CONNECT_PASSIVE			0x00004	/* don't try to connect */

#define BGP_BGP4PLUS_00_RCVD		0x00008
#define BGP_BGP4PLUS_00				0x00010	/* draft 00 */
#define BGP_BGP4PLUS_01				0x00020	/* draft 01 */
#define BGP_BGP4PLUS_AUTO			0x00040	/* auto detection */
#define BGP_BGP4PLUS_01_RCVD		0x00080	/* no fall-back */
#define BGP_BGP4PLUS_DEFAULT	(BGP_BGP4PLUS_AUTO|BGP_BGP4PLUS_01)
/* default is now "auto" */

#define BGP_EBGP_MULTIHOP			0x00100
#define BGP_NEXTHOP_SELF			0x00200
#define BGP_INTERNAL				0x00400
#define BGP_ROUTE_REFLECTOR_CLIENT	0x00800
#define BGP_DONTSEND_CAPABILITY		0x01000
#define BGP_REMOVE_PRIVATE_AS		0x02000
#define BGP_NEXTHOP_PEER 			0x04000
#define BGP_PEER_CISCO 				0x08000
#define BGP_PEER_TEST 				0x10000
#define BGP_PEER_SELF 				0x20000 /* on the same host */

typedef struct listen_socket_t {
    int sockfd;
    int ref_count;
    prefix_t *prefix;
    interface_t *interface;
    pthread_mutex_t mutex_lock;
    LINKED_LIST *ll_accept_sockets;
} listen_socket_t;


typedef struct accept_socket_t {
    int sockfd;
    u_char buffer_in[BGPMAXPACKETSIZE];
    u_char *read_ptr_in;	/* current ptr of read in buffer */
    time_t start_time;
    listen_socket_t *listen_socket;
    prefix_t *remote_prefix;
    prefix_t *local_prefix;
    int remote_port;
} accept_socket_t;


typedef struct _bgp_bitset_t {
        bitx_mask_t bits[(MAX_BGP_PEERS+BITX_NBITS-1)/BITX_NBITS];
} bgp_bitset_t;


typedef struct _bgp_local_t {
    int this_as;
#if 0
    int cport;			/* port to send out open on */
    int lport;			/* port to listen for open on */
#endif
    trace_t *trace;

  /* must fix ID stuff when adding interface things.  Currently everything
     gets the same router_id which is unnacceptable.  -- binkertn */
    u_long this_id;  
    u_long cluster_id;  
    pthread_mutex_t mutex_lock;

    /* LINKED_LIST *ll_views; */

    bgp_bitset_t view_mask;

    bgp_bitset_t bits_assigned;	/* record the peers' bits */
    pthread_mutex_t peers_mutex_lock; /* a lock for ll_bgp_peers */
    LINKED_LIST *ll_bgp_peers;
    int num_peers;		/* number of peers */
    int num_ipv4_peers;		/* number of IPv4 peers */

    int bind_interface_only;
    int num_interfaces;
    LINKED_LIST *ll_interfaces;
} bgp_local_t;


typedef struct _bgp_filters_t {
    int dlist_in;               /* list num for input filtering */
    int dlist_out;              /* list num for output filtering */
    int flist_in;               /* list num for input aspath filtering */
    int flist_out;              /* list num for output aspath filtering */
    int clist_in;               /* list num for input community filtering */
    int clist_out;              /* list num for output community filtering */
    int route_map_in;           /* num for input route-map */
    int route_map_out;          /* num for output route-map */
} bgp_filters_t;


typedef struct _bgp_peer_t {
    char *name;
    char *description;
    interface_t *bind_if;
    prefix_t *bind_addr;

    /* the following may be duplicated in gateway, 
	but these are ones specified by the user */
    prefix_t *peer_addr;	/* peer address only */
    int peer_as;			/* peer's as number */
    u_long peer_id;			/* peer's router id */
    int peer_port;			/* port number in case it isn't 179 */

    gateway_t *gateway;
    interface_t *interface;	/* interface once seen (for information) */
    prefix_t *local_addr;	/* local address for the peer */
    nexthop_t *nexthop; 	/* immediate next hop */
    int new_as;				/* this will be used at the next start */
    int new_id;				/* this will be used at the next start */
    LINKED_LIST *aliases;	/* peer's aliases */
    int sockfd;				/* sockect connected to peer */
    listen_socket_t *listen_socket;	/* sockect for listening incoming connection */
    u_long index;			/* index (used by view in mask) */
    u_long options;			/* see options above */
    bgp_local_t *local_bgp;	/* local bgp session */
    int neighbor_list;		/* if > 0, this is a neighbor list */
    LINKED_LIST *children;
    struct _bgp_peer_t *parent;
    bgp_bitset_t view_mask;	/* which views routes being injected */

    pthread_mutex_t mutex_lock;
    pthread_t self;			/* my thread ID */
    schedule_t *schedule;	/* event processing */

    /* packet parsing storage */
    u_char buffer[BGPMAXPACKETSIZE * 2];
    u_char *read_ptr;		/* current ptr of read in buffer */
    u_char *start_ptr;		/* current ptr of start of packet */
    u_char *packet;		/* pointer to the packet */

    accept_socket_t *accept_socket;
#if 0
    u_char buffer_in[BGPMAXPACKETSIZE];
    u_char *read_ptr_in;	/* current ptr of read in buffer */
    int sockfd_in;		/* sockect connected to peer (incoming) */
#endif

    LINKED_LIST *send_queue;
    pthread_mutex_t send_mutex_lock;

    /* timers */
    mtimer_t *timer_Start;
    mtimer_t *timer_ConnectRetry;
    mtimer_t *timer_KeepAlive;
    mtimer_t *timer_HoldTime;

    /* time value of intervals in seconds */
    int Start_Interval;
    int ConnectRetry_Interval;
    int KeepAlive_Interval;
    int HoldTime_Interval;

    /* tracing stuff */
    trace_t *trace;

    time_t time;
    int maximum_prefix;

    bgp_filters_t filters[MAX_BGP_VIEWS];	/* filters per view */
    int default_weight[MAX_BGP_VIEWS];

    int state; 
    int code;    
    int subcode;
    
    LINKED_LIST *ll_announce;
    LINKED_LIST *ll_withdraw;
    bgp_attr_t *attr;
    int safi;

    LINKED_LIST *ll_update_out;
    pthread_mutex_t update_mutex_lock;

    /* statistics */
    u_long num_packets_recv;
    u_long num_notifications_recv;
    u_long num_updates_recv;
    u_long num_packets_sent;
    u_long num_notifications_sent;
    u_long num_updates_sent;
    u_long num_connections_established;
    u_long num_connections_dropped;

    /* store incoming routes (rib_in) */
    radix_tree_t *routes_in[AFI_MAX][SAFI_MAX];
    time_t routes_in_check_time;

#define AFISAFI2CAP(afi, safi) (1 << ((((afi) - 1) << 2) + ((safi) - 1)))
    u_long cap_opt_requesting;
    u_long cap_opt_received;
    u_long cap_opt_negotiated;
} bgp_peer_t;

#include <view.h>

typedef struct _bgp_t {
    int cport;                  /* port to send out open on */  
    int lport;                  /* port to listen for open on */
    int default_local_pref;

    LINKED_LIST *ll_bgp_locals;		/* linked list of bgp routers */
    pthread_mutex_t locals_mutex_lock; /* a lock for ll_bgp_locals */

    int accept_all_peers;
    trace_t *trace;
    LINKED_LIST *ll_listen_sockets;

    HASH_TABLE *attr_hash;	/* hash of bgp attribute blocks */
    struct _view_t *views[MAX_BGP_VIEWS];
    bgp_bitset_t view_mask;     /* which views are defined */
    schedule_t *schedule;	/* event processing */

    void (*peer_down_call_fn) ();
    int (*update_call_fn) ();
    void (*state_change_fn) ();
    void (*peer_established_call_fn) ();
    int (*send_update_call_fn) ();

    /* Since view is created dynamically,
       there may be a dump request without a real view */
    char *dump_route_form[MAX_BGP_VIEWS];
    time_t dump_route_interval[MAX_BGP_VIEWS];
    time_t dump_route_time[MAX_BGP_VIEWS];
    int	dump_route_type[MAX_BGP_VIEWS];	/* DUMP_ASCII or DUMP_BINARY */
    int	dump_new_format;	/* bool */
    int	dump_direction;		/* 1 -- receiving, 2 -- sending, 3 -- both */

    char *dump_update_form;
    time_t dump_update_interval;
    time_t dump_update_time;
    u_long dump_update_types;
    int dump_update_family;

    pthread_mutex_t mutex_lock;

    time_t Default_Start_Interval;
    time_t Default_ConnectRetry_Interval;
    time_t Default_KeepAlive_Interval;
    time_t Default_HoldTime_Interval;

    mtimer_t *timer_house_keeping;

    u_int bgp_num_active_route_head;
    u_int bgp_num_active_route_node;

    HASH_TABLE *nexthop_hash_table;
} bgp_t;


extern bgp_t *BGP;

enum BGP_ATTR {
    BGP_NULL = 0,
    BGP_MY_AS,
    BGP_MY_ID,
    BGP_CURRENT_BGP,
    BGP_TRACE_STRUCT,
    BGP_PEER_DOWN_FN,
    BGP_PEER_ESTABLISHED_FN,
    BGP_RECV_UPDATE_FN,
    BGP_STATE_CHANGE_FN,
    BGP_SEND_UPDATE_FN, 	/* call this routine when sending updates */
    BGP_ACCEPT_ALL_PEERS,	/* start peering sesssion with anyone */
    BGP_LPORT,			/* port to listen for connections on */
    BGP_CPORT,			/* port to attempt connections to */
    BGP_USE_PORTSERVER,		/* use portserver library for listening */
    BGP_DUMP_ROUTE_FORM,	/* a file name used in dumping a route table */
    BGP_DUMP_UPDATE_FORM,	/* a file name used in dumping updates */
    BGP_DUMP_DIRECTION		/* 1 -- receiving, 2 -- sending, 3 -- both */
};


enum BGP_PEER_ATTR {
    BGP_PEER_NULL = 0,
    BGP_PEER_AS,
    BGP_PEER_ROUTER_ID,
    BGP_PEER_DESCRIPTION,
    BGP_PEER_VIEW,
    BGP_PEER_WEIGHT,
    BGP_PEER_ALIAS_ADD,
    BGP_PEER_ALIAS_DEL,
    BGP_PEER_MAXPREF,
    BGP_PEER_SETOPT,
    BGP_PEER_RESETOPT,
    BGP_PEER_DLIST_IN,
    BGP_PEER_DLIST_OUT,
    BGP_PEER_FLIST_IN,
    BGP_PEER_FLIST_OUT,
    BGP_PEER_CLIST_IN,
    BGP_PEER_CLIST_OUT,
    BGP_PEER_RTMAP_IN,
    BGP_PEER_RTMAP_OUT,
    BGP_PEER_HOLDTIME,
    BGP_PEER_KEEPALIVE,
    BGP_PEER_CONNECTRETRY,
    BGP_PEER_START
};


/* a convenience structure to store all prefixes with same BGP
 * attributes while we are building BGP update packets
 */
typedef struct _bgp_bucket_t {
    LINKED_LIST *ll_prefix;
    bgp_attr_t *attr;
} bgp_bucket_t;


typedef struct _bgp_packet_t {
    short len, offset;
    u_char *data;
} bgp_packet_t;


/* in bgp_pdu.c */
int bgp_read (bgp_peer_t * peer, int sockfd, u_char * ptr, int len);
int bgp_get_pdu (bgp_peer_t * peer);
int bgp_flush_queue (bgp_peer_t * peer);
void bgp_packet_del (bgp_packet_t *bgp_packet);
int bgp_process_update (bgp_peer_t * peer);
int bgp_process_open (bgp_peer_t * peer);
int bgp_process_notify (bgp_peer_t * peer);
int bgp_send_open (bgp_peer_t * peer);
int bgp_send_keepalive (bgp_peer_t * peer);
int bgp_send_notification (bgp_peer_t * peer, int code, int subcode);
int bgp_send_notification2 (int sockfd, prefix_t * prefix, int port,
			    int code, int subcode);
int bgp_send_notify_byte (bgp_peer_t * peer, int code, int subcode, int opt);
int bgp_send_notify_word (bgp_peer_t * peer, int code, int subcode, int opt);
int bgp_send_update (bgp_peer_t * peer, int len, u_char * data);
void bgp_reset_cap_opt (bgp_peer_t *peer);

/* in bgp_util.c */
int bgp_in_recv_open (bgp_peer_t *peer);
int peer_set_gateway (bgp_peer_t *peer, int as, u_long id);
char *bgp_notify_to_string (int code, int subcode);
char *bgpmessage2string (int type);
int bgp_start_transport_connection (bgp_peer_t * peer);
void bgp_release_resources (bgp_peer_t * peer);
bgp_peer_t *Find_BGP_Peer (bgp_local_t *local_bgp,
			   prefix_t * prefix, int as, u_long id);
bgp_peer_t *Find_BGP_Peer_ByID (bgp_local_t *local_bgp, char *name);
bgp_peer_t *Add_BGP_Peer (bgp_local_t *local_bgp, char *name, 
			  prefix_t * prefix, int as, u_long id, 
			  trace_t * trace);
void Destroy_BGP_Peer (bgp_peer_t * peer, int fast);
void bgp_flush_socket (bgp_peer_t * peer);
void bgp_broken_pipe (void);
void bgp_die (void);
int bgp_kill_peer (gateway_t * gateway);
void bgp_stop_peer (bgp_peer_t * peer);
void bgp_start_peer (bgp_peer_t * peer);
void bgp_kill_all (bgp_local_t *local_bgp);
void bgp_start_all (bgp_local_t *local_bgp);
/* void default_bgp_peer_down_fd (bgp_peer_t * peer); */
void bgp_start_peer_thread (bgp_peer_t * peer);
void bgp_start_main_thread ();
bgp_peer_t *find_bgp_peer (gateway_t * gateway);
void peer_set_as (bgp_peer_t *peer, int as);
bgp_local_t *init_bgp_local (int as, u_long id);
void remove_bgp_local (bgp_local_t *local_bgp);
int show_bgp_local (uii_connection_t * uii);
int show_bgp_views (uii_connection_t * uii);
void bgp_peer_down (bgp_peer_t * peer);
void bgp_peer_dead (bgp_peer_t * peer);
void dump_text_bgp_view (uii_connection_t * uii, view_t *view);
int set_BGP (int first, ...);
void start_bgp (void);
void stop_bgp (void);
void start_bgp_peer (bgp_peer_t * peer);
void bgp_start_listening (bgp_peer_t *peer);
int trace_bgp (uii_connection_t * uii);
int bgp_check_attr (bgp_peer_t * peer, bgp_attr_t * attr, int as);
int check_bgp_networks (prefix_t *prefix, int viewno);
listen_socket_t * init_BGP_listen (prefix_t *bind_addr, interface_t *bind_if);
int show_f_bgp (uii_connection_t * uii, int family);
int show_f_bgp_summary (uii_connection_t * uii, bgp_local_t *local_bgp, 
			int family, int summary);
int show_f_bgp_rt_view_regexp (uii_connection_t * uii, int family,
			       int viewno, char *expr, char *filtered);
int show_bgp_rt_view_prefix (uii_connection_t * uii, int viewno, 
			     prefix_t *prefix, char *options, char *filtered);
int show_f_bgp_neighbors_routes (uii_connection_t * uii, int family,
                             int viewno, char *peer_or_star, char *filtered);
int show_f_bgp_neighbors_errors (uii_connection_t * uii, int family,
                             char *peer_or_star);

/* in bgp_sm.c */
void bgp_change_state (bgp_peer_t * peer, int state, int event);
#ifdef notdef
void bgp_sm_state_idle (bgp_peer_t * peer, int event);
void bgp_sm_state_active (bgp_peer_t * peer, int event);
void bgp_sm_state_connect (bgp_peer_t * peer, int event);
void bgp_sm_state_opensent (bgp_peer_t * peer, int event);
void bgp_sm_state_openconfirm (bgp_peer_t * peer, int event);
void bgp_sm_state_established (bgp_peer_t * peer, int event);
#endif
void bgp_sm_process_event (bgp_peer_t * peer, int event);

/* in bgp_timer.c */
void bgp_timer_ConnectRetry_fire (mtimer_t * timer, bgp_peer_t * peer);
void bgp_timer_KeepAlive_fire (mtimer_t * timer, bgp_peer_t * peer);
void bgp_timer_HoldTime_fire (mtimer_t * timer, bgp_peer_t * peer);
void bgp_timer_StartTime_fire (mtimer_t * timer, bgp_peer_t * peer);

/* in bgp_thread.c */
void bgp_schedule_timer (mtimer_t * timer, bgp_peer_t * peer);
void bgp_schedule_socket (bgp_peer_t * peer);
void bgp_get_config_neighbor (bgp_peer_t * peer);
void bgp_schedule_get_config_neighbor (bgp_peer_t * peer);

/* public functions */
void init_BGP (trace_t * ltrace);

/* bgp_dump.c */
void bgp_write_mrt_msg (bgp_peer_t * peer, enum MRT_MSG_BGP_TYPES bgptype,
			u_char * buf, int length);
void bgp_write_status_change (bgp_peer_t * peer, u_short state);
int bgp_table_dump_write (int fd, int type, int subtype, int viewno,
			  int seq_num, u_char *pp, int len);
u_char *bgp_table_dump_entry (u_char *cp, u_char *end, int type, int subtype,
                      int viewno, prefix_t *prefix, int status,
                      time_t originated, bgp_attr_t *attr);
bgp_peer_t * create_fake_peer (void);
int dump_view_bgp_routes (int viewno, char *filename, int dump_type);

#define Find_BGP_Peer_ByPrefix(local_bgp, prefix) \
		Find_BGP_Peer(local_bgp, prefix, 0, 0)

#undef bgp_attr_t
#endif /* _BGP_H */

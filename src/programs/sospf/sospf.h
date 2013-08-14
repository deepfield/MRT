/*
 * $Id: sospf.h,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

#ifndef _OSPF_H
#define _OSPF_H

#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF	89
#endif /* IPPROTO_OSPF */

#define OSPF_VERSION	2

/* ospf neighbor states */
enum OSPF_STATE {
  OSPF_NEIGHBOR_DOWN,
  OSPF_NEIGHBOR_ATTEMPT,
  OSPF_NEIGHBOR_INIT,	
  OSPF_NEIGHBOR_2WAY,	
  OSPF_NEIGHBOR_EXSTART,
  OSPF_NEIGHBOR_EXCHANGE,	
  OSPF_NEIGHBOR_LOADING,
  OSPF_NEIGHBOR_FULL
};

extern char *ospf_states[];

/* ospf neighbor events */
enum OSPF_EVENT {
  OSPF_EVENT_START, 
  OSPF_EVENT_HELLORECEIVED,
  OSPF_EVENT_2WAYRECEIVED,
  OSPF_EVENT_NEGOTIATIONDONE,
  OSPF_EVENT_EXCHANGEDONE,
  OSPF_EVENT_BADLSREQ,
  OSPF_EVENT_LOADINGDONE,
  OSPF_EVENT_ADJOK,
  OSPF_EVENT_SEQNUMBERMISMATCH,
};

extern char *ospf_events[];

/* ospf constants. */
/* Ages are stored in seconds. */
#define OSPF_MaxAge 3600
#define OSPF_MaxAgeDiff 900

/* link types (used in router LSAs) */
enum LSA_LINK_TYPE {
   POINT_TO_POINT = 1,
   CONNECTION_TO_TRANSIT, 
   CONNECTION_TO_STUB,
   VIRTUAL_LINK
};


/*
 * ospf_neighbor_t
 * Used in adjacencies. Either the DR, BDR, or clients (if we are the DR/BDR) 
 */
typedef struct _ospf_neighbor_t {
  prefix_t			*prefix;	/* real address - use in unicasting */
  struct _ospf_interface_t	*ospf_interface;
  enum OSPF_STATE 		state;			/* OSPF_NEIGHBOR_DOWN, etc */	
  u_char			options;		/* options negotiated w nghbor */
  u_long			dd_seq_num;		/* seq num to send out */
  u_long			lastreceived_seq_num;	/* seq num received */
  u_char			master;			/* master or slave */
  u_char			I_M_MS;			/* I M MS to send out */
  u_char			lastreceived_I_M_MS;	/* I M MS received */
  u_long			neighbor_id;
  u_long			neighbor_priority;

  /* timers */
  mtimer_t			*inactivity_timer;
  mtimer_t			*delay_ack;
  
  LINKED_LIST			*ll_lsa_delay_ack;	/* ack these LSAs */
  LINKED_LIST			*ll_lsa_request;	/* lsa's we need to request */

} ospf_neighbor_t; 


/* flags for I_M_MS bits of neighbor database exchange */
#define OSPF_MS			1
#define OSPF_MORE		2
#define OSPF_INITIAL		4

/* 
 * ospf_interface is the OSPF interface holder. 
 */
typedef struct _ospf_interface_t {
  int			state;
  struct _ospf_area_t	*area;			/* what area we belong to */
  enum LSA_LINK_TYPE	type;
  prefix_t		*virtual_address;
  mtimer_t		*hello_timer;		/* send out periodic hellos */
  interface_t		*interface;
  LINKED_LIST		*ll_neighbors;	
  ospf_neighbor_t	*designated_router;

  u_char		authentication_type;	/* 0==none, 1==simple ASCII password */
  char			password[10];
} ospf_interface_t;


/* 
 *
 * the MAIN GLOBAL STRUCTURE to hold all of our OSPF gorp 
 *
 */
typedef struct _ospf_t {
  int		fd;			/* socket we are listening on */
  int		process_id;
  u_long	router_id;
  u_long	area_id;
  LINKED_LIST	*ll_ospf_interfaces;
  LINKED_LIST	*ll_ospf_areas;

  schedule_t	*schedule;

  /* LSA Database */
  LINKED_LIST   *ll_router_lsas;
  LINKED_LIST   *ll_network_lsas;
  LINKED_LIST   *ll_summary_lsas;
  LINKED_LIST   *ll_external_lsas;

  u_char	buffer[4096];		/* storage while reading in packets */
  u_char	*cp;			/* pointer to current position in buffer */

  u_int		default_hello_interval;
  u_int		default_dead_interval;

  /* statistics logging */
  char		*logformat;		/* save LSA packets to disk */
  int		create_time;		/* time we created the current log file */
  int		loginterval;		/* time (sec) of log interval */
  mtimer_t	*database_dump_timer;
  char 		*tableformat;		/* format of LSA database dump filename */
  int		database_dump_interval;	/* time between database dumps */

  /* ospf callback routines -- for use with tools like ospf_anal  */
  void (*ospf_lsa_call_fn)();
  void (*ospf_router_lsa_call_fn)();
  void (*ospf_network_lsa_call_fn)();
  void (*ospf_external_lsa_call_fn)();

} ospf_t;

extern ospf_t OSPF;


/* 
 * Structure for LSA header information
 */
typedef struct _ospf_lsa_t {
  /* Used to construct the shortest path tree.*/
  unsigned int          seen : 1;

  u_short		age;
  u_char		options;
  u_char		type;
  u_long		id;

  u_long		adv_router;
  u_long		seq_num;
  u_short		checksum;
  u_short		length;
} ospf_lsa_t;

/*
 * Structure to hold links for Router LSAs.
 */
typedef struct _ospf_router_link_t {
  u_char type;
  u_short metric;
  u_long link_id;
  u_long link_data;

  /* For now we ingore any TOS information. */
} ospf_router_link_t;

/*
 * Structure to hold Router LSAs.
 */
typedef struct _ospf_router_lsa_t {
  unsigned int v_bit : 1;
  unsigned int e_bit : 1;
  unsigned int b_bit : 1;

  u_short num_links;

  ospf_lsa_t *header;

  /* This is a dynamically allocated array of links. */
  ospf_router_link_t *links;

} ospf_router_lsa_t;

/*
 * Structure to hold Network LSAs.
 */
typedef struct _ospf_network_lsa_t {
  ospf_lsa_t	*header;
  u_long	network_mask;
  u_long	num_routers;
  u_long	*routers;   /* This is a dynamically allocated array of Router IDs. */
} ospf_network_lsa_t;

/*
 * Structure to hold Summary LSAs.
 */
typedef struct _ospf_summary_lsa_t {
  ospf_lsa_t *header;

  u_long network_mask;
  u_long metric;
} ospf_summary_lsa_t;

/*
 * Structure to hold AS external LSAs.
 */
typedef struct _ospf_external_lsa_t {
  unsigned int e_bit : 1;

  ospf_lsa_t *header;

  u_long network_mask;
  u_long metric;
  u_long forward_address;
  u_long external_route_tag;
} ospf_external_lsa_t;


/*
 * Structure to hold verticies for shortest path tree.
 */
typedef struct _ospf_vertex_t {
  /* The vertex id is the router id for router vertices.
   * For network vertices this is the IP address of the designated router.
   */
  u_long vertex_id;

  /* Only one of the following should be used depending on what type
   * of vertex this is.
   */
  ospf_router_lsa_t *router_lsa;
  ospf_network_lsa_t *network_lsa;

  /* The cost to get to this node from the root. */
  u_long cost;

  /* The parent vertex. */
  struct _ospf_vertex_t *parent_vertex;

  /* FIX need to add the next hops. */

  /* The list of next vertices. */
  LINKED_LIST *ll_next_vertices;
} ospf_vertex_t;

/*
 * Structure to hold links for the shortest path tree.
 */
typedef struct _ospf_vertex_link_t {
  struct _ospf_vertex_t *next_vertex;
  u_long interface;
} ospf_vertex_link_t;


/* 
 * OSPF area
 */
typedef struct _ospf_area_t {
  u_long	area_id;
  u_char        V_E_B;			/* V=virtual link, E=external, B=area border */
  LINKED_LIST	*ll_router_interfaces;	/* total links (interfaces) in this area */
  LINKED_LIST	*ll_routers_lsa;	/* list of routers LSAs in this area */
  LINKED_LIST	*ll_network_lsa;	/* list of network lsa's */
  LINKED_LIST	*ll_summary_lsa;
  /* shortest path tree structure */
  u_char	transit_capability;
  u_char	externalrouting_capability;
  int		stub_default_cost;
} ospf_area_t;


/* 
 * OSPF packet/header information
 */
typedef struct _ospf_header_t {
  struct sockaddr_in	from;	/* the real addr -- used for unicast communication */
  ospf_interface_t	*ospf_interface;
  u_char	version;
  u_char	type;
  u_long	rid;		/* the hello listed router_id */       
  u_long	area;
  u_short	checksum;
  u_short	authtype;
  char		password[10];

  char		*cp;		/* pointers to packet after header */
  u_short	len;		/* packet length */

#ifdef OSPF_ANAL
  time_t	time;		/* time header was received */
#endif /* OSPF_ANAL */
} ospf_header_t;


/* 
 * OSPF packet types
 */
#define	OSPF_HELLO			1
#define OSPF_DATABASE_DESCRIPTION	2
#define OSPF_LINK_STATE_REQUEST		3
#define OSPF_LINK_STATE_UPDATE		4
#define OSPF_LINK_STATE_ACK		5

/*
 * OSPF authentication types
 */
#define OSPF_AUTH_NULL			0
#define OSPF_AUTH_PASSWORD		1


/* LSA types */
#define OSPF_ROUTER_LSA			1
#define OSPF_NETWORK_LSA		2
#define OSPF_SUMMARY_LSA3		3
#define OSPF_SUMMARY_LSA4		4
#define OSPF_EXTERNAL_LSA		5


#define OSPF_LSA_HEADER_SIZE		20

#define OSPF_DEFAULT_HELLO_INTERVAL	40
#define OSPF_DEFAULT_DEAD_INTERVAL	40

#define OSPF_ALLSPFRouters "224.0.0.5"
#define OSPF_ALLDRouters "224.0.0.6"

#define MAX_AGE				3600		/* one hour - seconds */
#define MAX_AGE_DIFF			900		/* 15 min - seconds */
#define CHECK_AGE			300		/* 5 min - seconds */


#define OSPF_INITIAL_LS_SEQUENCE_NUM	0x80000001
#define OSPF_MAX_SEQUENCE_NUM		0x7fffffff

#define LS_INFINITY			0xffffff

#define M_CREAT				1

/* Extra definitions. */
#define UTIL_GET_NETTHREE(val, cp) \
        { \
	    register u_char *val_p; \
            val_p = (u_char *) &(val); \
	    *val_p++ = 0; \
	    *val_p++ = *(cp)++; \
	    *val_p++ = *(cp)++; \
	    *val_p++ = *(cp)++; \
	    (val) = ntohl(val); \
        }

extern trace_t *default_trace;


/* Misc */
void init_ospf ();
ospf_interface_t *add_ospf_interface (uii_connection_t *uii, prefix_t *prefix, int area);
ospf_interface_t *find_ospf_interface (prefix_t *prefix, int flag);
ospf_neighbor_t *ospf_find_neighbor (ospf_interface_t *network, u_long rid);
void ospf_state_change (ospf_neighbor_t *neighbor, int new_state, int event);
char *long_inet_ntoa (u_long addr);
void show_ospf_neighbors (uii_connection_t *uii);
void show_ospf_database (uii_connection_t *uii);
int packet_send_wire_multicast (char *multicast_addr, interface_t *interface, 
				char *cp, int len);
ospf_neighbor_t *ospf_add_neighbor (ospf_header_t *ospf_header);
void start_ospf_thread ();
int create_ospf_socket ();
int neighbor_state_machine (ospf_neighbor_t *neighbor, enum OSPF_EVENT);
short in_cksum(u_char *ip, int count);
ospf_area_t *ospf_find_area (int area);
void ospf_neighbor_inactive (mtimer_t *timer, ospf_neighbor_t *neighbor);
int packet_send_wire_unicast (prefix_t *prefix, char *cp, int len);


/* Packet processing protoypes */
void ospf_read_packet (void);
int ospf_process_link_state_update (ospf_header_t *header);
int ospf_process_hello (ospf_header_t *ospf_header);
int ospf_process_database (ospf_header_t *ospf_header);
void ospf_link_state_acknowledge (ospf_interface_t *network, u_long rid, ospf_lsa_t *lsa);
void ospf_process_lsa_during_exchange (ospf_neighbor_t *neighbor, char *cp, char *end);
int ospf_send_database (ospf_neighbor_t *neighbor);
void ospf_send_hello (mtimer_t *timer, ospf_interface_t *network);
int ospf_process_header (ospf_header_t *header, char *cp);
void ospf_build_lsa_request (ospf_neighbor_t *neighbor);
u_char *ospf_build_router_lsa (ospf_area_t *ospf_area);

/* Configuration Command prototypes */
void config_ospf_area_virtual_link (uii_connection_t * uii, int area, prefix_t *p);
void config_ip_ospf_dead_interval (uii_connection_t * uii, int interval);
void config_ip_ospf_routerid (uii_connection_t * uii, prefix_t *prefix);
void config_ip_ospf_hello_interval (uii_connection_t * uii, int interval);
int config_router_ospf (uii_connection_t * uii, int process_id);
int config_router_network (uii_connection_t * uii, prefix_t *p, int area);
void config_network_ospf_password (uii_connection_t *uii, 
				   prefix_t *prefix, char *password);
void config_dump_ospf_updates (uii_connection_t *uii, char *file, char *interval);
void config_dump_ospf_table (uii_connection_t *uii, char *format, char *interval);

/* LSA Database prototypes. */
void ospf_add_lsa_to_db (ospf_lsa_t *header, void *lsa);
void ospf_destroy_router_lsa (ospf_router_lsa_t *lsa);
void ospf_destroy_network_lsa (ospf_network_lsa_t *lsa);
void ospf_destroy_summary_lsa (ospf_summary_lsa_t *lsa);
void ospf_destroy_external_lsa (ospf_external_lsa_t *lsa);
void *ospf_find_lsa_in_db (ospf_lsa_t *header);
void ospf_database_dump ();

/* Network map prototypes. */
void show_ospf_net_map (uii_connection_t *uii);
ospf_vertex_t *ospf_create_net_map ();

#endif /* _OSPF_H */

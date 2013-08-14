/*
 * $Id: rtracker.h,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */


#define RTR_WITHDRAW   0
#define RTR_ANNOUNCE   1
#define RTR_LOAD       2

typedef struct _rtracker_t {
  int			sockfd;		/* socket on which we listen for connections */
  int			rtr_port;	/* port on which we listen for connections */
  int			access_list;
  int			connections;	/* current number of connections */
  int			max_connections;
  LINKED_LIST		*ll_database;
  char *bgp_log_dir;
} rtracker_t;

/* keep track of data source, (e.g. mae-east) and associated files */
typedef struct _rtr_database_t {
  struct _rtr_database_t	*next, *prev;	/* for linked_list */
  pthread_mutex_t	mutex_lock;
  int		type;		/* bgp, rip, ospf */
  char		*name;
  char		*path;
  LINKED_LIST	*ll_files;	/* BGP update files */
  LINKED_LIST   *ll_dump_files; /* RIB routing table dump files */
  mtimer_t	*rescan_timer;	/* timer to rescan available database files */
} rtr_database_t;


/* keep track of bgp and dump files on disk */
typedef struct _rtr_data_file_t {
  struct _rtr_data_file_t *next, *prev;
  char		*name;
  u_long	time;
} rtr_data_file_t;


/* a container structure to keep track of BGP attr and statistics */
typedef struct _rtracker_attr_t {
  bgp_attr_t	*bgp_attr;
  u_long	time;		/* time of last change */
  int		num_change;
} rtracker_attr_t;


typedef struct _rtr_route_head_t {
  int		state;		/* 0 down, 1 active */
  u_long	time;		/* time of last change */
  rtracker_attr_t *active;	/* active path, if any */
  LINKED_LIST	*ll_attr;

  /* statistics */
  int		num_tdown;
  int		num_tup;
  int		num_change;
} rtr_route_head_t;


typedef struct _rtracker_peer_t {
  gateway_t		*gateway;
  radix_tree_t		*radix;

  /* statistics information */
  int		total_announce;
  int		total_withdraw;
} rtracker_peer_t;


typedef struct _irr_connection_t {
  int                   sockfd;
  schedule_t            *schedule;
  prefix_t              *from;
  rtr_database_t	*database;
  char buffer[MAXLINE];
  char                  *answer;
  int                   answer_len;

  /* stuff for recieving updates -- need to preserve state */
  int                   state;
  u_short               withdrawn;      /* include withdrawn routes? */
  FILE                  *update_fd;
  u_long                start;

  /* query state stuff */
  u_long		start_window;	/* start time (UTC) */
  u_long		end_window;	/* end time (UTC) */
  u_long		sync;		/* synch with table dump (UTC) */
  int			AS;		/* scan for a peer AS */
  int			origin_AS;	/* scan for an origin AS */
  prefix_t		*prefix;	/* scan just for a specific prefix */
  int			type;		/* 0 = both, 1 = ann, 2 = with */

  /* query data */
  LINKED_LIST		*ll_peer;

  /* reporting */
  int			output_type; /* RTR_PREFIXES, etc */

#define MAXHIST 20
  char cmds[MAXHIST][MAXLINE];
  int cmdcp;                    /* number of current cmd */
  int cmdend;                   /* end of cmd history */
  char tmp[MAXLINE];
  char *cp;                     /* pointer to cursor in line */
  char *end;      
} irr_connection_t;


#define RTR_NO_OUTPUT		0
#define RTR_PREFIXES		1	       
#define RTR_ASCII_PREFIXES	2	       
#define RTR_PEER_TABLE		3

#define RTR_OUTPUT_BUFFER_SIZE  1024*6000

void irr_send_okay (irr_connection_t * irr);
int rtr_proccess_command (irr_connection_t * irr);
int irr_destroy_connection (irr_connection_t * connection);
void config_create_default ();
void config_bgp_log_dir (uii_connection_t * uii);

void output_routes (irr_connection_t *irr, u_long time, 
		    bgp_attr_t *attr, 
		    LINKED_LIST *ll_with_prefixes, 
		    LINKED_LIST *ll_ann_prefixes);
void config_rtr_database (uii_connection_t *uii, char *type, char *name, char *path);
int rtr_build_file_list (rtr_database_t *database);
void Delete_RTR_File (rtr_data_file_t *file);
int irr_add_answer (irr_connection_t *irr, char *format, ...);
void report (irr_connection_t *irr);
void irr_send_answer (irr_connection_t * irr);
int listen_telnet (void);
rtr_database_t *find_rtr_database (char *name);
void irr_send_error (irr_connection_t * irr);
void rtr_process_input (char *file, irr_connection_t *irr);
void irr_show_sources (irr_connection_t *irr);
void irr_lock (rtr_database_t *database);
void irr_unlock (rtr_database_t *database);
void rtr_database_rescan (mtimer_t *timer, rtr_database_t *db);
void Delete_Peer (rtracker_peer_t *peer);
rtracker_peer_t *find_peer (irr_connection_t *irr, gateway_t *gateway);
void update_adj_rib (irr_connection_t *irr,  rtracker_peer_t *peer,
		     int ann_flag,  prefix_t *prefix, u_long time,  bgp_attr_t *attr);
void load_rib_from_disk (irr_connection_t *irr, char *filename);
void rtr_dump_table (irr_connection_t *irr);
int rtr_delete_radix (rtracker_peer_t *rtr_peer);

extern rtracker_t RTR;
extern trace_t *default_trace;

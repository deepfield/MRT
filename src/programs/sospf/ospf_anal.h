/*
 * $Id: ospf_anal.h,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */



typedef struct _ospf_stats_t {
  LINKED_LIST	*ll_router_lsa;
  LINKED_LIST	*ll_network_lsa;
  LINKED_LIST	*ll_external_lsa;

  u_long	time;

  int		machine_readable;
  u_long	start_time;
  int		time_buckets[1440];	/* 15 minute buckets */
} ospf_stats_t;


typedef struct _ospf_router_lsa_stats_t {
  u_long		router_id;
  int			num_links;
  ospf_router_link_t	*ospf_router_links;

  int			num_changes;
  u_long		last; /* last time changed */
} ospf_router_lsa_stats_t;


typedef struct _ospf_network_lsa_stats_t {
  u_long		link_state_id;
  u_long		adver_router;

  u_long		network_mask;
  /* This is a dynamically allocated array of Router IDs. */
  u_long		num_routers;
  u_long		*routers;
  int			num_changes;
  u_long		last; /* last time changed */
} ospf_network_lsa_stats_t;


typedef struct _ospf_external_lsa_stats_t {
  u_long		link_state_id;
  u_long		adver_router;

  u_long		network_mask;
  u_long		metric;
  int			num_changes;
  u_long		last; /* last time changed */
} ospf_external_lsa_stats_t;

void ospf_stat_router_lsa (ospf_router_lsa_t *lsa);

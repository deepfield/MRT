/* 
 * $Id: ospf_anal.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <mrt.h>
#include <select.h>
#include <interface.h>
#include <config_file.h>
#include <io.h>
#include "sospf.h"
#include "ospf_anal.h"

/*
 * GLOBALS
 */
trace_t		*default_trace;
ospf_t		OSPF;
static		io_t *IO;
ospf_stats_t	OSPF_STATS;
int		TIME_ASCII = 0;

/* local functions */
static void process_input ();
static time_t calc_start_time (char *date);
int compare_links (int n, ospf_router_link_t *link1, ospf_router_link_t *link2);
void count_lsa (char *header, int num_lsa);
void ospf_stat_router_lsa (ospf_router_lsa_t *lsa);
void ospf_stat_network_lsa (ospf_network_lsa_t *lsa);
void ospf_stat_external_lsa (ospf_external_lsa_t *lsa);
void report ();

void main (int argc, char *argv[]) {
  char c;
  extern char *optarg;	/* getopt stuff */
  extern int optind;		/* getopt stuff */
  int file_flag = 0;

  int errors = 0;
  char *usage = "Usage: ospf_anal [-v] [-i] [-t] [-f file]\n";

  IO = New_IO (default_trace);
  io_set (IO, IO_INFILE, "stdin", NULL);
  default_trace = New_Trace ();
  init_ospf ();
  OSPF_STATS.ll_router_lsa = LL_Create (0);
  OSPF_STATS.ll_network_lsa = LL_Create (0);
  OSPF_STATS.ll_external_lsa = LL_Create (0);


  while ((c = getopt (argc, argv, "vmhf:id:t")) != -1)
    switch (c) {
    case 'v':		/* verbose */
      set_trace (default_trace, TRACE_FLAGS, TR_PACKET | NORM,
		 TRACE_LOGFILE, "stdout", NULL);
      break;
    case 'i':
    case 'f':
	file_flag = 1;
	break;
    case 'd':
      OSPF_STATS.start_time = calc_start_time (optarg);
      break;
    case 't':
      TIME_ASCII = 1;
      break;
    case 'm':
      OSPF_STATS.machine_readable = 1;
      break;
    case 'h':
    default: 
      errors++;
      break;
    }


  if (errors) {
    fprintf (stderr, usage);
    printf ("\nMRT version (%s) compiled on %s\n\n",
	    MRT_VERSION, __DATE__);
    printf ("Report format:\n");
    printf ("  TIME|NLSA|Advr Router|Link Id|Network Mask|[Routers|]...\n");
    printf ("  TIME|RLSA|Advr Router|Link Id|[linktype|link_id]...\n");
    exit (0);
  }

  init_mrt (default_trace);
  init_uii (default_trace);
  init_interfaces (default_trace);

  /* set up calback functions */
  OSPF.ospf_lsa_call_fn = count_lsa;
  OSPF.ospf_router_lsa_call_fn = ospf_stat_router_lsa;
  OSPF.ospf_network_lsa_call_fn = ospf_stat_network_lsa;
  OSPF.ospf_external_lsa_call_fn = ospf_stat_external_lsa;

  /* user commands */
  uii_add_command2 (UII_NORMAL, COMMAND_NORM, "config", 
		      (void *) start_config, 
		    "Configure sospf");
  uii_add_command2 (UII_NORMAL, COMMAND_NORM, "write", (void *) config_write, 
		    "Save configuration to disk");
  uii_add_command2 (UII_NORMAL, COMMAND_NORM,
		    "show config", show_config, "Display current configuration");
  uii_add_command2 (UII_NORMAL, COMMAND_NORM,
		    "show ip ospf neighbors", (void *) show_ospf_neighbors, 
		    "Show status of OSPF nieghbors");
  uii_add_command2 (UII_NORMAL, COMMAND_NORM, 
		    "show ip ospf database", (void *) show_ospf_database,
		    "Database summary");
    if (file_flag) {
    for ( ; optind < argc; optind++) {
      if (io_set (IO, IO_INFILE, (char *) argv[optind], NULL) < 0) {
	printf ("Failed to open infile %s", (char *) optarg);
	exit (0);
      }
      /*printf ("%s\n", argv[optind]);*/
      process_input ();
    }
  }
    
    if (OSPF_STATS.start_time > 0) {
      int i;
      for (i=0; i< 1440; i++) {
	printf ("%d %d\n", i, OSPF_STATS.time_buckets[i]);
      }
    }

    /*report ();*/
}


/*
void report () {
  char tmp1[MAXLINE], tmp2[MAXLINE];
  ospf_router_lsa_stats_t *router_lsa;
  ospf_network_lsa_stats_t *network_lsa;


  LL_Iterate (OSPF_STATS.ll_router_lsa, router_lsa) {
    printf ("%s [changes %d]\n", long_inet_ntoa (router_lsa->router_id), 
	    router_lsa->num_changes);
  }


  LL_Iterate (OSPF_STATS.ll_network_lsa, network_lsa) {
    sprintf (tmp1, "%s", long_inet_ntoa (network_lsa->network_mask));
    sprintf (tmp2, "%s", long_inet_ntoa (network_lsa->link_state_id));
    printf ("%d NLSA %s (link id: %s) network %s [changes %d]\n", 
	    long_inet_ntoa (network_lsa->adver_router), tmp2,
	    tmp1, network_lsa->num_changes);
  }

}
*/


void process_input () {
  static ospf_header_t ospf_header;
  mrt_msg_t *msg;
  int i;

  while (1) {
    if ((msg = (mrt_msg_t *) io_read (IO)) == NULL) {
      return;
    }

    /*printf ("Msg %d %d\n", msg->length, msg->tstamp);*/

    if (msg->type == MSG_PROTOCOL_OSPF) {
      OSPF_STATS.time =  msg->tstamp;
      if (ospf_process_header (&ospf_header, msg->value)) {
	
	/*printf ("Error %d\n",  msg->length);
	  if (i++ > 400) {exit (0);}*/

      }
    }
    Delete (msg);
  }
}


void count_lsa (char *header, int num_lsa) {
  u_long bucket;

  if (OSPF_STATS.start_time > 0) {
    bucket = (OSPF_STATS.time - OSPF_STATS.start_time) / (60);
    OSPF_STATS.time_buckets[bucket] += num_lsa;
  }
}



static time_t calc_start_time (char *date) {
  int y,m,d;
  struct tm timeptr;
  u_long l;

  sscanf (date, "%2d%2d%2d", &y, &m, &d);

  memset (&timeptr, 0, sizeof (struct tm));
  timeptr.tm_mday = d;
  timeptr.tm_mon = m -1;
  timeptr.tm_year = y;

  l = mktime (&timeptr);
  return (l);
}


void ospf_stat_router_lsa (ospf_router_lsa_t *lsa) {
  ospf_router_lsa_stats_t *tmp_lsa;
  ospf_router_link_t *link1, *link2;
  char tmp1[MAXLINE];
  int i, found = 0;
  u_long last;

  /*printf ("%s\n", long_inet_ntoa (lsa->header->id));*/

  LL_Iterate (OSPF_STATS.ll_router_lsa, tmp_lsa) {
    if (tmp_lsa->router_id == lsa->header->id) {
      found = 1;
      break;
    }
  }
  
  if (!found) {
    tmp_lsa = New (ospf_router_lsa_stats_t);
    tmp_lsa->router_id = lsa->header->adv_router;
    tmp_lsa->num_changes = 0;
    LL_Add (OSPF_STATS.ll_router_lsa, tmp_lsa);
    tmp_lsa->last =  OSPF_STATS.time;
  }

  /* compare the two */
  else if ((tmp_lsa->num_links != lsa->num_links) || 
      !compare_links (lsa->num_links, tmp_lsa->ospf_router_links, lsa->links)) {
    tmp_lsa->num_changes++; 
    Delete (tmp_lsa->ospf_router_links);
  }
  else {
    tmp_lsa->last = OSPF_STATS.time;
    return; /* exactly the same */
  }

  last = tmp_lsa->last;
  tmp_lsa->last = OSPF_STATS.time;

  sprintf (tmp1, "%s", long_inet_ntoa (lsa->header->id));
  printf ("%d|RLSA|%d|[%d]|(%d)|%s|%s|", (int) OSPF_STATS.time,
	  lsa->header->age,
	  tmp_lsa->num_changes, tmp_lsa->last - last,
	  long_inet_ntoa (lsa->header->adv_router), tmp1);
	  
  link2 = (ospf_router_link_t *) lsa->links;
  for (i=0; i < lsa->num_links; i++) {
    sprintf (tmp1, "%s", long_inet_ntoa (link2->link_data));
    printf ("%d|%s|%d|%s|", link2->type, long_inet_ntoa (link2->link_id),
	    link2->metric, tmp1);
    link2++;
  }
  printf ("\n");

  /* copy links */ 
  tmp_lsa->ospf_router_links = NewArray (ospf_router_link_t, lsa->num_links);  
  tmp_lsa->num_links = lsa->num_links;
  tmp_lsa->last = OSPF_STATS.time;
  link1 = tmp_lsa->ospf_router_links;
  link2 = lsa->links;
  
  for (i=0; i < lsa->num_links; i++) {
    link1->type = link2->type;
    link1->metric = link2->metric;
    link1->link_id = link2->link_id;
    link1->link_data = link2->link_data;
    link1++;
    link2++;
  }
}


int compare_links (int n, ospf_router_link_t *link1, ospf_router_link_t *link2) {
  ospf_router_link_t *tmp;
  int i, ii, found;

  for (i=0; i < n; i++) {
    found = 0;
    tmp = link2;
    for (ii=0; i < n; i++) { 
      if ((link1->type == tmp->type) && 
	  (link1->metric == tmp->metric) &&
	  (link1->link_id == tmp->link_id) &&
	  (link1->link_data ==  tmp->link_data)) {
	break;
	found =1;
      }
      tmp++;
    }
    if (!found) return (-1);
    link1++;
  }
  
  return (1);
}



void ospf_stat_network_lsa (ospf_network_lsa_t *lsa) {
  ospf_network_lsa_stats_t *network_lsa;
  char tmp1[MAXLINE], tmp2[MAXLINE], *cp;
  u_long router;
  int n, found = 0;
  u_long last; 

  LL_Iterate (OSPF_STATS.ll_network_lsa, network_lsa) {
    if (network_lsa->link_state_id == lsa->header->id) {
      found = 1;
      break;
    }
  }
  
  if (!found) {
    network_lsa = New (ospf_network_lsa_stats_t);
    LL_Add (OSPF_STATS.ll_network_lsa, network_lsa);
    network_lsa->last = OSPF_STATS.time;
  }
  else if ((network_lsa->num_routers != lsa->num_routers) ||
	   ((memcmp (network_lsa->routers, lsa->routers, 4*lsa->num_routers)) != 0)) {
    network_lsa->num_changes++;
    Delete (network_lsa->routers);
  }
  else {
    network_lsa->last = OSPF_STATS.time;
    return;
  }
  
  last = network_lsa->last;
  network_lsa->last =  OSPF_STATS.time;

  network_lsa->link_state_id = lsa->header->id;
  network_lsa->network_mask = lsa->network_mask;
  network_lsa->adver_router = lsa->header->adv_router;
  network_lsa->num_changes = 0;
  network_lsa->num_routers = lsa->num_routers;
  network_lsa->routers = NewArray (u_long, lsa->num_routers);
  memcpy (network_lsa->routers, lsa->routers, 4*lsa->num_routers);
  
  sprintf (tmp1, "%s", long_inet_ntoa (network_lsa->network_mask));
  sprintf (tmp2, "%s", long_inet_ntoa (network_lsa->link_state_id));
  printf ("%d|NLSA|%d|[%d]|(%d)|%s|%s|%s|",(int) OSPF_STATS.time,
	  lsa->header->age,
	  network_lsa->num_changes,
	  network_lsa->last - last, 
	  (char *) long_inet_ntoa (network_lsa->adver_router), tmp2, tmp1);

  n = lsa->num_routers;
  cp = (char *) lsa->routers;
  while (n--) {
    UTIL_GET_NETLONG (router, cp);
    printf ("%s|", long_inet_ntoa (router));
  }
  printf ("\n");
}



void ospf_stat_external_lsa (ospf_external_lsa_t *lsa) {
  ospf_external_lsa_stats_t *external_lsa = NULL;
  char tmp1[MAXLINE], tmp2[MAXLINE];
  int found = 0, m;
  u_long last;

  LL_Iterate (OSPF_STATS.ll_external_lsa, external_lsa) {
    if ((external_lsa->link_state_id == lsa->header->id) &&
	(external_lsa->network_mask == lsa->network_mask) &&
	(external_lsa->adver_router == lsa->header->adv_router)) {
      found = 1;
      break;
    }
  }
  
  if (!found) {
    external_lsa = New (ospf_external_lsa_stats_t);
    LL_Add (OSPF_STATS.ll_external_lsa, external_lsa);
    external_lsa->last = OSPF_STATS.time;
  }
  else if ((external_lsa->metric != lsa->metric)) {
    external_lsa->num_changes++;
  }
  else {
    external_lsa->last = OSPF_STATS.time;
    return;
  }

  last = external_lsa->last;
  external_lsa->last = OSPF_STATS.time;
  external_lsa->adver_router = lsa->header->adv_router;
  external_lsa->link_state_id = lsa->header->id;
  external_lsa->network_mask = lsa->network_mask;
  m = external_lsa->metric;
  external_lsa->metric = lsa->metric;


  if (external_lsa->num_changes > 0) {
    sprintf (tmp2, "%s", long_inet_ntoa (external_lsa->link_state_id));
    sprintf (tmp1, "%s", long_inet_ntoa (lsa->network_mask));
    printf ("%d|ELSA|%d|[%d]|(%d)|%s|%s|%s|%d\n", (int) OSPF_STATS.time, 
	    lsa->header->age,
	    external_lsa->num_changes,
	    external_lsa->last - last, 
	    (char *) long_inet_ntoa (external_lsa->adver_router), tmp2,
	    tmp1, (int) external_lsa->metric);
  }

}

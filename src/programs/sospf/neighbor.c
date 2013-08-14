/* 
 * $Id: neighbor.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

/* 
 * Routines to handle DR, BDR election, and nieghbor processing
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

#include "sospf.h"

/* local functions */
static int ospf_neighbor_exstart (ospf_neighbor_t *neighbor);
static void _ospf_neighbor_inactive (ospf_neighbor_t *neighbor);

/* either create, or just update the last time we heard from a nieghbor */
ospf_neighbor_t *ospf_add_neighbor (ospf_header_t *ospf_header) {
  ospf_neighbor_t *neighbor;
  ospf_interface_t *ospf_interface;

  ospf_interface = ospf_header->ospf_interface;

  LL_Iterate (ospf_interface->ll_neighbors, neighbor) {
    if (neighbor->neighbor_id == ospf_header->rid) {
      return (neighbor);
    }		
  }

  /* doesn't exist, so create a new neighbor */
  neighbor = New (ospf_neighbor_t);
  neighbor->ospf_interface = ospf_interface; 
  neighbor->neighbor_id = ospf_header->rid;
  
  neighbor->prefix = New_Prefix (AF_INET, &(ospf_header->from.sin_addr), 32);

  LL_Add (ospf_interface->ll_neighbors, neighbor);
  trace (NORM, default_trace, "Adding OSPF neighbor %s\n", 
	 prefix_toa (neighbor->prefix));
  neighbor->inactivity_timer = (mtimer_t *) 
    New_Timer (ospf_neighbor_inactive, OSPF.default_dead_interval,
	       "OSPF dead", (void *) neighbor);

  neighbor->ll_lsa_request = LL_Create (0);
  neighbor->ll_lsa_delay_ack = LL_Create (0);

  neighbor_state_machine (neighbor, OSPF_EVENT_HELLORECEIVED);

  return (neighbor);
}


ospf_neighbor_t *ospf_find_neighbor (ospf_interface_t *ospf_interface, u_long rid) {
  ospf_neighbor_t *neighbor;

  if (ospf_interface == NULL) return (NULL);

  LL_Iterate (ospf_interface->ll_neighbors, neighbor) {
    if (neighbor->neighbor_id == rid)
      return (neighbor);
  }		
  return (NULL);
}



int neighbor_state_machine (ospf_neighbor_t *neighbor, enum OSPF_EVENT event) {

  switch (event) {

  case OSPF_EVENT_START: 
    if (neighbor->state == OSPF_NEIGHBOR_DOWN) {
      ospf_send_hello (NULL, neighbor->ospf_interface);
      ospf_state_change (neighbor, OSPF_NEIGHBOR_ATTEMPT, event);
      /* start inactivity timer for neighbor */
    }
    break;


  case OSPF_EVENT_HELLORECEIVED:
    if (neighbor->state <= OSPF_NEIGHBOR_INIT) {
      /* restart the inactivity timer for neighbor */
      ospf_state_change (neighbor, OSPF_NEIGHBOR_INIT, event);
    }
    else {
      /* restart the inactivity timer for neighbor */
    }
    break;

  case OSPF_EVENT_2WAYRECEIVED:
    if (neighbor->state == OSPF_NEIGHBOR_INIT) {
      ospf_state_change (neighbor, OSPF_NEIGHBOR_EXSTART, event);
      ospf_neighbor_exstart (neighbor);
    }
    break;

  case OSPF_EVENT_NEGOTIATIONDONE:
    if (neighbor->state == OSPF_NEIGHBOR_EXSTART) {
      ospf_state_change (neighbor, OSPF_NEIGHBOR_EXCHANGE, event);
    }
    break;

  case OSPF_EVENT_EXCHANGEDONE:
    if (neighbor->state == OSPF_NEIGHBOR_EXCHANGE) {
      /* we have LSAs to request */
      if (LL_GetCount (neighbor->ll_lsa_request) > 0) {
	ospf_state_change (neighbor, OSPF_NEIGHBOR_LOADING, event);
	ospf_build_lsa_request (neighbor);
	ospf_state_change (neighbor, OSPF_NEIGHBOR_FULL, OSPF_EVENT_LOADINGDONE);
      }
      else
	ospf_state_change (neighbor, OSPF_NEIGHBOR_FULL, OSPF_EVENT_LOADINGDONE);
    }
    break;

  case OSPF_EVENT_LOADINGDONE:
    if ((neighbor->state == OSPF_NEIGHBOR_LOADING) ||
	(neighbor->state == OSPF_NEIGHBOR_EXCHANGE)) {
      ospf_state_change (neighbor, OSPF_NEIGHBOR_FULL, event);
    }
    break;

  case OSPF_EVENT_SEQNUMBERMISMATCH:
    ospf_state_change (neighbor, OSPF_NEIGHBOR_FULL, event);
    exit (0);
    break;


  default:
    trace (ERROR, default_trace, "ERROR -- Unknown OSPF event %d\n", event);
    break;
  }	 
  return (1);
}


/* ospf_state_change
 */
void ospf_state_change (ospf_neighbor_t *neighbor, int new_state, int event) {
  trace (NORM, default_trace, "OSPF state %s->%s on event %s\n", 
	 ospf_states[neighbor->state], 
	 ospf_states[new_state], ospf_events[event]);
  neighbor->state = new_state;

  if (neighbor->state == OSPF_NEIGHBOR_ATTEMPT) {
    Timer_Turn_ON ((mtimer_t *) neighbor->ospf_interface->hello_timer);
    ospf_send_hello (NULL, neighbor->ospf_interface);
  }

  return;
}


/* ospf_neighbor_exstart
 * A neighbor has entered exstart state. Begin the master-slave negotiation
 */
int ospf_neighbor_exstart (ospf_neighbor_t *neighbor) {

  /* increment number in dd_seq number. If first time, set to time
   * of day or something. 
   */
  if (neighbor->dd_seq_num == 0) {
    neighbor->dd_seq_num = time (NULL);
  }
  else
    neighbor->dd_seq_num++;

  /* declare ourselves master and start sending database description 
   * packets with I (initialize), M (more), and MS (master) bit set
   * retransmit at RxmtInterval until next state is entered
   */
  neighbor->I_M_MS = OSPF_MS | OSPF_MORE | OSPF_INITIAL;
  
  /* send emtpy database, and start timer to keep sending */
  ospf_send_database (neighbor);
  return (1);
}



/* ospf_neighbor_inactive
 * A neighbor hasn't sent us a hello in a while -- mark him as dead 
 */
void ospf_neighbor_inactive (mtimer_t *timer, ospf_neighbor_t *neighbor) {

  schedule_event2 ("ospf_neighbor_inactive", OSPF.schedule, 
		   _ospf_neighbor_inactive, 1, neighbor);
}


static void _ospf_neighbor_inactive (ospf_neighbor_t *neighbor) {
  trace (NORM, default_trace, "OSPF neighbor inactive -- removing %s\n",
         long_inet_ntoa (neighbor->neighbor_id));

  /* iterate through interfaces */
  /* iterate through areas */
  /* delete and/or turn off times */
  /* remove routes and LSA's from this neighbor? */
}

/* this needs to be scheduled */
void show_ospf_neighbors (uii_connection_t *uii) {
  ospf_interface_t *ospf_interface;
  ospf_neighbor_t *neighbor;


  uii_add_bulk_output (uii, "%-15s %-8s %-15s   %s\r\n", 
		       "Neighbor ID", "State", "Address", "Interface");
  
  LL_Iterate (OSPF.ll_ospf_interfaces, ospf_interface) {
    
    LL_Iterate (ospf_interface->ll_neighbors, neighbor) {
      uii_add_bulk_output (uii, "%-15s %-8s %-15s   %s\r\n", 
			   long_inet_ntoa (neighbor->neighbor_id), 
			   ospf_states[neighbor->state],
			   prefix_toa (neighbor->prefix),
			   ospf_interface->interface->name);
    }
  }
  uii_send_bulk_data (uii); 
}



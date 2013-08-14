/* 
 * $Id: database.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
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

/* local routines */
static int ospf_process_database_exchange (ospf_neighbor_t *neighbor, 
					   char *cp, char *end);
static int ospf_process_database_exstart (ospf_neighbor_t *neighbor, char *cp, char *end);
static char *ospf_neighbor_database_flags (int flags);

/* ospf_process_database -- process/munge a database packet */
int ospf_process_database (ospf_header_t *ospf_header) {
  u_short interface_mtu;
  u_char options, I_M_MS, *end, *cp;
  u_long dd_seq_num;
  ospf_neighbor_t *neighbor;


  cp = ospf_header->cp;
  end = cp + ospf_header->len - 24;

  if ((neighbor = 
       ospf_find_neighbor (ospf_header->ospf_interface, ospf_header->rid)) == NULL) {
    trace (ERROR, default_trace, "Error -- OSPF Database from uknown neighbor\n");
    return (-1);
  }


  UTIL_GET_NETSHORT (interface_mtu, cp);
  UTIL_GET_BYTE (options, cp);
  UTIL_GET_BYTE (I_M_MS, cp);
  UTIL_GET_NETLONG (dd_seq_num, cp);

  trace (NORM, default_trace, "Recv OSPF Database: imtu: %d, options: 0x%x, flags: %s\n",
	 interface_mtu, options, ospf_neighbor_database_flags (I_M_MS));

  trace (NORM, default_trace, "Recv OSPF Database: dd_seq: %d,  %d bytes\n", 
	 dd_seq_num, end - cp);

  neighbor->options = options;
  neighbor->lastreceived_seq_num = dd_seq_num;
  neighbor->lastreceived_I_M_MS = I_M_MS;

  switch (neighbor->state) {
  case OSPF_NEIGHBOR_EXSTART:
    ospf_process_database_exstart (neighbor, cp, end);
    break;
  case OSPF_NEIGHBOR_EXCHANGE:
    ospf_process_database_exchange (neighbor, cp, end);
    break;
  case OSPF_NEIGHBOR_DOWN:
  case OSPF_NEIGHBOR_ATTEMPT:
  case OSPF_NEIGHBOR_INIT:
  case OSPF_NEIGHBOR_2WAY:
  case OSPF_NEIGHBOR_LOADING:
  case OSPF_NEIGHBOR_FULL:
    printf ("Shouldn't be in this state (%s)", ospf_states[neighbor->state]);
    exit (0);
  }

  trace (NORM, default_trace, "\n");
  return (1);
}
  


/* 
 * ospf_process_database_exstart
 * EXSTART negotation (master-slave)
 */
static int ospf_process_database_exstart (ospf_neighbor_t *neighbor, char *cp, char *end) {
  
  /* we're a slave ... :( */
  if (neighbor->neighbor_id > OSPF.router_id) {
    neighbor->dd_seq_num = neighbor->lastreceived_seq_num;
    neighbor->I_M_MS = 0;
    neighbor->I_M_MS |= OSPF_MORE;
    if (cp != end) {
      trace (ERROR, default_trace, "OSPF ERROR *** expected packet to be emtpy...\n");
      exit (0);
    }
    ospf_send_database (neighbor); /* send empty database */
    neighbor_state_machine (neighbor, OSPF_EVENT_NEGOTIATIONDONE);
    return (1);
  }
  

  /* we're a master */
  neighbor->master = 1;
  trace (ERROR, default_trace, "Master (0x%x > 0x%x)\n",  OSPF.router_id, 
	 neighbor->neighbor_id);

  /* make sure we've been acknowledged */
  if (neighbor->lastreceived_I_M_MS & OSPF_MS) {
    trace (ERROR, default_trace, "We're master, but Master bit set by neighbor...\n");
    return (1);
  }

  /* otherwise, check the sequence number and verify we've
   * been acknowldegded as master */

  /* slave may have sent data */
  if (end - cp > 0) {
    ospf_process_lsa_during_exchange (neighbor, cp, end);
  }

  /* the slave has acknowledged us as a master! -- negotation is done */
  neighbor_state_machine (neighbor, OSPF_EVENT_NEGOTIATIONDONE);

  /*
   * poll for any database packets the slave might want to 
   * send us  
   */ 
  neighbor->dd_seq_num++;
  neighbor->I_M_MS = OSPF_MS;
  ospf_send_database (neighbor); /* send empty database */

  return (1);
}

 
 
 
/* 
 * ospf_process_database_exchange
 * process database packet when we're in the exchange state 
 */
static int ospf_process_database_exchange (ospf_neighbor_t *neighbor, 
					   char *cp, char *end) {

  /* sanity checking -- test MS bit */
  if (neighbor->master && !(neighbor->I_M_MS & OSPF_MS)) {
    trace (ERROR, default_trace, "Error -- OSPF MS bit mismatch\n");
    neighbor_state_machine (neighbor, OSPF_EVENT_SEQNUMBERMISMATCH);
    return (-1);
  }

  /* sanity checking -- test if initializie (I) bit set */
  if (neighbor->I_M_MS & OSPF_INITIAL) {
    trace (ERROR, default_trace, "Error -- OSPF I bit mismatch\n");
    neighbor_state_machine (neighbor, OSPF_EVENT_SEQNUMBERMISMATCH);
    return (-1);
  }

  /* 
   * we're a master 
   * --------------
   */
  if (neighbor->master) {
    
    /* duplicate packet detection */
    if (neighbor->lastreceived_seq_num != neighbor->dd_seq_num) {
      trace (ERROR, default_trace, "Error -- duplicate packet\n");
      return (0);
    }

    neighbor->I_M_MS = OSPF_MS;

    if (neighbor->lastreceived_I_M_MS == OSPF_MORE) {
      neighbor->dd_seq_num++;
      ospf_send_database (neighbor);
    }
    else
      neighbor_state_machine (neighbor, OSPF_EVENT_EXCHANGEDONE);

    return (1);
  }

  /* 
   * we're a slave 
   * -------------
   */
  else if (!neighbor->master) {
    neighbor->I_M_MS = 0;
    neighbor->dd_seq_num = neighbor->lastreceived_seq_num;

    /* more to acknowledge */
    if (neighbor->lastreceived_I_M_MS & OSPF_MORE) {
      ospf_send_database (neighbor);
    }
    else {
      neighbor_state_machine (neighbor, OSPF_EVENT_LOADINGDONE);
    }
  }
  return (1);
}


/* ospf_send_database
 */
int ospf_send_database (ospf_neighbor_t *neighbor) {
  u_char buf[1024], *cp = buf;
  u_short length, checksum;
  ospf_interface_t *ospf_interface = neighbor->ospf_interface;
  
  memset (buf, 0, 1023);
  UTIL_PUT_BYTE (OSPF_VERSION, cp);
  UTIL_PUT_BYTE (OSPF_DATABASE_DESCRIPTION, cp);
  cp += 2; /* skip length for now */
  UTIL_PUT_NETLONG (OSPF.router_id, cp);
  UTIL_PUT_NETLONG (ospf_interface->area->area_id, cp); 

  cp += 2; /* skip checksum for now */

  UTIL_PUT_NETSHORT (ospf_interface->authentication_type, cp);
  if (ospf_interface->authentication_type == OSPF_AUTH_NULL) {
    cp += 8; /* skip authentication */
  }
  if (ospf_interface->authentication_type == OSPF_AUTH_PASSWORD) {
    memcpy (cp, ospf_interface->password, 8);
    cp += 8; 
  }
  
  /* network mask */
  UTIL_PUT_NETSHORT (1500, cp); /* mtu */
  UTIL_PUT_BYTE (2, cp); /* options */

  /* build bits */
  UTIL_PUT_BYTE (neighbor->I_M_MS, cp); /* flags */

  UTIL_PUT_NETLONG (neighbor->dd_seq_num, cp);
  trace (NORM, default_trace, "\n");
  if (ospf_interface->authentication_type == OSPF_AUTH_PASSWORD)
    trace (NORM, default_trace, "Send OSPF Database password: %s\n", 
	   ospf_interface->password);
  trace (NORM, default_trace, "Send OSPF Database seq: %d, options 0x%x, flags %s\n", 
	 neighbor->dd_seq_num, neighbor->options, 
	 ospf_neighbor_database_flags (neighbor->I_M_MS));


  /* no LSA header  for time being -- just doing exstart stuff
   * right now 
   */
  
  /* go back and fill in length */
  length = cp - buf;
  if (length % 2 != 0) {
    length++; /* pad */
  }

  cp = buf; cp += 2;
  UTIL_PUT_SHORT (length, cp);

  /* go back and checksum */
  cp = buf;
  checksum = in_cksum (cp, length);
  cp += 12;
  UTIL_PUT_NETSHORT (checksum, cp);

  packet_send_wire_unicast (neighbor->prefix, buf, length);
  /*packet_send_wire_multicast (OSPF_ALLSPFRouters, ospf_interface->interface, 
			      buf, length);*/

  return (1);
}



/* ospf_neighbor_database_flags
 * translate database exchange I_M_MS flags into ASCII 
 */
static char *ospf_neighbor_database_flags (int flags) {
  static char tmp[MAXLINE];
  char *cp;

  cp = tmp;
  
  if (flags & OSPF_MS) {
    sprintf (cp, "MS ");
    cp += strlen (cp);
  }
  if (flags & OSPF_MORE) {
    sprintf (cp, "M ");
    cp += strlen (cp);
  }
  if (flags & OSPF_INITIAL) {
    sprintf (cp, "I ");
    cp += strlen (cp);
  }

  return (tmp);
}
  


/* 
 * $Id: ospf_hello.c,v 1.1.1.1 2000/08/14 18:46:12 labovit Exp $
 */

/* 
 * Routines to handle OSPF hello sending and processing 
 */

#include <config.h>
#include <stdio.h>
#ifndef NT
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
#endif /* NT */
#include <mrt.h>
#include <select.h>
#include <interface.h>
#include <io.h>
#include <ospf_proto.h>


static void _ospf_send_hello (ospf_interface_t *ospf_interface);


int ospf_process_hello (ospf_header_t *ospf_header) {
  u_long netmask, options, rtrp, rdead;
  u_long designated_router, designated_backup_router, neighbor;
  ospf_neighbor_t *ospf_neighbor;
  prefix_t *prefix;
  int found_ourselves = 0;
  u_short hello;
  u_char *end, *cp;

  netmask = hello = options = rtrp = rdead = 0;
  cp = ospf_header->cp;
  end = cp + ospf_header->len - 24;
  
  /* network mask */
  UTIL_GET_NETLONG (netmask, cp);
  UTIL_GET_NETSHORT (hello, cp);
  UTIL_GET_BYTE (options, cp); /* options */
  UTIL_GET_BYTE (rtrp, cp); /* Rtr priority */
  UTIL_GET_NETLONG (rdead, cp); /* router dead interval */
  UTIL_GET_NETLONG (designated_router, cp); /* designated router */
  UTIL_GET_NETLONG (designated_backup_router, cp); /* designated backup router */
  
  trace (TR_PACKET, OSPF.trace, "Recv OSPF mask:/%d, hello:%d, rtrp:%d, rdead: %d\n",
	 mask2len (&netmask, 32), hello, rtrp, rdead);
  trace (TR_PACKET, OSPF.trace, "Recv OSPF options 0x%x\n", options);

  /* check for timer mismatch */
  if ((hello != OSPF.default_hello_interval) || (rdead != OSPF.default_dead_interval)) {
    trace (NORM, OSPF.trace, "Recv OSPF Hello timer Mismatch from %s\n");
    return (-1);
  }

  /* process neighbors */
  while (cp < end) {
    UTIL_GET_NETLONG (neighbor, cp); 
    prefix = New_Prefix (AF_INET, (char *) &neighbor, 32);
    trace (TR_PACKET, OSPF.trace, 
	   "Recv OSPF       neighbor %s\n", prefix_toa (prefix));
    /*if (find_interface_local (prefix) != NULL) */
    if (prefix_tolong (prefix) == OSPF.router_id) 
      found_ourselves = 1;
    Delete (prefix);
  }

  trace (TR_PACKET, OSPF.trace, "\n");

  /* add this neighbor to the list of neigbors we have heard from in 
   * the last RouterDeadInterval seconds 
   */
  ospf_neighbor = ospf_add_neighbor (ospf_header);
  
  /* update the neighbor dead timer */
  Timer_Reset_Time (ospf_neighbor->inactivity_timer);
  
  /* change state if our neighbor has added us to his neighbor list */
  if (found_ourselves) {
    neighbor_state_machine (ospf_neighbor, OSPF_EVENT_2WAYRECEIVED);
  }

  return (1);
}


void ospf_send_hello (mtimer_t *timer, ospf_interface_t *ospf_interface) {
  schedule_event2 ("ospf_send_hello", OSPF.schedule, _ospf_send_hello, 1, (void *) ospf_interface);
}



/* ospf_send_hello
 * hello packets are sent out each interface to ALLOSPFRouters 
 */
static void _ospf_send_hello (ospf_interface_t *ospf_interface) {
  u_char buf[1024], *cp = buf, tmp[100];
  u_short length, checksum;
  ospf_neighbor_t *neighbor;

  /* yip! send out on the wire */
  if (ospf_interface->type == VIRTUAL_LINK) 
    trace (TR_PACKET, OSPF.trace, "Sending hello to virtual %s\n", 
	   prefix_toa (ospf_interface->virtual_address));
  else
    trace (TR_PACKET, OSPF.trace, "Send OSPF hello out via %s\n", ospf_interface->interface->name);

  memset (buf, 0, 1023);

  UTIL_PUT_BYTE (OSPF_VERSION, cp);
  UTIL_PUT_BYTE (OSPF_HELLO, cp);
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

  trace (TR_PACKET, OSPF.trace, "Send OSPF hello id:%s, area: %d\n", 
	 long_inet_ntoa (OSPF.router_id), ospf_interface->area->area_id);
  if (ospf_interface->authentication_type == OSPF_AUTH_PASSWORD)
    trace (NORM, OSPF.trace, "Send OSPF hello password: %s\n", ospf_interface->password);
  
  /* network mask */
  if (ospf_interface->type == VIRTUAL_LINK) {
    cp +=4; /* 0.0.0.0 on virtual links */
  }
  else {
    memcpy (cp, len2mask (ospf_interface->interface->primary->prefix->bitlen, tmp, 4), 4);
    cp += 4;
  }

  UTIL_PUT_NETSHORT (OSPF.default_hello_interval, cp);
  UTIL_PUT_BYTE (2, cp); /* options -- set external bit */
  UTIL_PUT_BYTE (0, cp); /* Rtr priority */
  UTIL_PUT_NETLONG (OSPF.default_dead_interval, cp); /* router dead interval */
  UTIL_PUT_NETLONG (0, cp); /* designated router */
  UTIL_PUT_NETLONG (0, cp); /* designated backup router */
  
  trace (TR_PACKET, OSPF.trace, "Send OSPF mask, hello:%d, rdead: %d\n",
	OSPF.default_hello_interval, OSPF.default_dead_interval);

  /* stick in neighbors */
  LL_Iterate (ospf_interface->ll_neighbors, neighbor) {
    UTIL_PUT_NETLONG (neighbor->neighbor_id, cp);
    trace (TR_PACKET, OSPF.trace, 
	   "Send OSPF        neighbor %s\n", long_inet_ntoa (neighbor->neighbor_id));
  }

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

  trace (TR_PACKET, OSPF.trace, "\n");

  /*if (ospf_interface->type == VIRTUAL_LINK) 
    packet_send_wire_unicast (ospf_interface->virtual_address, buf, length);
  else*/
    packet_send_wire_multicast (OSPF_ALLSPFRouters, ospf_interface->interface, buf, length);
}



/* 
 * $Id: link_state.c,v 1.1.1.1 2000/08/14 18:46:12 labovit Exp $
 */

/* various routines for building ande decoding link_state packets */

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


/* local functions */
static int ospf_process_lsa (u_char *cp, int packet_length, u_long rid, 
		      ospf_interface_t *network);
static int ospf_process_router_lsa (u_char *cp, int packet_length, u_long rid, 
			     ospf_interface_t *network, ospf_lsa_t *header);
static int ospf_process_network_lsa (u_char *cp, int packet_length, u_long rid,
			      ospf_interface_t *network, ospf_lsa_t *header);
static int ospf_process_summary_lsa (u_char *cp, int packet_length, u_long rid,
			      ospf_interface_t *network, ospf_lsa_t *header);
static int ospf_process_as_external_lsa (u_char *cp, int packet_length, u_long rid,
				  ospf_interface_t *network,
				  ospf_lsa_t *header) ;
/*static u_short ospf_set_ls_checksum (u_char *buf, u_short length, u_short checksum_pos);*/
static int ospf_check_ls_checksum (u_char *buf, u_short length);



/* ospf_process_link_state_update
 * Start of OSPF LSA update p;acket processing 
 */
int ospf_process_link_state_update (ospf_header_t *header) {
  u_char *end, *cp;
  u_long num_lsa;
  int result;

  cp = header->cp;
  end = cp + header->len - 24;

  UTIL_GET_NETLONG (num_lsa, cp);

  trace (NORM, OSPF.trace, "\n");
  trace (NORM, OSPF.trace, "Recv OSPF Link State Update (%d LSAs in packet)\n", 
	 num_lsa);

  if (OSPF.ospf_lsa_call_fn != NULL) 
    OSPF.ospf_lsa_call_fn (header, num_lsa);

  /* iterate through LSAs in update packet */
  while (cp < end) {
    result = ospf_process_lsa (cp, end - cp, header->rid, header->ospf_interface);
    if (result < 0) 
      return (-1);
    cp += result;
  }
  return (1);
}


/* 
 * ospf_process_lsa
 * Munge the OSPF header, call the appropriate LSA processing routine,
 * and return the length of the LSA (+header) we have just processed
 */
static int ospf_process_lsa (u_char *cp, int packet_length, u_long rid, 
		      ospf_interface_t *network) {
  u_char *start;
  u_short ls_length;
  int checksum_ok;

  ospf_lsa_t *ospf_lsa = New (ospf_lsa_t);

  start = cp;

  UTIL_GET_NETSHORT (ospf_lsa->age, cp);
  UTIL_GET_BYTE (ospf_lsa->options, cp);
  UTIL_GET_BYTE (ospf_lsa->type, cp);
  UTIL_GET_NETLONG (ospf_lsa->id, cp);
  UTIL_GET_NETLONG (ospf_lsa->adv_router, cp);
  UTIL_GET_NETLONG (ospf_lsa->seq_num, cp);
  UTIL_GET_NETSHORT (ospf_lsa->checksum, cp);
  UTIL_GET_NETSHORT (ls_length, cp);

  /* sanity check */
  if (ls_length > packet_length*2) {
    trace (NORM, OSPF.trace, 
	   "Recv OSPF LSA with bad ls_length: %d\n",  ls_length);
    Delete (ospf_lsa);
    return (-1);
  }

  checksum_ok = ospf_check_ls_checksum(start, ls_length);

  trace (NORM, OSPF.trace, "Recv OSPF LSA: age:%d, opt: 0x%x, type: %d\n",
	 ospf_lsa->age, ospf_lsa->options, ospf_lsa->type);
  trace (NORM, OSPF.trace, "Recv OSPF LSA: id: %s, seq: 0x%x\n",
	 long_inet_ntoa (ospf_lsa->id), ospf_lsa->seq_num);
  trace (NORM, OSPF.trace, "Recv OSPF LSA: advr: %s, chksum: 0x%x, len: %d\n",
	 long_inet_ntoa (ospf_lsa->adv_router), ospf_lsa->checksum, ls_length);
  trace (NORM, OSPF.trace, "Recv OSPF LSA: checksum %s\n",
	 checksum_ok ? "ok" : "not ok");

  switch (ospf_lsa->type) {
  case OSPF_ROUTER_LSA:
    ospf_process_router_lsa (cp, ls_length - OSPF_LSA_HEADER_SIZE, rid, network, ospf_lsa);
    break;
  case OSPF_NETWORK_LSA:
    ospf_process_network_lsa (cp, ls_length - OSPF_LSA_HEADER_SIZE, rid, network, ospf_lsa);
    break;
  case OSPF_SUMMARY_LSA3:
    ospf_process_summary_lsa (cp, ls_length - OSPF_LSA_HEADER_SIZE, rid, network, ospf_lsa);
    break;
  case OSPF_SUMMARY_LSA4:
    ospf_process_summary_lsa (cp, ls_length - OSPF_LSA_HEADER_SIZE, rid, network, ospf_lsa);
    break;
  case OSPF_EXTERNAL_LSA:
    ospf_process_as_external_lsa (cp, ls_length - OSPF_LSA_HEADER_SIZE, rid, network, ospf_lsa);
    break;
  default:
    trace (ERROR, OSPF.trace, "ERROR -- Unknown OSPF LSA type (%d)\n", 
	   ospf_lsa->type);
    Delete (ospf_lsa);
    return (-1);
  }

   /* not sure when we ack an LSA... should we process it first? */
  if (ospf_lsa) 
    ospf_link_state_acknowledge (network, rid, ospf_lsa);

  /* Delete (ospf_lsa); */
  return (ls_length);
}



/*
 *  ospf_process_router_lsa
 */
static int ospf_process_router_lsa (u_char *cp, int packet_length, u_long rid, 
			     ospf_interface_t *network, ospf_lsa_t *header) {

  u_char bits, *end, num_tos, tos;
  u_short num_links, tos_metric;
  ospf_router_lsa_t *router_lsa;
  ospf_router_link_t *curr_link;

  /* Allocate space for the router_lsa structure. */
  router_lsa = New (ospf_router_lsa_t);

  router_lsa->header = header;

  end = cp + packet_length;

  /* Read in the bits. */
  UTIL_GET_BYTE (bits, cp);
  cp++;
  router_lsa->b_bit = (bits & 1);
  router_lsa->e_bit = ((bits & 2) >> 1);
  router_lsa->v_bit = ((bits & 4) >> 2);

  /* Read in the number of links. */
  UTIL_GET_SHORT (router_lsa->num_links, cp);
  num_links = router_lsa->num_links;

  /* Allocate the space for the links. */
  router_lsa->links = NewArray (ospf_router_link_t, num_links);
  curr_link = router_lsa->links;

  while ((num_links--) && (cp < end)) {
    UTIL_GET_NETLONG (curr_link->link_id, cp);
    UTIL_GET_NETLONG (curr_link->link_data, cp);
    UTIL_GET_BYTE (curr_link->type, cp);
    UTIL_GET_BYTE (num_tos, cp);
    UTIL_GET_NETSHORT (curr_link->metric, cp);

    trace (NORM, OSPF.trace, "Recv OSPF LSA-Router: id:%s, t:%d\n",
	   long_inet_ntoa (curr_link->link_id), curr_link->type);

    
    while (num_tos--) {
      UTIL_GET_BYTE (tos, cp);
      cp++;
      UTIL_GET_NETSHORT (tos_metric, cp);
    }

    curr_link++;
  }

  if (OSPF.ospf_router_lsa_call_fn != NULL)
    OSPF.ospf_router_lsa_call_fn (router_lsa);

  /* Now add this LSA to the database. */
  ospf_add_lsa_to_db (header, (void *)router_lsa);
  return (1);
}

static int ospf_process_network_lsa (u_char *cp, int packet_length, u_long rid,
				     ospf_interface_t *network, ospf_lsa_t *header) {

  u_char *end;
  u_long *curr_router;
  ospf_network_lsa_t *network_lsa;
  int num_routers;

  network_lsa = New (ospf_network_lsa_t);

  network_lsa->header = header;

  end = cp + packet_length;

  /* Read the Network Mask. */
  UTIL_GET_NETLONG (network_lsa->network_mask, cp);

  trace (NORM, OSPF.trace, "Recv OSPF LSA-Network: mask:/%d\n",
	 mask2len (&(network_lsa->network_mask), 32));

  /* Allocate the array to store the routers. */
  num_routers = ((int)end - (int)cp) / 4;
  network_lsa->num_routers = num_routers;
  network_lsa->routers = NewArray (u_long, num_routers);
  curr_router = network_lsa->routers;

  while (cp < end) {
    /* Read in the attached routers. */
    UTIL_GET_NETLONG (*curr_router, cp);

    trace (NORM, OSPF.trace, "Recv OSPF LSA-Network: Attached Router: %s\n",
	   long_inet_ntoa (*curr_router));

    curr_router++;
  }

  if (OSPF.ospf_network_lsa_call_fn != NULL)
    OSPF.ospf_network_lsa_call_fn (network_lsa);

  /* Add this LSA to the database. */
  ospf_add_lsa_to_db (header, (void *)network_lsa);
  return (1);
}

static int ospf_process_summary_lsa (u_char *cp, int packet_length, u_long rid,
				     ospf_interface_t *network, ospf_lsa_t *lsa) {

  u_char *end;
  u_long tos_metric;
  u_char tos;
  ospf_summary_lsa_t *summary_lsa;

  summary_lsa = New (ospf_summary_lsa_t);

  summary_lsa->header = lsa;

  end = cp + packet_length;

  /* Read the Network Mask. */
  UTIL_GET_NETLONG (summary_lsa->network_mask, cp);

  /* Read in the metric. */
  /* FIX this might not be correct. */
  cp++; /* Skip the 0 byte. */
  UTIL_GET_NETTHREE (summary_lsa->metric, cp);

  trace (NORM, OSPF.trace, "Recv OSPF LSA-Summary: mask:/%d, metric: %d\n",
	 mask2len (&(summary_lsa->network_mask), 32), summary_lsa->metric);

  /* Read in any TOS information. */
  while (cp < end) {
    UTIL_GET_BYTE (tos, cp);
    UTIL_GET_NETTHREE (tos_metric, cp);
  }

  /* Add this LSA to the database. */
  ospf_add_lsa_to_db (lsa, (void *)summary_lsa);
  return (1);
}

static int ospf_process_as_external_lsa (u_char *cp, int packet_length, u_long rid,
					 ospf_interface_t *network,
					 ospf_lsa_t *header) {

  u_char *end;
  u_long forward_addr, extern_route_tag;
  u_long tos_metric;
  u_char e_bit, tos;
  ospf_external_lsa_t *external_lsa;

  external_lsa = New (ospf_external_lsa_t);

  external_lsa->header = header;

  end = cp + packet_length;

  /* Read the Network Mask. */
  UTIL_GET_NETLONG (external_lsa->network_mask, cp);

  /* Read the E bit. */
  UTIL_GET_BYTE (e_bit, cp);
  external_lsa->e_bit = e_bit >> 7;

  /* Read the metric. */
  UTIL_GET_NETTHREE (external_lsa->metric, cp);

  /* Read Forwarding address. */
  UTIL_GET_NETLONG (external_lsa->forward_address, cp);

  /* Read External Route Tag. */
  UTIL_GET_NETLONG (external_lsa->external_route_tag, cp);

  trace (NORM, OSPF.trace,
	 "Recv OSPF LSA-External: mask:/%d, e: %d, metric: %d\n",
	 mask2len (&(external_lsa->network_mask), 32),
	 external_lsa->e_bit, external_lsa->metric);
  trace (NORM, OSPF.trace, "Recv OSPF LSA-External: forward: %s\n",
	 long_inet_ntoa (external_lsa->forward_address));

  /* Strip off any more TOS information, but ignore it. */
  while (cp < end) {
    /* Read E bit and TOS. */
    UTIL_GET_BYTE (tos, cp);
    e_bit = tos >> 7;
    tos = (tos & 0x7f);

    /* Read TOS metric. */
    UTIL_GET_NETTHREE (tos_metric, cp);

    /* Read Forwarding address. */
    UTIL_GET_NETLONG (forward_addr, cp);

    /* Read External Route Tag. */
    UTIL_GET_NETLONG (extern_route_tag, cp);
  }

  if (OSPF.ospf_external_lsa_call_fn != NULL) 
    OSPF.ospf_external_lsa_call_fn (external_lsa);

  /* Add this LSA to the database. */
  ospf_add_lsa_to_db (header, (void *)external_lsa);
  return (1);
}


void ospf_link_state_acknowledge (ospf_interface_t *network, u_long rid, ospf_lsa_t *lsa) {
  u_char buf[1024], *cp = buf;
  u_char *lsa_ptr;
  u_short lsa_length, length, checksum;
  ospf_neighbor_t *neighbor;
  u_char *lsa_checksum_ptr;

  if ((neighbor = ospf_find_neighbor (network, rid)) == NULL) {
    trace (NORM, OSPF.trace, "Error -- trying to ACK LSA from non-neighbor\n");
    return;
  }

  trace (NORM, OSPF.trace, "\n");

  memset (buf, 0, 1023);

  UTIL_PUT_BYTE (OSPF_VERSION, cp);
  UTIL_PUT_BYTE (OSPF_LINK_STATE_ACK, cp);
  cp += 2; /* skip length for now */
  UTIL_PUT_NETLONG (OSPF.router_id, cp);
  UTIL_PUT_NETLONG (network->area->area_id, cp); 

  cp += 2; /* skip checksum for now */
  UTIL_PUT_NETSHORT (OSPF_AUTH_NULL, cp);
  cp += 8; /* skip authentication */
  
  /* Keep track of the beginning of the LSA. */
  lsa_ptr = cp;

  /* build LSA header 
   * we have to skip age in the building of the checksum. Why! (sigh) ??
   */
  UTIL_PUT_NETSHORT (lsa->age, cp);  /* skip age until done with LSA checksumfor now */
  UTIL_PUT_BYTE (neighbor->options, cp);
  UTIL_PUT_BYTE (lsa->type, cp);
  UTIL_PUT_NETLONG (lsa->id, cp);
  UTIL_PUT_NETLONG (lsa->adv_router, cp);
  UTIL_PUT_NETLONG (lsa->seq_num, cp);


  trace (TR_PACKET, OSPF.trace, "Send OSPF LSA_ACK: age:%d, options: 0x%x, type:%d\n",
	 lsa->age, neighbor->options, lsa->type);

  /* Skip the checksum for now.  --Don't really need to do this. */
  lsa_checksum_ptr = cp;
  cp += 2;

  /* LSA length. Just use empty lsa for now -- we're just acking */
  lsa_length = 20; 
  UTIL_PUT_NETSHORT (lsa_length, cp);
  
  /* Set the checksum. */
  UTIL_PUT_NETSHORT (lsa->checksum, lsa_checksum_ptr);
  checksum = lsa->checksum;

  trace (TR_PACKET, OSPF.trace, "Send OSPF LSA_ACK: checksum 0x%x\n", checksum);

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

  /* decide if we are sending to multicast ALLOSPFRouters, or ALLDRouters
   * or unicast depending on 13.5
   */

  packet_send_wire_multicast (OSPF_ALLDRouters, network->interface, buf, length);   
}


/* Length is the number of octets in the packet.
 * checksum_pos is the location of the first octet of the checksum,
 * assuming that the first octet is number 1.
 * Return the checksum value
 */
u_short ospf_set_ls_checksum (u_char *buf, u_short length,
			      u_short checksum_pos) {
  u_char C0 = 0, C1 = 0;
  u_short i;
  u_char *X, *Y;
  int temp1, temp2;

  X = &(buf[checksum_pos - 1]);
  Y = &(buf[checksum_pos]);

  buf += 2;

  for (i = 2; i < length; i++, buf++) {
    C0 = (C0 + *buf) % 255;
    C1 = (C1 + C0) % 255;
  }

  *X = ((-C1 + 255) + ((length - checksum_pos) * C0)) % 255;

  /* Do this in stages to get rid of negative numbers. */
  temp1 = ((length - checksum_pos + 1) * C0) % 255;
  temp2 = (-temp1 + 255) % 255;
  *Y = (C1 + temp2) % 255;

  return (*(u_short *)X);
}


static int ospf_check_ls_checksum (u_char *buf, u_short length) {
  u_char C0 = 0, C1 = 0;
  u_short i;

  /* Skip over the LS age field. */
  buf += 2;

  for (i = 2; i < length; i++, buf++) {
    C0 = (C0 + *buf) % 255;
    C1 = (C1 + C0) % 255;
  }

  if (C0 != 0 || C1 != 0) {
    return(0);
  } else {
    return(1);
  }
}


u_char *ospf_build_router_lsa (ospf_area_t *ospf_area) {
  u_char *buf, *cp;
  ospf_interface_t *network;

  buf = malloc(1024 * sizeof(char));
  cp = buf;

  memset (buf, 0, 1023);

  trace (TR_PACKET, OSPF.trace, "OSPF Router LSA Build Area %d\n",
	 ospf_area->area_id);


  UTIL_PUT_BYTE (OSPF_VERSION, cp);
  UTIL_PUT_BYTE (OSPF_LINK_STATE_UPDATE, cp);
  cp += 2; /* skip length for now */
  UTIL_PUT_NETLONG (OSPF.router_id, cp);
  UTIL_PUT_NETLONG (ospf_area->area_id, cp); 

  cp += 2; /* skip checksum for now */
  UTIL_PUT_NETSHORT (OSPF_AUTH_NULL, cp);
  cp += 8; /* skip authentication */
  
  UTIL_PUT_NETSHORT (0, cp);  /* LSA age */
  UTIL_PUT_BYTE (0, cp); /* options */
  UTIL_PUT_BYTE (OSPF_ROUTER_LSA, cp); /* options */
  UTIL_PUT_NETLONG (OSPF.router_id, cp); /* link state id */
  UTIL_PUT_NETLONG (OSPF.router_id, cp); /* adver router */
  UTIL_PUT_NETLONG (OSPF_INITIAL_LS_SEQUENCE_NUM, cp);

  cp+=2; /* skip LS checksum for now */
  cp+=2; /* skip length of of LSA (includes header) */

  UTIL_PUT_BYTE (ospf_area->V_E_B, cp);
  cp++; /* blank */

  UTIL_PUT_NETSHORT (LL_GetCount (ospf_area->ll_router_interfaces), cp); /* # links */
  
  LL_Iterate (ospf_area->ll_router_interfaces, network) {
    switch (network->type) {
    case POINT_TO_POINT:
      break;
    case CONNECTION_TO_TRANSIT:
      break;
    case CONNECTION_TO_STUB:
      break;
    case VIRTUAL_LINK:
      /* neighboring routers id */
      UTIL_PUT_LONG (prefix_tolong (network->virtual_address), cp);
      break;
    }

    /* link data */
    UTIL_PUT_LONG (0, cp);

    UTIL_PUT_BYTE (network->type, cp); /* type */
    UTIL_PUT_BYTE (0, cp); /* no TOS */
    UTIL_PUT_NETSHORT (10, cp); /* metric? what should this be? */
  }

  return (buf);
}


/*
 * ospf_process_lsa_during_exchange
 *  Used during database exchange -- add LSA to list of those 
 *  we need to request if we don't have allready
 */
void ospf_process_lsa_during_exchange (ospf_neighbor_t *neighbor, char *cp, char *end) {
  ospf_lsa_t *ospf_lsa;

  while (cp < end) {
    ospf_lsa = New (ospf_lsa_t);

    UTIL_GET_NETSHORT (ospf_lsa->age, cp);
    UTIL_GET_BYTE (ospf_lsa->options, cp);
    UTIL_GET_BYTE (ospf_lsa->type, cp);
    UTIL_GET_NETLONG (ospf_lsa->id, cp);
    UTIL_GET_NETLONG (ospf_lsa->adv_router, cp);
    UTIL_GET_NETLONG (ospf_lsa->seq_num, cp);
    UTIL_GET_NETSHORT (ospf_lsa->checksum, cp);
    UTIL_GET_NETSHORT (ospf_lsa->length, cp);
    trace (NORM, OSPF.trace, "Recv OSPF LSA HDR: age:%d, options:0x%x, type:%d\n",
	   ospf_lsa->age, ospf_lsa->options, ospf_lsa->type);
    trace (NORM, OSPF.trace, "Recv OSPF LSA HDR: id%s, adv_rtr: , seq: 0x%x\n", 
	   long_inet_ntoa (ospf_lsa->id), ospf_lsa->seq_num);

    if (ospf_find_lsa_in_db (ospf_lsa) == NULL) {
      LL_Add (neighbor->ll_lsa_request, ospf_lsa);
      trace (NORM, OSPF.trace, "Adding LSA to request list.......\n");
    }
    else 
      Delete (ospf_lsa);
  }
}



void ospf_build_lsa_request (ospf_neighbor_t *neighbor) {
  u_char buf[1024], *cp = buf;
  ospf_interface_t *ospf_interface;
  ospf_lsa_t *ospf_lsa;
  int length, checksum;

  memset (buf, 0, 1023);

  ospf_interface = neighbor->ospf_interface;

  trace (TR_PACKET, OSPF.trace, "OSPF Build LSA Request\n");

  UTIL_PUT_BYTE (OSPF_VERSION, cp);
  UTIL_PUT_BYTE (OSPF_LINK_STATE_REQUEST, cp);
  cp += 2; /* skip length for now */
  UTIL_PUT_NETLONG (OSPF.router_id, cp);
  UTIL_PUT_NETLONG (ospf_interface->area->area_id, cp); 

  cp += 2; /* skip checksum for now */
  UTIL_PUT_NETSHORT (OSPF_AUTH_NULL, cp);
  cp += 8; /* skip authentication */
  
  LL_Iterate (neighbor->ll_lsa_request, ospf_lsa) {
    UTIL_PUT_NETLONG (ospf_lsa->type, cp);  
    UTIL_PUT_NETLONG (ospf_lsa->id, cp);
    UTIL_PUT_NETLONG (ospf_lsa->adv_router, cp);
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

  packet_send_wire_multicast (OSPF_ALLSPFRouters, ospf_interface->interface, buf, length);
}

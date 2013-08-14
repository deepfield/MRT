/* 
 * $Id: packet.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
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
#include <io.h>
#include "sospf.h"

/* local routines */
static void _ospf_read_packet (void);
static int ospf_packet_dump (int subtype, char *buf, int len);


short in_cksum(u_char *ip, int count) {
  register const u_short *sp = (u_short *)ip;
  register u_long sum = 0;

  /*
   * Must do endian conversions for sum to work out right!
   */
  count >>= 1; /* Divide count by 2 to count shorts instead of bytes.  */
  for (; --count >= 0; )
    sum += htons(*sp++);
  while (sum > 0xffff)
    sum = (sum & 0xffff) + (sum >> 16);
  return ((short) ~sum & 0xffff);
}




void ospf_read_packet (void) {
  schedule_event2 ("ospf_read_packet", OSPF.schedule, _ospf_read_packet, 0, NULL);
}


/* ospf_read_packet 
 * read a raw OSPF packet off the wire. Decode the type field and forward 
 * to the appropriate decoding routine
 */
static void _ospf_read_packet (void) {
  static ospf_header_t ospf_header;
  u_short hlen, total_len;
  prefix_t *prefix;
  u_char *cp, vhl; 
  int n, len;

  /* we'll probably need to do more with this later -- I think we'll need to maintain
   * state and keep a buffer due to fragmentation...
   */
  OSPF.cp = OSPF.buffer;
  cp = OSPF.cp;

  len = sizeof (ospf_header.from);
  n = recvfrom (OSPF.fd, OSPF.cp, sizeof(OSPF.buffer), 0, 
		(struct sockaddr *) &(ospf_header.from), &len);
  select_enable_fd (OSPF.fd);

  prefix = New_Prefix (AF_INET, (char *) &(ospf_header.from.sin_addr), 32);

  /* ignore this packet if we sent it out */
  if (find_interface_local (prefix) != NULL) {
    Delete_Prefix (prefix);
    return;
  }

  ospf_header.ospf_interface = find_ospf_interface (prefix, 0);

  if (ospf_header.ospf_interface == NULL) {
    trace (TRACE, default_trace, "Packet from %s an unconfigured network! Ignoring\n",
	   inet_ntoa (ospf_header.from.sin_addr));
    return;
  }

  trace (TR_PACKET, default_trace, "Recv %d bytes %s\n", n, prefix_toa (prefix));
  Delete_Prefix (prefix);

  /* decode IP packet header bare essentials (we just really need the length) */
  UTIL_GET_BYTE (vhl, cp); /* version and header length */
  cp++; /* skip TOS */
  UTIL_GET_NETSHORT (total_len, cp);  /* total length (including IP header) */
  hlen = vhl & 15;

  /* skip IP header */
  cp += hlen*4 - 4;

  ospf_process_header (&ospf_header, cp);
}


/* ospf_process_header
 * munge an OSPF header and call the right packing processing routines
 */
int ospf_process_header (ospf_header_t *ospf_header, char *cp) {
  char *ptr_start_ospf = cp;

  /* decode OSPF payload */
  UTIL_GET_BYTE (ospf_header->version, cp);
  UTIL_GET_BYTE (ospf_header->type, cp);
  UTIL_GET_NETSHORT (ospf_header->len, cp);
  UTIL_GET_NETLONG (ospf_header->rid, cp);
  UTIL_GET_NETLONG (ospf_header->area, cp);
  UTIL_GET_NETSHORT (ospf_header->checksum, cp);
  memset (cp-2, 0, 2); /* TMP hack */

  UTIL_GET_NETSHORT (ospf_header->authtype, cp);
  memcpy (ospf_header->password, cp, 8);
  cp += 8; /* skip authentication */

  trace (TR_PACKET, default_trace, "Recv OSPF Version: %d, Type: %d, PacketLength: %d\n", 
	 ospf_header->version, ospf_header->type, ospf_header->len);
  trace (TR_PACKET, default_trace, "Recv OSPF router_id: %s, area_id: %d\n",
	 long_inet_ntoa (ospf_header->rid), ospf_header->area);
  trace (TR_PACKET, default_trace, "Recv OSPF authype: %d  pkt checksum: 0x%x\n", 
	 ospf_header->authtype, ospf_header->checksum);

  if (ospf_header->authtype == OSPF_AUTH_PASSWORD) 
    trace (TR_PACKET, default_trace, "Recv OSPF password: %s\n", ospf_header->password);

  /* check for area mismatch */
  if ((ospf_header->ospf_interface) &&
      (ospf_header->area != ospf_header->ospf_interface->area->area_id)) {
    trace (NORM, default_trace, "Recv OSPF Area Mismatch (%d) -- should be %d\n",
	   ospf_header->area, ospf_header->ospf_interface->area->area_id);
    return (-1);
  }
  
  ospf_header->cp = cp;

  /* if logging/dumping turned on, then save packet to disk */
  if (ospf_header->type != OSPF_HELLO)
    ospf_packet_dump (ospf_header->type, ptr_start_ospf, ospf_header->len);

  switch (ospf_header->type) {
  case OSPF_HELLO:
    ospf_process_hello (ospf_header);
    break;
  case OSPF_DATABASE_DESCRIPTION:
    ospf_process_database (ospf_header);
    break;
  case OSPF_LINK_STATE_REQUEST:
    trace (NORM, default_trace, "... OSPF LSA Request... \n");
    break;
  case OSPF_LINK_STATE_UPDATE:
    ospf_process_link_state_update (ospf_header);
    break;
  case OSPF_LINK_STATE_ACK:
    trace (NORM, default_trace, "... OSPF LSA ack... \n");
    break;
  default:
    trace (ERROR, default_trace, "ERROR -- Unknown OSPF packet (type %d)\n", 
	   ospf_header->type);
    return (-1);
  }
  
  return (1);
}

/* packet_send_wire_multicast
 * given a pointer to a buffer, send the buffer to the ALL_OSPFROUTERS,
 * or OSPF_ALLDRouters mulitcast group. Used for hellos. And (anything else?)
 */
int packet_send_wire_multicast (char *multicast_addr, interface_t *interface, 
				char *cp, int len) {
  struct ip_mreq mreq;
  prefix_t *multicast_prefix;
  struct sockaddr *sockaddr;

  multicast_prefix = ascii2prefix (AF_INET, multicast_addr);
  memcpy (&mreq.imr_multiaddr.s_addr, prefix_tochar (multicast_prefix), 4);

  
  if (setsockopt (OSPF.fd, IPPROTO_IP, IP_MULTICAST_IF, 
		  (char *) prefix_tochar (interface->primary->prefix),
		  sizeof (struct in_addr)) < 0) {
    trace (NORM, default_trace, "Error setting outbound mulitcast for %s: %s\n", 
	   interface->name,  strerror (errno));
    Delete (multicast_prefix);
    return (-1);
  }

  sockaddr =  prefix_tosockaddr (multicast_prefix);
  sendto (OSPF.fd, cp, len, 0, sockaddr, sizeof (struct sockaddr));
  Delete (multicast_prefix);
  Delete (sockaddr);
  return (1);
}




/* packet_send_wire_unicast
 *
 */
int packet_send_wire_unicast (prefix_t *prefix, char *cp, int len) {
  struct sockaddr *sockaddr;
  int n;

  sockaddr =  prefix_tosockaddr (prefix);
  n = sendto (OSPF.fd, cp, len, 0, sockaddr, sizeof (struct sockaddr));

  Delete (sockaddr);
  return (n);
}


/* ospf_packet_dump
 * Dump a packet to disk with a standard MRT header
 */
static int ospf_packet_dump (int subtype, char *buf, int len){ 
  u_char tmpx[MAX_MSG_SIZE], *cp = tmpx;
  static io_t *IO = NULL;
  char name[MAXLINE];
  struct tm *tm;
  u_long now;

  /* dumping/logging is not turned on */
  if (OSPF.logformat == NULL) return (1);

  if (IO == NULL) {
    IO = New_IO (NULL);
  }

  time (&now);

  /* roll over, or create a new log file */
  if ((OSPF.create_time == 0) || ((now - OSPF.create_time) >= OSPF.loginterval)) {
    tm = localtime (&now);
    strftime (name, sizeof (name), OSPF.logformat, tm);    

    if (io_set (IO, IO_OUTFILE, name, NULL) < 0) {
      trace (ERROR, default_trace, "MRT ERROR can not open dump file: %s (%s)\n",
	     name, strerror (errno));
      return (-1);
    }

    OSPF.create_time = now;
  }

  memcpy (cp, buf, len);
  len += (cp - tmpx);
  io_write (IO, 0, MSG_PROTOCOL_OSPF, subtype, len, (char *)tmpx);

  return (1);
}

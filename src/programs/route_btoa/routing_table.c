/*
 * $Id: routing_table.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

#include <mrt.h>

static bgp_peer_t *create_fake_peer ();

/*
 * 2  view # | 
 * 
 *  4 prefix | 1 mask | status (VRTS_SUPPRESS) | 4 time originated | 
 *  4 len | attributes  
 */

void print_routing_table_msg (mrt_msg_t *msg) {
  char *stime, **cpp, date[MAXLINE];
  u_char *cp;
  int mask, status;
  int view, attrlen, seq_num, peer_as;
  time_t originated, t;
  bgp_peer_t *peer;
  prefix_t *prefix;
  int len;
  char *_sorigins[] = {"i", "e", "?", "a"};
  int afi = AFI_IP;
  int family = AF_INET;
  int plen = 4;
  char peer_ip[16], addr[16];

  len = msg->length;
  cp = msg->value;
  BGP_GET_SHORT (view, cp);
  BGP_GET_SHORT (seq_num, cp);
  len -= 4;

  stime = my_strftime (msg->tstamp, "%D %T");
  if (seq_num == 0) {
    printf ("TIME: %s\n", stime);
    printf ("TYPE: %s", S_MRT_MSG_TYPES[msg->type]);
    if ((cpp = S_MRT_MSG_SUBTYPES[msg->type]) != NULL)
      printf ("/%s", cpp[msg->subtype]);
    printf("\n");
    Delete (stime);
  }
  afi = msg->subtype;
  if (afi != AFI_IP && afi != AFI_IP6) {
     fprintf (stderr, "unknown afi: %d\n", afi);
     exit (1);
  }
  if (afi == AFI_IP6) {
    family = AF_INET6;
    plen = 16;
  }

  peer = create_fake_peer ();
  peer->trace = MRT->trace;

  while (len > 12) {
    BGP_GET_DATA (addr, plen, cp);
    BGP_GET_BYTE (mask, cp);
    BGP_GET_BYTE (status, cp);
    BGP_GET_LONG (originated, cp);
    BGP_GET_DATA (peer_ip, plen, cp);	/* gateway */
    BGP_GET_SHORT (peer_as, cp);	/* gateway */

    BGP_GET_SHORT (attrlen, cp);

    prefix = New_Prefix (family, addr, mask);

    peer->attr = NULL;
    bgp_munge_attributes (attrlen, cp, peer);

    t = msg->tstamp - originated;
    if (t / 3600 > 99)
      sprintf (date, "%02lddy%02ldhr", 
	       t / (3600 * 24), (t % (3600 * 24)) / 3600);
    else
      sprintf (date, "%02ld:%02ld:%02ld", 
	       t / 3600, (t / 60) % 60, t % 60);

    if (peer->attr) 
      printf ("B   20  %-15s %-15s   hme0  %s  %s\n",
	      date, prefix_toax (prefix), aspath_toa (peer->attr->aspath),
	      _sorigins[peer->attr->origin]);

    Delete (prefix);
    if (peer->attr) 
      bgp_deref_attr (peer->attr);
    cp += attrlen;
    len -= attrlen;
    len -= 12;
  }

  Delete (peer);
}


static bgp_peer_t *create_fake_peer () {
  bgp_peer_t *peer;

  peer = New (bgp_peer_t);
  peer->aliases = NULL;
  peer->sockfd = -1;
  peer->sockfd_in = -1;
  peer->listen_socket = NULL;

  peer->dlist_in = peer->dlist_out = -1;
  peer->flist_in = peer->flist_out = -1;
  peer->route_map_in = peer->route_map_out = -1;

  peer->read_ptr = peer->buffer;
  peer->start_ptr = peer->buffer;
  peer->packet = NULL;
  peer->read_ptr_in = peer->buffer_in;

  peer->state = BGPSTATE_IDLE;

  peer->maximum_prefix = 0;

  peer->Start_Interval = -1;
  peer->ConnectRetry_Interval = -1;
  peer->KeepAlive_Interval = -1;
  peer->HoldTime_Interval = -1;

  return (peer);
}

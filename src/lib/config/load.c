/*
 * $Id: load.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>

/* load_rib_from_disk
 * Mainly used in testing -- load a binary routing table dump
 * into our RIB
 */
int
load_f_bgp_routes (char *filename, int this_family_only)
{
  mrt_msg_t *msg;
  io_t *io;
  int i;
  u_char *cp, *end_cp;
  u_long status, mask;
  int view_num, seq_num, attrlen;
  time_t originated;
  prefix_t *prefix;
  bgp_peer_t *peer;
  view_t *view;
  char addr[16], peer_ip[16];
  int peer_as;
  int count = 0;

  io = New_IO (MRT->trace);
  if (io_set (io, IO_INFILE, (char *)filename, 0) < 0) {
    return (-1);
  }

  peer = create_fake_peer ();
  while ((msg = (mrt_msg_t *) io_read (io)) != NULL) {

   cp = msg->value;
   end_cp = msg->value + msg->length;

if (msg->type == MSG_PROTOCOL_BGP4MP && msg->subtype == BGP4MP_ENTRY) {
      time_t t;
      int afi, safi, nhlen, bitlen;
      int family = AF_INET;
      int plen = 4;
    nexthop_t *nexthop = NULL;
#ifdef HAVE_IPV6
    nexthop_t *link_local = NULL;
#endif /* HAVE_IPV6 */
    bgp_attr_t *attr;

      BGP_GET_SHORT (view_num, cp);
      BGP_GET_BYTE (mask, cp);
      BGP_GET_BYTE (status, cp);
      BGP_GET_LONG (t, cp);
      BGP_GET_SHORT (afi, cp);
      BGP_GET_BYTE (safi, cp);
      BGP_GET_BYTE (nhlen, cp);
#ifdef HAVE_IPV6
      if (afi == AFI_IP6) {
	  plen = 16;
	  family = AF_INET6;
      }
#endif /* HAVE_IPV6 */
      if (this_family_only != 0 && family != this_family_only) {
	Delete (msg);
	continue;
      }

      BGP_GET_DATA (addr, plen, cp);
      prefix = New_Prefix (family, addr, nhlen * 8);
      nexthop = add_nexthop (prefix, NULL);
      Deref_Prefix (prefix);

#ifdef HAVE_IPV6
      if (afi == AFI_IP6 && nhlen == 32) {
          BGP_GET_DATA (addr, plen, cp);
          prefix = New_Prefix (family, addr, nhlen * 8);
          link_local = add_nexthop (prefix, NULL);
          Deref_Prefix (prefix);
      }
#endif /* HAVE_IPV6 */

      BGP_GET_BITCOUNT (bitlen, cp);
#ifdef HAVE_IPV6
      if (afi == AFI_IP6)
          BGP_GET_PREFIX6 (bitlen, addr, cp);
    else
#endif /* HAVE_IPV6 */
      BGP_GET_PREFIX (bitlen, addr, cp);
      prefix = New_Prefix (family, addr, bitlen);

      BGP_GET_SHORT (attrlen, cp);
      peer->attr = NULL;
      bgp_munge_attributes (attrlen, cp, peer);
      if (peer->attr == NULL) {
        Deref_Prefix (prefix); 
	Delete (msg);
	continue;
      }
      cp += attrlen;
    attr = peer->attr;

    if (attr->nexthop == NULL || attr->nexthop->prefix->family != family) {
#ifdef HAVE_IPV6
	if (attr->nexthop && attr->nexthop->prefix->family == AF_INET) {
	    attr->nexthop4 = attr->nexthop;
	    attr->nexthop = NULL;
	}
#endif /* HAVE_IPV6 */
	if (attr->nexthop)
	    deref_nexthop (attr->nexthop);
	attr->nexthop = nexthop;
    }
#ifdef HAVE_IPV6
    if (attr->link_local == NULL && 
	    attr->nexthop->prefix->family == AF_INET6) {
	attr->link_local = link_local;
    }
#endif /* HAVE_IPV6 */

      attr->gateway = ref_nexthop (attr->nexthop);

      for (i = 0; i < MAX_BGP_VIEWS; i++) {
	if ((view = BGP->views[i]) == NULL ||
	    view->local_bgp == NULL ||
	    view->afi != family2afi (prefix->family))
	  continue;

	view_open (view);
	bgp_add_route (view, prefix, attr);
	bgp_process_changes (view);
	view_close (view);
      }
      count++;

      /* I still don't understand when we can delete prefixes */
      Deref_Prefix (prefix); 

      if (attr) 
	bgp_deref_attr (attr);
}
else if (msg->type == MSG_TABLE_DUMP) {
    int family = AF_INET;
    int plen = 4;
    int afi = msg->subtype;
    if (afi == AFI_IP6) {
        plen = 16;
	family = AF_INET6;
    }
    if (this_family_only != 0 && family != this_family_only) {
	Delete (msg);
	continue;
    }
    BGP_GET_SHORT (view_num, cp);
    BGP_GET_SHORT (seq_num, cp);

    while (end_cp - cp >= 16) {
      BGP_GET_DATA (addr, plen, cp);
      BGP_GET_BYTE (mask, cp);
      BGP_GET_BYTE (status, cp);
      BGP_GET_LONG (originated, cp);
      BGP_GET_DATA (peer_ip, plen, cp);
      BGP_GET_SHORT (peer_as, cp);

      BGP_GET_SHORT (attrlen, cp);
      peer->attr = NULL;
      bgp_munge_attributes (attrlen, cp, peer);
      cp += attrlen;
      if (peer->attr == NULL)
	continue;

      prefix = New_Prefix (family, peer_ip, plen * 8);
      peer->attr->gateway = add_gateway (prefix, peer_as, NULL);
      Deref_Prefix (prefix);

      prefix = New_Prefix (family, addr, mask);

      for (i = 0; i < MAX_BGP_VIEWS; i++) {
	if ((view = BGP->views[i]) == NULL ||
	    view->local_bgp == NULL ||
	    view->afi != family2afi (prefix->family))
	  continue;

	view_open (view);
	bgp_add_route (view, prefix, peer->attr);
      
	bgp_process_changes (view);
	view_close (view);
      }
      count++;

      Deref_Prefix (prefix); 

      if (peer->attr) 
	bgp_deref_attr (peer->attr);
    }
}
    Delete (msg);
  }
  io_set (io, IO_OUTNONE, 0);
  Delete_IO (io);
  Delete (peer);
  return (count);
}


int
load_rib_from_disk (char *filename) {
    return (load_f_bgp_routes (filename, 0));
}

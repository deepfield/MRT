/*  
 * $Id: bgp_dump2.c,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */ 
 
#include <mrt.h>
#include <bgp.h>
#include <io.h>
#ifndef NT
#include <sys/wait.h>
#endif /* NT */


int
bgp_table_dump_write (int fd, int type, int subtype, int viewno,
		      int seq_num, u_char *pp, int len)
{
    u_char buffer[MAX_MSG_SIZE], *cp = buffer;
    time_t now;
    time (&now);

    BGP_PUT_LONG (now, cp);
    BGP_PUT_SHORT (type, cp);
    BGP_PUT_SHORT (subtype, cp);

    if (type == MSG_PROTOCOL_BGP4MP) {
	assert (subtype == BGP4MP_ENTRY);
        BGP_PUT_LONG (len, cp);
    }
    else {
        assert (type == MSG_TABLE_DUMP);
        BGP_PUT_LONG (len + 4, cp);
  	BGP_PUT_SHORT (viewno, cp);		/* view */
  	BGP_PUT_SHORT (seq_num, cp);		/* sequence number */
    }
    memcpy (cp, pp, len);
    cp += len;

    trace (TR_INFO, MRT->trace, 
	   "Dumping routing table (%d bytes) to disk on fd %d\n", cp - buffer,
	   fd);
    return (write (fd, buffer, cp - buffer));
}


u_char *
bgp_table_dump_entry (u_char *cp, u_char *end, int type, int subtype, 
		      int viewno, prefix_t *prefix, int status,
		      time_t originated, bgp_attr_t *attr)
{
    int plen = 4;
    int afi = AFI_IP;
    u_char *start_attr, *p_total_attrib_len;

    assert (prefix);
    assert (attr);

#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6) {
	plen = 16;
	afi = AFI_IP6;
    }
#endif /* HAVE_IPV6 */

    if (type == MSG_PROTOCOL_BGP4MP) {
        int safi = 1;
        int nexthoplen = 4;

	assert (subtype == BGP4MP_ENTRY);

#ifdef HAVE_IPV6
      if (prefix->family == AF_INET6) {
	nexthoplen = 16;
	if (attr->link_local)
	    nexthoplen += 16;
      }
#endif /* HAVE_IPV6 */

      BGP_PUT_SHORT (viewno, cp);	/* view */
      BGP_PUT_BYTE (status, cp);	/* active ? */
      BGP_PUT_BYTE (attr->type, cp);	/* proto ? */

      /* age, or really time last changed */
      BGP_PUT_LONG (originated, cp);

      BGP_PUT_SHORT (afi, cp);
      BGP_PUT_BYTE (safi, cp);
      BGP_PUT_BYTE (nexthoplen, cp);
      BGP_PUT_DATA (prefix_tochar (attr->nexthop->prefix), plen, cp);
#ifdef HAVE_IPV6
      if (nexthoplen == 32 && attr->link_local)
          BGP_PUT_DATA (prefix_tochar (attr->link_local->prefix), plen, cp);
      if (prefix->family == AF_INET6)
          BGP_PUT_PREFIX6 (prefix->bitlen, prefix_tochar (prefix), cp);
#endif /* HAVE_IPV6 */
      BGP_PUT_PREFIX (prefix->bitlen, prefix_tochar (prefix), cp);
}
else {
      BGP_PUT_DATA (prefix_tochar (prefix), plen, cp);
      BGP_PUT_BYTE (prefix->bitlen, cp);

      /* XXX I need to check this Craig's code.
	 Probably it's OK putting state_bits but it's u_long. masaki */
      BGP_PUT_BYTE (status, cp);	/* active ? */
      /* age, or really time last changed */
      BGP_PUT_LONG (originated, cp);

      /* peer */
      BGP_PUT_DATA (prefix_tochar (attr->gateway->prefix), plen, cp);
      BGP_PUT_SHORT (attr->gateway->AS, cp);
}

      /* skip attribute length for now */
      p_total_attrib_len = cp;
      BGP_PUT_SHORT (0, cp);
      start_attr = cp;

      cp = bgp_add_attributes (cp, end - cp, attr, NULL);
#ifdef HAVE_IPV6
      cp = bgp_add_attr_ipv6 (cp, end - cp, attr, NULL);
#endif /* HAVE_IPV6 */

      BGP_PUT_SHORT (cp - start_attr, p_total_attrib_len);
    return (cp);
}


bgp_peer_t *
create_fake_peer (void)
{
  bgp_peer_t *peer;
  int viewno;

  peer = New (bgp_peer_t);
  peer->trace = MRT->trace;
  peer->aliases = NULL;
  peer->sockfd = -1;
  peer->accept_socket = NULL;
  peer->listen_socket = NULL;

  for (viewno = 0; viewno < MAX_BGP_VIEWS; viewno++) {
      peer->filters[viewno].dlist_in = peer->filters[viewno].dlist_out = -1;
      peer->filters[viewno].flist_in = peer->filters[viewno].flist_out = -1;
      peer->filters[viewno].clist_in = peer->filters[viewno].clist_out = -1;
      peer->filters[viewno].route_map_in = -1;
      peer->filters[viewno].route_map_out = -1;
      peer->default_weight[viewno] = -1;
  }

  peer->read_ptr = peer->buffer;
  peer->start_ptr = peer->buffer;
  peer->packet = NULL;

  peer->state = BGPSTATE_IDLE;

  peer->maximum_prefix = 0;

  peer->Start_Interval = -1;
  peer->ConnectRetry_Interval = -1;
  peer->KeepAlive_Interval = -1;
  peer->HoldTime_Interval = -1;

  /* index zero is used for the faked peer */
  peer->index = 0;
  peer->attr = NULL;
  BIT_SET (peer->options, BGP_BGP4PLUS_DEFAULT);

  return (peer);
}

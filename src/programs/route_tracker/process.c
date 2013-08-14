/*
 * $Id: process.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

#include <stdio.h>
#include <string.h>
#include <mrt.h>
#include <trace.h>
#include <interface.h>
#include <rip.h>
#include <time.h>
#include <bgp.h>
#include <signal.h>
#include <config_file.h>
#include <fcntl.h>
#include <io.h>
#include <dirent.h>
#include "rtracker.h"


extern bgp_t *BGP;
extern rip_t *RIP;
extern trace_t *default_trace;

void rtr_process_bgp_update (mrt_msg_t * msg, irr_connection_t *irr);
void rtr_update_route (rtracker_peer_t *peer, prefix_t *prefix, bgp_attr_t *attr);
void rtr_update_peer (int flag, rtracker_peer_t *tmp, prefix_t *prefix, bgp_attr_t *attr);
int count_routes (rtracker_peer_t *peer);

/* rtr_process_input
 * Run through a given file and process it... 
 */
void rtr_process_input (char *file, irr_connection_t *irr) {
  mrt_msg_t *msg;
  io_t *IO;
  
  IO = New_IO (default_trace);

  trace (NORM, default_trace, "Opening %s\n", file);

  if (io_set (IO, IO_INFILE, file, 0)) {
    trace (NORM, default_trace, "Failed to open file  %s\n", file);
    Delete (IO);
    return;
  }

  while (1) {
    if ((msg = (mrt_msg_t *) io_read (IO)) == NULL) {
      /*       printf("\nInvalid MSG "); */
      io_set (IO, IO_INNONE, NULL);
      Delete_IO (IO);
      return;
    }

    if (msg->length > 4096*2) {
      printf("\nInvalid MSG %d\n", (int) msg->length);
      io_set (IO, IO_INNONE, NULL);
      Delete_IO (IO);
      return;
    }

    if (!irr->sync && (msg->tstamp < irr->start_window)) {
      Delete (msg);
      continue;
    }
    if (!irr->sync && (msg->tstamp > irr->end_window)) {
      Delete (msg);
      io_set (IO, IO_INNONE, NULL);
      Delete_IO (IO);
      return;
    }

    switch (msg->type) {
    case MSG_PROTOCOL_BGP:
      if (irr->sync && (msg->subtype == MSG_BGP_SYNC)) {
	char *cp;
	cp = my_strftime (msg->tstamp, "%D %T");
	trace (NORM, default_trace, "Found sync message at %s\n", cp);
	cp = my_strftime (irr->sync, "%D %T");
	trace (NORM, default_trace, "Expected sync at %s\n", cp);
	irr->start_window = msg->tstamp;
	irr->sync = 0;
      }
      else if (msg->subtype == MSG_BGP_UPDATE) {
	rtr_process_bgp_update (msg, irr);
      }
      break;
      
    default:
      break;
    }

    Delete (msg);
  }

  return;
}



/* rtr_process_bgp_update
 * Called from rtr_process_input -- process a individual BGP packet
 *
 */
void rtr_process_bgp_update (mrt_msg_t * msg, irr_connection_t *irr) {
  LINKED_LIST *ll_with_prefixes, *ll_ann_prefixes;
  gateway_t *gateway_to;
  bgp_attr_t *attr;
  rtracker_peer_t *peer;
  prefix_t *prefix;
  short *pref;


  attr = NULL;
  ll_with_prefixes = NULL;
  ll_ann_prefixes = NULL;
  pref = NULL;

  bgp_process_update_msg (msg->type, mgp->subtype, 
			  msg->value, msg->length,
			  &gateway_to, &attr,
			  &ll_with_prefixes, &ll_ann_prefixes);


  /* we should probably filter here */


  /* 
   * 1. Just dump prefix trace 
   */
  if ((irr != NULL) && 
      ((irr->output_type == RTR_PREFIXES) || (irr->output_type == RTR_ASCII_PREFIXES))) {
    output_routes (irr, msg->tstamp, attr, ll_with_prefixes, ll_ann_prefixes);
    if (ll_ann_prefixes) 
      LL_Destroy (ll_ann_prefixes);
    if (ll_with_prefixes) 
      LL_Destroy (ll_with_prefixes);
    bgp_deref_attr (attr);
    return;
  }


  /*
   * 2. Update RIB information
   */
  peer = find_peer (irr, attr->gateway);

  if (ll_ann_prefixes) {
    LL_Iterate (ll_ann_prefixes, prefix) {
      peer->total_announce++;
      update_adj_rib (irr, peer, RTR_ANNOUNCE, prefix, msg->tstamp, attr);
    }
    LL_Destroy (ll_ann_prefixes);
  }

  if (ll_with_prefixes) {
    LL_Iterate (ll_with_prefixes, prefix) {
      peer->total_withdraw++;
      update_adj_rib (irr, peer, RTR_WITHDRAW, prefix, msg->tstamp, attr);
    }
    LL_Destroy (ll_with_prefixes);
  }
  bgp_deref_attr (attr);
  
  return;
}



/* 
 * report
 * Output neat table
 */
void report (irr_connection_t *irr) {
  rtracker_peer_t *peer;

  if (irr == NULL) return;

  irr_add_answer (irr, "#%5s %-20s %-8s   %-8s   %-8s   %s\r\n",
		  "AS", "IP", "Unique", "Ann", "With", "Ann+With");
  
  LL_Iterate (irr->ll_peer, peer) {
    irr_add_answer (irr, "%5d %-20s %-8d   %-8d   %-8d   %d\n",
		    peer->gateway->AS, prefix_toa (peer->gateway->prefix), 
		    count_routes (peer),
		    peer->total_announce,  peer->total_withdraw, 
		    peer->total_announce + peer->total_withdraw);
  }
}

int count_routes (rtracker_peer_t *peer) {
  radix_node_t *node;
  int count = 0;

  RADIX_WALK (peer->radix->head, node) {
    if (node->data != NULL) count++;
  }
  RADIX_WALK_END;

  return (count);
}




void output_routes (irr_connection_t *irr, u_long time, 
		    bgp_attr_t *attr, 
		    LINKED_LIST *ll_with_prefixes, 
		    LINKED_LIST *ll_ann_prefixes) {

  char tmp[MAXLINE];
  prefix_t *prefix;
  int ann_flag = 1;
  int with_flag = 1;

  /* check if matching against a given AS */
  if ((irr->AS > 0) && (attr->gateway->AS != irr->AS)) return;

  /* if there are withdrawn prefixes, and we are searching for a specific
   * prefix, the test to see if this list contains that prefix. If it does,
   * set the flag and wee will print this below
   */
  if ((ll_ann_prefixes) && (irr->prefix)) {
    ann_flag = 0;
    LL_Iterate (ll_ann_prefixes, prefix) 
      if (prefix_compare (irr->prefix, prefix)) {
	ann_flag = 1;
	break;
      }
  }
  if ((ll_with_prefixes) && (irr->prefix)) {
    with_flag = 0;
    LL_Iterate (ll_with_prefixes, prefix) 
      if (prefix_compare (irr->prefix, prefix)) {
	with_flag = 1;
	break;
      }
  }
  
  /* announce only */
  if (irr->type == 1) with_flag = 0;
  /* withdraw only */ 
  if (irr->type == 2) ann_flag = 0;


  /* check if we are just searching for an origin AS */
  if ((irr->origin_AS > 0) && (irr->origin_AS != attr->home_AS))
    ann_flag = 0;
  
  strftime (tmp, MAXLINE, "%h %e %T", localtime (&time));

  if (ann_flag && (ll_ann_prefixes)) {
    if (irr->output_type == RTR_ASCII_PREFIXES) {
      irr_add_answer (irr, "%s Announce From AS%d %s\r\n", tmp, attr->gateway->AS, 
		    prefix_toax (attr->gateway->prefix));
      irr_add_answer (irr, "  ASPATH=%s\r\n",  aspath_toa (attr->aspath));
      irr_add_answer (irr, "  NextHop= %s    Origin=%s\r\n", 
		      prefix_toa (attr->nexthop->prefix), 
		      origin2string (attr->origin));
      if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_METRIC)) 
	irr_add_answer (irr, "  MULTIExit=%d\r\n",  attr->multiexit);
      if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_COMMUNITY)) 
	irr_add_answer (irr, "  Community=%s\r\n",  attr->community);
       if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_AGGREGATOR))
	 irr_add_answer (irr, "  Aggregator: AS%d %s\r\n", attr->aggregator.as, 
			 prefix_toa (attr->aggregator.prefix));
    }
    else {
      irr_add_answer (irr, "A|%d|%d|%s|%s\r\n", time, attr->gateway->AS, 
		      prefix_toax (attr->gateway->prefix), bgp_attr_toa (attr));
    }

    LL_Iterate (ll_ann_prefixes, prefix) {
      if ((irr->prefix != NULL) && (!prefix_compare (irr->prefix, prefix))) continue;
      irr_add_answer (irr, "   +%s\r\n", prefix_toax (prefix));
    }
  }

  if (with_flag && (ll_with_prefixes)) {
    if (irr->output_type == RTR_ASCII_PREFIXES) {
      irr_add_answer (irr, "%s Withdraw From AS%d %s\r\n", tmp, attr->gateway->AS, 
		      prefix_toax (attr->gateway->prefix));
    }
    else if (irr->output_type == RTR_PREFIXES) {
      irr_add_answer (irr, "W|%d|%d|%s\r\n", time, attr->gateway->AS, 
		      prefix_toax (attr->gateway->prefix));
    }
    LL_Iterate (ll_with_prefixes, prefix) {
      if ((irr->prefix != NULL) && (!prefix_compare (irr->prefix, prefix))) continue;
      irr_add_answer (irr, "-%s\r\n", prefix_toax (prefix));
    }
  }

  if (irr->output_type == RTR_ASCII_PREFIXES) 
    irr_add_answer (irr, "\r\n");
}



/* 
 * $Id: bgp_dump.c,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#include <mrt.h>
#include <bgp.h>
#include <io.h>
#ifndef NT
#include <sys/wait.h>
#endif /* NT */

/* local functions */
static void dump_binary_bgp_view (int fd, view_t *view); 
static void dump_routing_table (time_t now, int viewnow, char *sync, 
			        int *synclen);


static void
bgp_write_mrt_msg2 (bgp_peer_t *peer, enum MRT_MSG_BGP_TYPES bgptype, 
		    u_char *buf, int length, LINKED_LIST *ll_syncs, 
		    time_t now) {
    u_char tmpx[MAX_MSG_SIZE], *cp = tmpx;
    int len = length;
    enum MRT_MSG_TYPES msgtype = MSG_PROTOCOL_BGP;
#if defined(_REENTRANT) && defined(HAVE_LOCALTIME_R)
    struct tm my_tm;
#endif
    int as = 0;
    prefix_t *peer_prefix = NULL;
    int ifindex = 0;

    if (peer->gateway) {
        as = peer->gateway->AS;
        peer_prefix = peer->gateway->prefix;
	if (peer->gateway->interface)
            ifindex = peer->gateway->interface->index;
    }
    else {
        as = peer->peer_as;
        peer_prefix = peer->peer_addr;
    }

    /* dump update packet to disk */
    if (BGP->dump_update_form && 
		(BGP->dump_update_family == 0 ||
		 BGP->dump_update_family == peer_prefix->family)) {
        static io_t *IO = NULL;

        if (IO == NULL) {
	    IO = New_IO (NULL);
        }
  
        if (BGP->dump_update_time == 0 ||
	   (BGP->dump_update_interval && 
		BGP->dump_update_time + BGP->dump_update_interval <= now)) {

	    char name[MAXLINE];
	    struct tm *tm;

#if defined(_REENTRANT) && defined(HAVE_LOCALTIME_R)
	    tm = localtime_r (&now, &my_tm);
#else
	    tm = localtime (&now);
#endif
            strftime (name, sizeof (name), BGP->dump_update_form, tm);

	    /* there may be a delay 
	       so this doesn't result in every intervals but it's ok */
	    BGP->dump_update_time = now;

	    if (io_set (IO, IO_OUTFILE, name, NULL) < 0) {
		trace (TR_ERROR, MRT->trace, 
		       "can not open dump file: %s (%m)\n", name);
		return;
	    }
	}

if (BGP->dump_new_format) {
        msgtype = MSG_PROTOCOL_BGP4MP;

	assert (bgptype == BGP4MP_STATE_CHANGE || 
		bgptype == BGP4MP_MESSAGE || 
		bgptype == BGP4MP_MESSAGE_OLD);
        BGP_PUT_SHORT (as, cp); /* source as number */
	BGP_PUT_SHORT (peer->local_bgp->this_as, cp); /* destination as */
	BGP_PUT_SHORT (ifindex, cp); 
#ifdef HAVE_IPV6
        if (peer_prefix->family == AF_INET6) {
	    BGP_PUT_SHORT (AFI_IP6, cp);
            BGP_PUT_ADDR6 (prefix_tochar (peer_prefix), cp);
            if (peer->local_addr) {
	        assert (peer->local_addr->family == AF_INET6);
	        BGP_PUT_ADDR6 (prefix_tochar (peer->local_addr), cp);
	    }
	    else {
	        memset (cp, 0, 16);
                cp += 16;
	    }
	}
	else
#endif /* HAVE_IPV6 */
{
	BGP_PUT_SHORT (AFI_IP, cp);
        BGP_PUT_NETLONG (prefix_tolong (peer_prefix), cp);
        if (peer->local_addr) {
	    assert (peer->local_addr->family == AF_INET);
	    BGP_PUT_NETLONG (prefix_tolong (peer->local_addr), cp);
	}
	else {
	    BGP_PUT_NETLONG (0L, cp);
	}
}
}
else {
        /* from */
        BGP_PUT_SHORT (as, cp);

#ifdef HAVE_IPV6
        if (peer_prefix->family == AF_INET6) {
            memcpy (cp, prefix_tochar (peer_prefix), 16);
            cp += 16;
        }
        else
#endif /* HAVE_IPV6 */
        BGP_PUT_NETLONG (prefix_tolong (peer_prefix), cp);

	/*
	 * To be compatible with Craig's code, AS and addr for 'to' 
	 * should not be included in this MRT message at the moment. 
	 *   -- masaki
	 */
	if (bgptype != MSG_BGP_STATE_CHANGE) {

	  /* to */
	  BGP_PUT_SHORT (peer->local_bgp->this_as, cp);

#ifdef HAVE_IPV6
	  if (peer_prefix->family == AF_INET6) {
            if (peer->local_addr) {
	      assert (peer->local_addr->family == AF_INET6);
	      memcpy (cp, prefix_tochar (peer->local_addr), 16);
	    }
	    else {
	      memset (cp, 0, 16);
	    }
            cp += 16;
	  }
	  else
#endif /* HAVE_IPV6 */
	    if (peer->local_addr)
	      BGP_PUT_NETLONG (prefix_tolong (peer->local_addr), cp);
	    else
	      BGP_PUT_NETLONG (0L, cp);
	}
#ifdef HAVE_IPV6
        if (peer_prefix->family == AF_INET6) {
	  if (BIT_TEST (peer->options, BGP_BGP4PLUS_01))
	    msgtype = MSG_PROTOCOL_BGP4PLUS_01;
	  else
	    msgtype = MSG_PROTOCOL_BGP4PLUS;
        }
#endif /* HAVE_IPV6 */

}
        memcpy (cp, buf, length);
        len += (cp - tmpx);

 	/* flush sync info */
	if (ll_syncs != NULL && LL_GetCount (ll_syncs) > 0) {
	    char *sync;
	    LL_Iterate (ll_syncs, sync) {
if (BGP->dump_new_format) {
	        io_write (IO, 0, msgtype, BGP4MP_SNAPSHOT, 
			  strlen (sync) + 1, sync);
}
else {
/* Craig, why only when running with pthread? */
#ifdef HAVE_LIBPTHREAD
	  	io_write (IO, 0, msgtype, MSG_BGP_SYNC, 
			  strlen (sync) + 1, sync);
#endif /* HAVE_LIBPTHREAD */
}
	    }
	}

        io_write (IO, 0, msgtype, bgptype, len, (char *)tmpx);
    }
}


void
bgp_write_mrt_msg (bgp_peer_t *peer, enum MRT_MSG_BGP_TYPES bgptype, 
		   u_char *buf, int length) {
    char sync[MAXLINE];
    int synclen = 0;
    time_t now;
    LINKED_LIST *ll_syncs = LL_Create (LL_DestroyFunction, FDelete, 0);
    int i;

    pthread_mutex_lock (&BGP->mutex_lock);
    time (&now);

    for (i = 0; i < MAX_BGP_VIEWS; i++) {
	if (!BITX_TEST (&peer->view_mask, i))
	    continue;
        dump_routing_table (now, i, sync, &synclen);
	if (synclen > 0)
	    LL_Add (ll_syncs, strdup (sync));
    }
    bgp_write_mrt_msg2 (peer, bgptype, buf, length, 
			ll_syncs, now);
    LL_Destroy (ll_syncs);
    pthread_mutex_unlock (&BGP->mutex_lock);
}


void
bgp_write_status_change (bgp_peer_t *peer, u_short state) {
    u_char buf[2+2], *cp = buf;

    BGP_PUT_SHORT (peer->state, cp); /* previous */
    BGP_PUT_SHORT (state, cp); /* new */
if (BGP->dump_new_format)
    bgp_write_mrt_msg (peer, BGP4MP_STATE_CHANGE, buf, 4);
else
    bgp_write_mrt_msg (peer, MSG_BGP_STATE_CHANGE, buf, 4);
}


/* dump_binary_bgp_view 
 * 4 time stamp | 2 type | 2 subtype (familly) | 4 length
 * 2  view # | 
 *
 *  4 prefix | 1 mask | status (VRTS_SUPPRESS) | 4 time originated |
 *  4 len | attributes 
 * 
 */
static void 
dump_binary_bgp_view (int fd, view_t *view)
{
  bgp_route_head_t *rt_head;
  bgp_route_t *route;
  u_char buffer[MAX_MSG_SIZE];
  time_t now;
  u_char *cp, *end;
  short seq_num = 0;
  int afi;
  int plen = 4;
  int type, subtype;
  
  time (&now);

  cp = buffer;
  end = buffer + MAX_MSG_SIZE;

  assert (view);
  afi = view->afi;
#ifdef HAVE_IPV6
  if (afi == AFI_IP6)
    plen = 16;
#endif /* HAVE_IPV6 */
if (BGP->dump_new_format) {
  type = MSG_PROTOCOL_BGP4MP;
  subtype = BGP4MP_ENTRY;
}
else {
  type = MSG_TABLE_DUMP;
  subtype = afi;
}

  VIEW_RADIX_WALK (view, rt_head) {

    if ((end - cp) < 500) {
	int i;
	i = bgp_table_dump_write (fd, type, subtype, 
			      view->viewno, seq_num, buffer, cp - buffer);
	trace (TR_TRACE, view->trace, "dump %d bytes written\n", i);
        seq_num++;
      cp = buffer;
      memset (cp, 0, MAX_MSG_SIZE);
    }
      
    /* 
     * BGP Routes 
     */
    LL_Iterate (rt_head->ll_routes, route) {
	bgp_attr_t *attr = route->attr;
	int status = 0;

if (BGP->dump_new_format) {
      /* XXX I need to check this Craig's code.
	 Probably it's OK putting state_bits but it's u_long. masaki */
      /* status */
      if (BIT_TEST (rt_head->state_bits, VRTS_SUPPRESS))
	status = VRTS_SUPPRESS;
      else if (BIT_TEST (rt_head->state_bits, VRTS_DELETE))
	status = VRTS_DELETE;
      else if (route == rt_head->active)
	status = VRTS_ACTIVE;
}
else {
      if (BIT_TEST (rt_head->state_bits, VRTS_SUPPRESS))
	status = VRTS_SUPPRESS;
      else if (BIT_TEST (rt_head->state_bits, VRTS_DELETE))
	status = VRTS_DELETE;
      else
	status = 1; /* active ? */
}
    cp = bgp_table_dump_entry (cp, end, type, subtype, 
		      view->viewno, rt_head->prefix, status,
		      route->time, attr);
    }
  }
  VIEW_RADIX_WALK_END;

    if (cp - buffer > 0) {
	int i;
	i = bgp_table_dump_write (fd, type, subtype, 
			      view->viewno, seq_num, buffer, cp - buffer);
	trace (TR_TRACE, view->trace, "dump %d bytes written\n", i);
        seq_num++;
    }
}


int 
dump_view_bgp_routes (int viewno, char *filename, int dump_type)
{
    int fd;
#ifndef NT
#ifndef HAVE_LIBPTHREAD
    pid_t pid = -1;
#endif /* HAVE_LIBPTHREAD */
#endif /* NT */ 
    view_t *view;

    if ((fd = open (filename, (O_CREAT | O_APPEND | O_WRONLY), 0666)) < 0) {
        return (fd);
    }

    /* open of dump file succeeded ! */

    view = BGP->views[viewno];
    assert (view);
    /* lock the routing table before forking */
    view_open (view);

#ifndef NT
#ifndef HAVE_LIBPTHREAD
  /* it was taking too long to do the dumps, hopefully forking
   * will be faster...
   */

#define BGP_DUMP_FORK_THREASHOLD 5000
  if (view->num_bgp_routes + view->num_imp_routes >= 
		BGP_DUMP_FORK_THREASHOLD) {
      if ((pid = fork ()) < 0) {
        trace (TR_ERROR, BGP->trace, "Fork error in bgp_dump.c (%d)\n", pid);
        return (-1);
      }
      else if (pid > 0) {	/* parent -- main process */
        trace (NORM, BGP->trace, "Parent before waitpid (%d)\n", pid);
    
        if (waitpid (pid, NULL, 0) != pid)
          trace (TR_ERROR, BGP->trace, "waitpid error (%m)\n");

        trace (NORM, BGP->trace, "Parent after waitpid. Now returning...\n");
        /* parent has to close the fd inherited by the child */
        view_close (view);
        close (fd);
        return (0);
      }

      /* set_thread_id (pid); */
      trace (NORM, BGP->trace, "Forked once (%d)\n", pid);

      /* so pid == 0, first child 
       * fork again so that not being a process group leader  
       */
      if ((pid = fork ()) < 0) {
        trace (TR_ERROR, BGP->trace, 
	       "Error in second fork in bgp_dump.c (%d)\n", pid);
        exit (1);
      }
      else if (pid > 0) {	/* parent of second fork */
        exit (0);
      }

      /* okay, so now only orphaned child should be proceeding on */
      /* set_thread_id (pid); */
      trace (NORM, BGP->trace, "Forked twice (%d). I am dump grandchild...\n", 
	     pid);
    }

#endif /* not HAVE_LIBPTHREAD */
#endif /* NT */

  lseek (fd, 0, SEEK_END);
  if (dump_type == DUMP_ASCII) {
      uii_connection_t uii;
      memset (&uii, 0, sizeof (uii));
      uii.sockfd = -1;
      uii.sockfd_out = fd;
      /* uii.answer will be assigned automatically */
      dump_text_bgp_view (&uii, view);
      if (uii.answer && buffer_data_len (uii.answer) > 0)
          write (fd, buffer_data (uii.answer), buffer_data_len (uii.answer));
      if (uii.answer)
        Delete_Buffer (uii.answer);
  }
  else
      dump_binary_bgp_view (fd, view);
  view_close (view);
  close (fd);
  
#ifndef HAVE_LIBPTHREAD
#ifndef NT
  if (pid >= 0) {
      /* we are the child, exit here */
      trace (NORM, BGP->trace, "Dump child exiting..\n");

      exit (0);
  }
#endif /* NT */
#endif /* HAVE_LIBPTHREAD */
  return (0);
}


/*
 * dump_routing_table
 */
static void 
dump_routing_table (time_t now, int viewno, char *sync, int *synclen)
{
    char name[MAXLINE];
    struct tm *tm;

    if (BGP->dump_route_form[viewno] == NULL)
	return;

    /* Dump binary/ascii routing table */
      if (BGP->dump_route_time[viewno] == 0) {
	BGP->dump_route_time[viewno] = now;
	return;
      }

    if (BGP->dump_route_time[viewno] + BGP->dump_route_interval[viewno] > now)
	return;

    tm = localtime (&now);
    strftime (name, sizeof (name), BGP->dump_route_form[viewno], tm);

    /* there may be a delay 
       so this doesn't result in every intervals but it's ok */
    BGP->dump_route_time[viewno] = now;

    if (dump_view_bgp_routes (viewno, name, BGP->dump_route_type[viewno]) < 0)
	return;

  /* set sync information */
    BGP_PUT_SHORT (viewno, sync);
    strcpy (sync, name);
    *synclen = sizeof (short) + strlen (name) + 1 /* for zero */;

}


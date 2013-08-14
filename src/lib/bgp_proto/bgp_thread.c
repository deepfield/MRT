/* 
 * $Id: bgp_thread.c,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#include <mrt.h>
#include <bgp.h>


#ifdef notdef
void 
bgp_start_peer_thread (bgp_peer_t * peer)
{
    init_mrt_thread_signals ();

#ifdef HAVE_LIBPTHREAD
    trace (TR_THREAD, peer->trace, "THREAD starting\n");
    while (1)
	schedule_wait_for_event (peer->schedule);
    /* NOT REACHED */
#else
    return;
#endif /* HAVE_LIBPTHREAD */
}
#endif


#ifdef notdef
void 
bgp_start_main_thread ()
{
    init_mrt_thread_signals ();

#ifdef HAVE_LIBPTHREAD
    trace (TR_THREAD, BGP->trace, "THREAD starting\n");
    while (1)
	schedule_wait_for_event (BGP->schedule);
    /* NOT REACHED */
#else
    return;
#endif /* HAVE_LIBPTHREAD */
}
#endif


/* this routine runs under interuptted situation */
void 
bgp_schedule_timer (mtimer_t * timer, bgp_peer_t * peer)
{

    if (timer == peer->timer_ConnectRetry)
	schedule_event2 ("bgp_timer_ConnectRetry_fire",
	       peer->schedule, bgp_timer_ConnectRetry_fire, 2, timer, peer);
    else if (timer == peer->timer_KeepAlive)
	schedule_event2 ("bgp_timer_KeepAlive_fire",
		  peer->schedule, bgp_timer_KeepAlive_fire, 2, timer, peer);
    else if (timer == peer->timer_HoldTime)
	schedule_event2 ("bgp_timer_HoldTime_fire",
		   peer->schedule, bgp_timer_HoldTime_fire, 2, timer, peer);
    else if (timer == peer->timer_Start)
	schedule_event2 ("bgp_timer_StartTime_fire",
		  peer->schedule, bgp_timer_StartTime_fire, 2, timer, peer);
}


#ifdef undef
/* this routine runs under interuptted situation */
void 
bgp_schedule_socket (bgp_peer_t * peer)
{
    schedule_event2 ("bgp_get_pdu",
		     peer->schedule, (void_fn_t) bgp_get_pdu, 1, peer);
}
#endif


#ifdef notdef
void bgp_get_config_neighbor (bgp_peer_t *peer) {
  pthread_mutex_t *mutex;
  
  /* stop BGP peer thread */
  mutex = intervene_thread_start (peer->schedule);

  config_add_output ("  neighbor %s remote-as %d\n",
		     prefix_toa (peer->gateway->prefix), peer->gateway->AS);

  /* restart peer */
  intevene_thread_end (mutex);


}


void bgp_schedule_get_config_neighbor (bgp_peer_t *peer) {
  
  schedule_event2 ("bgp_get_config_neighbor", peer->schedule, 
		   (void_fn_t) bgp_get_config_neighbor, 1, peer);
}
#endif

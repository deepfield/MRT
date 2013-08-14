/*
 * $Id: bgp_timer.c,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#include <mrt.h>
#include <bgp.h>

void 
bgp_timer_ConnectRetry_fire (mtimer_t * timer, bgp_peer_t * peer)
{
    trace (TR_TIMER, peer->trace, "Connect Retry timer fired\n");
    bgp_sm_process_event (peer, BGPEVENT_CONNRETRY);
}

void 
bgp_timer_KeepAlive_fire (mtimer_t * timer, bgp_peer_t * peer)
{
    trace (TR_TIMER, peer->trace, "KeepAlive timer fired\n");
    bgp_sm_process_event (peer, BGPEVENT_KEEPALIVE);

}


void 
bgp_timer_HoldTime_fire (mtimer_t * timer, bgp_peer_t * peer)
{
    trace (TR_TIMER, peer->trace, "HoldTime timer fired\n");
    bgp_sm_process_event (peer, BGPEVENT_HOLDTIME);
}


void 
bgp_timer_StartTime_fire (mtimer_t * timer, bgp_peer_t * peer)
{
    Timer_Turn_OFF (peer->timer_Start);
    trace (TR_TIMER, peer->trace, "Start timer fired\n");
    bgp_sm_process_event (peer, BGPEVENT_START);
}

/*
 * $Id: monitor.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _MONITOR_H
#define _MONITOR_H

#include <trace.h>

#define MONITOR_DEFAULT_PORT 5674


typedef struct _monitor_t {
   int lport;	/* port to listen on */
   int sockfd;	 /* socket we're listening on */


   trace_t *trace;

   int start_time;
   int start_memory;
   int counters_uptime;
   int maxroutes;

   int numpackets;
   int num_announce;
   int num_withdraw;

} monitor_t;




int init_monitor ();
void proccess_command (int *sockfd);
int send_dump (int sockfd);
int send_client_data (int fd, ...);
void client_dead ();
void send_client_route  (int sockfd, char *route);
void send_client_status (int sockfd);

void process_update ();
void peer_down ();


#endif /* _MONITOR_H */

/*
 * $Id: simple_rip.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

#include <stdio.h>
#include <version.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <mrt.h>
#include <route_manager.h>
#include <timer.h>
#include <io.h>
#include "rip.h"
#include "interface.h"
#include "protocol.h"

rip_t *RIP;
Route_Manager_Struct *ROUTE_MANAGER;
Interface_Master_Struct *INTERFACES;

void srip_recv_update ();


main () {

   ROUTE_MANAGER = (Route_Manager_Struct *) New_Route_Manager (32);

   /*ifinit ();*/

   io_init ();

   init_timer_master();

   init_rip (RIP_RECV_UPDATE_FN, srip_recv_update, NULL);

   if (init_rip_listen () == -1) {
      printf("\ninit_rip_listen failed!");
      exit (0);
   }

   /*init_rip_broadcast ();*/

   /* broadcast request for routes */
   rip_send_request ();

   while (1) 
      mrt_select ();
}


void srip_recv_update (prefix_t *prefix, u_char *cp, int len) {
   /*print_prefix (prefix);

   printf("\n\n\n\n");*/

   if (io_write (NULL, MSG_PROTOCOL_RIP, 0, len, cp) < 0) {
      trace (FATAL, NULL, "Error Writing Ouput");
      perror ("\nwrite failed");
      exit (0);
   }
}

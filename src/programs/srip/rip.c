/*
 * $Id: rip.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

#include <stdio.h>
#include <version.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <select.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <mrt.h>
#include <route_manager.h>
#include <timer.h>
#include "rip.h"
#include "interface.h"
#include "protocol.h"

RIP_Struct *RIP;
Route_Manager_Struct *ROUTE_MANAGER;
Interface_Master_Struct *INTERFACES;


main () {

   ROUTE_MANAGER = (Route_Manager_Struct *) New_Route_Manager (32);

   ifinit ();

   init_timer_master();

   init_rip ();

   if (init_rip_listen () == -1) {
      printf("\ninit_rip_listen failed!");
      exit (0);
   }

   init_rip_broadcast ();

   /* broadcast request for routes */
   rip_send_request ();

   while (1) 
      mrt_select ();
}


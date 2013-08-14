/* 
 * $Id: interface.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <mrt.h>
#include <select.h>
#include <interface.h>
#include "sospf.h"


/* find_ospf_interface2
 * If flag is set, create the interface if it does not exist 
 */
ospf_interface_t *find_ospf_interface (prefix_t *prefix, int flag) {
  ospf_interface_t *network;
  interface_t *interface;

  interface = find_interface (prefix);

  LL_Iterate (OSPF.ll_ospf_interfaces, network) {
    if (network->interface == interface) return (network);
  }

  return (NULL);
}


ospf_interface_t *add_ospf_interface (uii_connection_t *uii, prefix_t *prefix, int area) {
  ospf_interface_t *network;
  interface_t *interface;

  if ((interface = find_interface (prefix)) == NULL) {
    config_notice (NORM, uii, "Could not find interface for network %s\r\n", 
		   prefix_toax (prefix));
    return (NULL);
  }

  LL_Iterate (OSPF.ll_ospf_interfaces, network) {
    if (network->interface == interface) {
      config_notice (NORM, uii, "Interface for network already configured\n");
      return (NULL);
    }
  }

  network = New (ospf_interface_t);
  network->interface = interface;
  network->area = ospf_find_area (area);
  network->ll_neighbors = LL_Create (0);


  network->hello_timer =  (mtimer_t *) New_Timer (ospf_send_hello, 
						  OSPF.default_hello_interval,
						  "OSPF hello", (void *) network);
  timer_set_jitter ((mtimer_t *) network->hello_timer, 4);
  

  trace (NORM, default_trace, "Config OSPF network %s (%s) area %d\n", 
	 prefix_toax (prefix), interface->name, area);



  
  LL_Add (OSPF.ll_ospf_interfaces, network);
  return (network);
}



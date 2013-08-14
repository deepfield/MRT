/* 
 * $Id: config.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
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
#include <config_file.h>
#include "sospf.h"


/* dump ospf table /tmp/ospf.updates.%y%m%d.%H:%M 15m 
 * Periodically write LSA database to disk
 */
void config_dump_ospf_table (uii_connection_t *uii, char *format, char *interval) {
  char hms[MAXLINE];
  int n;
  
  OSPF.tableformat = strdup (format);
  if (sscanf (interval, "%d%s", &n, hms) != 2) {
    config_notice (NORM, uii, "%s not valid time period\r\n");
    return;
  }

  if ((hms[0] == 'M') || (hms[0] == 'm')) {
    OSPF.database_dump_interval = n*60;
  }
  else {
    config_notice (NORM, uii, "%s not of form \%dM\r\n");
    return;
  }

  trace (NORM, default_trace, "Config OSPF dump table %s %s [%d seconds]\n", 
	 format, interval, OSPF.database_dump_interval);

  OSPF.database_dump_timer =  (mtimer_t *) 
    New_Timer (ospf_database_dump, OSPF.database_dump_interval,
	       "OSPF database dump", NULL);
  timer_set_jitter ((mtimer_t *)  OSPF.database_dump_timer, 
		    OSPF.database_dump_interval/10);
  Timer_Turn_ON ((mtimer_t *)  OSPF.database_dump_timer);
  return;
}


/* dump ospf updates /tmp/ospf.updates.%y%m%d.%H:%M 15m 
 * Save all ospf updates to disk. The file name and log turning interval
 * are options
 */
void config_dump_ospf_updates (uii_connection_t *uii, char *format, char *interval) {
  char hms[MAXLINE];
  time_t now;
  int n;
  
  OSPF.logformat = strdup (format);
  if (sscanf (interval, "%d%s", &n, hms) != 2) {
    config_notice (NORM, uii, "%s not valid time period\r\n");
    return;
  }

  if ((hms[0] == 'M') || (hms[0] == 'm')) {
    OSPF.loginterval = n*60;
  }
  else {
    config_notice (NORM, uii, "%s not of form \%dM\r\n");
    return;
  }

  trace (NORM, default_trace, "Config OSPF dump updates %s %s [%d seconds]\n", 
	 format, interval, OSPF.loginterval);

  time (&now);
  OSPF.create_time = 0;

}

/* <router ospf> network %p authentication-key %s */
void config_network_ospf_password (uii_connection_t *uii, 
				   prefix_t *prefix, char *password) {
  ospf_interface_t *ospf_interface;
  
  ospf_interface = find_ospf_interface (prefix, M_CREAT);
  memcpy (ospf_interface->password, password, 8);
  ospf_interface->authentication_type = OSPF_AUTH_PASSWORD;
  trace (NORM, default_trace, "Config OSPF network %s authentication %s\n", 
	 prefix_toa (prefix), password);
  
  Delete_Prefix (prefix);
  Delete (password);
}

/* ip ospf routerid  */
void config_ip_ospf_routerid (uii_connection_t * uii, prefix_t *prefix) {

  OSPF.router_id = prefix_tolong (prefix);
  trace (NORM, default_trace, "Config OSPF router-id %s\n", 
	 prefix_toa (prefix));
  Delete (prefix);

  return;
}

/* ip ospf hello-interval  */
void config_ip_ospf_hello_interval (uii_connection_t * uii, int interval) {
  OSPF.default_hello_interval = interval;
  trace (NORM, default_trace, "Config OSPF default_hello_interval %d\n", 
	 OSPF.default_hello_interval);
  return;
}

/* ip ospf dead-interval  */
void config_ip_ospf_dead_interval (uii_connection_t * uii, int interval) {
  OSPF.default_dead_interval = interval;
  trace (NORM, default_trace, "Config OSPF default_dead_interval %d\n", 
	 OSPF.default_dead_interval);
  return;
}


/* <router ospf> area %d virtual_link %p */
void config_ospf_area_virtual_link (uii_connection_t * uii, int area, prefix_t *prefix) {
  ospf_interface_t *network;

  /* create a virtual interface for this virtual link */
  network = New (ospf_interface_t);
  network->interface = NULL;
  network->area = ospf_find_area (area);
  network->ll_neighbors = LL_Create (0);
  network->hello_timer =  (mtimer_t *) 
    New_Timer (ospf_send_hello, OSPF.default_hello_interval,
	       "OSPF hello", (void *) network);
  timer_set_jitter ((mtimer_t *) network->hello_timer, 4);
  network->virtual_address = prefix;
  network->type = VIRTUAL_LINK;
  LL_Add (OSPF.ll_ospf_interfaces, network);
  trace (NORM, default_trace, "Config ospf virtrual link %s area %d\n", 
	 prefix_toa (prefix), area);
  return;
}


void get_config_router_ospf () {
  ospf_interface_t *network;

  config_add_output ("router ospf %d\r\n", OSPF.process_id);
  
  LL_Iterate (OSPF.ll_ospf_interfaces, network) {
    config_add_output ("  network %s area %d\r\n", 
		       prefix_toax (network->interface->primary->prefix),
		       network->area);
  }
}


/* router ospf %d */
int config_router_ospf (uii_connection_t * uii, int process_id) {
  uii->protocol = PROTO_OSPF;
  uii->state = UII_CONFIG_ROUTER;
  MRT->protocols |= (1 << PROTO_OSPF);
  config_add_module (CF_DELIM, "router ospf", get_config_router_ospf, NULL);
  return (1);
}


void get_config_network () {

}


/* <router ospf>   network %p area %d */
int config_router_network (uii_connection_t * uii, prefix_t *prefix, int area) { 
    interface_t *interface;
    LINKED_LIST *ll;

    config_add_module (0, "network", get_config_network, 
		       Ref_Prefix (prefix));

    if ((ll = find_network (prefix)) != NULL) {
      LL_Iterate (ll, interface) {
	switch (uii->protocol) {
	case PROTO_OSPF:
	  add_ospf_interface (uii, prefix, area);
	  break;
	}
      }
      LL_Destroy (ll);
      Delete_Prefix (prefix);
    }
    else {
      config_notice (NORM, uii, "CONFIG ERROR -- could not find interface %s\r\n", 
		     prefix_toax (prefix));
      return (-1);
    }
    
    return (1);
}



/* ospf_find_area
 * Given an area id, return (or create) an area structure 
 */
ospf_area_t *ospf_find_area (int area_id) {
  ospf_area_t *ospf_area;

  LL_Iterate (OSPF.ll_ospf_areas, ospf_area) {
    if (ospf_area->area_id == area_id) return (ospf_area);
  }

  ospf_area = New (ospf_area_t);
  ospf_area->ll_router_interfaces = LL_Create (0);
  ospf_area->area_id = area_id;

  LL_Add (OSPF.ll_ospf_areas, ospf_area);
  return (ospf_area);
}

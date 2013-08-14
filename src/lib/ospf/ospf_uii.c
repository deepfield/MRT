/*
 * $Id: ospf_uii.c,v 1.1.1.1 2000/08/14 18:46:12 labovit Exp $
 */


#include <config.h>
#include <stdio.h>
#ifndef NT
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
#endif /* NT */
#include <mrt.h>
#include <select.h>
#include <interface.h>
#include <io.h>
#include <ospf_proto.h>



void show_ospf_neighbors (uii_connection_t *uii) {
  ospf_interface_t *ospf_interface;
  ospf_neighbor_t *neighbor;


  uii_add_bulk_output (uii, "%-15s %-8s %-15s   %s\r\n", 
		       "Neighbor ID", "State", "Address", "Interface");
  
  LL_Iterate (OSPF.ll_ospf_interfaces, ospf_interface) {
    
    LL_Iterate (ospf_interface->ll_neighbors, neighbor) {
      uii_add_bulk_output (uii, "%-15s %-8s %-15s   %s\r\n", 
			   long_inet_ntoa (neighbor->neighbor_id), 
			   ospf_states[neighbor->state],
			   prefix_toa (neighbor->prefix),
			   ospf_interface->interface->name);
    }
  }
  uii_send_bulk_data (uii); 
}


/* 
 * show_ospf_database
 * Show the current LSA database. Called by UII handler
 */
void show_ospf_database (uii_connection_t *uii, FILE *fd) {
  ospf_router_lsa_t *router_lsa;
  ospf_network_lsa_t *network_lsa;
  ospf_summary_lsa_t *summary_lsa;
  ospf_external_lsa_t *external_lsa;
  char tmp[MAXLINE];
  u_short i;

  pthread_mutex_lock (&OSPF.mutex_lock);

  if (uii) 
    uii_add_bulk_output (uii, "\r\n       OSPF Router with ID (%s) \r\n\r\n", 
			 long_inet_ntoa (OSPF.router_id));
  else
    fprintf (fd, "\r\n       OSPF Router with ID (%s) \r\n\r\n",
	     long_inet_ntoa (OSPF.router_id));


  /* Print out the Router LSAs. */
  if (LL_GetHead (OSPF.ll_router_lsas) != NULL) {
    if (uii) {
      uii_add_bulk_output (uii,
			   "                Router Link States (Area %d)\r\n", 
			   OSPF.area_id);
      
      uii_add_bulk_output (uii,
			   "\r\nLink ID         ADV Router      Age    Seq#   "
			   "    Checksum Link count\r\n");
    }
    else {
      fprintf (fd, "                Router Link States (Area %d)\r\n", 
	       (int) OSPF.area_id);
      
      fprintf (fd, "\r\nLink ID         ADV Router      Age    Seq#   "
	       "    Checksum Link count\r\n");
    }

    LL_Iterate (OSPF.ll_router_lsas, router_lsa) {
      for (i = 0; i < router_lsa->num_links; i++) {
	sprintf (tmp, "%s", long_inet_ntoa (router_lsa->links[i].link_id));
	if (uii) 
	  uii_add_bulk_output (uii, "%-15s %-15s %-6u 0x%-8X 0x%-4X   %u\r\n",
			       tmp,
			       long_inet_ntoa (router_lsa->header->adv_router),
			       router_lsa->header->age,
			       router_lsa->header->seq_num,
			       router_lsa->header->checksum,
			       i + 1);
	else
	  fprintf (fd, "%-15s %-15s %-6u 0x%-8X 0x%-4X   %u\r\n",
		   tmp,
		   long_inet_ntoa (router_lsa->header->adv_router),
		   router_lsa->header->age,
		   router_lsa->header->seq_num,
		   router_lsa->header->checksum,
		   (u_long) i + 1);
      } /* for */
    } /* LL_Iterate */
  }

  /* Print out the Network LSAs. */
  if (LL_GetHead (OSPF.ll_network_lsas) != NULL) {
    if (uii) {
      uii_add_bulk_output (uii, "\r\n                Net Link States (Area %d)\r\n",
			   OSPF.area_id);
      uii_add_bulk_output (uii,"\r\nLink ID         ADV Router      Age    Seq#    "
			   "   Checksum\r\n");
    }
    else {
      fprintf (fd, "\r\n                Net Link States (Area %d)\r\n",
	       OSPF.area_id);
      fprintf (fd, "\r\nLink ID         ADV Router      Age    Seq#    "
	       "   Checksum\r\n");
    }

    LL_Iterate (OSPF.ll_network_lsas, network_lsa) {
      sprintf (tmp, "%s",  long_inet_ntoa (network_lsa->network_mask));
      if (uii) 
	uii_add_bulk_output (uii, "%-15s %-15s %-6u 0x%-8X 0x%-4X\r\n",
			     tmp,
			     long_inet_ntoa (network_lsa->header->adv_router),
			     network_lsa->header->age,
			     network_lsa->header->seq_num,
			     network_lsa->header->checksum);
      else
	fprintf (fd, "%-15s %-15s %-6u 0x%-8X 0x%-4X\r\n",
		 tmp,
		 long_inet_ntoa (network_lsa->header->adv_router),
		 network_lsa->header->age,
		 network_lsa->header->seq_num,
		 network_lsa->header->checksum);
    } /* LL_Iterate */
  } /* if */

  /* Print out the Summary LSAs. */
  if (LL_GetHead (OSPF.ll_summary_lsas) != NULL) {
    uii_add_bulk_output (uii,
			 "\r\n                Summary Link States (Area %d)\r\n",
			 OSPF.area_id);

    uii_add_bulk_output (uii,
			 "\r\nLink ID         ADV Router      Age    Seq#    "
			 "   Checksum Metric\r\n");

    LL_Iterate (OSPF.ll_summary_lsas, summary_lsa) {
      uii_add_bulk_output (uii, "%-15s %-15s %-6u 0x%-8X 0x%-4X   %u\r\n",
			   long_inet_ntoa (summary_lsa->network_mask),
			   long_inet_ntoa (summary_lsa->header->adv_router),
			   summary_lsa->header->age,
			   summary_lsa->header->seq_num,
			   summary_lsa->header->checksum,
			   summary_lsa->metric);
    } /* LL_Iterate */
  } /* if */


  /* Print out the External LSAs. */
  if (LL_GetHead (OSPF.ll_external_lsas) != NULL) {
    if (uii) {
      uii_add_bulk_output (uii,
			   "\r\n                "
			   "External Link States (Area %d)\r\n",
			   OSPF.area_id);

      uii_add_bulk_output (uii,
			   "\r\nLink ID         ADV Router      Age    Seq#    "
			   "   Checksum Metric\r\n");
    }  
    else {
      fprintf (fd,  "\r\n                "
	       "External Link States (Area %d)\r\n",
	       OSPF.area_id);
      fprintf (fd,  "\r\nLink ID         ADV Router      Age    Seq#    "
	       "   Checksum Metric\r\n");
    }
    
    LL_Iterate (OSPF.ll_external_lsas, external_lsa) {
      sprintf (tmp, "%s", long_inet_ntoa (external_lsa->network_mask));
      if (uii) {
	uii_add_bulk_output (uii, "%-15s %-15s %-6u 0x%-8X 0x%-4X   %u\r\n",
			     tmp,
			     long_inet_ntoa (external_lsa->header->adv_router),
			     external_lsa->header->age,
			     external_lsa->header->seq_num,
			     external_lsa->header->checksum,
			     external_lsa->metric);
      }
      else {
	fprintf (fd, "%-15s %-15s %-6u 0x%-8X 0x%-4X   %u\r\n",
		 tmp,
		 long_inet_ntoa (external_lsa->header->adv_router),
		 external_lsa->header->age,
		 external_lsa->header->seq_num,
		 external_lsa->header->checksum,
		 external_lsa->metric);
      }
    } /* LL_Iterate */
  } /* if external_lsas */

  pthread_mutex_unlock (&OSPF.mutex_lock);

  if (uii) 
    uii_send_bulk_data (uii);

}
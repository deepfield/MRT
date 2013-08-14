/* 
 * $Id: net_map.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */


/* Code for maitaining the Network Map.
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


static void _show_ospf_net_map (ospf_vertex_t *vertex, int level,
				uii_connection_t *uii, FILE *fd);



void ospf_clear_seen_bits () {
  ospf_router_lsa_t *router_lsa;
  ospf_network_lsa_t *network_lsa;

  LL_Iterate (OSPF.ll_router_lsas, router_lsa) {
    router_lsa->header->seen = 0;
  }

  LL_Iterate (OSPF.ll_network_lsas, network_lsa) {
    network_lsa->header->seen = 0;
  }
} /* ospf_clear_seen_bits */

int ospf_compare_net_nodes (ospf_vertex_t *a,
			    ospf_vertex_t *b) {

  if (a->cost != b->cost) {
    return (a->cost - b->cost);
  } else if (b->network_lsa != NULL && a->network_lsa == NULL) {
    /* a and b have equal cost, but b is a network, so (b < a). */
    return(1);
  } else {
    /* Return -1 as a default (a < b). */
    return(-1);
  }

} /* ospf_compare_net_nodes */


void show_ospf_net_map (uii_connection_t *uii) {
  _show_ospf_net_map (ospf_create_net_map(ospf_find_area(OSPF.area_id)),
		      0, uii, NULL);
}

static void _show_ospf_net_map (ospf_vertex_t *vertex, int level,
				uii_connection_t *uii, FILE *fd) {

  int i;
  ospf_vertex_link_t *curr_link;

  if (level == 0) {
    if (uii) {
      uii_add_bulk_output (uii, "\r\nOSPF Network Map\r\n\r\n");
    } else {
      fprintf (fd, "\r\nOSPF Network Map\r\n\r\n");
    }
  } /* if level == 0 */

  for (i = 0; i < level; i++) {
    if (uii) {
      uii_add_bulk_output (uii, " ");
    } else {
      fprintf (fd, " ");
    }
  }

  if (uii) {
    uii_add_bulk_output (uii, "Vertex: %s, cost %d, links:\r\n",
			 long_inet_ntoa (vertex->vertex_id),
			 vertex->cost);
  } else {
    fprintf (fd, "Vertex: %s, cost %d, links:\r\n",
	     long_inet_ntoa (vertex->vertex_id),
	     vertex->cost);
  }

  LL_Iterate (vertex->ll_next_vertices, curr_link) {
    _show_ospf_net_map (curr_link->next_vertex, level + 1, uii, fd);
  } /* LL_Iterate */

  if (uii) {
    uii_send_bulk_data (uii);
  }

} /* _show_ospf_net_map */



ospf_vertex_t *ospf_create_net_map (ospf_area_t *ospf_area) {
  ospf_vertex_t *root_vertex; /* This is the base of the tree. */
  ospf_vertex_t *new_node;
  ospf_vertex_t *curr_vertex;
  ospf_vertex_t *far_vertex;
  ospf_router_lsa_t *router_lsa;
  ospf_router_link_t *curr_link;
  ospf_lsa_t temp_header;
  LINKED_LIST *candidates;
  u_long new_cost;
  u_long far_vertex_id;
  int skip, found;
  ospf_router_link_t *curr_router_link;
  u_long *curr_network_link;
  int i;
  ospf_network_lsa_t *network_lsa;
  ospf_vertex_link_t *new_link;
  ospf_router_lsa_t root_router_lsa;
  ospf_lsa_t root_lsa_header;
  ospf_interface_t *network;

  trace (NORM, default_trace, "Starting to create net map for area %d\n",
	 ospf_area->area_id);

  /* Clear all the seen bits. */
  ospf_clear_seen_bits();

  /* Initialize the candidate list. */
  candidates = LL_Create (LL_AutoSort, True,
			  LL_CompareFunction, ospf_compare_net_nodes,
			  NULL);


  /* Initialize the temporary header. */
  temp_header.age = 0;
  temp_header.options = 0;
  temp_header.adv_router = 0;
  temp_header.seq_num = 0;
  temp_header.checksum = 0;
  temp_header.length = 0;

  /* Create a node for ourselves. */
  root_vertex = New (ospf_vertex_t);
  root_vertex->vertex_id = OSPF.router_id;
  root_vertex->cost = 0;
  root_vertex->ll_next_vertices = LL_Create (0);

  /* FIX */
  /* We never actually send out a router LSA, so create one explicitly */
  /* ospf_header.ospf_interface = NULL;
     ospf_process_header(&ospf_header,
     ospf_build_router_lsa (ospf_find_area (0)));
     */
  root_router_lsa.header = &root_lsa_header;
  root_router_lsa.header->seen = 0;
  root_router_lsa.header->age = 0;
  root_router_lsa.header->options = 0;
  root_router_lsa.header->type = OSPF_ROUTER_LSA;
  root_router_lsa.header->id = OSPF.router_id;
  root_router_lsa.header->adv_router = OSPF.router_id;
  root_router_lsa.header->seq_num = OSPF_INITIAL_LS_SEQUENCE_NUM;
  root_router_lsa.header->checksum = 0;
  root_router_lsa.header->length = 0;
  root_router_lsa.v_bit = ospf_area->V_E_B & 4 >> 2;
  root_router_lsa.e_bit = ospf_area->V_E_B & 2 >> 1;
  root_router_lsa.b_bit = ospf_area->V_E_B & 1;
  root_router_lsa.num_links = LL_GetCount (OSPF.ll_ospf_interfaces);
  trace (NORM, default_trace, "Number of links %d\n", root_router_lsa.num_links);
  root_router_lsa.links =
    (ospf_router_link_t *) calloc (root_router_lsa.num_links,
				   sizeof (ospf_router_link_t));
  curr_link = root_router_lsa.links;
  LL_Iterate (OSPF.ll_ospf_interfaces, network) {
    curr_link->type = network->type;
    curr_link->metric = 10;
    curr_link->link_id = 0;
    curr_link->link_data = 0;
    switch (network->type) {
    case POINT_TO_POINT:
      break;
    case CONNECTION_TO_TRANSIT:
      curr_link->link_id = prefix_tolong (network->designated_router->prefix);
      break;
    case CONNECTION_TO_STUB:
      break;
    case VIRTUAL_LINK:
      curr_link->link_id = prefix_tolong (network->virtual_address);
      break;
    }
  }

  /* Find the LSA for ourselves. */
  /*
  temp_header.type = OSPF_ROUTER_LSA;
  temp_header.id = OSPF.router_id;
  root_vertex->router_lsa =
    (ospf_router_lsa_t *)ospf_find_lsa_in_db (&temp_header);
    */

  root_vertex->router_lsa = &root_router_lsa;

  /* Now create the map. */
  curr_vertex = root_vertex;

  while (curr_vertex != NULL) {
    if (curr_vertex == NULL) {
      break;
    }


    if (curr_vertex->router_lsa != NULL) {
      /* This is a router vertex. */

      trace (NORM, default_trace, "Processing Router Vertex %s\n",
	     long_inet_ntoa (curr_vertex->vertex_id));

      /* Mark this vertex as seen. */
      curr_vertex->router_lsa->header->seen = 1;

      for (curr_router_link = curr_vertex->router_lsa->links, i = 0;
	   i < curr_vertex->router_lsa->num_links;
	   curr_router_link++, i++) {

	trace (NORM, default_trace, "Found a link going out. %s\n",
	       long_inet_ntoa (curr_vertex->vertex_id));

	if (curr_router_link->type == 3) {
	  /* This is a connection to a stub network, we'll consider it later.*/
	  continue;
	}

	/* Now look up the LSA for the far end of this link. */
	temp_header.id = curr_router_link->link_id;

	temp_header.type = OSPF_ROUTER_LSA;
	router_lsa = (ospf_router_lsa_t *)ospf_find_lsa_in_db (&temp_header);
	if (router_lsa == NULL) {
	  network_lsa = NULL;
	} else {
	  temp_header.type = OSPF_NETWORK_LSA;
	  network_lsa =
	    (ospf_network_lsa_t *)ospf_find_lsa_in_db (&temp_header);
	}

	if ((router_lsa == NULL && network_lsa == NULL) ||
	    (router_lsa != NULL && router_lsa->header->age == OSPF_MaxAge) ||
	    (network_lsa != NULL && network_lsa->header->age == OSPF_MaxAge)) {
	  /* This isn't a valid LSA, so ignore this link. */
	  continue;
	}

	/* Skip this if W is already in the tree. */
	if ((router_lsa != NULL && router_lsa->header->seen) ||
	    (network_lsa != NULL && network_lsa->header->seen)) {
	  continue;
	}

	/* Calculate the cost of the far vertex. */
	new_cost = curr_vertex->cost + curr_link->metric;

	/* Now search for this vertex in the candidate list. */
	if (router_lsa != NULL) {
	  far_vertex_id = router_lsa->header->id;
	} else {
	  far_vertex_id = network_lsa->header->adv_router;
	}

	skip = 0;
	found = 0;
	LL_Iterate (candidates, far_vertex) {
	  if (far_vertex->vertex_id == far_vertex_id) {
	    /* We've found a match. */
	    found = 1;

	    if (new_cost > far_vertex->cost) {
	      skip = 1;
	      break;
	    }

	    if (new_cost == far_vertex->cost) {
	      /* FIX Calculate next hops. */
	    }

	    if (new_cost < far_vertex->cost) {
	      /* We've found a better link. */
	      far_vertex->cost = new_cost;

	      /* Change the parent vertex. */
	      far_vertex->parent_vertex = curr_vertex;

	      /* We've modified the cost, so re-sort the list. */
	      LL_ReSort (candidates, far_vertex);

	      /* FIX Calculate next hops. */

	    } /* if new_cost < old_cost */
	  } /* if they match */
	} /* LL_Iterate */

	if (skip) {
	  continue;
	}

	if (!found) {
	  /* Create a new node. */
	  far_vertex = New (ospf_vertex_t);
	  far_vertex->cost = new_cost;
	  far_vertex->ll_next_vertices = LL_Create (0);
	  if (router_lsa != NULL) {
	    far_vertex->vertex_id = router_lsa->header->id;
	    far_vertex->router_lsa = router_lsa;
	    far_vertex->network_lsa = NULL;
	  } else {
	    far_vertex->vertex_id = network_lsa->header->adv_router;
	    far_vertex->router_lsa = NULL;
	    far_vertex->network_lsa = network_lsa;
	  }

	  /* Update the parent. */
	  far_vertex->parent_vertex = curr_vertex;
	  
	  /* Add this vertex to the candidate list. */
	  LL_Add (candidates, far_vertex);

	  /* FIX Calculate next hops. */

	} /* if !found */

      } /* for curr_router_link */

    } else {
      /* This is a network vertex. */

      trace (NORM, default_trace, "Processing Network Vertex %s\n",
	     long_inet_ntoa (curr_vertex->vertex_id));

      /* Mark this vertex as seen. */
      curr_vertex->network_lsa->header->seen = 1;

      for (curr_network_link = curr_vertex->network_lsa->routers, i = 0;
	   i < curr_vertex->network_lsa->num_routers;
	   curr_network_link++, i++) {

	/* Now look up the LSA for the far end of this link. */
	temp_header.id = *curr_network_link;

	temp_header.type = OSPF_ROUTER_LSA;
	router_lsa = (ospf_router_lsa_t *)ospf_find_lsa_in_db (&temp_header);
	if (router_lsa == NULL) {
	  network_lsa = NULL;
	} else {
	  temp_header.type = OSPF_NETWORK_LSA;
	  network_lsa =
	    (ospf_network_lsa_t *)ospf_find_lsa_in_db (&temp_header);
	}

	if ((router_lsa == NULL && network_lsa == NULL) ||
	    (router_lsa != NULL && router_lsa->header->age == OSPF_MaxAge) ||
	    (network_lsa != NULL && network_lsa->header->age == OSPF_MaxAge)) {
	  /* This isn't a valid LSA, so ignore this link. */
	  continue;
	}

	/* Skip this if W is already in the tree. */
	if ((router_lsa != NULL && router_lsa->header->seen) ||
	    (network_lsa != NULL && network_lsa->header->seen)) {
	  continue;
	}

	/* Calculate the cost of the far vertex. */
	new_cost = curr_vertex->cost;

	/* Now search for this vertex in the candidate list. */
	if (router_lsa != NULL) {
	  far_vertex_id = router_lsa->header->id;
	} else {
	  far_vertex_id = network_lsa->header->adv_router;
	}

	skip = 0;
	found = 0;
	LL_Iterate (candidates, far_vertex) {
	  if (far_vertex->vertex_id == far_vertex_id) {
	    /* We've found a match. */
	    found = 1;

	    if (new_cost > far_vertex->cost) {
	      skip = 1;
	      break;
	    }

	    if (new_cost == far_vertex->cost) {
	      /* FIX Calculate next hops. */
	    }

	    if (new_cost < far_vertex->cost) {
	      /* We've found a better link. */
	      far_vertex->cost = new_cost;

	      /* Change the parent vertex. */
	      far_vertex->parent_vertex = curr_vertex;

	      /* We've modified the cost, so re-sort the list. */
	      LL_ReSort (candidates, far_vertex);

	      /* FIX Calculate next hops. */

	    } /* if new_cost < old_cost */
	  } /* if they match */
	} /* LL_Iterate */

	if (skip) {
	  continue;
	}

	if (!found) {
	  /* Create a new node. */
	  far_vertex = New (ospf_vertex_t);
	  far_vertex->cost = new_cost;
	  far_vertex->ll_next_vertices = LL_Create (0);
	  if (router_lsa != NULL) {
	    far_vertex->vertex_id = router_lsa->header->id;
	    far_vertex->router_lsa = router_lsa;
	    far_vertex->network_lsa = NULL;
	  } else {
	    far_vertex->vertex_id = network_lsa->header->adv_router;
	    far_vertex->router_lsa = NULL;
	    far_vertex->network_lsa = network_lsa;
	  }

	  /* Update the parent. */
	  far_vertex->parent_vertex = curr_vertex;
	  
	  /* Add this vertex to the candidate list. */
	  LL_Add (candidates, far_vertex);

	  /* FIX Calculate next hops. */

	} /* if !found */

      } /* for curr_network_link */


    } /* if router_lsa */

    /* Pull the next vertex off the list. */
    curr_vertex = LL_GetHead (candidates);
    LL_Remove (candidates, curr_vertex);

    if (curr_vertex != NULL) {
      /* We're permanently adding this vertex, add it to the parent's
       * list of links. */

      new_link = New (ospf_vertex_link_t);
      new_link->next_vertex = curr_vertex;
      new_link->interface = 0; /* FIX */
      LL_Add (curr_vertex->parent_vertex->ll_next_vertices, new_link);

    } /* if curr_vertex */



  } /* while */

  return (root_vertex);

} /* ospf_create_net_map */

/* FIX what about different areas?? I don't think we're handling
   that correctly. */

/* 
 * $Id: lsa_database.c,v 1.1.1.1 2000/08/14 18:46:12 labovit Exp $
 */


/* code for inserting, searching, aging, deleting, etc the link state databases */

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


/* local functions */
//static void _ospf_database_dump ();
//static void _show_ospf_database (uii_connection_t *uii, FILE *fd);


/* ospf_database_dump
 * Dump a copy of the current LSA database to disk for statistics/analysis
 * This is usually called via the dump timer (if configured)
 */
void ospf_database_dump () {
  char name[MAXLINE];
  FILE *fd;
  struct tm *tm;
  u_long now;

  time (&now);
  tm = localtime (&now);
  strftime (name, sizeof (name), OSPF.tableformat, tm);  
  if ((fd = fopen (name, "w")) == NULL) {
    trace (ERROR, OSPF.trace, "OSPF error -- could not open %s for dumping database\n",
	   name);
    return;
  }
  show_ospf_database (NULL, fd);
  fclose (fd);

  trace (NORM, OSPF.trace, "OSPF Dumped LSA database to %s\n", name);
  return;
}





int ospf_replace_lsa (ospf_lsa_t *old, ospf_lsa_t *new) {
  int replace = 0;

  if (old->seq_num < new->seq_num) {
    /* LSA in database is older, replace it. */
    replace = 1;

  } else if (old->seq_num == new->seq_num) {
    /* Sequence numbers are identical. */

    if (old->checksum < new->checksum) {
      /* LSA in database has smaller checksum, replace it. */
      replace = 1;

    } else if (old->checksum == new->checksum) {
      /* Checksums are identical. */

      if (new->age == OSPF_MaxAge &&
	  old->age != OSPF_MaxAge) {
	/* Only the new has age MaxAge, replace. */
	replace = 1;

      } else if (abs(new->age - old->age) > 
		 OSPF_MaxAgeDiff) {
	/* The two ages differ by more than MaxAgeDiff. */
	if (new->age < old->age) {
	  /* new_lsa has a younger age. */
	  replace = 1;
	} /* if new age < curr age */
      } /* if age difference > MaxAgeDiff */
    } /* if checksums identical */
  } /* if seq_nums are identical */

  return(replace);
}

void ospf_add_router_lsa (ospf_router_lsa_t *new_lsa) {
  ospf_router_lsa_t *curr_lsa;
  int replace = 0;
  int found = 0;

#ifdef OSPF_ANAL
  ospf_stat_router_lsa (new_lsa);
#endif /* OSPF_ANAL */

  LL_Iterate (OSPF.ll_router_lsas, curr_lsa) {
    if (curr_lsa->header->id == new_lsa->header->id &&
	curr_lsa->header->adv_router == new_lsa->header->adv_router) {
      /* The two packets are the same, figure out which one is newer. */
      found = 1;

      replace = ospf_replace_lsa(curr_lsa->header, new_lsa->header);
     } /* if packets are the same */

    if (found) {
      if (replace) {
	/* FIX We should probably let the LL code do this. */
	/* Delete (curr_lsa->header); */
 	/* Delete (curr_lsa->links); */
	LL_Remove (OSPF.ll_router_lsas, curr_lsa);
	/* Delete (curr_lsa);*/

	LL_Add (OSPF.ll_router_lsas, new_lsa);
      }

      break;
    }
  } /* LL_Iterate */

  if (!found) {
    /* We didn't find it, so just add it to the database. */
    LL_Add (OSPF.ll_router_lsas, new_lsa);
  }

} /* ospf_add_router_lsa */

void ospf_destroy_router_lsa (ospf_router_lsa_t *lsa) {
  Delete (lsa->header);
  Delete (lsa->links);
  Delete (lsa);
} /* ospf_destroy_router_lsa */

void ospf_add_network_lsa (ospf_network_lsa_t *new_lsa) {
  ospf_network_lsa_t *curr_lsa;
  int replace;
  int found = 0;

  LL_Iterate (OSPF.ll_network_lsas, curr_lsa) {
    if (curr_lsa->header->id == new_lsa->header->id &&
	curr_lsa->header->adv_router == new_lsa->header->adv_router) {
      /* The two packets are the same, figure out which one is newer. */
      found = 1;

      replace = ospf_replace_lsa(curr_lsa->header, new_lsa->header);
     } /* if packets are the same */

    if (found) {
      if (replace) {
	/* FIX We should probably let the LL code do this. */
	/* Delete (curr_lsa->header); */
	/* Delete (curr_lsa->routers); */
	LL_Remove (OSPF.ll_network_lsas, curr_lsa);
	/* Delete (curr_lsa); */

	LL_Add (OSPF.ll_network_lsas, new_lsa);
      }

      break;
    }
  } /* LL_Iterate */

  if (!found) {
    /* We didn't find it, so just add it to the database. */
    LL_Add (OSPF.ll_network_lsas, new_lsa);
  }

} /* ospf_add_network_lsa */


void ospf_destroy_network_lsa (ospf_network_lsa_t *lsa) {
  Delete (lsa->header);
  Delete (lsa->routers);
  Delete (lsa);
} /* ospf_destroy_network_lsa */

void ospf_add_summary_lsa (ospf_summary_lsa_t *new_lsa) {
  ospf_summary_lsa_t *curr_lsa;
  int replace;
  int found = 0;

  LL_Iterate (OSPF.ll_summary_lsas, curr_lsa) {
    if (curr_lsa->header->id == new_lsa->header->id &&
	curr_lsa->header->adv_router == new_lsa->header->adv_router) {
      /* The two packets are the same, figure out which one is newer. */
      found = 1;

      replace = ospf_replace_lsa(curr_lsa->header, new_lsa->header);
     } /* if packets are the same */

    if (found) {
      if (replace) {
	/* FIX We should probably let the LL code do this. */
	/* Delete (curr_lsa->header); */
	LL_Remove (OSPF.ll_summary_lsas, curr_lsa);
	/* Delete (curr_lsa); */

	LL_Add (OSPF.ll_summary_lsas, new_lsa);
      }

      break;
    }
  } /* LL_Iterate */

  if (!found) {
    /* We didn't find it, so just add it to the database. */
    LL_Add (OSPF.ll_summary_lsas, new_lsa);
  }

} /* ospf_add_summary_lsa */


void ospf_destroy_summary_lsa (ospf_summary_lsa_t *lsa) {
  Delete (lsa->header);
  Delete(lsa);
} /* ospf_destroy_summary_lsa */


void ospf_add_external_lsa (ospf_external_lsa_t *new_lsa) {
  ospf_external_lsa_t *curr_lsa;
  int replace;
  int found = 0;

  LL_Iterate (OSPF.ll_external_lsas, curr_lsa) {
    if (curr_lsa->header->id == new_lsa->header->id &&
	curr_lsa->header->adv_router == new_lsa->header->adv_router) {
      /* The two packets are the same, figure out which one is newer. */
      found = 1;

      replace = ospf_replace_lsa(curr_lsa->header, new_lsa->header);
     } /* if packets are the same */

    if (found) {
      if (replace) {
	LL_Remove (OSPF.ll_external_lsas, curr_lsa);
	LL_Add (OSPF.ll_external_lsas, new_lsa);
      }

      break;
    }
  } /* LL_Iterate */

  if (!found) {
    /* We didn't find it, so just add it to the database. */
    LL_Add (OSPF.ll_external_lsas, new_lsa);
  }

} /* ospf_add_external_lsa */


void ospf_destroy_external_lsa (ospf_external_lsa_t *lsa) {
  Delete (lsa->header);
  Delete(lsa);
} /* ospf_destroy_external_lsa */



/* lsa is a pointer to one of the three LSA packet structures.
 */
void ospf_add_lsa_to_db (ospf_lsa_t *header, void *lsa) {
  switch (header->type) {
  case OSPF_ROUTER_LSA:
    ospf_add_router_lsa ((ospf_router_lsa_t *)lsa);
    break;
  case OSPF_NETWORK_LSA:
    ospf_add_network_lsa ((ospf_network_lsa_t *)lsa);
    break;
  case OSPF_SUMMARY_LSA3:
    ospf_add_summary_lsa ((ospf_summary_lsa_t *)lsa);
    break;
  case OSPF_SUMMARY_LSA4:
    ospf_add_summary_lsa ((ospf_summary_lsa_t *)lsa);
    break;
  case OSPF_EXTERNAL_LSA:
    ospf_add_external_lsa ((ospf_external_lsa_t *)lsa);
    break;
  default:
    trace (ERROR, OSPF.trace, "ERROR -- Attempting to add "
	   "unknown OSPF LSA type (%d) to database\n", 
	   header->type);
    break;
  }
} /* ospf_add_lsa_to_db */


/* The header _must_ specify the type of LSA.
 * Age and options are ignored, and for all other fields a 0 value is
 * considered a field that doesn't need to be compared.
 * The function returns a pointer to a LSA of that type or NULL if it's not
 * found.
 */
void *ospf_find_lsa_in_db (ospf_lsa_t *header) {
  ospf_router_lsa_t *router_lsa;
  ospf_network_lsa_t *network_lsa;
  ospf_summary_lsa_t *summary_lsa;

  switch (header->type) {
  case OSPF_ROUTER_LSA:
    LL_Iterate (OSPF.ll_router_lsas, router_lsa) {
      if ((header->id == 0 || (header->id == router_lsa->header->id)) &&
	  (header->adv_router == 0 || (header->adv_router ==
				       router_lsa->header->adv_router)) &&
	  (header->seq_num == 0 || (header->seq_num ==
				    router_lsa->header->seq_num)) &&
	  (header->checksum == 0 || (header->checksum ==
				     router_lsa->header->checksum))) {
	/* We've found a match! */
	return ((void *)router_lsa);
      }
    } /* LL_Iterate */
    break;
  case OSPF_NETWORK_LSA:
    LL_Iterate (OSPF.ll_network_lsas, network_lsa) {
      if ((header->id == 0 || (header->id == network_lsa->header->id)) &&
	  (header->adv_router == 0 || (header->adv_router ==
				       network_lsa->header->adv_router)) &&
	  (header->seq_num == 0 || (header->seq_num ==
				    network_lsa->header->seq_num)) &&
	  (header->checksum == 0 || (header->checksum ==
				     network_lsa->header->checksum))) {
	/* We've found a match! */
	return ((void *)network_lsa);
      }
    } /* LL_Iterate */
    break;
  case OSPF_SUMMARY_LSA3:
  case OSPF_SUMMARY_LSA4:
    LL_Iterate (OSPF.ll_summary_lsas, summary_lsa) {
      if ((header->id == 0 || (header->id == summary_lsa->header->id)) &&
	  (header->adv_router == 0 || (header->adv_router ==
				       summary_lsa->header->adv_router)) &&
	  (header->seq_num == 0 || (header->seq_num ==
				    summary_lsa->header->seq_num)) &&
	  (header->checksum == 0 || (header->checksum ==
				     summary_lsa->header->checksum))) {
	/* We've found a match! */
	return ((void *)summary_lsa);
      }
    } /* LL_Iterate */
    break;
  default:
    trace (ERROR, OSPF.trace, "ERROR -- Attempting to find "
	   "unknown OSPF LSA type (%d) in database\n",
	   header->type);
    break;
  }

  /* We didn't find anything. */
  return (NULL);
} /* ospf_find_lsa_in_db */





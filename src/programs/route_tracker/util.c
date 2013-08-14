/*
 * $Id: util.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

#include <stdio.h>
#include <string.h>
#include <mrt.h>
#include <trace.h>
#include <interface.h>
#include <rip.h>
#include <time.h>
#include <bgp.h>
#include <dirent.h>
#include <signal.h>
#include <config_file.h>
#include <fcntl.h>
#include <io.h>
#include <dirent.h>
#include "rtracker.h"

/* file_comp
 * used to sort database files 
 */
int file_comp (rtr_data_file_t *f1, rtr_data_file_t *f2) {
  return (f1->time - f2->time);
}



/* rtr_build_file_list
 * Scan the database directory and build up a linked_list of all the currently 
 * available files
 */
int rtr_build_file_list (rtr_database_t *database) {
  struct dirent *entry, *buf;
  rtr_data_file_t *rtr_file;
  char tmp[MAXLINE];
  DIR *dp;
  static struct tm tm;
  u_long t;

  irr_lock (database);
  LL_Clear (database->ll_files);
  LL_Clear (database->ll_dump_files);

  if ((dp = opendir (database->path)) == NULL) {
    irr_unlock (database);
    return (-1);
  }

#ifdef HAVE_LIBPTHREAD
  entry = malloc (sizeof(struct dirent) +  _PC_NAME_MAX + 1000);
  readdir_r (dp, entry, &buf);
  while (buf != NULL) {
#else
  while ((buf = (struct direct *) readdir (dp)) != NULL) {
#endif /* HAVE_LIBPTHREAD */
    memset (&tm, 0, sizeof (struct tm));
    memcpy (tmp, buf->d_name, buf->d_reclen);

    /* BGP update files */
    if (sscanf (tmp, "bgp.%2d%2d%2d.%2d:%d", &tm.tm_year, &tm.tm_mon, 
		&tm.tm_mday, &tm.tm_hour, &tm.tm_min) >= 5) {
      tm.tm_mon--;
      tm.tm_isdst = -1;
      /*tm.tm_hour--;*/

      if ((t = mktime(&tm)) == -1) {
	printf ("BAD file %s\n", tmp);
	continue;
      }

      rtr_file = New (rtr_data_file_t);
      sprintf (tmp, "%s/%s", database->path, buf->d_name);
      rtr_file->name = strdup (tmp);
      rtr_file->time = t;

      LL_Add (database->ll_files, rtr_file);
    }

    /* routing table dumps */
    else if (sscanf (tmp, "dumps.%2d%2d%2d.%2d:%d", &tm.tm_year, &tm.tm_mon, 
		     &tm.tm_mday, &tm.tm_hour, &tm.tm_min) >= 5) {
      tm.tm_mon--;
      tm.tm_isdst = -1;

      if ((t = mktime(&tm)) == -1) {
	printf ("BAD file %s\n", tmp);
	continue;
      }

      rtr_file = New (rtr_data_file_t);
      sprintf (tmp, "%s/%s", database->path, buf->d_name);
      rtr_file->name = strdup (tmp);
      rtr_file->time = t;

      LL_Add (database->ll_dump_files, rtr_file);
    }


#ifdef HAVE_LIBPTHREAD
    readdir_r (dp, entry, &buf);
#endif /* HAVE_LIBPTHREAD */
  }
  closedir (dp);
#ifdef HAVE_LIBPTHREAD
  free (entry);
#endif /* HAVE_LIBPTHREAD */

  LL_Sort (database->ll_files, file_comp);
  LL_Sort (database->ll_dump_files, file_comp);

  trace (NORM, default_trace, "Built BGP update file list for %s [%d files]\n", 
	 database->name,
	 LL_GetCount (database->ll_files));
  trace (NORM, default_trace, "Built dump file list for %s [%d files]\n", database->name,
	 LL_GetCount (database->ll_dump_files));

  irr_unlock (database);
  return (1);
}


/* Delete_RTR_File
 */
void Delete_RTR_File (rtr_data_file_t *file) {

  Delete (file->name);
  Delete (file);
}




/* find_rtr_database
 */
rtr_database_t *find_rtr_database (char *name) {
  rtr_database_t *db;

  LL_Iterate (RTR.ll_database, db) {
    if (!strcmp (name, db->name)) {
      return (db);
    }
  }

  return (NULL);


}

void irr_lock (rtr_database_t *database) {
  if (database == NULL) return;

  pthread_mutex_lock (&database->mutex_lock);
}

void irr_unlock (rtr_database_t *database) {
  if (database == NULL) return;

  pthread_mutex_unlock (&database->mutex_lock);
}



void rtr_database_rescan (mtimer_t *timer, rtr_database_t *db) {
  rtr_build_file_list (db);
}


void Delete_Node (radix_node_t *node) {
  LINKED_LIST *ll_rtr_attr;
  rtracker_attr_t *rtr_attr;
  rtr_route_head_t *head;

  head = (rtr_route_head_t *) node->data;
  if (head) 
    ll_rtr_attr = head->ll_attr;
  else
    ll_rtr_attr = NULL;

  if (ll_rtr_attr != NULL) {
    LL_SetAttributes (ll_rtr_attr, LL_DestroyFunction, free, 0);
    LL_Iterate (ll_rtr_attr, rtr_attr) {
      bgp_deref_attr (rtr_attr->bgp_attr);
    }
    
    LL_Destroy (ll_rtr_attr);
  }
  Delete (head);

  if (node->prefix) Deref_Prefix (node->prefix);
  Delete (node);
}

int rtr_delete_radix (rtracker_peer_t *rtr_peer) {
  radix_node_t *node = NULL;
  LINKED_LIST *ll_tmp;

  ll_tmp = LL_Create (LL_DestroyFunction, Delete_Node, 0);

  if (rtr_peer->radix != NULL) {
    RADIX_WALK_ALL (rtr_peer->radix->head, node) {
      LL_Add (ll_tmp, node);
    }
    RADIX_WALK_END;
  }
  else
    printf ("SHould never get here\n");

  LL_Destroy (ll_tmp);
  if (rtr_peer->radix != NULL) {
    Delete (rtr_peer->radix);
  }
  return (1);
}


void Delete_Peer (rtracker_peer_t *peer) {
  
  rtr_delete_radix (peer);
  Delete (peer);
}



rtracker_peer_t *find_peer (irr_connection_t *irr, gateway_t *gateway) {

  rtracker_peer_t *tmp;
  int new = 1;

  LL_Iterate (irr->ll_peer, tmp) {
    if (prefix_compare (tmp->gateway->prefix, gateway->prefix)) {
      new = 0;
      break;
    }
  }

  if (new) {
    tmp = New (rtracker_peer_t);
    tmp->radix = New_Radix (32);
    tmp->gateway = gateway;
    LL_Add (irr->ll_peer, tmp);
  }

  return (tmp);
}

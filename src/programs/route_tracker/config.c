/*
 * $Id: config.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

#include <stdio.h>
#include <string.h>
#include <mrt.h>
#include <trace.h>
#include <interface.h>
#include <rip.h>
#include <time.h>
#include <bgp.h>
#include <signal.h>
#include <config_file.h>
#include <fcntl.h>
#include "rtracker.h"



void get_config_rtr_database (rtr_database_t *database) {
  char *type;

  if (database->type == 0)
    type = "bgp";
  else
    type = "ospf";

  config_add_output ("rtr_database %s %s path %s\r\n", 
		     type, database->name, database->path);
}


/* rtr_database <bgp|ospf|rip> <name> path <path> */
void config_rtr_database (uii_connection_t *uii, char *type, char *name, char *path) {
  rtr_database_t *database;
  int typev;

  if (!strcasecmp (type, "bgp"))
    typev = 0;
  else if (!strcasecmp (type, "ospf"))
    typev = 1;
  else {
    config_notice (NORM, uii, "CONFIG error -- %s not valid\r\n", type);
    return;
  }
    
  database = New (rtr_database_t);
  database->name = name;
  database->path = path;
  database->type = typev;
  database->ll_files = LL_Create (LL_DestroyFunction, Delete_RTR_File, 0);
  database->ll_dump_files = LL_Create (LL_DestroyFunction, Delete_RTR_File, 0);
  pthread_mutex_init (&database->mutex_lock, NULL);


  database->rescan_timer = (mtimer_t *)
    New_Timer (rtr_database_rescan, 3*60, "RTR database rescan", database);
  timer_set_jitter (database->rescan_timer, 40);
  Timer_Turn_ON ((mtimer_t *) database->rescan_timer);

  trace (NORM, default_trace, "Config rtr_database %s %s %s\n", 
	 type, name, path);


  if (rtr_build_file_list (database) <= 0) {
    trace (ERROR, default_trace, "Error building file list for %s\n", name);
    return;
  }
  LL_Add (RTR.ll_database, database);


  config_add_module (0, "config_rtr_database", get_config_rtr_database, database);
  return;
}







void config_create_default () {
  char *tmp;
  CONFIG.ll_modules = LL_Create (0);

  tmp = strdup ("#####################################################################");
  config_add_module (0, "comment", get_comment_config, tmp);

  tmp = malloc (512);
  sprintf (tmp, "# RouteTrackerD -- MRT version %s ", MRT_VERSION);
  config_add_module (0, "comment", get_comment_config, tmp);
		
  tmp = strdup  ("#####################################################################");
  config_add_module (0, "comment", get_comment_config, tmp);


  config_add_module (0, "comment", get_comment_config, strdup ("#"));
  config_add_module (0, "debug", get_debug_config, NULL);
  config_add_module (0, "comment", get_comment_config, strdup ("#"));  

  


}

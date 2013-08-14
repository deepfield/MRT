/*
 * $Id: commands.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
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


extern bgp_t *BGP;
extern rip_t *RIP;
extern rtracker_t RTR;
extern trace_t *default_trace;

void rtr_list_time (irr_connection_t *irr);
void rtr_set_prefix (irr_connection_t *irr);
void rtr_set_as (irr_connection_t *irr);
void rtr_run (irr_connection_t *irr);
void rtr_set_time (irr_connection_t *irr);
void rtr_set_database (irr_connection_t *irr);
void rtr_load_table (irr_connection_t *irr);
int irr_less_all (irr_connection_t *irr, prefix_t *prefix);
int irr_exact (irr_connection_t *irr, prefix_t *prefix);

/* irr_proccess_command
 * read/parse the !command and call the appropriate handler
 */
int rtr_proccess_command (irr_connection_t * irr) {
  char *line, tmp[MAXLINE];

  line = irr->buffer;
  irr->cp = irr->buffer;

    trace (NORM, default_trace, "Command: %s\n",irr->cp);
    /* built-in functions */
    if (!strcasecmp (irr->cp, "quit")) {
      irr_destroy_connection (irr);
      return (1);
    }
    if (!strcasecmp (irr->cp, "exit")) {
      irr_destroy_connection (irr);
      return (1);
    }
    if (!strncasecmp (irr->cp, "!q", 2)) {
      irr_destroy_connection (irr);
      return (1);
    }
    /* for testing -- exit program */
    if (!strncasecmp (irr->cp, "!poof", 4)) {
      exit (0);
    }

    /* ignore -- for backward compatability (persistent query) */
    if (!strncasecmp (irr->cp, "!!", 2)) {
      return (1);
    }
    /* list times available */
    if (!strncasecmp (irr->cp, "!lt", 3)) {
      rtr_list_time (irr);
      return (1);
    }
    /* !st set times available */
    if (!strncasecmp (irr->cp, "!st", 3)) {
      rtr_set_time (irr);
      return (1);
    }

    /* !lr load routing table */
    if (!strncasecmp (irr->cp, "!lr", 3)) {
      rtr_load_table (irr);
      return (1);
    }
    
    /* !mr routing table <start> <end> */
    if (!strncasecmp (irr->cp, "!mr", 3)) {
      rtr_load_table (irr);
      return (1);
    }
    
    /* !sa -- set AS */
     if (!strncasecmp (irr->cp, "!sa", 3)) {
       rtr_set_as (irr);
       return (1);
     }

    /* !su -- set update type */
     if (!strncasecmp (irr->cp, "!sua", 4)) {
       irr->type = 1;
       irr_send_okay (irr);
       return (1);
     }
     if (!strncasecmp (irr->cp, "!suw", 4)) {
       irr->type = 2;
       irr_send_okay (irr);
       return (1);
     }

     /* !sp -- set prefix */
     if (!strncasecmp (irr->cp, "!sp", 3)) {
       rtr_set_prefix (irr);
       return(1);
     } 

     /* !sd -- set database */
     if (!strncasecmp (irr->cp, "!sd", 3)) {
       rtr_set_database (irr);
       return(1);
     }
     
     /* set output table */
     if (!strncasecmp (irr->cp, "!sotable", 7)) {
       irr->output_type = RTR_PEER_TABLE;
       irr_send_okay (irr);
       return (1);
     }
     /* setoutput prefixes */
     if (!strncasecmp (irr->cp, "!soprefixes", 7)) {
       irr->output_type = RTR_PREFIXES;
       irr_send_okay (irr);
       return (1);
     }
     /* setoutput prefixes */
     if (!strncasecmp (irr->cp, "!soascii_prefixes", 7)) {
       irr->output_type = RTR_ASCII_PREFIXES;
       irr_send_okay (irr);
       return (1);
     }

     /* !s-lc -- list available database */
     if (!strncasecmp (irr->cp, "!s-lc", 5)) {
       irr_show_sources (irr);
       return (1);
     }

      /* !rd -- dump routing table */
     if (!strncasecmp (irr->cp, "!rd", 3)) {
       rtr_dump_table (irr);
       return (1);
     }

     
     /* Route searches.
      * Default finds exact prefix/len match.
      *  o - return origin of exact match(es)
      *  l - one-level less specific
      * eg, !r141.211.128/24,l
      */
     if (!strncasecmp (irr->cp, "!r", 2)) {
       char *cp = NULL;
       prefix_t *prefix;

       irr->cp += 2;
       cp = strrchr(irr->cp, ',');
      
       if (cp == NULL) {
	 if ((prefix = ascii2prefix (AF_INET, irr->cp)) == NULL)
	   irr_send_error (irr);
	 else {
	   irr_exact (irr, prefix);
	   Delete_Prefix (prefix);
	 }
       }
       else if (!strncmp (",l", cp, 2)) {
	 *cp = '\0';
	 if ((prefix = ascii2prefix (AF_INET, irr->cp)) == NULL) {
	   irr_send_error (irr);
	 }
	else {
	  irr_less_all (irr, prefix);
	  Delete_Prefix (prefix);
	}
       }
       return (1);
     }
     
     
     /* 
      * !run
      * okay, process the data!! 
      */
     if (!strncasecmp (irr->cp, "!run", 4)) {
       if (irr->database == NULL) 
    	 return (-1);

       if ((irr->output_type == RTR_PREFIXES) || 
	   (irr->output_type == RTR_ASCII_PREFIXES)) {
	 rtr_run (irr);
	 if (irr->ll_peer) {
	   LL_Clear (irr->ll_peer);
	   trace (NORM, default_trace, "Cleaned up memory...\n");
	 }
       }
       else if (irr->output_type == RTR_PEER_TABLE) {
	 rtr_run (irr);
	 report (irr);
	 irr_send_answer (irr);
	 LL_Clear (irr->ll_peer);
	 trace (NORM, default_trace, "Cleaned up memory...\n");
	 return (1);
       }
       return(1);
     }

     
     /* !rst -- reset the search flags  */
     if (!strncasecmp (irr->cp, "!rst", 4)) {
       irr->prefix = NULL;
       irr->AS = 0;
       irr->type = 0;

       /* reset time */
       irr_send_okay (irr);
       return(1);
     }


    /* error -- command unrecognized */
    sprintf (tmp, "F\r\n");
    write (irr->sockfd, tmp, strlen (tmp));
    return (-1);
}

/* !sd -- set database */
void rtr_set_database (irr_connection_t *irr) {
  irr->cp += 3;

  if ((irr->database = find_rtr_database (irr->cp)) == NULL) {
    irr_send_error (irr);
    return;
  }

  irr_send_okay (irr);
  return;
}


/* !sp -- set as prefix */
void rtr_set_prefix (irr_connection_t *irr) {

  irr->cp += 3;
  if ((irr->prefix = ascii2prefix (AF_INET, irr->cp)) != NULL)
    irr_send_okay (irr);
  else
    irr_send_error (irr);
}



/* !sa -- set as number */
void rtr_set_as (irr_connection_t *irr) {
  irr->cp += 3;

  if (!strncasecmp (irr->cp, "AS", 2)) 
    irr->cp +=2;

  irr->AS = atoi (irr->cp);

  irr_send_okay (irr);
}



/* run and go scan the file ! */
void rtr_run (irr_connection_t *irr) {
  rtr_data_file_t *file;
  
  if (irr->database == NULL) {
    irr_send_error (irr);
    return;
  }
  
  irr_lock (irr->database);

  LL_Iterate (irr->database->ll_files, file) {
    if (file->time < irr->start_window) continue;
    if (file->time > irr->end_window) break;

    rtr_process_input (file->name, irr);
  }
  trace (NORM, default_trace, "Sending %d bytes \n", irr->answer_len);
  irr_unlock (irr->database);
	 
  if (irr->output_type != RTR_PEER_TABLE) {
    irr_send_answer (irr);
  }

  return;
}


/* !st <start_time> <end time> */
void rtr_set_time (irr_connection_t *irr) {
  int start, end;
  char *cp;

  cp = irr->cp + 3;
  if (sscanf (cp, "%d %d", &start, &end) == 2) {
    irr->start_window = start;
    irr->end_window = end;
    irr_send_okay (irr);
    return;
  }

  irr->end_window = 0;
  irr->start_window = 0;

  irr_send_error (irr);
}


/* !lt <time> */
void rtr_load_table (irr_connection_t *irr) {
  rtr_data_file_t *file, *dump_file, *bgp_file;
  rtracker_peer_t *peer;
  int time, end_time, n;
  char *cp, *stime;

  if (irr->database == NULL) return;

  time = end_time = 0;

  cp = irr->cp + 3;
  n = sscanf (cp, "%d %d", &time, &end_time);
  if ((n < 1) || (n > 2)) {
    irr_send_error (irr);
    return;
  }

  stime = my_strftime (time, "%D %T");
  trace (NORM, default_trace, "Building routing table at %s\n", stime);
  Delete (stime);
  if (end_time > 0) {
    stime = my_strftime (end_time, "%D %T");
    trace (NORM, default_trace, "Monitor until %s\n", stime);
    Delete (stime);
  }

  irr_lock (irr->database);
  irr->output_type = RTR_NO_OUTPUT;

  /* clear old radix trees */
  LL_Iterate (irr->ll_peer, peer) {
    rtr_delete_radix (peer);
    /* reset statistics */
  }

  /* find RIB dump */
  dump_file = NULL;
  LL_Iterate (irr->database->ll_dump_files, file) {
    if (file->time < time) 
      dump_file = file;
    if (file->time > time) 
      break;
  }

  if (dump_file == NULL) {
    stime = my_strftime (time, "%D %T");
    trace (NORM, default_trace, "Routing Table dump not found befor %s (%d)\n", 
	   stime, time);
    Delete (stime);
    irr_send_error (irr);
    irr_unlock (irr->database);
    return;
  }
    
  /* now find spot in bgp files. find last file _before_ dump */
  LL_Iterate (irr->database->ll_files, file) {
    if (file->time < dump_file->time) {
      bgp_file = file;
      continue;
    }
    if (file->time >dump_file->time) break;
  }
  

  trace (NORM, default_trace, "Loading RIB %s\n", dump_file->name);
  load_rib_from_disk (irr, dump_file->name);
  trace (NORM, default_trace, "Done loading RIB %s\n", dump_file->name);

  if (end_time == 0) 
    irr->end_window = time;
  else
    irr->end_window = end_time;

  rtr_process_input (bgp_file->name, irr);

  while ((bgp_file = LL_GetNext (irr->database->ll_files, bgp_file))) {
    if (bgp_file->time > irr->end_window) 
      break;
    rtr_process_input (bgp_file->name, irr);
  }

  stime = my_strftime (time, "%D %T");
  trace (NORM, default_trace, "Routing Table now synced at %s\n", stime);
  Delete (stime);
  irr_unlock (irr->database);
  irr_send_okay (irr);
}




/* !lta */
void rtr_list_time (irr_connection_t *irr) {
  rtr_data_file_t *file;
  int first = 1;

  if (irr->database == NULL) {
    irr_send_error (irr);
    return;
  }

  irr_lock (irr->database);

  if (!strncasecmp (irr->cp, "!lta", 4)) {
    file = LL_GetHead (irr->database->ll_files);
    irr_add_answer (irr, "%d ", file->time);
    file = LL_GetTail (irr->database->ll_files);
    irr_add_answer (irr, "%d ", file->time);
  }  
  else {
    LL_Iterate (irr->database->ll_files, file) {
      if ((first) && (file->time > irr->start_window)) {
	irr_add_answer (irr, "%d ", file->time);
	first = 0;
      }
      if (file->time > irr->end_window) {
	break;
      }
    }
    if (file == NULL) file = LL_GetTail (irr->database->ll_files);
    irr_add_answer (irr, "%d ", file->time);
  }

  irr_unlock (irr->database);

  irr_send_answer (irr);
}


/* !s-lc   list available databases */
void irr_show_sources (irr_connection_t *irr) {
  rtr_database_t *database;
  int first = 1;

  LL_ContIterate (RTR.ll_database, database) {
    if (first != 1) { irr_add_answer (irr, ",");}
    first = 0;
    irr_add_answer (irr, "%s", database->name);
  }

  irr_send_answer (irr);
}

/*
 * Copyright (c) 1997, 1998
 *      The Regents of the University of Michigan ("The Regents").
 *      All rights reserved.
 *
 * Contact: ipma-support@merit.edu
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      Michigan and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *    
 */   

#include <mrt.h>
#include <timer.h>
#include <linked_list.h>
#include <config_file.h>
#include <protoconf.h>

#include "publisher.h"
#include "db.h"
#include "bgp_db.h"
#include "util.h"
#include "daemon.h"
#include "asExplorerPublisher.h"
#include "report_publisher.h"
#ifdef GEN_OLD_FILES
#include "gen_old_files.h"
#endif GEN_OLD_FILES

#define DATADSTL_VERSION						"1.0"

#define DEFAULT_PUBLISH_INTERVAL				(15*60) 	/* 15 minutes */

int publish_interval_fg  = DEFAULT_PUBLISH_INTERVAL;
int publish_interval_ftd = DEFAULT_PUBLISH_INTERVAL;
int publish_interval_ase = DEFAULT_PUBLISH_INTERVAL;

mtimer_t *publish_timer_fg  = NULL;
mtimer_t *publish_timer_ftd = NULL;
mtimer_t *publish_timer_ase = NULL;
trace_t *default_trace;
char *appname;
pthread_mutex_t io_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef GEN_OLD_FILES
/* flags to determine which programs to re-run over old files.
 */
int dump_fg = 0;
int dump_ftd = 0;
int dump_ase = 0;
#endif GEN_OLD_FILES

#define PORT	"5680"
#ifdef GEN_OLD_FILES
#define CONFIG "old.conf"
#else
#define CONFIG "datadstl.conf"
#endif GEN_OLD_FILES

/* prototypes for private functions */
static void register_command_handlers();
static void register_config_writers();
static void set_prompt(char *name);

void terminate(uii_connection_t *ignored) {
	trace(TR_TRACE, default_trace, "Received terminate command\n");
	terminate_publisher_thread();
	free(appname);
/*pthread_mutex_destroy(&io_lock);*/
	mrt_exit(0);
}

int main(int argc, char **argv) {
	int errors = 0;
	int daemon = 0;
	int verbose = 0;
#ifdef GEN_OLD_FILES
	char *usage = "Usage: %s [-f config_file] [-g | -t | -x | -a] [-v];\n\t where g=FlapGraph, t= FlapTableDaily, x=ASExplorer, a= all three.\n";
#else 
	char *usage = "Usage: %s [-f config_file] [-p uii_port ] [-v] [-d]\n";
#endif GEN_OLD_FILES
	char *config_file = CONFIG;
	char *port = PORT;
	char c;
	int found_one = 0;

	tzset();	/* needed by my_mktime, must be before multi-thread */
	appname = strdup(argv[0]);

#ifdef GEN_OLD_FILES
       /* check if no args supplied */
       if (argc == 1) {
		fprintf (stderr, usage, appname);
		printf ("\nDerived from: DataDistiller %s (MRT %s) compiled on %s\n\n",
			DATADSTL_VERSION, MRT_VERSION, __DATE__);
		exit (1);
       }

       while ((c = getopt (argc, argv, "f:gtxav")) != -1) {
#else 
	   while ((c = getopt (argc, argv, "f:p:vd")) != -1) {
#endif GEN_OLD_FILES
		switch (c) {
		case 'f':		/* config file */
		    config_file = optarg;
		    break;
#ifdef GEN_OLD_FILES
		case 'g':               /* old FlapGraph files */
		    if (found_one) {
			errors++;
		    }
		    else {
			dump_fg = 1;
			found_one = 1;
		    }
		    break;
		case 't':               /* old FlapTableDaily files */
		    if (found_one) {
			errors++;
		    }
		    else {
			dump_ftd = 1;
			found_one = 1;
		    }
		    break;
		case 'x':
		    if (found_one) {
			errors++;
		    }
		    else {
			dump_ase = 1;       /* old ASExplorer files */
			found_one = 1;
		    }
		    break;
		case 'a':               /* all 3 above */
		    if (found_one) {
			errors++;
		    }
		    else {
			dump_fg = dump_ftd = dump_ase = 1;
			found_one = 1;
		    }
		    break;
#else 
			case 'p':		/* uii port number */
				port = optarg;
				break;
#endif GEN_OLD_FILES
			case 'v':		/* verbose */
				verbose = 1;
				break;
#ifndef GEN_OLD_FILES
			case 'd':		/* set self up as daemon */
				daemon = 1;
				break;
#endif GEN_OLD_FILES
			default:
				errors++;
				break;
		}
	   }

	if (errors) {
		fprintf (stderr, usage, appname);
		printf ("\nDataDistiller %s (MRT %s) compiled on %s\n\n",
			DATADSTL_VERSION, MRT_VERSION, __DATE__);
		exit (1);
	}

	default_trace = New_Trace2(appname);
	if (daemon)
		daemon_init();

	if (verbose)
		set_trace (default_trace, TRACE_FLAGS, NORM | TR_ERROR,
			TRACE_LOGFILE, "stdout", NULL);

/* XXX check for NULL pointers */
	init_trace(appname, 0);
	init_mrt(default_trace);
	init_mrt_reboot(argc, argv);
	init_interfaces (default_trace);

	init_uii(default_trace);
	init_mrtd_config (default_trace);
	set_prompt(strrchr(appname, '/')+1); /* after init_mrtd_config so it sticks */
	init_config(default_trace);

	init_BGP (default_trace);
	init_asExplorerPublisher(default_trace);
	start_publisher_thread(default_trace);
	register_command_handlers();
	register_config_writers();

	config_bgp_init ();
	config_from_file2 (default_trace, config_file);

#ifdef GEN_OLD_FILES
	if (dump_fg) {
	    flapGraphAndTablePublisher_FGDump();
	}

	if (dump_ftd) {
	    if (dump_fg) { /* if we are in dump all mode */
		reinitialize_ixpinfo();
	    }
	    flapGraphAndTablePublisher_FTDDump ();
	}

	if (dump_ase) {
	    asExplorerPublisher_Dump();
	}

	mrt_exit (0);
#else 
	publish_timer_fg = New_Timer (flapGraphAndTablePublisher_doFGUpdate,
		publish_interval_fg, "FlapGraph Update Timer", NULL);
	if (publish_interval_fg > 0) {
		flapGraphAndTablePublisher_doFGUpdate();
		Timer_Turn_ON (publish_timer_fg);
	}

	publish_timer_ftd = New_Timer (flapGraphAndTablePublisher_doFTDUpdate,
		publish_interval_fg, "FlapTableDaily Update Timer", NULL);
	if (publish_interval_ftd > 0) {
		flapGraphAndTablePublisher_doFTDUpdate();
		Timer_Turn_ON (publish_timer_ftd);
	}

	publish_timer_ase = New_Timer (asExplorerPublisher_doUpdate,
		publish_interval_ase, "ASExplorer Update Timer", NULL);
	if (publish_interval_ase > 0) {
		asExplorerPublisher_doUpdate();
		Timer_Turn_ON (publish_timer_ase);
	}
#endif GEN_OLD_FILES
	listen_uii2(port);

	mrt_main_loop();

	/* not reached */

	return 0;				/* just to make gcc happy */
}

void set_interval_fg(uii_connection_t *uii, int num_seconds) {
	if (num_seconds < 0) {
		uii_send_data (uii, "Publish interval must be non-negative.\n");
		return;
	}

	publish_interval_fg = num_seconds;
	
	/* reading config file at startup -- not yet initialized */
	if (publish_timer_fg == NULL)
		return;
		
	if (num_seconds == 0)
		Timer_Turn_OFF (publish_timer_fg);
	else {
		flapGraphAndTablePublisher_doFGUpdate();
		Timer_Set_Time (publish_timer_fg, publish_interval_fg);
		Timer_Reset_Time (publish_timer_fg);			/* necessary? */
		Timer_Turn_ON (publish_timer_fg);
	}
}

void set_interval_ftd(uii_connection_t *uii, int num_seconds) {
	if (num_seconds < 0) {
		uii_send_data (uii, "Publish interval must be non-negative.\n");
		return;
	}

	publish_interval_ftd = num_seconds;
	
	/* reading config file at startup -- not yet initialized */
	if (publish_timer_ftd == NULL)
		return;
		
	if (num_seconds == 0)
		Timer_Turn_OFF (publish_timer_ftd);
	else {
		flapGraphAndTablePublisher_doFTDUpdate();
		Timer_Set_Time (publish_timer_ftd, publish_interval_ftd);
		Timer_Reset_Time (publish_timer_ftd);			/* necessary? */
		Timer_Turn_ON (publish_timer_ftd);
	}
}

void set_interval_ase(uii_connection_t *uii, int num_seconds) {
	if (num_seconds < 0) {
		uii_send_data (uii, "Publish interval must be non-negative.\n");
		return;
	}

	publish_interval_ase = num_seconds;
	
	/* reading config file at startup -- not yet initialized */
	if (publish_timer_ase == NULL)
		return;

	if (num_seconds == 0)
		Timer_Turn_OFF (publish_timer_ase);
	else {
		asExplorerPublisher_doUpdate();
		Timer_Set_Time (publish_timer_ase, publish_interval_ase);
		Timer_Reset_Time (publish_timer_ase);			/* necessary? */
		Timer_Turn_ON (publish_timer_ase);
	}
}

void get_interval_fg(void *ignored) {
	config_add_output (PARAM_FG_PUBLISH_INTERVAL " %d\r\n",
		publish_interval_fg);
}

void get_interval_ftd(void *ignored) {
	config_add_output (PARAM_FTD_PUBLISH_INTERVAL " %d\r\n",
		publish_interval_ftd);
}

void get_interval_ase(void *ignored) {
	config_add_output (PARAM_ASE_PUBLISH_INTERVAL " %d\r\n",
		publish_interval_ase);
}

/* private */
static void register_command_handlers() {
	/* FlapGraph */
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_FG_OUTTYPE
		" %s", (void *) flapGraphAndTablePublisher_setFGOutType, DESC_FG_OUTTYPE);
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_FG_PUBLISH_INTERVAL
		" %d", (void *) set_interval_fg, DESC_FG_PUBLISH_INTERVAL);
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_FG_TIMEFLAG " %d",
		(void *) flapGraphAndTablePublisher_setLocaltimeFlag, DESC_FG_TIMEFLAG);
#ifdef GEN_OLD_FILES
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_FG_START_DATE " %s",
			  (void *) flapGraph_setStartDate, DESC_FG_START_DATE);
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_FG_END_DATE " %s",
			  (void *) flapGraph_setEndDate, DESC_FG_END_DATE);
#endif GEN_OLD_FILES
	/* FlapTableDaily */
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_FTD_OUTTYPE
		" %s", (void *) flapGraphAndTablePublisher_setFTDOutType, DESC_FTD_OUTTYPE);
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_FTD_PUBLISH_INTERVAL
		" %d", (void *) set_interval_ftd, DESC_FTD_PUBLISH_INTERVAL);
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_FTD_TIMEFLAG " %d",
		(void *) flapGraphAndTablePublisher_setLocaltimeFlag, DESC_FTD_TIMEFLAG);
#ifdef GEN_OLD_FILES
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_FTD_START_DATE " %s",
			  (void *) flapTableDaily_setStartDate, 
			  DESC_FTD_START_DATE);
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_FTD_END_DATE " %s",
			  (void *) flapTableDaily_setEndDate, 
			  DESC_FTD_END_DATE);
#endif GEN_OLD_FILES

	/* ASExplorer */
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_ASE_OUTTYPE
		" %s", (void *) asExplorerPublisher_setOutType, DESC_ASE_OUTTYPE);
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_ASE_PUBLISH_INTERVAL
		" %d", (void *) set_interval_ase, DESC_ASE_PUBLISH_INTERVAL);
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_ASE_DURATION " %d",
		(void *) asExplorerPublisher_setDuration, DESC_ASE_DURATION);
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_ASE_PNAME " %s %s",
		(void *) asExplorerPublisher_setProbeName, DESC_ASE_PNAME);
#ifdef GEN_OLD_FILES
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_ASE_START_DATE " %s",
			  (void *) asExplorer_setStartDate, 
			  DESC_ASE_START_DATE);
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_ASE_END_DATE " %s",
			  (void *) asExplorer_setEndDate, 
			  DESC_ASE_END_DATE);
#endif GEN_OLD_FILES

	/* BGP Database */
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_BGPDB_PATH " %s",
		(void *) bgp_db_set_db_path, DESC_BGPDB_PATH);
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_BGPDB_FILE_SPAN " %d",
		(void *) bgp_db_set_file_span, DESC_BGPDB_FILE_SPAN);
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_BGPDB_DCACHE_TIME " %d",
		(void *) bgp_db_set_dir_cache_time, DESC_BGPDB_DCACHE_TIME);
	uii_add_command2 (UII_CONFIG, COMMAND_NORM, PARAM_BGPDB_FTIME_FLAG " %d",
		(void *) bgp_db_setLocaltimeFlag, DESC_BGPDB_FTIME_FLAG);
	/* misc. */
	uii_add_command2 (UII_NORMAL, COMMAND_NODISPLAY, "terminate", (void *)
		terminate, "Shutdown the server");
}

static void register_config_writers() {
	/* FlapGraph */
	config_add_module (0, PARAM_FG_PUBLISH_INTERVAL, get_interval_fg, NULL);
	config_add_module (0, PARAM_FG_OUTTYPE, flapGraphAndTablePublisher_getFGOutType, NULL);
#ifdef GEN_OLD_FILES
	config_add_module (0, PARAM_FG_START_DATE,
			   flapGraph_getStartDate, NULL);
	config_add_module (0, PARAM_FG_END_DATE,
			   flapGraph_getEndDate, NULL);
#endif GEN_OLD_FILES
	/* FlapTableDaily */
	config_add_module (0, PARAM_FTD_PUBLISH_INTERVAL, get_interval_ftd, NULL);
	config_add_module (0, PARAM_FTD_OUTTYPE, flapGraphAndTablePublisher_getFTDOutType,
		NULL);
#ifdef GEN_OLD_FILES
	config_add_module (0, PARAM_FTD_START_DATE,
			   flapTableDaily_getStartDate, NULL);
	config_add_module (0, PARAM_FTD_END_DATE,
			   flapTableDaily_getEndDate, NULL);
#endif GEN_OLD_FILES

	/* FlapGraph+FlapTableDaily */
	config_add_module (0, PARAM_FG_TIMEFLAG,
		flapGraphAndTablePublisher_getLocaltimeFlag, NULL);
	/* ASExplorer */
	config_add_module (0, PARAM_ASE_PUBLISH_INTERVAL, get_interval_ase, NULL);
	config_add_module (0, PARAM_ASE_OUTTYPE, asExplorerPublisher_getOutType, NULL);
	config_add_module (0, PARAM_ASE_DURATION, asExplorerPublisher_getDuration,
		NULL);
#ifdef GEN_OLD_FILES
	config_add_module (0, PARAM_ASE_START_DATE,
			   asExplorer_getStartDate, NULL);
	config_add_module (0, PARAM_ASE_END_DATE,
			   asExplorer_getEndDate, NULL);
#endif GEN_OLD_FILES

	/* BGP Database*/
	config_add_module (0, PARAM_BGPDB_PATH, bgp_db_get_db_path, NULL);
	config_add_module (0, PARAM_BGPDB_FILE_SPAN, bgp_db_get_file_span, NULL);
	config_add_module (0, PARAM_BGPDB_DCACHE_TIME, bgp_db_get_dir_cache_time,
		NULL);
	config_add_module (0, PARAM_BGPDB_FTIME_FLAG, bgp_db_getLocaltimeFlag, NULL);
}

static void set_prompt(char *name) {
	char *prompt;

/* XXX ??? */
	prompt = malloc (sizeof(char) * strlen(name)+3);
	sprintf (prompt, "%s> ", name);
	
	set_uii (UII, UII_PROMPT, 1, prompt, 0);

	free(prompt);
}

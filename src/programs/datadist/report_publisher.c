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
#include <trace.h>
#include <config_file.h>

#include "report_publisher.h"
#include "publisher.h"
#include "salypublisher.h"
#include "diskpublisher.h"
#include "db.h"
#include "bgp_db.h"
#include "flapCounter.h"
#include "util.h"
#include "mytime.h"

#ifdef GEN_OLD_FILES
#include "gen_old_files.h"
#endif GEN_OLD_FILES

#define OUTTYPE_DISK			"files"
#define OUTTYPE_DOLPHIN			"dolphin"

#define MODULE_NAME						"FlapGraph+FlapTable"
#define FLAP_GRAPH_CHANNEL				"FlapGraph"
#define FLAP_TABLE_DAILY_CHANNEL		"FlapTableDaily"
#define SCHEDULE_NAME					MODULE_NAME " Publisher"
#define THREAD_NAME						MODULE_NAME " Publisher"
#define FIELD_EXCHANGE					BGP_DB_FIELD_EXCHANGE
#define FIELD_TIME						BGP_DB_FIELD_TIME
#define DEFAULT_OUTTYPE			OUTTYPE_DISK
#define TIME_FORMAT						"%H:%M:%S"

#ifdef GEN_OLD_FILES
#define BASE_YEAR 1900
#endif GEN_OLD_FILES

#define NUM_BUCKETS 10

typedef struct {
	char *name;
	time_t update_from;
	flapGraph_t *flapCounter;
} ixp_info_t;

/* imported from driver.c */
extern char *appname;

/* make instance variables? */
static schedule_t *schedule = NULL;
static publisher_t *flap_graph_publisher = NULL;
static publisher_t *flap_table_daily_publisher = NULL;
static HASH_TABLE *ixp_info = NULL;
static trace_t *tracer;
static io_t *io;
static int use_localtime = 0;
/* XXX free on terminate */
static char *fg_outtype = NULL;
static char *ftd_outtype = NULL;

#ifdef GEN_OLD_FILES
time_t fg_start_time, fg_end_time;
time_t ftd_start_time, ftd_end_time;
static time_t current_start_time, current_end_time;

void flapGraphAndTablePublisher_FGDump();
void flapGraphAndTablePublisher_FTDDump();
/* also used in ASExplorerPublisher - so dont make it static */
time_t get_midnight_of_date (time_t some_other_day);
#endif GEN_OLD_FILES


/* callbacks */
void flapGraphAndTablePublisher_mainloop();
void flapGraphAndTablePublisher_FGUpdate();
void flapGraphAndTablePublisher_FTDUpdate();

/* private */
static ixp_info_t *get_ixp_info(char *ixp_name);
static time_t get_midnight();

void ixpDelete(DATA_PTR node_data) {
/*
what to delete?
the fgData and ftdData, for sure.
the name?
*/
}

void start_publisher_thread(trace_t *t) {
	ixp_info_t sample;
/*LINKED_LIST *a;*/

	if (schedule != NULL)
		return;

	tracer = t;
	io = New_IO(tracer);
	
	ixp_info = HASH_Create(NUM_BUCKETS, HASH_EmbeddedKey, False, HASH_KeyOffset,
		HASH_Offset(&sample, &sample.name), HASH_DestroyFunction, ixpDelete,
		NULL);

	fg_outtype = strdup(DEFAULT_OUTTYPE);
	ftd_outtype = strdup(DEFAULT_OUTTYPE);
	schedule = New_Schedule (SCHEDULE_NAME, NULL);
	mrt_thread_create (THREAD_NAME, schedule,
		(void *) flapGraphAndTablePublisher_mainloop, NULL);
}

#ifdef GEN_OLD_FILES
void reinitialize_ixpinfo() {
    ixp_info_t sample;

    HASH_Destroy (ixp_info);
    ixp_info = HASH_Create(NUM_BUCKETS, HASH_EmbeddedKey, False, HASH_KeyOffset,
			   HASH_Offset(&sample, &sample.name), HASH_DestroyFunction, ixpDelete,
			   NULL);

}
#endif GEN_OLD_FILES


void terminate_publisher_thread() {
	HASH_Destroy(ixp_info);
/* need to get rid of bgp_summaries for ixp_info entries */
	Delete_Publisher(flap_graph_publisher);
	Delete_Publisher(flap_table_daily_publisher);
}

void flapGraphAndTablePublisher_doFGUpdate() {
	schedule_event(schedule, flapGraphAndTablePublisher_FGUpdate, NULL);
}

void flapGraphAndTablePublisher_doFTDUpdate() {
	schedule_event(schedule, flapGraphAndTablePublisher_FTDUpdate, NULL);
}

/* there's a race possibility here. i haven't bothered to protect it with
	mutexes since the likelihood is soooooo low. (use_localtime should be
	protected.) */
void flapGraphAndTablePublisher_getLocaltimeFlag(void *ignored) {
	/* choice of FG instead of FTD is abitrary */
	config_add_output (PARAM_FG_TIMEFLAG " %d\r\n", use_localtime);
}

void flapGraphAndTablePublisher_setLocaltimeFlag(uii_connection_t *uii, int val)
{
	if ((val != 0) && (val != 1)) {
		uii_send_data (uii, "Specify 0 (for UTC) or 1 (for local time).\r\n");
		return;
	} else if (use_localtime != val) {
		use_localtime = val;
		uii_send_data (uii,
			"A reboot is recommended, as the cached data are probably invalid.\n");
	}
}

/* XXX fix races in get/set outtype */	

void flapGraphAndTablePublisher_setFGOutType(uii_connection_t *uii, char *mode) {
        publisher_t *new_publish; 
        LINKED_LIST *args;
        
        if (strcmp(mode, OUTTYPE_DISK)==0) {
                args = makeargs(PUBLISHER_CHANNEL_PREFIX, FLAP_GRAPH_CHANNEL, PUBLISHER_TRACE,
			tracer, NULL);
                new_publish = New_DiskPublisher(args);
                LL_Destroy(args);
        } else if (strcmp(mode, OUTTYPE_DOLPHIN)==0) {
                args = makeargs(PUBLISHER_CHANNEL_PREFIX, FLAP_GRAPH_CHANNEL, PUBLISHER_TRACE,
			tracer, NULL);
                new_publish = New_SalyPublisher(args);
                LL_Destroy(args);
        } else {
                uii_send_data (uii, "Unknown output type.\r\n");
                return;
        }
                
        if (flap_graph_publisher != NULL)
                Delete_Publisher(flap_graph_publisher);
        flap_graph_publisher = new_publish;
        free(fg_outtype);
        fg_outtype = strdup(mode);
} 

void flapGraphAndTablePublisher_getFGOutType(void *ignored) {
        config_add_output (PARAM_FG_OUTTYPE " %s\r\n", fg_outtype);
}

void flapGraphAndTablePublisher_setFTDOutType(uii_connection_t *uii, char *mode) {
        publisher_t *new_publish; 
        LINKED_LIST *args;
        
        if (strcmp(mode, OUTTYPE_DISK)==0) {
                args = makeargs(PUBLISHER_CHANNEL_PREFIX, FLAP_TABLE_DAILY_CHANNEL,
			PUBLISHER_TRACE, tracer, NULL);
                new_publish = New_DiskPublisher(args);
                LL_Destroy(args);
        } else if (strcmp(mode, OUTTYPE_DOLPHIN)==0) {
                args = makeargs(PUBLISHER_CHANNEL_PREFIX, FLAP_TABLE_DAILY_CHANNEL,
			PUBLISHER_TRACE, tracer, NULL);
                new_publish = New_SalyPublisher(args);
                LL_Destroy(args);
        } else {
                uii_send_data (uii, "Unknown output type.\r\n");
                return;
        }
                
        if (flap_table_daily_publisher != NULL)
                Delete_Publisher(flap_table_daily_publisher);
        flap_table_daily_publisher = new_publish;
        free(ftd_outtype);
        ftd_outtype = strdup(mode);
} 

void flapGraphAndTablePublisher_getFTDOutType(void *ignored) {
        config_add_output (PARAM_FTD_OUTTYPE " %s\r\n", ftd_outtype);
}


#ifdef GEN_OLD_FILES
/* this func doesnt bother being re-entrant and all that since
 * is only used to generate historic data. if used for anything
 * else, please make mktime thread safe.
 */
time_t 
get_date_from_str (char *indate) {
  time_t longtime;
  int mn, dt, yr;
  char in_date[100];
  char tmp_buf[6];
  int i, j;
  struct tm tmptm;


  longtime = 0;
  strcpy (in_date, indate);

  i = j = 0;

  /* get month */
  while (in_date[i] != '/') {
     tmp_buf [j++] = in_date[i++];
  }

  tmp_buf[j] = 0;
  mn = atoi (tmp_buf);

  /* get date */
  j = 0;
  i++; /* get past slash  */

  while (in_date[i] != '/') {
     tmp_buf [j++] = in_date[i++];
  }
  tmp_buf[j] = 0;
  dt = atoi (tmp_buf);

  /* get year */
  j = 0;
  i++; /* get past slash  */

  while (in_date[i] != 0 ) {
     tmp_buf [j++] = in_date[i++];
  }
  tmp_buf[j] = 0;
  yr = atoi (tmp_buf);

  tmptm.tm_sec = tmptm.tm_min = tmptm.tm_hour = 0;
  tmptm.tm_mday = dt;
  tmptm.tm_mon = mn - 1;
  tmptm.tm_year = yr - BASE_YEAR; 
  tmptm.tm_isdst = 0;

  longtime = mktime (&tmptm);
  return longtime;
}


void flapTableDaily_getStartDate (void *ignored) {
    config_add_output (PARAM_FTD_START_DATE " %u\r\n", ftd_start_time);
}

void flapTableDaily_setStartDate(uii_connection_t *uii, char *mode) {

   /* parse date */

   ftd_start_time = get_date_from_str (mode);
}

void flapTableDaily_getEndDate (void *ignored) {
    config_add_output (PARAM_FTD_START_DATE " %u\r\n", ftd_end_time);
}


void flapTableDaily_setEndDate(uii_connection_t *uii, char *mode) {

   /* parse date */

   ftd_end_time = get_date_from_str (mode) + ONE_DAY - 1;
}


void flapGraph_setStartDate(uii_connection_t *uii, char *mode) {

   /* parse date */

   fg_start_time = get_date_from_str (mode);
   /* current_end_time = current_start_time + ONE_DAY;*/
   trace (TR_TRACE, tracer, "fg start  time = %u\n", fg_start_time);
}


void flapGraph_getStartDate (void *ignored) {
    config_add_output (PARAM_FG_START_DATE " %u\r\n", fg_start_time);
}

void flapGraph_setEndDate(uii_connection_t *uii, char *mode) {

   /* parse date */

   fg_end_time = get_date_from_str (mode) + ONE_DAY - 1;
   trace (TR_TRACE, tracer, "fg end  time = %u\n", fg_end_time);
}


void flapGraph_getEndDate (void *ignored) {
    config_add_output (PARAM_FG_START_DATE " %u\r\n", fg_end_time);
}

#endif GEN_OLD_FILES
	
/* pseudo-private functions */

void flapGraphAndTablePublisher_mainloop() {
#if defined(_REENTRANT)
	init_mrt_thread_signals();

	while(1) {
		trace (TR_INFO, tracer,
			THREAD_NAME " waiting for new request...\n");
		schedule_wait_for_event(schedule);
		trace (TR_INFO, tracer, THREAD_NAME " finished request\n");
	}
#endif
}

LINKED_LIST* read_data() {
	LINKED_LIST *ixps;
	char *current_exchange;
	db_select_t match_exchange, match_time_start, match_time_end;
	LINKED_LIST *selectors;

	match_time_start.field = FIELD_TIME;
	match_time_start.operator = DB_OPERATOR_GREATER_EQ;
	match_time_end.field = FIELD_TIME;
	match_time_end.operator = DB_OPERATOR_LESS_EQ;
	match_exchange.field = FIELD_EXCHANGE;
	match_exchange.operator = DB_OPERATOR_EQUAL;

	ixps = bgp_db_avail(FIELD_EXCHANGE);
															if (ixps == NULL) goto error_noixp;

	selectors = makelistn(3, &match_exchange, &match_time_start,
		&match_time_end);
	LL_Iterate(ixps, current_exchange) {
		ixp_info_t *current_exchange_info;
/*		flapGraph_t *current_flapCounter; */
		time_t start_time, end_time;
#if defined(_REENTRANT)
		struct tm st, et;					/* kludge so we can use same code with */
#endif
		struct tm *stp, *etp;			/* or without threads */
/*
   it would be nice to print out the nicely formatted time, instead of the
   # of seconds since epoch. but (despite what the manpage says) cftime
   is NOT thread-safe on solaris 2.5.
*/
/*		char start_time_s[100], end_time_s[100]; */

		trace (TR_TRACE, tracer, "current exchange is %s\n",
			current_exchange);

		match_exchange.value = current_exchange;
		match_time_start.value = &start_time;
		match_time_end.value = &end_time;
		current_exchange_info = get_ixp_info(current_exchange);
		
		if (current_exchange_info == NULL) {
			trace (TR_ERROR, tracer, "Could not process %s\n",
				current_exchange);
			continue;
		}

		start_time = current_exchange_info -> update_from;

/* if the time call fails, we'll end up reading every single file next time
we run. that would be terrible! */
		end_time = time(0);

		if (use_localtime) {
#if defined(_REENTRANT)
			stp = localtime_r(&start_time, &st);
			etp = localtime_r(&end_time, &et);
#else
			stp = localtime(&start_time);
			etp = localtime(&end_time);
#endif
		} else {
#if defined(_REENTRANT)
			stp = gmtime_r(&start_time, &st);
			etp =gmtime_r(&end_time, &et);
#else
			stp = gmtime(&start_time);
			etp = gmtime(&end_time);
#endif
		}

/* XXX add DST check? */
		if (stp->tm_mday != etp->tm_mday) {
			/* Crossed midnight. Clear cache. */
			trace(TR_TRACE, tracer, "Crossed midnight. Clearing cache.\n");
			Delete_flapGraph(current_exchange_info -> flapCounter);

			start_time = get_midnight();

			current_exchange_info -> flapCounter = New_flapGraph(tracer,
				start_time);
		} else {
			/* Same day as last run. Clear out the overlapping data. */
			start_time -= 15 * 60;		/* re-read last file of last run */		
			flapGraph_clear(current_exchange_info->flapCounter, &start_time,
				&end_time);
		}

/*		current_flapCounter = current_exchange_info -> flapCounter; */
		current_exchange_info -> update_from = end_time;

/*
		cftime(start_time_s, TIME_FORMAT, &start_time);
		cftime(end_time_s, TIME_FORMAT, &end_time);
*/
		trace(TR_TRACE, tracer, "Examining %s from %u to %u\n",
			current_exchange, start_time, end_time);
		bgp_db_query(tracer, (bgp_db_callback_t) flapGraph_add,
			current_exchange_info -> flapCounter, selectors, io);
/* XXX find files that were modified since the last run, and process them too.
   don't forget to clear data first, though */
	}
/*	LL_Destroy(ixps); */

	LL_Destroy(selectors);		
	return ixps;
	
	error_noixp:
		return NULL;
}


#ifdef GEN_OLD_FILES
LINKED_LIST* read_old_data() {
    LINKED_LIST *ixps;
    char *current_exchange;
    db_select_t match_exchange, match_time_start, match_time_end;
    LINKED_LIST *selectors;
    time_t start_time=0, end_time=0;
    
    match_time_start.field = FIELD_TIME;
    match_time_start.operator = DB_OPERATOR_GREATER_EQ;
    match_time_end.field = FIELD_TIME;
    match_time_end.operator = DB_OPERATOR_LESS_EQ;
    match_exchange.field = FIELD_EXCHANGE;
    match_exchange.operator = DB_OPERATOR_EQUAL;
    
    ixps = bgp_db_avail(FIELD_EXCHANGE);
    if (ixps == NULL) goto error_noixp;
    
    selectors = makelistn(3, &match_exchange, &match_time_start,
			  &match_time_end);
    LL_Iterate(ixps, current_exchange) {
	ixp_info_t *current_exchange_info;

#if defined(_REENTRANT)
	struct tm st, et;					/* kludge so we can use same code with */
#endif
	struct tm *stp, *etp;			/* or without threads */
	/*
	  it would be nice to print out the nicely formatted time, instead of the
	  # of seconds since epoch. but (despite what the manpage says) cftime
	  is NOT thread-safe on solaris 2.5.
	*/
	
	trace (TR_TRACE, tracer, "current exchange is %s\n",
	       current_exchange);
	
	match_exchange.value = current_exchange;
	match_time_start.value = &start_time;
	match_time_end.value = &end_time;
	current_exchange_info = get_ixp_info(current_exchange);
	start_time = current_exchange_info -> update_from;  
		
	trace (TR_TRACE, tracer, "start time from get ixp info is %u\n",
	       start_time);
	/* if the time call fails, we'll end up reading every single file next time
	   we run. that would be terrible! */

	end_time = start_time + ONE_DAY - 1;
	
	if (current_exchange_info == NULL) {
	    trace (TR_ERROR, tracer, "Could not process %s\n",
		   current_exchange);
	    continue;
	}
	
	
	
	if (use_localtime) {
#if defined(_REENTRANT)
	    stp = localtime_r(&start_time, &st);
	    etp = localtime_r(&end_time, &et);
#else
	    stp = localtime(&start_time);
	    etp = localtime(&end_time);
#endif
	} else {
#if defined(_REENTRANT)
	    stp = gmtime_r(&start_time, &st);
	    etp =gmtime_r(&end_time, &et);
#else
	    stp = gmtime(&start_time);
	    etp = gmtime(&end_time);
#endif
	}
	
	/* XXX add DST check? */
	/* Crossed midnight. Clear cache. */
	trace(TR_TRACE, tracer, "Crossed midnight. Clearing cache.\n");
	Delete_flapGraph(current_exchange_info -> flapCounter);
	
	start_time = get_midnight_of_date(start_time);
	current_start_time = start_time;
	current_end_time = start_time + ONE_DAY -1;
	current_exchange_info -> flapCounter = New_flapGraph(tracer,
							     start_time);
        current_exchange_info -> update_from = end_time; 
	
	trace(TR_TRACE, tracer, "Examining %s from %u to %u\n",
	      current_exchange, start_time, end_time);
	bgp_db_query(tracer, (bgp_db_callback_t) flapGraph_add,
		     current_exchange_info -> flapCounter, selectors, io);
	/* XXX find files that were modified since the last run, and process them too.
	   don't forget to clear data first, though */
    }
    /*	LL_Destroy(ixps); */
    
    LL_Destroy(selectors);
    current_start_time = end_time + 1; /* take it to the next day */
    current_end_time = current_start_time + ONE_DAY;
    return ixps;
    
 error_noixp:
    return NULL;
}

void flapGraphAndTablePublisher_FGDump() {
    LINKED_LIST *ixp_list;
    char *current_exchange;
    
    if (flap_graph_publisher == NULL)
	goto error_nopublisher;
    
    current_start_time  = fg_start_time;
    current_end_time = 0;
    while (current_end_time <= (fg_end_time + 1)) {
	trace (TR_TRACE, tracer,
	       "FGDump: current_end_time = %u, fg_end_time = %u\n",
	       current_end_time, fg_end_time);

	ixp_list = read_old_data();
	if (ixp_list == NULL) goto error_noixp;
	
	LL_Iterate(ixp_list, current_exchange) {
	    ixp_info_t *current_exchange_info;
	    
	    current_exchange_info = get_ixp_info(current_exchange);
	    flapCounter_flapGraph_publish(current_exchange_info->flapCounter,
					  flap_graph_publisher, current_exchange);
	}
	LL_Destroy(ixp_list);
	
	publisher_channel_list_send(flap_graph_publisher);
	publisher_channel_list_clear(flap_graph_publisher);
    }
    return;
    
 error_nopublisher:
    trace(TR_WARN, tracer,
	  "FlapGraph skipped report because no publisher is specified.\n");
    return;	
 error_noixp:
    trace(TR_ERROR, tracer,
	  "FlapGraph could not publish because no IXPs are available.\n");
    return;
}

void flapGraphAndTablePublisher_FTDDump() {
    LINKED_LIST *ixp_list;
    char *current_exchange;
    
    if (flap_table_daily_publisher == NULL)
	goto error_nopublisher;

    current_start_time = ftd_start_time;
    current_end_time = 0;
    while (current_end_time <= (ftd_end_time + 1)) {
	ixp_list = read_old_data();
	if (ixp_list ==	NULL) 
	    goto error_noixp;
	
	LL_Iterate(ixp_list, current_exchange) {
	    ixp_info_t *current_exchange_info;
	    
	    current_exchange_info = get_ixp_info(current_exchange);
	    flapCounter_flapTableDaily_publish(current_exchange_info -> flapCounter,
					       flap_table_daily_publisher, current_exchange);
	}
	LL_Destroy(ixp_list);
	
	publisher_channel_list_send(flap_table_daily_publisher);
	publisher_channel_list_clear(flap_table_daily_publisher);
	
    }
    return;
    
 error_nopublisher:
    trace(TR_WARN, tracer,
	  "FlapTableDaily skipped report because no publisher is specified.\n");
    return;
 error_noixp:
    trace(TR_ERROR, tracer,
	  "FlapTableDaily could not publish because no IXPs are available.\n");
}


#endif GEN_OLD_FILES




void flapGraphAndTablePublisher_FGUpdate() {
	LINKED_LIST *ixp_list;
	char *current_exchange;

	if (flap_graph_publisher == NULL)
		goto error_nopublisher;

	ixp_list = read_data();
								if (ixp_list == NULL) goto error_noixp;

	LL_Iterate(ixp_list, current_exchange) {
		ixp_info_t *current_exchange_info;
																	
		current_exchange_info = get_ixp_info(current_exchange);
		flapCounter_flapGraph_publish(current_exchange_info->flapCounter,
			flap_graph_publisher, current_exchange);
	}
	LL_Destroy(ixp_list);

	publisher_channel_list_send(flap_graph_publisher);
	publisher_channel_list_clear(flap_graph_publisher);

	return;

        error_nopublisher:
                trace(TR_WARN, tracer,
                        "FlapGraph skipped report because no publisher is specified.\n");
                return;	
	error_noixp:
		trace(TR_ERROR, tracer,
			"FlapGraph could not publish because no IXPs are available.\n");
		return;
}

void flapGraphAndTablePublisher_FTDUpdate() {
	LINKED_LIST *ixp_list;
	char *current_exchange;
	
	if (flap_table_daily_publisher == NULL)
		goto error_nopublisher;

	ixp_list = read_data();
								if (ixp_list == NULL) goto error_noixp;

	LL_Iterate(ixp_list, current_exchange) {
		ixp_info_t *current_exchange_info;
		
		current_exchange_info = get_ixp_info(current_exchange);
		flapCounter_flapTableDaily_publish(current_exchange_info -> flapCounter,
			flap_table_daily_publisher, current_exchange);
	}
	LL_Destroy(ixp_list);

	publisher_channel_list_send(flap_table_daily_publisher);
	publisher_channel_list_clear(flap_table_daily_publisher);
	
	return;

        error_nopublisher:
                trace(TR_WARN, tracer,
                        "FlapTableDaily skipped report because no publisher is specified.\n");
                return;
	error_noixp:
		trace(TR_ERROR, tracer,
			"FlapTableDaily could not publish because no IXPs are available.\n");
}

/* private functions */

static ixp_info_t *get_ixp_info(char *ixp_name) {
	ixp_info_t *ret;

	ret = HASH_Lookup(ixp_info, ixp_name);
	if (ret != NULL) {
		return ret;
	} else {
		char *key;
		
		key = strdup(ixp_name);
															if (key == NULL) goto error_mem1;

		ret = malloc (sizeof(ixp_info_t));
															if (ret == NULL) goto error_mem2;
		ret -> name = key;
#ifdef GEN_OLD_FILES
	ret-> update_from = current_start_time;
	ret-> flapCounter =  New_flapGraph (tracer, get_midnight_of_date(current_start_time));		
#else
		ret -> update_from = get_midnight();
		ret -> flapCounter = New_flapGraph(tracer, get_midnight());
#endif GEN_OLD_FILES
															if (ret->flapCounter == NULL)
																goto error_mem3;
		HASH_Insert(ixp_info, ret);
		return ret;

		/* if error, deallocate all successfully allocated memory, and log */
		error_mem3:
			free (ret);
		error_mem2:
			free (key);
		error_mem1:
			trace(TR_ERROR, tracer, "Could not allocate new ixp_info\n");
			perror("get_ixp_info");
			return NULL;
	}
}

/* figure out midnight of today and express it in unix time */
static time_t get_midnight() {
#if defined(_REENTRANT)
	struct tm todays;					/* kludge so we can use same code with */
#endif
	struct tm *todayp;				/* thread and non-thread */
	time_t now, midnight_as_utc, tz_offset;

	now = time(0);
	if (now == -1) {
		trace(TR_ERROR, tracer,
			"Couldn't get current time! Ignoring report request.\n");
		perror("get_midnight");
		return -1;	/* is this really what we want? */
	}

	/* mktime assumes the time you're converting *from* is in local timezone.
	   so if the output isn't supposed to be localtime, then we figure out
		the difference between local and UTC, and doctor the output of mktime.
		is there a better way? --mukesh */
	if (!use_localtime)
		tz_offset = get_tz_offset();
	 else 
		tz_offset = 0;

	/* this is probably confusing, but i think it works. --mukesh */
	now += tz_offset;
#if defined(_REENTRANT)
	todayp = localtime_r(&now, &todays);
#else
	todayp = localtime(&now);
#endif
	
	todayp->tm_hour = 0; todayp->tm_min = 0; todayp->tm_sec = 0;
		todayp->tm_isdst = -1;
	midnight_as_utc = mktime_r(todayp);
	return midnight_as_utc-tz_offset;
}


/* figure out midnight of today and express it in unix time */
time_t get_midnight_of_date(time_t notnow) {
#if defined(_REENTRANT)
    struct tm todays;					/* kludge so we can use same code with */
#endif
    struct tm *todayp;				/* thread and non-thread */
    time_t midnight_as_utc, tz_offset;
    
    /* now = time(0); */
    if (notnow == -1) {
	trace(TR_ERROR, tracer,
	      "Couldn't get current time! Ignoring report request.\n");
	perror("get_midnight");
	return -1;	/* is this really what we want? */
    }
    
    /* mktime assumes the time you're converting *from* is in local timezone.
       so if the output isn't supposed to be localtime, then we figure out
       the difference between local and UTC, and doctor the output of mktime.
       is there a better way? --mukesh */
    if (!use_localtime)
	tz_offset = get_tz_offset();
    else 
	tz_offset = 0;
    
    /* this is probably confusing, but i think it works. --mukesh */
    notnow += tz_offset;
#if defined(_REENTRANT)
    todayp = localtime_r(&notnow, &todays);
#else
    todayp = localtime(&notnow);
#endif
    
    todayp->tm_hour = 0; todayp->tm_min = 0; todayp->tm_sec = 0;
    todayp->tm_isdst = -1;
    midnight_as_utc = mktime_r(todayp);
    return midnight_as_utc-tz_offset;
}


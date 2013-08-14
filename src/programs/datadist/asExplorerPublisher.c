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

#include "asExplorerPublisher.h"
#include "publisher.h"
#include "salypublisher.h"
#include "diskpublisher.h"
#include "db.h"
#include "bgp_db.h"
#include "flapSourcer.h"
#include "util.h"
#ifdef GEN_OLD_FILES
#include "gen_old_files.h"
#endif

#define OUTTYPE_DISK		"files"
#define OUTTYPE_DOLPHIN		"dolphin"

#define MODULE_NAME						"ASExplorer"
#define CHANNEL							"ASExplorer"
#define SCHEDULE_NAME					MODULE_NAME " Publisher"
#define THREAD_NAME						MODULE_NAME " Publisher"
#define FIELD_EXCHANGE					BGP_DB_FIELD_EXCHANGE
#define FIELD_TIME						BGP_DB_FIELD_TIME
#define DEFAULT_DURATION				(75*60)
#define DEFAULT_OUTTYPE			OUTTYPE_DISK

#define NUM_BUCKETS 10

typedef struct {
	char *dir_name;
	char *probe_name;
} probe_info_t;

/* imported from driver.c */
extern char *appname;

/* make instance variables? */
static schedule_t *schedule = NULL;
static trace_t *tracer;
static io_t *io;
static publisher_t *asE_publish = NULL;
static int duration = DEFAULT_DURATION; /*-1;*/
static HASH_TABLE *probe_info = NULL;
/* XXX free on terminate!! */
static char *outtype = NULL;

#ifdef GEN_OLD_FILES
time_t ase_start_time, ase_end_time;
static time_t current_start_time, current_end_time;
void asExplorerPublisher_Dump();
#endif GEN_OLD_FILES

/* callbacks */
void asExplorerPublisher_mainloop();
void asExplorerPublisher_publish();

void probeDelete(probe_info_t *node_data) {
	free(node_data->dir_name);
	free(node_data->probe_name);
}

void init_asExplorerPublisher(trace_t *t) {
	probe_info_t sample;
/*LINKED_LIST *a;*/

	if (schedule != NULL)
		return;

	tracer = t;
	io = New_IO(tracer);

	probe_info = HASH_Create(NUM_BUCKETS, HASH_EmbeddedKey, False, HASH_KeyOffset,
		HASH_Offset(&sample, &sample.dir_name), HASH_DestroyFunction, probeDelete,
		NULL);
	outtype = strdup(DEFAULT_OUTTYPE);

	schedule = New_Schedule (SCHEDULE_NAME, NULL);
	mrt_thread_create (THREAD_NAME, schedule,
		(void *) asExplorerPublisher_mainloop, NULL);
}

void terminate_asExplorerPublisher() {
	Delete_Publisher(asE_publish);
}

void asExplorerPublisher_doUpdate() {
	schedule_event(schedule, asExplorerPublisher_publish, NULL);
}

/*
   these functions operate asynchronously of update events, and need
   to be made thread-safe. (although the set name and port functions are
   also asynch, publisher is thread-safe.) 
*/



void asExplorerPublisher_setOutType(uii_connection_t *uii, char *mode) {
	publisher_t *new_publish;
	LINKED_LIST *args;

	if (strcmp(mode, OUTTYPE_DISK)==0) {
		args = makeargs(PUBLISHER_CHANNEL_PREFIX, CHANNEL, PUBLISHER_TRACE, tracer, NULL);
		new_publish = New_DiskPublisher(args);
		LL_Destroy(args);
	} else if (strcmp(mode, OUTTYPE_DOLPHIN)==0) {
		args = makeargs(PUBLISHER_CHANNEL_PREFIX, CHANNEL, PUBLISHER_TRACE, tracer, NULL);
		new_publish = New_SalyPublisher(args);
		LL_Destroy(args);
	} else {
		uii_send_data (uii, "Unknown output type.\r\n");
		return;
	}

	if (asE_publish != NULL)
		Delete_Publisher(asE_publish);
	asE_publish = new_publish;
	free(outtype);
	outtype = strdup(mode);
}

void asExplorerPublisher_getOutType(void *ignored) {
	config_add_output (PARAM_ASE_OUTTYPE " %s\r\n", outtype);
}

void asExplorerPublisher_getDuration(void *ignored) {
	config_add_output (PARAM_ASE_DURATION " %d\r\n", duration);
}

void asExplorerPublisher_setDuration(uii_connection_t *uii, int new_duration) {
	if (new_duration <= 0) {
		uii_send_data (uii, "Duration must be greater than zero.\r\n");
		return;
	}

	duration = new_duration;
}

void asExplorerPublisher_setProbeName(uii_connection_t *uii, char *dir_name,
char *probe_name) {
	probe_info_t *p;

	if (probe_info == NULL) {
		trace (TR_ERROR, tracer,
			"Configuring asExplorerPublisher before initialization!\n");
		return;
	}

	p = HASH_Lookup(probe_info, dir_name);
	if (p == NULL) {
/* check for NULLs */
		p = malloc(sizeof(probe_info_t));
		p->dir_name = strdup(dir_name);
		p->probe_name = strdup(probe_name);
		HASH_Insert(probe_info, p);
	} else {
		free (p->probe_name);
		p->probe_name = strdup(probe_name);
	}

	config_add_module(0, PARAM_ASE_PNAME, asExplorerPublisher_getProbeName,
		dir_name);
}

void asExplorerPublisher_getProbeName(char *dir_name) {
	probe_info_t *p;

	if (probe_info == NULL)
		return;
			
	p = HASH_Lookup(probe_info, dir_name);
	if (p == NULL)
		trace(TR_WARN, tracer, "Lookup of probe name for %s failed\n", dir_name);
	else
		config_add_output (PARAM_ASE_PNAME " %s %s\r\n", dir_name, p->probe_name);
}

#ifdef GEN_OLD_FILES
void asExplorer_setStartDate(uii_connection_t *uii, char *mode) {

   /* parse date */

   ase_start_time = get_date_from_str (mode);
   current_start_time  = ase_start_time;
}

void asExplorer_getStartDate (void *ignored) {
    config_add_output (PARAM_ASE_START_DATE " %u\r\n", ase_start_time);
}

void asExplorer_setEndDate(uii_connection_t *uii, char *mode) {

   /* parse date */

   ase_end_time = get_date_from_str (mode) + ONE_DAY -1;
}


void asExplorer_getEndDate (void *ignored) {
    config_add_output (PARAM_ASE_START_DATE " %u\r\n", ase_end_time);
}

#endif GEN_OLD_FILES


void asExplorerPublisher_mainloop() {
#if defined(_REENTRANT)
	init_mrt_thread_signals();
	
	while(1) {
		trace (TR_INFO, tracer, THREAD_NAME
			" waiting for new request...\n");
		schedule_wait_for_event(schedule);
		trace (TR_INFO, tracer, THREAD_NAME " finished request\n");
	}
#endif
}

void asExplorerPublisher_publish() {
	time_t start, end;
	LINKED_LIST *selectors, *ixps;
	flapSourcer_t *asExplorerData;
	db_select_t match_exchange, match_time_start, match_time_end;
	char *current_exchange;

	if (asE_publish == NULL)
		goto error_nopublisher;
	
	end = time(0);
	start = end - duration;
	match_time_start.field = match_time_end.field = FIELD_TIME;
	match_time_start.operator = DB_OPERATOR_GREATER_EQ;
	match_time_end.operator = DB_OPERATOR_LESS_EQ;
	match_exchange.field = FIELD_EXCHANGE;
	match_exchange.operator = DB_OPERATOR_EQUAL;
	
	match_time_start.value = &start;
	match_time_end.value = &end;

	ixps = bgp_db_avail(FIELD_EXCHANGE);
															if (ixps == NULL) goto error_noixp;
															
	selectors = makelistn(3, &match_exchange, &match_time_start,
		&match_time_end);

	LL_Iterate(ixps, current_exchange) {
		probe_info_t *pinfo;
		char *listener_name;
		
		pinfo = HASH_Lookup(probe_info, current_exchange);
		if (pinfo == NULL)
			listener_name = current_exchange;
		else
			listener_name = pinfo->probe_name;
		
		match_exchange.value = current_exchange;
		asExplorerData = New_flapSourcer(tracer, start, end);
		bgp_db_query(tracer, (bgp_db_callback_t)flapSourcer_add, asExplorerData,
			selectors, io);
		flapSourcer_publish(asExplorerData, asE_publish, listener_name);
/*		free(listener_name); */
		Delete_flapSourcer(asExplorerData);
	}
	LL_Destroy(ixps);
	LL_Destroy(selectors);		

	publisher_channel_list_send(asE_publish);
	publisher_channel_list_clear(asE_publish);

	return;

	error_nopublisher:
		trace(TR_WARN, tracer,
			"ASExplorer skipped report because no publisher is specified.\n");
		return;
	error_noixp:
		trace(TR_ERROR, tracer,
			"Could not publish ASExplorer because no IXPs are available.\n");
		return;
		
}


#ifdef GEN_OLD_FILES
void asExplorerPublisher_Dump() {
    time_t start, end;
    LINKED_LIST *selectors, *ixps;
    flapSourcer_t *asExplorerData;
    db_select_t match_exchange, match_time_start, match_time_end;
    char *current_exchange;
    
    if (asE_publish == NULL)
	goto error_nopublisher;
    
    start = current_start_time;
    end = start + ONE_DAY;
    match_time_start.field = match_time_end.field = FIELD_TIME;
    match_time_start.operator = DB_OPERATOR_GREATER_EQ;
    match_time_end.operator = DB_OPERATOR_LESS_EQ;
    match_exchange.field = FIELD_EXCHANGE;
    match_exchange.operator = DB_OPERATOR_EQUAL;
    
    match_time_start.value = &start;
    match_time_end.value = &end;
    
    ixps = bgp_db_avail(FIELD_EXCHANGE);
    if (ixps == NULL) goto error_noixp;
    
    current_end_time = 0;
    while (current_end_time <= (ase_end_time + 1)) {
        selectors = makelistn(3, &match_exchange, &match_time_start,
			  &match_time_end);
	LL_Iterate(ixps, current_exchange) {
	    probe_info_t *pinfo;
	    char *listener_name;
	    
	    pinfo = HASH_Lookup(probe_info, current_exchange);
	    if (pinfo == NULL)
		listener_name = current_exchange;
	    else
		listener_name = pinfo->probe_name;
	    
	    match_exchange.value = current_exchange;
	    asExplorerData = New_flapSourcer(tracer, start, end);
	    bgp_db_query(tracer, (bgp_db_callback_t)flapSourcer_add, 
			 asExplorerData,
			 selectors, io);
	    flapSourcer_publish(asExplorerData, asE_publish, listener_name);
	    Delete_flapSourcer(asExplorerData);
	}
	LL_Destroy(selectors);		
    
	start = current_start_time = end ;
	end = current_end_time = current_start_time + ONE_DAY;
       
	publisher_channel_list_send(asE_publish);
	publisher_channel_list_clear(asE_publish);
    }
    LL_Destroy(ixps); 
    return;
    
 error_nopublisher:
    trace(TR_WARN, tracer,
	  "ASExplorer skipped report because no publisher is specified.\n");
    return;
 error_noixp:
    trace(TR_ERROR, tracer,
	  "Could not publish ASExplorer because no IXPs are available.\n");
    return;
    
}

#endif GEN_OLD_FILES

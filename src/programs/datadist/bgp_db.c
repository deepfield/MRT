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

#include <linked_list.h>
/*#include <sys/varargs.h>*/
#include <config_file.h>
#include <dirent.h>

#include "db.h"
#include "bgp_db.h"
#include "util.h"
#include "mytime.h"

#define DEFAULT_DB_PATH				"/"
#define BGP_FILES_PATTERN			"^bgp\.[^r]*[^z]$"
/*
   the ^r is to keep out the bgp.routes files in 6bone. the *^z is to keep
   out the compressed files
*/
#define DEFAULT_TIME_RANGE	 		(15 /*minutes*/ * 60 /*sec/min*/ - 1) 

#define NUM_IXP_BUCKETS 			10
#define DEFAULT_DIR_CACHE_TIME 	(5 /* minutes */ * 60 /*sec/min*/)

#define SET_WRITE_LOCK(x) \
{ \
trace(TR_TRACE, CONFIG.trace, "--| write lockout (swl) %s @ %d\n", x->ixp_name, __LINE__); \
pthread_mutex_lock(&(x->write_lockout)); \
trace(TR_TRACE, CONFIG.trace, "--> write lockout (swl) %s @ %d\n", x->ixp_name, __LINE__); \
}

#define CLEAR_WRITE_LOCK(x) \
{ \
pthread_mutex_unlock(&(x->write_lockout));\
trace(TR_TRACE, CONFIG.trace, "<-- write lockout (cwl) %s @ %d\n", x->ixp_name, __LINE__); \
}

#define SET_READ_LOCK(x) {																	\
trace(TR_TRACE, CONFIG.trace, "--| counter lock (srl) %s @ %d\n", x->ixp_name, __LINE__); \
		pthread_mutex_lock(&(x->counter_lock));										\
trace(TR_TRACE, CONFIG.trace, "--> counter lock (srl) %s @ %d\n", x->ixp_name, __LINE__); \
		x->readers_counter++;																\
		if (x->readers_counter == 1)														\
{ \
trace(TR_TRACE, CONFIG.trace, "--| write lockout (srl) %s @ %d\n", x->ixp_name, __LINE__); \
			pthread_mutex_lock(&(x->write_lockout));									\
trace(TR_TRACE, CONFIG.trace, "--> write lockout (srl) %s @ %d\n", x->ixp_name, __LINE__); \
} \
		pthread_mutex_unlock(&(x->counter_lock));										\
trace(TR_TRACE, CONFIG.trace, "<-- counter lock (srl) %s @ %d\n", x->ixp_name, __LINE__); \
	}
	
#define CLEAR_READ_LOCK(x) {																\
trace(TR_TRACE, CONFIG.trace, "--| counter lock (crl) %s @ %d\n", x->ixp_name, __LINE__); \
		pthread_mutex_lock(&(x->counter_lock));										\
trace(TR_TRACE, CONFIG.trace, "--> counter_lock (crl) %s @ %d\n", x->ixp_name, __LINE__); \
		x->readers_counter--;																\
		if (x->readers_counter == 0)														\
{ \
			pthread_mutex_unlock(&(x->write_lockout));								\
trace(TR_TRACE, CONFIG.trace, "<-- write lockout (crl) %s @ %d\n", x->ixp_name, __LINE__); \
} \
		pthread_mutex_unlock(&(x->counter_lock));										\
trace(TR_TRACE, CONFIG.trace, "<-- counter lock (crl) %s @ %d\n", x->ixp_name, __LINE__); \
	}

typedef struct {
	LINKED_LIST *file_list;
	time_t last_read;
/*	pthread_mutex_t lock; */
	pthread_mutex_t counter_lock, write_lockout;
	int readers_counter;
	char *ixp_name;
} ixp_files_t;

/* global variables that are defined elsewhere */
extern config_t CONFIG;		/* XXX pass trace in somehow instead? */
extern pthread_mutex_t io_lock;

/* module variables */
/* threading implications for these variables? */
static char db_path[MAXPATHLEN+1] = DEFAULT_DB_PATH;
static int file_span = DEFAULT_TIME_RANGE;
static int dir_cache_freshness_time = DEFAULT_DIR_CACHE_TIME;
static int use_localtime = 1;
/* ixp list cache */
static pthread_mutex_t ixp_list_lock = PTHREAD_MUTEX_INITIALIZER;
static time_t ixps_last_read = 0;		/* a long time ago */
static LINKED_LIST *ixp_list = NULL;	/* need LINKED_LIST release strategy */
/* file list caches */
static HASH_TABLE *file_lists = NULL;  /* need HASH_TABLE release strategy */
static pthread_mutex_t hash_lock = PTHREAD_MUTEX_INITIALIZER;

/* prototypes for private functions */
static int valid_query(LINKED_LIST *query, LINKED_LIST *date_rules,
	LINKED_LIST *exchange_rules);
#if 0		/* to be written later, perhaps */
static void reread_ixps();
static void reread_file_lists();
#endif
static LINKED_LIST *get_ixps();
/*static LINKED_LIST *get_files(char *ixp);*/
static ixp_files_t *get_files(char *ixp);
static int match_ixp(char *ixpname, LINKED_LIST *match_criteria);
static int match_time_file(char *filename, LINKED_LIST *date_criteria);
static int match_time_message(time_t message_time, LINKED_LIST *date_criteria);
static time_t get_time(char *file);
static int process_file(io_t *io_port, char *pathname, trace_t *tracer,
	LINKED_LIST *match_criteria, bgp_db_callback_t func, void *func_state);
static int parsename(char *name, int *yr, int *mon, int *day, int *hr,
	int *min);

/* callbacks */
void bgp_db_ixpinfo_delete(ixp_files_t *node) {
	free(node->ixp_name);
	LL_Destroy(node->file_list);
	free(node);
}

/* public */
LINKED_LIST *bgp_db_avail(db_field_t field) {
	if (strcmp(field, DB_SEARCHABLE_FIELDS)==0) {
		return makelistn(2, BGP_DB_FIELD_TIME, BGP_DB_FIELD_TIME);
	} else if (strcmp(field, BGP_DB_FIELD_TIME)==0) {
/* list available dates, not yet implemented */
return NULL;
	} else if (strcmp(field, BGP_DB_FIELD_EXCHANGE)==0) {
		return get_ixps();
	} else {
fprintf(stderr, "%s is not a searchable field\n", field);
		return NULL;
	}
}

/* caller must not destroy memory for attribute names or values before we return */
void bgp_db_query(trace_t *tracer, void(func)(void *state, void *data),
void *pf_state, LINKED_LIST *match_criteria, io_t *io_port) {
	LINKED_LIST *date_criteria, *exchange_criteria, *ixps;
	char *current_ixp;
	
	date_criteria = LL_Create(0);
	exchange_criteria = LL_Create(0);
	if (!valid_query(match_criteria, date_criteria, exchange_criteria))
		goto error_badquery;
	
	ixps = get_ixps();
															if (ixps == NULL) goto error_noixp;

	LL_Iterate(ixps, current_ixp) {
		if (match_ixp (current_ixp, exchange_criteria)) {
			char *current_file;
			ixp_files_t *files;

			files = get_files(current_ixp);
			SET_READ_LOCK(files);
			
			if (files->file_list != NULL) {
				LL_Iterate(files->file_list, current_file) {
					trace (TR_DEBUG, tracer, "Checking %s\n", current_file); 
					if (match_time_file (current_file, date_criteria)) {
						char filepath[MAXPATHLEN+1];

/* XXX use snprintf instead of sprintf (buffer overrun) */
/* XXX should isolate this from changes in db_path. */
						sprintf (filepath, "%s/%s/%s", db_path, current_ixp,
							current_file);
						trace (TR_INFO, tracer, "Processing file: %s\n",
							filepath);
						process_file(io_port, filepath, tracer, date_criteria, func,
							pf_state);
					}
				}
/*				LL_Destroy(files); */
			} else {
				trace (TR_WARN, tracer, "No data files for ixp %s\n",
					current_ixp);
			}
			CLEAR_READ_LOCK(files);
		}
	}

	LL_Destroy(ixps);
	LL_Destroy(date_criteria);
	LL_Destroy(exchange_criteria);
	return;
		
	error_badquery:
		trace(TR_WARN, tracer, "Ignoring a bad query.\n");
		LL_Destroy(date_criteria);
		LL_Destroy(exchange_criteria);
		return;
		
	error_noixp:
		trace(TR_ERROR, tracer,
			"Query aborted because no IXPs were found.\n");
		LL_Destroy(date_criteria);
		LL_Destroy(exchange_criteria);
		return;
}

#if 0
void bgp_db_refresh() {
	reread_ixps();
	reread_file_lists();
}
#endif

/* XXX not thread-safe */
void bgp_db_set_db_path(uii_connection_t *uii, char *new_path) {
	DIR *d;
	
	if (strlen(new_path) > MAXPATHLEN) {
		uii_send_data (uii, "The specifed path is too long.\n");
		free(new_path);
		return;
	}
	
	/* some might consider this a security risk... revealing information
		about the directory structure */
	d = opendir(new_path);
	if (d==NULL) {
		uii_send_data (uii, "Could not open specified path.\n");
		trace(TR_WARN, CONFIG.trace,
			"Could not set database path to %s because it could not be opened.\n",
			new_path);
		perror("set_db_path");
		free(new_path);
		return;
	}
	
	closedir(d);
/* XXX can probably avoid the copy */
	strncpy(db_path, new_path, MAXPATHLEN+1);
	free(new_path);
}

void bgp_db_set_file_span(uii_connection_t *uii, int fspan) {
	if (fspan <= 0) {
		uii_send_data (uii, "File span must be greater than 0.\n");
		return;
	}
	
	file_span = fspan;
}

void bgp_db_set_dir_cache_time(uii_connection_t *uii, int t) {
	if (t < 0) {
		uii_send_data (uii, "Directory cache time must be >= 0.\n");
		return;
	}
	
	dir_cache_freshness_time = t;
}

void bgp_db_setLocaltimeFlag(uii_connection_t *uii, int val)
{
	if ((val != 0) && (val != 1)) {
		uii_send_data (uii, "Specify 0 (for UTC) or 1 (for local time).\r\n");
		return;
	} else if (use_localtime != val) {
		use_localtime = val;
		uii_send_data (uii,
			"If you are publishing FlapGraph or FlapTableDaily a reboot is "
			"recommended, as the cache for these channels are probably invalid.\n")
			;
	}
}

void bgp_db_get_db_path(void *ignored) {
	config_add_output(PARAM_BGPDB_PATH " %s\r\n", db_path);
}

void bgp_db_get_file_span(void *ignored) {
	config_add_output(PARAM_BGPDB_FILE_SPAN " %d\r\n", file_span);
}

void bgp_db_get_dir_cache_time(void *ignored) {
	config_add_output(PARAM_BGPDB_DCACHE_TIME " %d\r\n",
		dir_cache_freshness_time);
}

void bgp_db_getLocaltimeFlag(void *ignored) {
	config_add_output (PARAM_BGPDB_FTIME_FLAG " %d\r\n", use_localtime);
}

/* "private" functions */
static int valid_query(LINKED_LIST *query, LINKED_LIST *date_rules,
LINKED_LIST *exchange_rules) {
	db_select_t *selector;
	int valid = TRUE;

	LL_Iterate(query, selector) {	
		if (strcmp(BGP_DB_FIELD_TIME, selector->field) == 0) {
			switch (selector -> operator) {
				case DB_OPERATOR_EQUAL:
				case DB_OPERATOR_GREATER:
				case DB_OPERATOR_GREATER_EQ:
				case DB_OPERATOR_LESS:
				case DB_OPERATOR_LESS_EQ:
				case DB_OPERATOR_NOT_EQUAL:
					LL_Add(date_rules, selector);
					break;
				default:
					/* anything else is an unsupported operator. error. */
printf ("invalid operator for date field\n");
					valid = FALSE;
			}
		} else if (strcmp(BGP_DB_FIELD_EXCHANGE, selector->field) == 0) {
			switch (selector -> operator) {
				case DB_OPERATOR_EQUAL:
				case DB_OPERATOR_NOT_EQUAL:
					LL_Add(exchange_rules, selector);
					break;
				default:
					/* anything else is unsupported */
printf ("invalid operator for exchange field\n");
					valid = FALSE;	
			}
		} else {
printf ("invalid field for match: %s\n", selector->field);
			valid = FALSE;
		}
	}

	return valid;
}

/* copying is fine for ixp list, because it is small. but file lists are
   large, and copying takes a long time */
static LINKED_LIST *get_ixps() {
	LINKED_LIST *copy;

trace(TR_TRACE, CONFIG.trace, "--| ixp_list_lock\n");	
	pthread_mutex_lock(&ixp_list_lock);
trace(TR_TRACE, CONFIG.trace, "--> ixp_list_lock\n");
#ifndef GEN_OLD_FILES
	if (time(0) - ixps_last_read > dir_cache_freshness_time) {
#endif GEN_OLD_FILES
		if (ixp_list != NULL) LL_Destroy(ixp_list);
#ifndef GEN_OLD_FILES
		ixps_last_read = time(0);
#endif GEN_OLD_FILES
		ixp_list = get_files_match(db_path, NULL, FALSE);
#ifndef GEN_OLD_FILES
	}
#endif

	copy = copy_file_list(ixp_list);
	pthread_mutex_unlock(&ixp_list_lock);
trace(TR_TRACE, CONFIG.trace, "<-- ixp_list_lock\n");
	return copy;
}

#if 0
static void reread_ixps() {
	pthread_mutex_lock(&ixp_list_lock);
	if (ixp_list != NULL)
		LL_Destroy(ixp_list);
		ixps_last_read = time(0);
		ixp_list = get_files_match(db_path, NULL, FALSE);
	pthread_mutex_unlock(&ixp_list_lock);
}
#endif

/* i think the next three are safe from deadlocks, but haven't analyzed it
   deeply */

static ixp_files_t *get_file_struct (char *ixpname) {
	ixp_files_t *ixpinfo;
	
trace(TR_TRACE, CONFIG.trace, "--| hash_lock\n");
	pthread_mutex_lock(&hash_lock);
trace(TR_TRACE, CONFIG.trace, "--> hash_lock\n");
	if (file_lists == NULL) {
		ixp_files_t sample;
		
		file_lists = HASH_Create(NUM_IXP_BUCKETS, HASH_EmbeddedKey, False,
			HASH_KeyOffset, HASH_Offset(&sample, &sample.ixp_name),
			HASH_DestroyFunction, bgp_db_ixpinfo_delete, NULL);
	}

	ixpinfo = HASH_Lookup(file_lists, ixpname);
	if (ixpinfo == NULL) {
		ixpinfo = malloc(sizeof(ixp_files_t));
/* if malloc fails? */
		ixpinfo -> ixp_name = strdup(ixpname);
/* check for NULL pointer */
		ixpinfo -> file_list = NULL;
		ixpinfo -> last_read = 0;	/* a long time ago */
/*		pthread_mutex_init(&(ixpinfo->lock), NULL); */
ixpinfo->readers_counter = 0;
pthread_mutex_init(&(ixpinfo->counter_lock), NULL);
pthread_mutex_init(&(ixpinfo->write_lockout), NULL);
/* should check return value */
		HASH_Insert(file_lists, ixpinfo);
	}

	pthread_mutex_unlock(&hash_lock);	
trace(TR_TRACE, CONFIG.trace, "<-- hash_lock\n");
	return ixpinfo;
}

/*static LINKED_LIST *get_files(char *ixp) {*/
static ixp_files_t *get_files(char *ixp) {
	char path[MAXPATHLEN+1];
	ixp_files_t *ixpinfo;

	ixpinfo = get_file_struct(ixp);
#if 0
trace(TR_TRACE, CONFIG.trace, "--| %s->lock\n", ixp);
	pthread_mutex_lock(&(ixpinfo->lock));
trace(TR_TRACE, CONFIG.trace, "--> %s->lock\n", ixp);
#endif
#ifndef GEN_OLD_FILES
	SET_READ_LOCK(ixpinfo);
	if (time(0) - ixpinfo->last_read > dir_cache_freshness_time) {
		CLEAR_READ_LOCK(ixpinfo);
#endif GEN_OLD_FILES
		SET_WRITE_LOCK(ixpinfo);
		if (ixpinfo->file_list != NULL)
			LL_Destroy(ixpinfo->file_list);
#ifndef GEN_OLD_FILES
		ixpinfo->last_read = time(0);
#endif GEN_OLD_FILES
/* XXX use snprintf instead of sprintf  */
		sprintf(path, "%s/%s", db_path, ixp);
		ixpinfo->file_list = get_files_match(path, BGP_FILES_PATTERN, FALSE);
		CLEAR_WRITE_LOCK(ixpinfo);
#ifndef GEN_OLD_FILES
	} else {
		CLEAR_READ_LOCK(ixpinfo);
}
#endif GEN_OLD_FILES

#if 0
	if (ixpinfo->file_list != NULL)
		copy = copy_file_list(ixpinfo->file_list);
	else
		copy = NULL;

	pthread_mutex_unlock(&(ixpinfo->lock));
trace (TR_TRACE, CONFIG.trace, "<-- %s->lock\n", ixp);
	return copy;
#endif
	return ixpinfo;
}

#if 0
static void reread_file_lists() {
	ixp_files_t *cur_file_list;
	
	/* the function is reread. not read! */
	if (file_lists == NULL) return;
	
	pthread_mutex_lock(&hash_lock);
	HASH_Iterate(file_lists, cur_file_list) {
		char path[MAXPATHLEN+1];
		
SET_WRITE_LOCK(cur_file_list->lock);
		if (cur_file_list->file_list != NULL)
			LL_Destroy(cur_file_list->file_list);
		cur_file_list->last_read = time(0);
/* XXX use snprintf instead of sprintf  */
		sprintf(path, "%s/%s", db_path, cur_file_list->ixp_name);
		cur_file_list->file_list = get_files_match(path, BGP_FILES_PATTERN,
			FALSE);
CLEAR_WRITE_LOCK(cur_file_list->lock);
	}
	pthread_mutex_unlock(&hash_lock);
}
#endif

/* assuming that the field for each rule really does say exchange */
/* **implied conjunction ** */
static int match_ixp(char *ixpname, LINKED_LIST *match_criteria) {
	db_select_t *current_rule;
	
	LL_Iterate(match_criteria, current_rule) {
		if (current_rule -> operator == DB_OPERATOR_EQUAL) {
			if (strcmp(current_rule -> value, ixpname) != 0)
				return FALSE;
		} else if (current_rule -> operator == DB_OPERATOR_NOT_EQUAL) {
			if (strcmp(current_rule -> value, ixpname) == 0)
				return FALSE;
		} else {
fprintf(stderr, "invalid operator in match_ixp!\n");
return FALSE;
		}
	}

	return TRUE;
}

/* assuming that the field for each rule really does say date */
/* for now, assume filenames are in local time */
/* **implied conjunction** */
static int match_time_file(char *filename, LINKED_LIST *date_criteria) {
	db_select_t *current_rule;
	time_t file_start, file_end;

	file_start = get_time(filename);
	file_end = file_start + file_span;


	trace(TR_TRACE, CONFIG.trace, "file is %s, start is %d, end is %d\n",
		filename, file_start, file_end);

	LL_Iterate(date_criteria, current_rule) {
		time_t match_time;

		match_time = * (time_t *) (current_rule->value);
trace(TR_TRACE, CONFIG.trace, "query is %u\n", match_time);
		if (current_rule -> operator == DB_OPERATOR_EQUAL) {
			if (file_start > match_time)
				return FALSE;
			if (file_end < match_time)
				return FALSE;

/*
			trace (TR_DEBUG, CONFIG.trace, "matched %d, operator =\n", match_time);
*/
		} else if (current_rule -> operator == DB_OPERATOR_GREATER) {
			if (file_end <= match_time)
				return FALSE;

/*
			trace (TR_DEBUG, CONFIG.trace, "matched %d, operator >\n", match_time);
*/
		} else if (current_rule -> operator == DB_OPERATOR_GREATER_EQ) {
			if (file_end < match_time)
				return FALSE;
				
/*
			trace (TR_DEBUG, CONFIG.trace, "matched %d, operator >=\n",
				match_time);
*/
		} else if (current_rule -> operator == DB_OPERATOR_LESS) {
			if (file_start >= match_time)
				return FALSE;

/*
			trace (TR_DEBUG, CONFIG.trace, "matched %d, operator <\n", match_time);
*/
		} else if (current_rule -> operator == DB_OPERATOR_LESS_EQ) {
			if (file_start > match_time)
				return FALSE;
				
/*
			trace (TR_DEBUG, CONFIG.trace, "matched %d, operator <=\n",
				match_time);
*/
		} else {
			trace (TR_WARN, CONFIG.trace, "illegal operator %d om query\n",
				current_rule -> operator);
		}
		/* we don't filter files based on DB_OPERATOR_NOT_EQUAL, because
			files contain ranges of times. since NOT_EQUAL only specifies
			a single moment, we can't use it to eliminate a whole file */
	}

	return TRUE;
}

/* assuming that each rule really does say date */
/* **implied conjunction ** */
static int match_time_message(time_t message_time, LINKED_LIST *date_criteria) {
	db_select_t *current_rule;

	LL_Iterate(date_criteria, current_rule) {
		time_t match_time;
		match_time = * (time_t *) (current_rule->value);

		if (current_rule -> operator == DB_OPERATOR_EQUAL) {
			if (message_time != match_time)
				return FALSE;
		} else if (current_rule -> operator == DB_OPERATOR_GREATER) {
			if (message_time <= match_time)
				return FALSE;
		} else if (current_rule -> operator == DB_OPERATOR_GREATER_EQ) {
			if (message_time < match_time)
				return FALSE;
		} else if (current_rule -> operator == DB_OPERATOR_LESS) {
			if (message_time >= match_time)
				return FALSE;
		} else if (current_rule -> operator == DB_OPERATOR_LESS_EQ) {
			if (message_time > match_time)
				return FALSE;
		} else if (current_rule -> operator == DB_OPERATOR_NOT_EQUAL) {
			if (message_time == match_time)
				return FALSE;
		}
	}

	return TRUE;
}

static time_t get_time(char *file) {
	int year, month, daymonth, hour, minute;
	struct tm filetime;
	time_t tz_offset;

	if (parsename(file, &year, &month, &daymonth, &hour, &minute) != 0)
/* XXX not a great solution */
		return -1;

	filetime.tm_year = year; filetime.tm_mon = month-1;
		filetime.tm_mday = daymonth;
	filetime.tm_hour = hour; filetime.tm_min = minute; filetime.tm_sec = 0;
	filetime.tm_isdst = -1; /* i think that tells mktime "you figure it out" */

	if (!use_localtime)
		tz_offset = get_tz_offset();
	else
		tz_offset = 0;
		
	return (mktime_r(&filetime)+tz_offset);
}

static int process_file(io_t *IO, char *pathname, trace_t *tracer,
LINKED_LIST *match_criteria, void(func)(void *state, void *data),
void *func_state) {
	mrt_msg_t *msg;
	int res;

/* some day, MRT may support multiple IO ports. when it does, we can remove
   the locking code below. --mukesh */

trace(TR_TRACE, CONFIG.trace, "--| io_lock\n");
	pthread_mutex_lock(&io_lock);
trace(TR_TRACE, CONFIG.trace, "--> io_lock\n");
	res = io_set (IO, IO_INFILE, pathname, 0);
															if (res!=0) goto error_open;

	while (1) {
		/* XXX distinguish between error and eof ? */
		msg = (mrt_msg_t *) io_read (IO);
															if (msg==NULL) break;
															if (msg->length > 4096*2)
																goto error_msg_length;

		if ((msg->subtype == MSG_BGP_UPDATE) && match_time_message (msg->tstamp,
		match_criteria)) {
			LINKED_LIST *ll_with_prefixes, *ll_ann_prefixes;
			gateway_t *gateway_to;
  			bgp_attr_t *attr;
			bgp_db_data_t new_data;

			ll_with_prefixes = ll_ann_prefixes = NULL;
			attr = NULL;

			bgp_process_update_msg (msg->type, msg->subtype, msg->value, msg->length,
				&gateway_to, &attr, &ll_with_prefixes, &ll_ann_prefixes);

			if (attr == NULL) {
				trace(TR_WARN, tracer,
					"Error decoding message? (attr is NULL) Ignoring.\n");
				continue;
			}
			
			if (!(attr->gateway)) { /* || (attr->gateway->AS <= 0)) {
				printf("\nInvalid origin AS\n"); */
				trace(TR_WARN, tracer, "Message has no origin AS. "
					"Ignorning it.\n");
				continue;
			}


			new_data.time = msg->tstamp;
			new_data.received_by = gateway_to;
			new_data.attr = attr;
			new_data.announces = ll_ann_prefixes;
			new_data.withdraws = ll_with_prefixes;
			func(func_state, &new_data);

			if (ll_ann_prefixes != NULL)
				LL_Destroy(ll_ann_prefixes);
			if (ll_with_prefixes != NULL)
				LL_Destroy(ll_with_prefixes);
			bgp_deref_attr(attr);
		}
		Delete (msg);
	}

   io_set (IO, IO_INNONE, NULL);
	pthread_mutex_unlock(&io_lock);
trace(TR_TRACE, CONFIG.trace, "<-- io_lock\n");
	return 0;

	error_open:
		trace (TR_ERROR, tracer, "couldn't open file %s\n", pathname);
		perror("process_file");
		io_set (IO, IO_INNONE);	
		pthread_mutex_unlock(&io_lock);
trace(TR_TRACE, CONFIG.trace, "<-- io_lock\n");
		return 1;

	error_msg_length:
		trace (TR_ERROR, tracer, "Message is too long (%d). "
			"Skipping rest of file %s.\n", (int) msg->length, pathname);
      io_set (IO, IO_INNONE, NULL);
		Delete(msg);
		pthread_mutex_unlock(&io_lock);
trace(TR_TRACE, CONFIG.trace, "<-- io_lock\n");
      return 1;
	
}

#define EPOCH 1900
static int parsename(char *name, int *yr, int *mon, int *day, int *hr,
int *min) {
	/* this is the expected case */
	if (sscanf(name, "bgp.%4d%2d%2d.%2d:%2d", yr, mon, day, hr, min) == 5) {
		*yr -= EPOCH;							/* mktime wants offset from EPOCH */
		return 0;
	}

	/* this is for legacy data at Merit */
	if (sscanf(name, "bgp.%2d%2d%2d.%2d:%2d", yr, mon, day, hr, min) == 5) {
		if (*yr < 95)							/* window around y2k problem */
			*yr += 100;
		return 0;
	}

	/* this is for legacy 6bone data at Merit */
	if (sscanf(name, "bgp.updates.%2d%2d%2d.%2d:%2d", yr, mon, day, hr, min)
	== 5) {
		if (*yr < 95)							/* window around y2k problem */
			*yr += 100;
		return 0;
	}
		
	return -1;
}

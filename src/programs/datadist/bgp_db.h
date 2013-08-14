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

#ifndef BGP_DB_H
#define BGP_DB_H

/*
   didn't implement matching on dates because that would be timezone dependant.
   e.g. matching for 08/24/98 EST would mean matching for 04:00 08/24/98 -
	04:00 08/25/98 in GMT. we could decide on a mapping at the server end,
	but i think it makes more sense to have the client tell us exactly
	what it wants
*/
#define BGP_DB_FIELD_TIME			"time"
#define BGP_DB_FIELD_EXCHANGE		"exchange"

#define PARAM_BGPDB_PATH			"database_directory"
#define PARAM_BGPDB_FILE_SPAN		"file_timespan"
#define PARAM_BGPDB_DCACHE_TIME	"dircache_time"
#define PARAM_BGPDB_FTIME_FLAG	"filename_timezone_local"

#define DESC_BGPDB_PATH \
	"Toplevel directory of routing message files"
#define DESC_BGPDB_FILE_SPAN \
	"Range of time covered in each file (in seconds)"
#define DESC_BGPDB_DCACHE_TIME \
	"Maximum time (in seconds) to cache directory listings"
#define DESC_BGPDB_FTIME_FLAG \
	"Are the data filenames in local time? (1=yes, 0=no)"
#include "db.h"

typedef struct {
	time_t time;
	gateway_t *received_by;
	bgp_attr_t *attr;
	LINKED_LIST *announces, *withdraws;
} bgp_db_data_t;

typedef void(*bgp_db_callback_t)(void *state, void *data);

LINKED_LIST *bgp_db_avail(db_field_t field);

void bgp_db_query(trace_t *tracer, bgp_db_callback_t callback_fn,
	void *pf_state, LINKED_LIST *match_criteria, io_t *io_port);
void bgp_db_get_db_path(void *ignored);
void bgp_db_get_file_span(void *ignored);
void bgp_db_get_dir_cache_time(void *ignored);
void bgp_db_getLocaltimeFlag(void *ignored);
void bgp_db_set_db_path(uii_connection_t *uii, char *new_path);
void bgp_db_set_file_span(uii_connection_t *uii, int fspan);
void bgp_db_set_dir_cache_time(uii_connection_t *uii, int t);
void bgp_db_setLocaltimeFlag(uii_connection_t *uii, int val);
#endif

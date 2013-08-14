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

#include <hash.h>
#include <config_file.h>
#include <trace.h>

#include "../SalyClient2/propertyList.h"
#include "bgp_db.h"
#include "flapSourcer.h"
#include "util.h"

/* globals defined elsewhere */
extern config_t CONFIG;		/* XXX should be passed as arg? */

#define LOCATION_PROPERTY "LOCATION"

#define NUM_BUCKETS 1000
#define ILLEGAL_AS 0

typedef struct {
	int asNum;
	int count;
} msg_counter;

typedef struct {
	int asNum;
	HASH_TABLE *recv_counts;
	HASH_TABLE *send_counts;
} as_msg_count;

/* callbacks */

/* probably not a great hash function, but probably good enough */
unsigned asHash(int *asNumber, unsigned size) {
	return ((*asNumber)%size);
}

unsigned asCompare(int *as1, int *as2) {
	return (*as1==*as2);
}

void flapSourcer_NodeDelete(as_msg_count *node_data) {
	HASH_Destroy(node_data->recv_counts);
	HASH_Destroy(node_data->send_counts);
	free (node_data);
}

/* prototypes of private functions */
static void increment(HASH_TABLE *h, int send_AS, int recv_AS, int delta);

flapSourcer_t *New_flapSourcer(trace_t *tracer, time_t start, time_t end) {
	flapSourcer_t *t;
	as_msg_count sample;
	
	t = malloc (sizeof(flapSourcer_t));
	t -> tracer = tracer;
	t -> start = start;
	t -> end = end;
	t -> msg_per_gateway = HASH_Create(NUM_BUCKETS, HASH_EmbeddedKey, True,
		HASH_KeyOffset, HASH_Offset(&sample, &sample.asNum),
		HASH_HashFunction, asHash, HASH_LookupFunction, asCompare,
		HASH_DestroyFunction, flapSourcer_NodeDelete, NULL);
	t -> observer_AS = ILLEGAL_AS;	
		
	return t;
}

void Delete_flapSourcer(flapSourcer_t *sum) {
	HASH_Destroy(sum->msg_per_gateway);
	free(sum);
}

void flapSourcer_add(flapSourcer_t *collector, bgp_db_data_t *nd) {
	if (nd->time < collector->start) {
		trace(TR_WARN, collector->tracer,
			"flapSourcer: invalid data (too early)\n.");
		return;
	}
	
	if (nd->time > collector->end) {
		trace(TR_WARN, collector->tracer,
			"flapSourcer: invalid data (too late)\n.");
		return;
	}
	
	if (nd->announces != NULL) {
		int num_msgs, receiver_as;
		aspath_segment_t *cur_path_seg;

		if (collector->observer_AS == ILLEGAL_AS)
			collector->observer_AS = nd->received_by->AS;
		else if (collector->observer_AS != nd->received_by->AS)
			trace(TR_WARN, collector->tracer,
				"Observer AS for message is inconsistent (first: %d, this: %d)\n",
				collector->observer_AS, nd->received_by->AS);
				
		num_msgs = LL_GetCount(nd->announces);
		receiver_as = collector->observer_AS;
/*
fprintf (stderr, "%d announcements, %ld path elements\n", num_msgs, LL_GetCount(
nd->attr->aspath));
*/
		if (nd->attr->aspath == NULL)
			trace(TR_WARN, collector->tracer,
				"AS path is NULL. Ignoring.\n");
		else
			LL_Iterate(nd->attr->aspath, cur_path_seg) {
				int i;
/* this algorithm was devined from looking at asexplorer.pl and aspath.c. i
   hope i got it right! -- mukesh */
				for (i=0; i<cur_path_seg->len; i++) {
/*
fprintf (stderr, "%d announcements from %d to %d\n", num_msgs, receiver_as,
cur_path_seg->as[i]);
*/
					increment(collector -> msg_per_gateway, cur_path_seg->as[i],
						receiver_as, num_msgs);
					receiver_as = cur_path_seg->as[i];
				}
			}
	}
}

#define START_TIME			"TIME_START"
#define END_TIME				"TIME_END"
#define OBSERVER_AS			"START_AS"
#define OBSERVER_LOCATION	"LOCATION"
void flapSourcer_publish(flapSourcer_t *collector, publisher_t *publish,
char *location) {
	char *channel;
	as_msg_count *current_as;
	msg_counter *current_counter;
	plist_t properties;
	char line_buffer[1000];
#ifdef GEN_OLD_FILES
	char tmpstr[50];
#endif GEN_OLD_FILES

	properties = createPropertyList();
/* XXX use snprintf? */
	sprintf(line_buffer, "%lu", collector->start);
		updateProperty(properties, START_TIME, line_buffer);	
	sprintf(line_buffer, "%lu", collector->end);
		updateProperty(properties, END_TIME, line_buffer);
	sprintf(line_buffer, "%d", collector->observer_AS);
		updateProperty(properties, OBSERVER_AS, line_buffer);
	updateProperty(properties, OBSERVER_LOCATION, location);
#ifdef GEN_OLD_FILES
	sprintf (tmpstr, "%d", collector->start);
	updateProperty (properties, TIME_PROPERTY, tmpstr);
#endif GEN_OLD_FILES
	publisher_plist_load(publish, properties);
	destroyPropertyList(properties);
	publisher_buffer_clear(publish);
	
	HASH_Iterate(collector->msg_per_gateway, current_as) {
		char buffer[102400];		/* no more than 100K data per AS */
		char *bufp = buffer;
		
/* XXX use snprintf? */
		bufp += sprintf (bufp, "#%d\n", current_as->asNum);
		HASH_Iterate (current_as->recv_counts, current_counter) {
			bufp += sprintf (bufp, "%d %d ", current_counter->asNum,
				current_counter->count);
		}

		bufp += sprintf (bufp, "\n");

		HASH_Iterate (current_as->send_counts, current_counter) {
			bufp += sprintf (bufp, "%d %d ", current_counter->asNum,
				current_counter->count);
		}
		bufp += sprintf (bufp, "\n");

		publisher_buffer_append(publish, buffer, bufp-buffer);		
	}
	channel = strdup(location);
/* check for NULL */
	publisher_buffer_send(publish, channel);
	free(channel);
}

/* private functions */

#define NUM_BUCK_2 10

static as_msg_count *get_counters(HASH_TABLE *h, int asNum) {
	as_msg_count *fc;

	fc = HASH_Lookup(h, &asNum);

	if (fc==NULL) {
		msg_counter sample;
		
		fc = malloc (sizeof (as_msg_count));
/* if malloc fails? */
		fc -> asNum = asNum;

		fc -> recv_counts = HASH_Create(NUM_BUCK_2, HASH_EmbeddedKey, True,
			HASH_KeyOffset, HASH_Offset(&sample, &sample.asNum),
			HASH_HashFunction, asHash,
			HASH_LookupFunction, asCompare,
			HASH_DestroyFunction, DeleteNodeData, NULL);

		fc -> send_counts = HASH_Create(NUM_BUCK_2, HASH_EmbeddedKey, True,
			HASH_KeyOffset, HASH_Offset(&sample, &sample.asNum),
			HASH_HashFunction, asHash,
			HASH_LookupFunction, asCompare,
			HASH_DestroyFunction, DeleteNodeData, NULL);
		HASH_Insert(h, fc);
	}

	return fc;
}

static void inc_counter(HASH_TABLE *counter, int asNum, int change) {
	msg_counter *count_this_as;
	
	count_this_as = HASH_Lookup(counter, &asNum);
	
	if (count_this_as == NULL) {
		count_this_as = malloc(sizeof(msg_counter));
/* if malloc fails? */
		count_this_as->asNum = asNum;
		count_this_as->count = change;
		HASH_Insert(counter, count_this_as);
	} else {
		count_this_as->count += change;
	}
}

static void increment(HASH_TABLE *h, int send_as, int recv_as, int delta) {
	as_msg_count *sender_tally, *reciever_tally;
/*
fprintf (stderr, "%d messages from %d to %d\n", delta, send_as, recv_as);	
*/
	sender_tally = get_counters(h, send_as);
	reciever_tally = get_counters(h, recv_as);
	
	inc_counter(sender_tally->send_counts, recv_as, delta);
	inc_counter(reciever_tally->recv_counts, send_as, delta);
}

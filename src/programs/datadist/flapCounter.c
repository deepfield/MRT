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

#include <math.h>
#include <hash.h>
#include <config_file.h>
#include <trace.h>

#include "../SalyClient2/propertyList.h"
#include "bgp_db.h"
#include "flapCounter.h"

/* globals defined elsewhere */
extern config_t CONFIG;		/* XXX should be passed as arg? */

#define LOCATION_PROPERTY "LOCATION"

#define NUM_AS_BUCKETS 10
#define NUM_PREFIX_BUCKETS 1000

#define ANNOUNCE 1
#define WITHDRAW 2

typedef struct {
	u_short asNum;
	prefix_t *ip_addr;
} fg_gateway_t;

typedef struct {
	fg_gateway_t gateway;
	int announce[NUM_SAMPLES];
	int withdraw[NUM_SAMPLES];
	HASH_TABLE *prefix_seen;
} fg_data_t;

/* callbacks */

unsigned flapGraph_Hash(fg_gateway_t *gateway, unsigned size) {
	return ((gateway->asNum)%size);
}

unsigned flapGraph_Lookup(fg_gateway_t *key1, fg_gateway_t *key2) {
	if ((key1->asNum) != (key2->asNum))
		return FALSE;

	return (prefix_compare2(key1->ip_addr, key2->ip_addr)==0);
}

void flapGraph_NodeDelete(fg_data_t *node_data) {
	Deref_Prefix (node_data->gateway.ip_addr);
	HASH_Destroy(node_data->prefix_seen);
	free (node_data);
}

unsigned prefix_Hash(prefix_t *prefix, unsigned size) {
	if (prefix->family == AF_INET)
		return ((prefix->add.sin.s_addr) % size);
#ifdef HAVE_IPV6
	else if (prefix->family == AF_INET6)
	  return ((prefix->add.sin6.s6_addr[0]) % size);
#endif /* HAVE_IPV6 */
	else {
		trace(TR_ERROR, CONFIG.trace, "Unknown prefix family.\n");
		return 1; /* no particular reason */
	}
}

unsigned prefix_Lookup(prefix_t *p1, prefix_t *p2) {
	return (prefix_compare2(p1, p2)==0);
}

/* prototypes of private functions */
static void generate_report_text(publisher_t *p, int *announce_data,
	int *withdraw_data);
static void generate_report_text1(publisher_t *p, HASH_TABLE *sum_data);
static void increment(trace_t *tracer, HASH_TABLE *h, int type,
	int gateway_asNum, prefix_t * gateway_ip_addr, prefix_t *prefix_named,
	int index);

flapGraph_t *New_flapGraph(trace_t *tracer, time_t start_time) {
	flapGraph_t *t;
	fg_data_t fd_sample;
	
	t = malloc (sizeof(flapGraph_t));
/* if malloc fails? */
	t -> tracer = tracer;
	t -> msg_per_gateway = HASH_Create(NUM_AS_BUCKETS, HASH_EmbeddedKey, True,
		HASH_KeyOffset, HASH_Offset(&fd_sample, &fd_sample.gateway),
		HASH_HashFunction, flapGraph_Hash, HASH_LookupFunction, flapGraph_Lookup,
		HASH_DestroyFunction, flapGraph_NodeDelete, NULL);
	t -> start_time = start_time;
	
	memset(t->total_announce, 0, sizeof(int) * NUM_SAMPLES);
	memset(t->total_withdraw, 0, sizeof(int) * NUM_SAMPLES);

	return t;
}

void Delete_flapGraph(flapGraph_t *sum) {
	HASH_Destroy(sum->msg_per_gateway);
	free(sum);
}

#define SEC_MIN	(60)
#define SEC_HOUR	(60 * SEC_MIN)
#define SEC_DAY	(24 * SEC_HOUR)

void flapGraph_add(flapGraph_t *collector, void *newdata) {
	bgp_db_data_t *nd;
	prefix_t *prefix;
	int index;

	nd = (bgp_db_data_t *) newdata;

	if (nd->time < collector->start_time) {
		trace(TR_WARN, collector->tracer,
			"flapGraph: Invalid data (too early).\n");
		return;
	}

	if (nd->time > (collector->start_time + SEC_DAY - 1)) {
		trace(TR_WARN, collector->tracer,
			"flapGraph: Invalid data (too late).\n");
		return;
	}
	
	index = ((float)(nd->time - collector->start_time)) / SEC_DAY *
		NUM_SAMPLES;
	
	if (nd->announces != NULL) {
		LL_Iterate(nd->announces, prefix) {
			collector -> total_announce[index]++;
			increment(collector->tracer, collector -> msg_per_gateway, 
				ANNOUNCE, nd->attr->gateway->AS, nd->attr->gateway->prefix, prefix,
				index);
		}
	}
	
	if (nd->withdraws != NULL) {
		LL_Iterate(nd->withdraws, prefix) {
			collector -> total_withdraw[index]++;
			increment(collector->tracer, collector -> msg_per_gateway, 
				WITHDRAW, nd->attr->gateway->AS, nd->attr->gateway->prefix, prefix,
				index);
		}
	}	
}

/* note: we have no way of clearing prefixes seen. it's not a problem
   as far as FlapGraph or FlapTable are concerned (the data is still
	accurate), but the programming interface might not be clear. */
void flapGraph_clear(flapGraph_t *collector, time_t *clear_from,
time_t *clear_thru) {
	time_t from, thru, report_start, report_end;
	int from_index, thru_index, num_clear;
	fg_data_t *asData;
	
	from = *clear_from;
	thru = *clear_thru;
	
	report_start = collector->start_time;
	report_end = report_start + SEC_DAY-1;
	
	if (from > report_end) {
/* error */
		return;
	}
	
	if (thru < report_start) {
/* error */
		return;
	}
	
	if (from < report_start)	from = report_start;
	if (thru > report_end)		thru = report_end;

	from_index = ((float)(from - report_start)) / SEC_DAY * NUM_SAMPLES;
	thru_index = ((float)(thru - report_start)) / SEC_DAY * NUM_SAMPLES;

	num_clear = thru_index - from_index + 1;

	HASH_Iterate(collector->msg_per_gateway, asData) {
		memset (asData->announce + from_index, 0, sizeof(int) * num_clear);
		memset (asData->withdraw + from_index, 0, sizeof(int) * num_clear);
	}
	
	memset (collector->total_announce + from_index, 0, sizeof(int) * num_clear);
	memset (collector->total_withdraw + from_index, 0, sizeof(int) * num_clear);

	*clear_from = from_index * (SEC_DAY / NUM_SAMPLES) + report_start;
	*clear_thru = (thru_index + 1) * (SEC_DAY / NUM_SAMPLES) + report_start - 1;
}

/* right now, if there are >1 gateways for the same AS# at the same IXP,
   then we arbitrarily publish data  for one of them. (well, actually, we
	publish both, but the last one published is what salamander will keep.)
	this is because the client code only supports one gateway per as per ixp. 
	this really should be fixed. (and the fix for the backend is easy: simply
	give them different channel names. e.g., include the gateway IP addr) */

#define MAX_AS_DIGITS 10
void flapCounter_flapGraph_publish(flapGraph_t *collector, publisher_t *publish,
char *exchange_point) {
	char *channel;
	fg_data_t *current_as;
	plist_t properties;
#ifdef GEN_OLD_FILES
	char tmpstr[50];
#endif GEN_OLD_FILES

	properties = createPropertyList();
	updateProperty(properties, LOCATION_PROPERTY, exchange_point);
#ifdef GEN_OLD_FILES
	sprintf (tmpstr, "%d", collector->start_time);
	updateProperty (properties, TIME_PROPERTY, tmpstr);	
#endif GEN_OLD_FILES
	publisher_plist_load(publish, properties);
	destroyPropertyList(properties);
	
	generate_report_text(publish, collector->total_announce,
		collector->total_withdraw);
	channel = malloc(sizeof(char)*(strlen(exchange_point)+MAX_AS_DIGITS
		+4)); /* +4 = :AS and terminator */
/* check for NULL */
	sprintf (channel, "%s:all", exchange_point);
	publisher_buffer_send(publish, channel);
	
	HASH_Iterate(collector->msg_per_gateway, current_as) {
		if (log10(current_as->gateway.asNum) > MAX_AS_DIGITS) {
			trace (TR_WARN, collector->tracer, "AS number is too long for channel "
				"name buffer. Will not publish %s:AS%d\n", exchange_point,
				current_as->gateway.asNum);
		} else {
			generate_report_text(publish, current_as -> announce,
				current_as -> withdraw);

			sprintf (channel, "%s:AS%d", exchange_point, current_as ->
				gateway.asNum);
			publisher_buffer_send(publish, channel);
		}
	}
	free(channel);
}

void flapCounter_flapTableDaily_publish(flapGraph_t *collector, publisher_t *publish,
char *exchange_point) {
	char *channel;
	plist_t properties;
#ifdef GEN_OLD_FILES
	char tmpstr[50];
#endif GEN_OLD_FILES

	properties = createPropertyList();
	updateProperty(properties, LOCATION_PROPERTY, exchange_point);
#ifdef GEN_OLD_FILES
	sprintf (tmpstr, "%d", collector->start_time);
	updateProperty (properties, TIME_PROPERTY, tmpstr);
#endif GEN_OLD_FILES
	publisher_plist_load(publish, properties);
	destroyPropertyList(properties);

	generate_report_text1(publish, collector->msg_per_gateway);
	channel = strdup(exchange_point);
/* check for NULL */
	publisher_buffer_send(publish, channel);
	free(channel);
}

/* private functions */

static void increment(trace_t *tracer, HASH_TABLE *h, int type, int
gateway_asNum, prefix_t *gateway_ip_addr, prefix_t *prefix_named, int index) {
	fg_data_t *f;
	fg_gateway_t g;
	
	g.asNum = gateway_asNum;
	g.ip_addr = gateway_ip_addr;
	
	f = HASH_Lookup(h, &g);

	if (f==NULL) {
		prefix_t prefix_sample;
		
		f = malloc (sizeof (fg_data_t));
/* if malloc fails? */
		f -> gateway.asNum = gateway_asNum;
		Ref_Prefix(gateway_ip_addr);
		f->gateway.ip_addr = gateway_ip_addr;
		memset (f -> announce, 0, sizeof(int) * NUM_SAMPLES);
		memset (f -> withdraw, 0, sizeof(int) * NUM_SAMPLES);

		f->prefix_seen = HASH_Create(NUM_PREFIX_BUCKETS, HASH_EmbeddedKey, True,
			HASH_KeyOffset, HASH_Offset(&prefix_sample, &prefix_sample),
			HASH_HashFunction, prefix_Hash, HASH_LookupFunction, prefix_Lookup,
			HASH_DestroyFunction, Deref_Prefix, NULL);
		HASH_Insert(h, f);
	}

	if (type == ANNOUNCE) {
		(f -> announce)[index] += 1;
	} else if (type == WITHDRAW) {
		(f -> withdraw)[index] += 1;
	}

	if (!HASH_Lookup(f->prefix_seen, prefix_named)) {
		/* technically, i should grab the lock before reading the
		   field, but i don't think it's a big deal, since this is just
			debugging and shouldn't ever happen anyway */
		if (prefix_named->ref_count != 1)
			trace (TR_DEBUG, tracer, "Added prefix to hashtable twice?\n");

		Ref_Prefix(prefix_named);
		HASH_Insert(f->prefix_seen, prefix_named);
	}
}

static void generate_report_text(publisher_t *p, int *announce_data,
int *withdraw_data) {
	int i;
	
	publisher_buffer_clear(p);

	for (i=0; i < NUM_SAMPLES; i++) {
		int hr, min, len;
		char line_buffer[200];
		
		hr = i / 4;
		min = (i % 4) * 15;
/* XXX snprintf? */		
		len = sprintf(line_buffer, "%02d.%02d\t%d\t%d\t%d\n", hr, min,
			announce_data[i]+withdraw_data[i], announce_data[i], withdraw_data[i]);
		publisher_buffer_append(p, line_buffer, len);
	}
}

static void generate_report_text1(publisher_t *p, HASH_TABLE *sum_data) {
	fg_data_t *current_gateway;
	int len;
	
	publisher_buffer_clear(p);

	HASH_Iterate(sum_data, current_gateway) {
		char line_buffer[200];
		int unique=0, sum_announce=0, sum_withdraw=0, i;
		
		for (i=0; i < NUM_SAMPLES; i++) {
			sum_announce += current_gateway->announce[i];
			sum_withdraw += current_gateway->withdraw[i];
		}

	unique = HASH_GetCount(current_gateway->prefix_seen);

/* XXX snprintf? */
/* i'm not clear on who releases the memory allocated in prefix_to_a. so this
   might be a memory leak here -- mukesh */
		len = sprintf(line_buffer, "%d %s %d %d %d %d\n",
			current_gateway->gateway.asNum, prefix_toa(current_gateway->
			gateway.ip_addr), unique, sum_announce, sum_withdraw,
			sum_announce + sum_withdraw);
		publisher_buffer_append(p, line_buffer, len);
	}
}

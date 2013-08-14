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

#include <stdarg.h>

#include <config_file.h>

#include "publisher.h"

/* imported from driver.c */
extern config_t CONFIG;

/* private functions */
static void add_channel(publisher_t *p, char *name);
static void send_data(publisher_t *p, void *data, int dataLen, char *channel);

/* would prefer publisher_t*, but can't -- see publisher.h */
static void delete(void *p);
static void do_send_data(void *p, void *data, int dataLen, char *channel);

/* XXX need to check return values of plist functions */


publisher_t *_New_Publisher(LINKED_LIST *args) {
	publisher_t *p;
	void *arg;
	
	p = malloc (sizeof(publisher_t));

	/* functions */
	p -> delete = delete;
	p -> do_send_data = do_send_data;

	/* default values */
	p -> channel_prefix = NULL;
	p -> do_timestamp = 1;
	p -> trace = CONFIG.trace;

	p -> channels = malloc (sizeof(char) *
		PUB_CHANNEL_BUFFER_SIZE);
	p -> next_channel_entry = p -> channels;
	p -> channel_buffer_size = PUB_CHANNEL_BUFFER_SIZE;
	
	p -> data_buffer_start = malloc (sizeof(char) *
		PUB_DATA_BUFFER_SIZE);
	p -> data_buffer_next = p -> data_buffer_start;
	p -> data_buffer_size = PUB_DATA_BUFFER_SIZE;

	p -> properties = NULL;

	LL_Iterate(args, arg) {
		switch ((int)arg) {
			case PUBLISHER_CHANNEL_PREFIX: {
				arg = LL_GetNext(args, arg);
				
				p -> channel_prefix_len = strlen(arg);
				p -> channel_prefix = strdup(arg);
/* check for NULL */
				break;
			} case PUBLISHER_TIMESTAMPING: {
				arg = LL_GetNext(args, arg);
				
				p->do_timestamp = (int)arg;
				break;
			} case PUBLISHER_TRACE: {
				arg = LL_GetNext(args, arg);
								
				p->trace = (trace_t *)arg;
				break;
			}
		}
	}

	return p;
}

static void delete(void *v) {
	publisher_t *p = (publisher_t *) v;
	
	if (p==NULL)
		return;
	
	free (p->channel_prefix);
	p->channel_prefix = NULL;
	free (p->channels);
	p->channels = NULL;
	p->next_channel_entry = NULL;
	p->channel_buffer_size = 0;
	free (p->data_buffer_start);
	p->data_buffer_start = NULL;
	p->data_buffer_next = NULL;
	p->data_buffer_size = NULL;
	destroyPropertyList(p->properties);
	p->properties = NULL;
	free (p);
}

void publisher_plist_load (publisher_t *p, plist_t list) {
	destroyPropertyList(p->properties);
	p->properties = copyPropertyList(list);
}

void publisher_plist_clear (publisher_t *p) {
	destroyPropertyList(p->properties);
	p->properties = NULL;
}

void publisher_buffer_clear (publisher_t *p) {
	p -> data_buffer_next = p -> data_buffer_start;
}

void publisher_buffer_append (publisher_t *p, void *data, int dataLen) {
	if ((p->data_buffer_next+dataLen) - p->data_buffer_start >
	p->data_buffer_size) {
		size_t offset;
	
		p->data_buffer_size += dataLen;
		offset = p->data_buffer_next - p->data_buffer_start;
		p->data_buffer_start =
			realloc(p->data_buffer_start, sizeof(char) * p->data_buffer_size);
/* if realloc fails? */
		p->data_buffer_next = p->data_buffer_start + offset;
	}

	memcpy(p->data_buffer_next, data, dataLen);
	p->data_buffer_next += dataLen;
}

void publisher_buffer_send (publisher_t *p, char *channel) {
	char *full_channel;

	full_channel = malloc (sizeof(char)*(strlen(channel)+p->channel_prefix_len
		+ 2));		/* +2 = ":" + \0 */
	sprintf (full_channel, "%s:%s", p->channel_prefix, channel);


	/* zero byte data is not permitted in the protocol. moreover, some
	   implementations close the connection when they receive a packet
		with zero bytes of data. --mukesh */
	if (p->data_buffer_next - p->data_buffer_start == 0) {
		trace (TR_WARN, p->trace,
			"Did not publish %s because it has no data.\n", full_channel);
	} else {
		trace(TR_INFO, p->trace, "Publishing %s...\n", full_channel);
		send_data(p, p->data_buffer_start, p->data_buffer_next -
			p-> data_buffer_start, full_channel);
		add_channel(p, full_channel);
	}
	free (full_channel);
}

void publisher_channel_list_clear(publisher_t *p) {
	p -> next_channel_entry = p -> channels;
}

void publisher_channel_list_send(publisher_t *p) {
	char *channel_list_channel_name;

	channel_list_channel_name = malloc (sizeof(char)*
		(strlen(PUB_CHANNELLIST_CHANNEL)+strlen(p->channel_prefix)+1));
	strcpy(channel_list_channel_name, PUB_CHANNELLIST_CHANNEL);
	strcat(channel_list_channel_name, p->channel_prefix);

	trace (TR_INFO, p->trace, "Sending channel list: %s\n",
		channel_list_channel_name);

	send_data (p, p->channels, (p->next_channel_entry - p->channels),
		channel_list_channel_name);
	free(channel_list_channel_name);
	
}

/* add_channel doesn't check for duplicate entries. so if you keep adding
   channels, and never clear the channel list, then you'll just keep
	getting a larger channel list, with duplicate entries. */
static void add_channel(publisher_t *p, char *channel) {
	if (p->next_channel_entry + (strlen(channel)+1) >
	p->channels + p->channel_buffer_size) {
		size_t offset;
		
		p -> channel_buffer_size += strlen(channel)+1;
		offset = p->next_channel_entry - p->channels;
		p -> channels =
			realloc (p->channels, sizeof(char) * p->channel_buffer_size);
		p -> next_channel_entry = p -> channels + offset;
	}	

	p -> next_channel_entry +=
		sprintf (p->next_channel_entry, "%s|", channel);
}

/* should be renamed. prep_data? */
static void send_data (publisher_t *p, void *data, int dataLen, char *channel) {
	if (p->properties == NULL)
		p->properties = createPropertyList();
	updateProperty(p->properties, COMMAND_PROPERTY, PUBLISH_COMMAND);
	updateProperty(p->properties, NAME_PROPERTY, channel);
	if (p->do_timestamp) {
		char tmp[20];		/* too lazy to count the actual number */
/* if time call fails? */
/* XXX snprintf? (probably overkill) */
#ifndef GEN_OLD_FILES
		sprintf (tmp, "%lu", time(NULL));
		updateProperty(p->properties, TIME_PROPERTY, tmp);
#endif GEN_OLD_FILES
	}

   p->do_send_data(p, data, dataLen, channel);
}

static void do_send_data(void *p, void *data, int dataLen, char *channel) {
/* error! */
}

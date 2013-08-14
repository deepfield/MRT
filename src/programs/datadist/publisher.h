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

#ifndef PUBLISHER_H
#define PUBLISHER_H

#include "../SalyClient2/propertyList.h"

#define PUBLISHER_CHANNEL_PREFIX			1
#define PUBLISHER_TIMESTAMPING			2
#define PUBLISHER_TRACE						3


#define PUB_CHANNEL_BUFFER_SIZE 5120
#define PUB_DATA_BUFFER_SIZE 10240
#define PUB_CHANNELLIST_CHANNEL "ChannelList:"

#define TIME_PROPERTY "TIME"

#define MAXHOSTLEN 256

/* keepalive option? */
typedef struct {
	/* methods */
/* first arg declared as void* because we can't refer to a
   publisher_t* as an argument. */
	void (*delete)(void *p);
	void (*do_send_data)(void *p, void *data, int dataLen, char *channel);
	
	/* fields */
	char *channel_prefix;
	int channel_prefix_len;
	int do_timestamp;
	char *channels;
	char *next_channel_entry;
	int channel_buffer_size;
	char *data_buffer_start;
	char *data_buffer_next;
	trace_t *trace;
	int data_buffer_size;
	plist_t properties;

	/* for subclassing */
	void *super;
	void *extend;
} publisher_t;


void publisher_plist_load (publisher_t *p, plist_t list);
void publisher_plist_clear (publisher_t *p);
void publisher_buffer_clear(publisher_t *p);
void publisher_buffer_append(publisher_t *p, void *data, int dataLen);
void publisher_buffer_send(publisher_t *p, char *channelName);
void publisher_channel_list_clear(publisher_t *p);
void publisher_channel_list_send(publisher_t *p);

#define Delete_Publisher(p)						p->delete(p)

/* publisher is an abstract class */
#ifdef PUBLISHER_SUBCLASS
publisher_t *_New_Publisher(LINKED_LIST *args);
#endif

#endif

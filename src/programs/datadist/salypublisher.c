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

#define PUBLISHER_SUBCLASS

#include <stdarg.h>
#include <config_file.h>
#include <trace.h>

#include "publisher.h"
#include "salypublisher.h"
#include "util.h"

#define DEFAULT_SALY_SERVER	"nowhere.nil"
#define DEFAULT_SALY_PORT	8899
#define SALAMANDER_KEY			123456

#define PARAM_SERVER				"salamander"
#define ARG_SERVER				" %s"
#define PARAM_PORT				"port"
#define ARG_PORT				" %d"
#define DESC_SERVER				"Name of server to which to publish this data"
#define DESC_PORT				"Port number of server"

/* imported from driver.c */
extern config_t CONFIG;

/* private functions */
static int set_salserver(publisher_t *p, uii_connection_t *uii,
	char *server);
static void write_salserver(publisher_t *p);
static int set_salport(publisher_t *p, uii_connection_t *uii, int port);
static void write_salport(publisher_t *p);

/* would prefer publisher_t*, but can't -- see publisher.h */
static void do_send_data(void *p, void *data, int dataLen, char *channel);
static void delete(void *p);

/* XXX need to check return values of plist functions */


publisher_t *New_SalyPublisher(LINKED_LIST *args) {
	publisher_t *p;
	salypublisher_extend_t *ex;
	salypublisher_super_t *sup;
	void *arg;
	
	p = _New_Publisher(args);
	p -> extend = ex = malloc (sizeof(salypublisher_extend_t));
	p -> super = sup = malloc (sizeof(salypublisher_super_t));

	/* functions */
	sup->delete = p->delete;
	p->do_send_data = do_send_data;
	p->delete = delete;
	
	/* default values */
	ex -> server_prefix = NULL;
	ex -> salserver = strdup(DEFAULT_SALY_SERVER);
	ex -> salkey = SALAMANDER_KEY;
	ex -> salport = DEFAULT_SALY_PORT;
	pthread_mutex_init(&(ex->salylock), NULL);
	ex -> saly = New_Salamander(0);
	
	LL_Iterate(args, arg) {
		switch ((int)arg) {
			case PUBLISHER_TIMESTAMPING:
			case PUBLISHER_TRACE:
				break;
			case PUBLISHER_CHANNEL_PREFIX:
				arg = LL_GetNext(args, arg);

				add_command(arg, PARAM_SERVER ARG_SERVER, set_salserver, p, DESC_SERVER);
				add_command(arg, PARAM_PORT ARG_PORT, set_salport, p, DESC_PORT);
				add_config(arg, PARAM_SERVER, write_salserver, p);
				add_config(arg, PARAM_PORT, write_salport, p);
				break;
			case SALYPUBLISHER_SERVERNAME: {
				arg = LL_GetNext(args, arg);
				
				set_salserver(p, NULL, arg);
				break;
			} case SALYPUBLISHER_SERVERPORT: {
				arg = LL_GetNext(args, arg);
				
				set_salport(p, NULL, (int)arg);
				break;
			} case SALYPUBLISHER_SERVERKEY: {
				arg = LL_GetNext(args, arg);
				
				ex->salkey = (int)arg;
				break;
			} default :
; /* error unless called from superclass */
		}
	}

	return p;
}

/* XXX delete should unregister commands */
static void delete(void *v) {
	publisher_t *p = (publisher_t *) v;
	salypublisher_extend_t *ex;
	salypublisher_super_t *sup;

	if (p==NULL)
		return;

	ex = p->extend;
	sup = p->super;
	
	Deref_Prefix(ex->server_prefix);

	pthread_mutex_lock(&(ex->salylock));
	Delete_Salamander(ex->saly);
	ex->saly = NULL;
	pthread_mutex_unlock(&(ex->salylock));
	pthread_mutex_destroy(&(ex->salylock));

	free (ex->salserver);
	free (ex);

	sup->delete(p);
	free(sup);
}

static void do_send_data (void *v, void *data, int dataLen, char *channel) {
	publisher_t *p = (publisher_t *) v;
	salypublisher_extend_t *ex;
	int res;

if (p==NULL) return;
ex = p->extend;

	pthread_mutex_lock(&(ex->salylock));
	if (!salamander_connected(ex->saly)) {
		if (ex->server_prefix == NULL) {
			ex->server_prefix = string_toprefix(ex->salserver, p->trace);
															if (ex->server_prefix == NULL)
																goto error_hostname;
		}

		res = connectToSalamanderServer(ex->saly, ex->server_prefix);
															if (!salamander_connected(ex->saly))
																goto error_connect;
	}

	res = salamanderSendServerData(ex->saly, p->properties, data, dataLen);
															if (res != SALAMANDER_OK)
																goto error_send;

	pthread_mutex_unlock(&(ex->salylock));
	return;

	error_send:
		trace(TR_ERROR, p->trace,
			"salamanderSendServerData error. Return code %d.\n", res);
		perror("send_data");
		pthread_mutex_unlock(&(ex->salylock));
		return;
	error_hostname:
		trace(TR_ERROR, p->trace,
			"Couldn't connect to %s because name lookup failed.\n", ex->salserver);
		pthread_mutex_unlock(&(ex->salylock));
		return;

	error_connect:
		trace(TR_ERROR, p->trace,
			"Failed to connect to %s. Return code is %d.\n", ex->salserver, res);
		perror("send_data");
		pthread_mutex_unlock(&(ex->salylock));
		return;
}

static int set_salserver(publisher_t *p, uii_connection_t *uii,
char *server) {
	salypublisher_extend_t *ex;
	prefix_t *new_prefix;

if (p==NULL) return -1;
	ex = p->extend;
	
	pthread_mutex_lock(&(ex->salylock));
	new_prefix = string_toprefix(server, NULL);
	if (new_prefix == NULL) {
		uii_send_data (uii, "The specifed hostname is invalid.\r\n");
		pthread_mutex_unlock(&(ex->salylock));
		return -1;
	}

	disconnectFromSalamanderServer(ex->saly);

	Deref_Prefix(ex->server_prefix);
	ex->server_prefix = new_prefix;
	free(ex->salserver);
	ex->salserver = strdup(server);

	pthread_mutex_unlock(&(ex->salylock));
	return 0;
}

#define ENDLINE "\r\n"

static void write_salserver(publisher_t *p) {
        salypublisher_extend_t *ex;
                
if (p==NULL) return;
        ex = p->extend;
        
        pthread_mutex_lock(&(ex->salylock));
	config_add_output("%s " PARAM_SERVER ARG_SERVER ENDLINE, p->channel_prefix, ex->salserver);
	pthread_mutex_unlock(&(ex->salylock));
}

static int set_salport(publisher_t *p, uii_connection_t *uii, int
port) {
	salypublisher_extend_t *ex;
	
if (p==NULL) return -1;
	ex = p->extend;
	
	if (port < 1) {
		uii_send_data (uii, "The port number is invalid.\r\n");
		return -1;
	}
	
	pthread_mutex_lock(&(ex->salylock));
	disconnectFromSalamanderServer(ex->saly);
	Delete_Salamander(ex->saly);
	ex->salport = port;
	ex->saly = New_Salamander(ex->salport);
	pthread_mutex_unlock(&(ex->salylock));
	return 0;
}

static void write_salport(publisher_t *p) {
        salypublisher_extend_t *ex;

if (p==NULL) return;  
        ex = p->extend;
        
        pthread_mutex_lock(&(ex->salylock));
	config_add_output("%s " PARAM_PORT ARG_PORT ENDLINE, p->channel_prefix, ex->salport);
        pthread_mutex_unlock(&(ex->salylock));
}

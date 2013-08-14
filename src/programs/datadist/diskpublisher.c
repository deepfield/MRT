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
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>
#include <dirent.h>

#include <config_file.h>
#include <trace.h>

#include "publisher.h"
#include "diskpublisher.h"
#include "util.h"

#define PARAM_BASEDIR				"basedir"
#define ARG_BASEDIR				" %s"
#define DESC_BASEDIR				"Base directory for output files"
#define DEFAULT_BASEDIR				"/"

/* imported from driver.c */
extern config_t CONFIG;

/* private functions */
static int set_basedir(publisher_t *p, uii_connection_t *uii, char *basedir);
static void write_basedir(publisher_t *p);

/* would prefer publisher_t*, but can't -- see publisher.h */
static void do_send_data(void *p, void *data, int dataLen, char *channel);
static void delete(void *p);

/* XXX need to check return values of plist functions */


publisher_t *New_DiskPublisher(LINKED_LIST *args) {
	publisher_t *p;
	diskpublisher_extend_t *ex;
	diskpublisher_super_t *sup;
	void *arg;
	
	p = _New_Publisher(args);
	p -> extend = ex = malloc (sizeof(diskpublisher_extend_t));
	p -> super = sup = malloc (sizeof(diskpublisher_super_t));

	/* functions */
	sup->delete = p->delete;
	p->do_send_data = do_send_data;
	p->delete = delete;
	
	/* default values */
	ex -> basedir = strdup(DEFAULT_BASEDIR);
	pthread_mutex_init(&(ex->mutex), NULL);
	
	LL_Iterate(args, arg) {
		switch ((int)arg) {
			case PUBLISHER_TIMESTAMPING:
			case PUBLISHER_TRACE:
				break;
			case PUBLISHER_CHANNEL_PREFIX:
				arg = LL_GetNext(args, arg);

				add_command(arg, PARAM_BASEDIR ARG_BASEDIR, set_basedir, p, DESC_BASEDIR);
				add_config(arg, PARAM_BASEDIR, write_basedir, p);
				break;
			case DISKPUBLISHER_BASEDIR: {
				arg = LL_GetNext(args, arg);
				
				set_basedir(p, NULL, arg);
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
	diskpublisher_extend_t *ex;
	diskpublisher_super_t *sup;

	if (p==NULL)
		return;

	ex = p->extend;
	sup = p->super;
	
	pthread_mutex_lock(&(ex->mutex));
	free (ex->basedir);
	ex->basedir = NULL;
	pthread_mutex_unlock(&(ex->mutex));
	pthread_mutex_destroy(&(ex->mutex));

	free (ex);

	sup->delete(p);
	free(sup);
}

/* XXX make configurable */
#define ARCHIVE_MODE DISKPUBLISHER_ARCLAST
#define NAME_MODE		DISKPUBLISHER_NAMEBYDATE


#define BASE_YEAR 1900	/* not gonna change, but made it a define for clarity */
#define FILE_PERMS (S_IRUSR | S_IWUSR | S_IRGRP)
#define DIR_PERMS (S_IRWXU | S_IROTH | S_IXOTH)
static void do_send_data (void *v, void *data, int dataLen, char *channel) {
	publisher_t *p = (publisher_t *) v;
	diskpublisher_extend_t *ex;
	int res;
	salamander_t *salserver;
	int fd;
	char filepath[PATH_MAX+1], dir[PATH_MAX+1], filelast[PATH_MAX+1];
	char *channelf, *chanpath;
#if defined(_REENTRANT)
	struct tm ftime;				/* ftimep is a kludge so that we can use */
#endif
	struct tm *ftimep;			/* the same code for thread & non-thread */
	time_t now;
#ifdef GEN_OLD_FILES
	char * tmpc;
	time_t oldtime;
#endif GEN_OLD_FILES
	mode_t openmode;

if (p==NULL) return;
ex = p->extend;

	pthread_mutex_lock(&(ex->mutex));
		chanpath = strrep(strdup(channel), ':', '/');
/* XXX snprintf */
		sprintf(dir, "%s/%s", ex->basedir, chanpath);
	pthread_mutex_unlock(&(ex->mutex));
	free(chanpath);
	channelf = strrep(strdup(channel), ':', '_');

#ifdef GEN_OLD_FILES
	tmpc = getProperty (p->properties, TIME_PROPERTY);
	if (tmpc == NULL) {
	    now = time (0);
	    trace (TR_TRACE, p->trace, "DiskPublisher: filename set to now\n");
        }
	
	else { 
	    oldtime = atol (tmpc);
	    trace (TR_TRACE, p->trace, 
		   "DiskPublisher: filename set to oldtime = %u\n", oldtime);
        }
	
        now = oldtime;	
#else 
	now = time(0); /* XXX use time property of data?? */
#endif GEN_OLD_FILES
#if defined(_REENTRANT)
		ftimep = gmtime_r(&now, &ftime);
#else
		ftimep = gmtime(&now);
#endif

/* XXX snprintf */
	sprintf(filelast, "%s/%s.last", dir, channelf);
/* this naming convention doesn't deal well with DT<->ST changes */
	if (NAME_MODE == DISKPUBLISHER_NAMEBYDATE)
		sprintf(filepath, "%s/%s.%d.%02d.%02d", dir, channelf,
			ftimep->tm_year+BASE_YEAR, ftimep->tm_mon+1, ftimep->tm_mday);
	else if (NAME_MODE == DISKPUBLISHER_NAMEBYTIME)
		sprintf(filepath, "%s/%s.%d.%02d.%02d_%02d.%02d", dir, channelf,
			ftimep->tm_year+BASE_YEAR, ftimep->tm_mon+1, ftimep->tm_mday,
			ftimep->tm_hour, ftimep->tm_min);
	else if (NAME_MODE == DISKPUBLISHER_NAMEBYUTCSEC)
		sprintf(filepath, "%s/%s.%lu", dir, channelf, now);
	else if (NAME_MODE == DISKPUBLISHER_NAMELAST)
		strcpy(filepath, filelast);
	else
/* error */;

	if (ARCHIVE_MODE == DISKPUBLISHER_ARCLAST)
		openmode = O_WRONLY | O_CREAT | O_TRUNC;
	else if (ARCHIVE_MODE == DISKPUBLISHER_ARCALL)
		openmode = O_WRONLY | O_CREAT | O_APPEND;
	else
/* error */;
		
	fd = open(filepath, openmode, FILE_PERMS);
	if (fd==-1) {
		if (errno==ENOENT) {
			if (rmkdir(dir, DIR_PERMS) != 0)
				goto error_mkdir;
			fd = open(filepath, openmode, FILE_PERMS);
			if (fd==-1)
				goto error_open;
		} else
			goto error_open;
	}
	
	free(channelf); 
	salserver = New_SalamanderFile(fd);
	res = salamanderSendServerData(salserver, p->properties, data, dataLen);
															if (res != SALAMANDER_OK)
																goto error_send;
	Delete_Salamander(salserver);

#ifndef GEN_OLD_FILES
	if (symlink(filepath, filelast) != 0) {
		if (errno == EEXIST) {
			if (unlink(filelast)!=0)
				goto error_unlink;
			if (symlink(filepath, filelast)!=0)
				goto error_link;
		} else
			goto error_link;
	}
#endif GEN_OLD_FILES	

	return;

	error_mkdir:
		perror("send_data");
		trace(TR_ERROR, p->trace, "Could not make directory %s\n", dir);
		free(channelf);
		return;
	error_open:
		perror("send_data");
		trace(TR_ERROR, p->trace, "Could not open %s\n", filepath);
		free(channelf);
		return;
	error_send:
		perror("send_data");
		trace(TR_ERROR, p->trace,
			"salamanderSendServerData error. Return code %d.\n", res);
		Delete_Salamander(salserver);
		return;
	error_link:
		perror("send_data");
		trace(TR_ERROR, p->trace, "Could not make link %s\n", filelast);
		return;
	error_unlink:
		perror("send_data");
		trace(TR_ERROR, p->trace, "Could not unlink %s\n", filelast);
}

static int set_basedir(publisher_t *p, uii_connection_t *uii, char *basedir) {
	diskpublisher_extend_t *ex;
	DIR *d;

if (p==NULL) return -1;
	ex = p->extend;
	
	pthread_mutex_lock(&(ex->mutex));

	if ((d=opendir(basedir))!=NULL)
		closedir(d);
	else if (rmkdir(basedir, S_IRWXU | S_IROTH | S_IXOTH) != 0) {
		uii_send_data (uii, "The specifed directory could not be created.\r\n");
		perror("set_basedir");
		pthread_mutex_unlock(&(ex->mutex));
		return -1;
	}

	free(ex->basedir);
	ex->basedir = strdup(basedir);

	pthread_mutex_unlock(&(ex->mutex));
	return 0;
}

#define ENDLINE "\r\n"
static void write_basedir(publisher_t *p) {
	diskpublisher_extend_t *ex;

if (p==NULL) return;
	ex = p->extend;

	pthread_mutex_lock(&(ex->mutex));
	config_add_output("%s " PARAM_BASEDIR ARG_BASEDIR ENDLINE, p->channel_prefix,
		ex->basedir); 
	pthread_mutex_unlock(&(ex->mutex));
}


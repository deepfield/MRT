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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <config_file.h>
#include <trace.h>
#include "dir.h"

/* globals defined elsewhere */
extern config_t CONFIG;				/* XXX pass in as arg? */

dir_t *New_dir() {
	dir_t *t;
	
	t = malloc (sizeof(dir_t));
															if (t==NULL) goto error;	

	t -> dirinfo = NULL;
#if defined(_REENTRANT)
	t -> curfile = NULL;
#endif
	t -> open = FALSE;

	return t;
	
	error:
		trace(TR_ERROR, CONFIG.trace, "New_dir failed to allocate memory.\n");
		perror("New_dir");
		return NULL;
}

void Delete_dir(dir_t *t) {
	if (t->open)
		dir_close(t);

	free (t);
}

/* return 0 on okay, -1 on error */
int dir_open(dir_t *d, char *path) {
	if (d->open) {
		trace(TR_WARN, CONFIG.trace, "dir_open called when already open.\n");
		return -1;
	}

#if defined(_REENTRANT)	
	d->curfile = malloc (sizeof(struct dirent) + MAXPATHLEN + 1);
															if (d->curfile == NULL)
																goto error_memory;
#endif

	d->dirinfo = opendir(path);
															if (d->dirinfo == NULL)
																goto error_dir;
	
	d->open = TRUE;
	return 0;

#if defined(_REENTRANT)
	error_memory:
		trace(TR_ERROR, CONFIG.trace,
			"Couldn't open directory because malloc failed.\n");
		perror("dir_open");
		return -1;
#endif

	error_dir:
		trace(TR_ERROR, CONFIG.trace, "Couldn't open directory %s\n", path);
		perror("dir_open");
		return -1;
}

/* return 0 on okay, -1 on error */
int dir_close(dir_t *d) {
	int res;
	
	res = closedir(d->dirinfo);
															if (res != 0) goto error;
	d->dirinfo = NULL;
	d->open = FALSE;
#if defined(_REENTRANT)
	free(d->curfile);
	d->curfile = NULL;
#endif
	return 0;
	
	error:
		d->dirinfo = NULL;
		d->open = FALSE;
#if defined(_REENTRANT)
		free(d->curfile);
		d->curfile = NULL;
#endif
		trace(TR_ERROR, CONFIG.trace, "Failed to close directory.\n");
		perror("dir_close");
		return -1;
}

/*
	return result from readdir_r
	user must copy path before next call to dir_get_next
*/
int dir_get_next(dir_t *d, char **path) {
#if defined(_REENTRANT)
	struct dirent *file;
	int res;

	res = readdir_r(d->dirinfo, d->curfile, &file);
															if (res != 0) goto error;
						
	if (file != NULL)
		*path = strdup(d->curfile->d_name);
	else 
		*path = NULL;
		
/*fprintf(stderr, "%s\n", *path);*/
	return res;

	error:
		if (res != EINVAL)	/* what we get when we read past the end */
			trace(TR_ERROR, CONFIG.trace, "dir_get_next: %s\n", strerror(res));
		*path = NULL;
		return res;
#else
	struct dirent *file;
	
	errno = 0;
	file = readdir(d->dirinfo);
															if (errno != 0) goto error;
															
	if (file != NULL)
		*path = strdup(file->d_name);
	else
		*path = NULL;
	return 0;
	
	error:
		trace(TR_ERROR, CONFIG.trace, "dir_get_next: %s\n", strerror(errno));
		*path = NULL;
		return errno;
#endif
}

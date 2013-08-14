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
#include <stdlib.h>
#include <sys/types.h>
#include <regex.h>
#include <sys/stat.h>

#include <linked_list.h>
#include <mrt.h>
#include <config_file.h>

#include "dir.h"
#include "mytime.h"

#define APP_DESC					"Data Distiller"

#define PROMPT_PASSWORD			"password> "
#define PROMPT_CONFIG			"config> "

#define COMMAND_CONFIG			"config"
#define COMMAND_WRITE			"write"
#define COMMAND_REBOOT			"reboot"
#define COMMAND_SHOW_CONFIG	"show config"

#define HELP_CONFIG				"Modify settings"
#define HELP_WRITE				"Save settings"
#define HELP_REBOOT				"Restart"
#define HELP_SHOW_CONFIG		"Show settings"

LINKED_LIST *makeargs(int first, ...) {
        va_list argp;
        LINKED_LIST *list;
        void *arg; 
 
        list = LL_Create(0, NULL);
        
        va_start(argp, first);
	LL_Add(list, (void *)first);
	while ((arg = va_arg(argp, void*)) != NULL)
		LL_Add(list, arg);
        va_end(list);

        return list;
}

LINKED_LIST *makelistn(int count, ...) {
	va_list argp;
	LINKED_LIST *list;
	void *arg;
	int i;
	
	list = LL_Create(0, NULL);

	va_start(argp, count);
	for (i=0; i < count; i++) {
		arg = va_arg(argp, void *);
		LL_Add(list, arg);
	}
	va_end(list);
	
	return list;
}

void DeleteNodeData(DATA_PTR node_data) {
	free (node_data);
}

LINKED_LIST *copy_file_list(LINKED_LIST *orig) {
	char *name;
	LINKED_LIST *list_copy;

trace(TR_TRACE, CONFIG.trace, "==> copy_file_list\n");	
	if (orig==NULL)
		return NULL;
		
	list_copy = LL_Create(LL_DestroyFunction, DeleteNodeData, NULL);
	
	LL_Iterate(orig, name) {
		char *name_copy;
		
		name_copy = strdup(name);
/* check for NULL */
		LL_Add(list_copy, name_copy);		
	}
trace(TR_TRACE, CONFIG.trace, "<== copy_file_list\n");	
	return list_copy;
}

LINKED_LIST *get_files_match(char *path, char *regexp, int include_dotfiles) {
	dir_t *d;
	char *name;
	regex_t re;
	LINKED_LIST *file_list;
	int res;

	if (regexp != NULL) {
		res = regcomp(&re, regexp, REG_EXTENDED);
															if (res != 0)
																goto error_compile;
	}

	file_list = LL_Create(LL_DestroyFunction, DeleteNodeData, NULL);

	d = New_dir();
	res = dir_open (d, path);
															if (res != 0) goto error_open;
	
	/* any error in dir_get_next will cause us to terminate the directory
	   scan. (since dir_get_next returns NULL on any error, in addition
		to when it reaches the end of the directory list.) */
	dir_get_next(d, &name);
	while (name != NULL) {
		int matches_re, is_dotfile;

/* XXX check regexec call return for error */
		if (regexp)
			matches_re = regexec(&re, name, 0, NULL, 0);
		else							/* not necessary, but makes gcc shut up */
			matches_re = 0;

		is_dotfile = (*name == '.');
				
		if (((!regexp) || (matches_re!=REG_NOMATCH)) && (include_dotfiles ||
		!is_dotfile)) {
			char *name_copy;
			
			name_copy = strdup(name);
			LL_Add(file_list, name_copy);
		}
		
		free(name);
		dir_get_next(d, &name);
	}
	
	dir_close(d);
	Delete_dir(d);

	return file_list;

	error_open:
		trace(TR_ERROR, CONFIG.trace, "Couldn't open directory %s.\n", path);
		perror("get_files_match");
		Delete_dir(d);
		LL_Destroy(file_list);
		return NULL;

	error_compile:
		trace (TR_ERROR, CONFIG.trace, "Could not compile regexp.\n");
		perror("get_files_match");
		return NULL;
}

/* must call init_config(trace_t) before using this function */
void setup_config() {
	/*
	 I ripped this from route_tracker/config.c. AFAICT, the reason for
	 having separate calls to config_add_module (instead of making one giant
	 string) is because get_comment_config handles the \r\n convention for
	 over-the-wire EOL. I guess freeing the memory we allocate here is
	 somebody else's responsibility. --mukesh
	*/
	char *tmp;

	tmp = strdup ("#####################################################################");
	config_add_module (0, "comment", get_comment_config, tmp);

	tmp = malloc (512);
	sprintf (tmp, "# %s -- MRT version %s ", APP_DESC, MRT_VERSION);
	config_add_module (0, "comment", get_comment_config, tmp);

	tmp = strdup  ("#####################################################################");
	config_add_module (0, "comment", get_comment_config, tmp);

	config_add_module (0, "comment", get_comment_config, strdup ("!"));
	config_add_module (0, "debug", get_debug_config, NULL);
}

time_t get_tz_offset() {
#if defined(_REENTRANT)
	struct tm now_utc_struct;
#endif
	struct tm *now_utc_struct_p;
	time_t now_local_seconds, now_utc_seconds;

	now_utc_seconds = time(0);
#if defined(_REENTRANT)
	now_utc_struct_p = gmtime_r(&now_utc_seconds, &now_utc_struct);
#else
	now_utc_struct_p = gmtime(&now_utc_seconds);
#endif
	now_utc_struct_p->tm_isdst = -1;
	now_local_seconds = mktime_r(now_utc_struct_p);
	return now_local_seconds - now_utc_seconds;
}

int rmkdir(char *path, mode_t mode) {
	char *end, *curr;
	int res=0;
	
	curr = path;
	if(*curr == '/') curr++;
	end = strchr(curr, '/');
	while (end != NULL) {
		*end = '\0';
		res = mkdir(path, mode);
		*end = '/';

		/*
		   we only abort on NOENT because the others (e.g. EEXIST)
		   may be recoverable. (e.g. path is /a/b/c/d, and we're

			for example
				rmkdir("/a/b/c/d", blah);
				if /a/b exists, then mkdir("/a/b") we'll get an EEXIST, but we
				want to continue.
				if it doesn't, then mkdir("/a/b/c") will get a ENOENT, and
				then we've only "wasted" one iteration.
		*/
			
		if ((res==-1) && (errno==ENOENT))
			return res;
			
		curr = end+1;
	
		end = strchr(curr, '/');
	}
	if (path[strlen(path)] != '/')
		res = mkdir(path, mode);

	return res;
}

char *strrep(char *str, char old, char new) {
	char *t;
	
	while((t=strchr(str, old))!=NULL)
		*t = new;

	return str;
}

int add_command(char *prefix, char *command, void *func, void *arg, char
*desc) {
	char *buffer;
	int ret;

	buffer = malloc(sizeof(char)*(strlen(prefix)+strlen(command)+2));
	sprintf(buffer, "%s %s", prefix, command);
	ret = uii_add_command_arg(UII_CONFIG, COMMAND_NORM, buffer, func, arg, desc);
	free(buffer);
	return ret;
}

int add_config(char *prefix, char *command, void *func, void *arg) {
	char *buffer;
	int ret;

	buffer = malloc(sizeof(char)*(strlen(prefix)+strlen(command)+2));
	sprintf(buffer, "%s %s", prefix, command);
	ret = config_add_module(0, buffer, func, arg);
	free(buffer);
	return ret;
}


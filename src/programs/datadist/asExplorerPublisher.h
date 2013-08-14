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

#ifndef ASEXPLORER_PUBLISHER_H
#define ASEXPLORER_PUBLISHER_H

#define PARAM_ASE_OUTTYPE			"ASExplorer output_method"
#define PARAM_ASE_PUBLISH_INTERVAL		"ASExplorer update_interval"
#define PARAM_ASE_DURATION					"ASExplorer report_time_range"
#define PARAM_ASE_PNAME						"ASExplorer probe_name"
#define DESC_ASE_OUTTYPE \
	"How cooked data should be stored"
#define DESC_ASE_PUBLISH_INTERVAL \
	"Time between ASExplorer updates in seconds, 0 to disable"
#define DESC_ASE_SALY_SERVER \
	"Publish ASExplorer data to this host"
#define DESC_ASE_SALY_PORT \
	"Port that Salamander is running on"
#define DESC_ASE_DURATION \
	"Time range covered in a report"
#define DESC_ASE_PNAME \
	"Set LOCATION property for a directory"

void init_asExplorerPublisher(trace_t *trace);
void asExplorerPublisher_doUpdate();
void asExplorerPublisher_setOutType(uii_connection_t *uii, char *mode);
void asExplorerPublisher_getOutType(void *ignored);
void asExplorerPublisher_setDuration(uii_connection_t *uii, int new_duration);
void asExplorerPublisher_getDuration(void *ignored);
void asExplorerPublisher_setProbeName(uii_connection_t *uii, char *dir_name,
	char *probe_name);
void asExplorerPublisher_getProbeName(char *dir_name);
#ifdef GEN_OLD_FILES
void asExplorer_setStartDate(uii_connection_t *uii, char *mode);
void asExplorer_setEndDate(uii_connection_t *uii, char *mode);
void asExplorer_getStartDate(void *ignored);
void asExplorer_getEndDate(void *ignored);
#endif GEN_OLD_FILES
#endif

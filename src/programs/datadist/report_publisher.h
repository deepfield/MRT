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
#ifndef REPORT_PUBLISHER_H
#define REPORT_PUBLISHER_H

#define PARAM_FG_PUBLISH_INTERVAL	"FlapGraph update_interval"
#define PARAM_FG_OUTTYPE                       "FlapGraph output_method"

#define PARAM_FTD_PUBLISH_INTERVAL	"FlapTableDaily update_interval"
#define PARAM_FTD_OUTTYPE                       "FlapTableDaily output_method"


#define PARAM_FG_TIMEFLAG				"FlapGraph use_localtime"
#define PARAM_FTD_TIMEFLAG				"FlapTableDaily use_localtime"

#define DESC_FG_PUBLISH_INTERVAL \
	"Time between FlapGraph updates in seconds, 0 to disable"
#define DESC_FTD_PUBLISH_INTERVAL \
	"Time between FlapTableDaily updates in seconds, 0 to disable"
#define DESC_FG_OUTTYPE \
        "How cooked data should be stored"
#define DESC_FTD_OUTTYPE \
        "How cooked data should be stored"

#define DESC_FG_TIMEFLAG \
	"Use local time for FlapGraph reports? (will also change FlapTableDaily)"
#define DESC_FTD_TIMEFLAG \
	"Use local time for FlapTableDaily reports? "\
	"(will also change FlapGraph)"

void start_publisher_thread(trace_t *trace);
void terminate_publisher_thread();
void flapGraphAndTablePublisher_doFGUpdate();
void flapGraphAndTablePublisher_doFTDUpdate();
void flapGraphAndTablePublisher_setFGOutType(uii_connection_t *uii, char *mode);
void flapGraphAndTablePublisher_setFTDOutType(uii_connection_t *uii, char *mode);
void flapGraphAndTablePublisher_setLocaltimeFlag(uii_connection_t *uii,
	int val);
#ifdef GEN_OLD_FILES
void flapGraph_setStartDate(uii_connection_t *uii, char *mode);
void flapGraph_setEndDate(uii_connection_t *uii, char *mode);
void flapTableDaily_setStartDate(uii_connection_t *uii, char *mode);
void flapTableDaily_setEndDate(uii_connection_t *uii, char *mode);
#endif GEN_OLD_FILES
void flapGraphAndTablePublisher_getFGOutType(void *ignored);
void flapGraphAndTablePublisher_getFTDOutType(void *ignored);
void flapGraphAndTablePublisher_getLocaltimeFlag(void *ignored);
#ifdef GEN_OLD_FILES
void flapGraph_getStartDate(void *ignored) ;
void flapGraph_getEndDate(void *ignored);
void flapTableDaily_getStartDate(void *ignored) ;
void flapTableDaily_getEndDate(void *ignored);
#endif GEN_OLD_FILES
#endif

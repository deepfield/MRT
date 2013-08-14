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

#ifndef DISKPUBLISHER_H
#define DISKPUBLISHER_H

#include "../SalyClient2/salamanderInterface.h"
#include "../SalyClient2/propertyList.h"

#define DISKPUBLISHER_BASEDIR 		21
#define DISKPUBLISHER_NAMEMODE		22
#define DISKPUBLISHER_ARCMODE			23

#define DISKPUBLISHER_NAMEBYDATE			1
#define DISKPUBLISHER_NAMEBYTIME			2
#define DISKPUBLISHER_NAMEBYUTCSEC		3
#define DISKPUBLISHER_NAMELAST			4

#define DISKPUBLISHER_ARCLAST				1
#define DISKPUBLISHER_ARCALL				2

typedef struct {
/* new fields */
	char *basedir;
	pthread_mutex_t mutex;
} diskpublisher_extend_t;

/* have super_t defined in base class? */
typedef struct {
	void (*delete)(void *p);
} diskpublisher_super_t;

publisher_t *New_DiskPublisher(LINKED_LIST *args);

#endif

/*
 * $Id: mrt_thread.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _MRT_THREAD_H
#define _MRT_THREAD_H

#include "config.h"

#ifndef HAVE_LIBPTHREAD
#include "pthread_fake.h"
#else
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif /* HAVE_PTHREAD_H */
#endif /* HAVE_LIBPTHREAD */

#ifndef HAVE_SIGPROCMASK
typedef unsigned long sigset_t;
#endif /* HAVE_SIGPROCMASK */

#ifndef HAVE_PTHREAD_ATTR_SETSCOPE
#define pthread_attr_setscope(attr, scope) /* nothing */
#endif /* HAVE_PTHREAD_ATTR_SETSCOPE */

#endif /* _MRT_THREAD_H */

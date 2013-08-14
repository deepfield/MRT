/*
 * $Id: object.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _OBJECT_H
#define _OBJECT_H

/* The object_master is just a handy place to keep track of
 * all the threads/objects floating around. Sometimes need to
 * do things as shutting down all objects (i.e. releasing message
 * queues, or shutting down sockets cleanly on exit).
 *
 * In future, may have scheduling control.
 */


typedef struct _object_master_t {
  LINKED_LIST *ll_objects;
} object_master_t;

int init_object ();
int add_object (void *obj);
int delete_object (void *obj);
int shutdown_objects ();

#endif /* _OBJECT_H */

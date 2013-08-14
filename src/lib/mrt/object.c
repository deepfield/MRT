/*
 * $Id: object.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <linked_list.h>
#include <object.h>


object_master_t *OBJECT_MASTER;

int 
init_object ()
{
  OBJECT_MASTER = New (object_master_t);
  OBJECT_MASTER->ll_objects = LL_Create (NULL);

  return (1);
}


int 
add_object (void *obj) {
  


}

int 
delete_object (void *obj) {
  


}


int 
shutdown_objects () {



}

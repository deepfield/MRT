/*
 * $Id: protocol.h,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */


typedef struct _Protocol_Struct {
   int (*same_peer)(generic_attr_t *p_attr1, generic_attr_t *p_attr2);

} Protocol;


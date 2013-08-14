/*
 * $Id: filter.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _FILTER_H
#define _FILTER_H

#include <aspath.h>

#define ROUTE_MAP_ASPATH_PREPEND 0x01

#define MAX_ROUTE_MAP 100
typedef struct _route_map_t {
    int num;
    int precedence;
    u_long flag;
    int alist;
    int flist;
    int clist;
    bgp_attr_t *attr;
} route_map_t;

route_map_t *add_route_map (int num, int precedence, u_long flag);
int get_route_map_num (int num);
int del_route_map (int num, int precedence);
bgp_attr_t *apply_route_map (int num, bgp_attr_t *attr, prefix_t *prefix, int destructive);
void route_map_out (int num, void_fn_t fn);
int apply_route_map_alist (int num, prefix_t *prefix);

#endif /* _FILTER_H */

/*
 * $Id: none.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>


int
read_interfaces (trace_t * ltrace)
{
    /* new_interface (name, flags, mtu, index); */
    /* add_addr_to_interface (interface, family, addr, len, broadcast); */
    return (1);
}


int 
kernel_add_route (prefix_t * dest, prefix_t * next_hop)
{
    return (1);
}

int sys_kernel_read_rt_table ()
{
   /* add_kernel_route (family, dest, nhop, masklen, index); */
   return (1);
}

/* kernel_update_route
 * 0 = add, 1 = change, 2 = delete
 */
int sys_kernel_update_route (prefix_t *dest, 
			 prefix_t *next_hop, prefix_t *old_hop, 
			 int index, int oldindex)
{
    return (1);
}

int kernel_init ()
{
    return (1);
}

#ifndef __included_vcdp_common_h__
#define __included_vcdp_common_h__

#include <vnet/vnet.h>

typedef struct
{
  u32 service_bitmap;
  u16 tenant_index;
  u8 tcp_flags;
} vcdp_buffer_opaque_t;

STATIC_ASSERT (sizeof (vcdp_buffer_opaque_t) <=
		 sizeof (vnet_buffer ((vlib_buffer_t *) 0)->unused),
	       "size of vcdp_buffer_opaque_t must be <= size of "
	       "vnet_buffer_opaque_t->unused");

#define vcdp_buffer(b) ((vcdp_buffer_opaque_t *) vnet_buffer (b)->unused)

#endif

#ifndef __VCDP_SESSION_H__
#define __VCDP_SESSION_H__

#include <vcdp/vcdp.h>

static inline vcdp_session_t *
vcdp_session_from_lookup_value(vcdp_main_t *vcdp, u64 value, u32 *thread_index, u32 *session_index)
{
  // Figure out if this is local or remote thread
  *thread_index = vcdp_thread_index_from_lookup(value);
  /* known flow which belongs to this thread */
  u32 flow_index = value & (~(u32) 0);
  *session_index = vcdp_session_from_flow_index(flow_index);
  vcdp_per_thread_data_t *ptd = vec_elt_at_index(vcdp->per_thread_data, *thread_index);
  return vcdp_session_at_index_check(ptd, *session_index);
}

#endif /* __VCDP_SESSION_H__ */

/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_vcdp_timer_h__
#define __included_vcdp_timer_h__
#include <vppinfra/tw_timer_2t_1w_2048sl.h>
#include <vppinfra/vec.h>
typedef tw_timer_wheel_2t_1w_2048sl_t vcdp_tw_t;
#define vcdp_tw_init			   tw_timer_wheel_init_2t_1w_2048sl
#define vcdp_timer_start		   tw_timer_start_2t_1w_2048sl
#define vcdp_timer_stop			   tw_timer_stop_2t_1w_2048sl
#define vcdp_timer_update		   tw_timer_update_2t_1w_2048sl
#define vcdp_expire_timers		   tw_timer_expire_timers_2t_1w_2048sl
#define VCDP_TIMER_SI_MASK		   (0x7fffffff)
#define VCDP_TIMER_INTERVAL		   ((f64) 1.0) /*in seconds*/
#define VCDP_TIMER_EMBRYONIC_TIMEOUT	   (5)
#define VCDP_TIMER_ESTABLISHED_TIMEOUT	   (120)
#define VCDP_TIMER_TCP_ESTABLISHED_TIMEOUT (3600)
#define VCDP_TIMER_SECURITY_TIMER	   (30)

static_always_inline uword
vec_reset_len_return (u32 *v)
{
  vec_reset_length (v);
  return 0;
}

#define vcdp_session_index_iterate_expired(ptd, s)                            \
  for (u32 *s_ptr = (ptd)->expired_sessions;                                  \
       ((s_ptr < vec_end (ptd->expired_sessions)) &&                          \
	(((s) = s_ptr[0]) || 1)) ||                                           \
       vec_reset_len_return ((ptd)->expired_sessions);                        \
       s_ptr++)

#endif /* __included_vcdp_timer_h__ */
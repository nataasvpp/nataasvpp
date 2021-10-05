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
#ifndef __included_vcdp_tcp_check_h__
#define __included_vcdp_tcp_check_h__

#include <vlib/vlib.h>
#include <vcdp/vcdp.h>
/* Convention: uppercase relates to responder lowercase to initiator */
#define foreach_vcdp_tcp_check_session_flag                                   \
  _ (WAIT_FOR_RESP_SYN, 0, "S")                                               \
  _ (WAIT_FOR_INIT_ACK_TO_SYN, 1, "a")                                        \
  _ (WAIT_FOR_RESP_ACK_TO_SYN, 2, "A")                                        \
  _ (SEEN_FIN_INIT, 3, "f")                                                   \
  _ (SEEN_FIN_RESP, 4, "F")                                                   \
  _ (SEEN_ACK_TO_FIN_INIT, 5, "r")                                            \
  _ (SEEN_ACK_TO_FIN_RESP, 6, "R")                                            \
  _ (ESTABLISHED, 7, "U")                                                     \
  _ (REMOVING, 8, "D")                                                        \
  _ (BLOCKED, 9, "X")

typedef enum
{
#define _(name, x, str) VCDP_TCP_CHECK_SESSION_FLAG_##name = (1 << (x)),
  foreach_vcdp_tcp_check_session_flag VCDP_TCP_CHECK_SESSION_N_FLAG
#undef _
} vcdp_tcp_check_session_flag_t;

#define VCDP_TCP_CHECK_TCP_FLAGS_MASK (0x17)
#define VCDP_TCP_CHECK_TCP_FLAGS_FIN  (0x1)
#define VCDP_TCP_CHECK_TCP_FLAGS_SYN  (0x2)
#define VCDP_TCP_CHECK_TCP_FLAGS_RST  (0x4)
#define VCDP_TCP_CHECK_TCP_FLAGS_ACK  (0x10)
/* transitions are labelled with TCP Flags encoded in u8 as
   0 0 0 ACK 0 RST SYN FIN
   Transition table for each direction is 32x9
   result of the lookup is (what is set, what is cleared)
 */
/*#define foreach_vcdp_tcp_check_forward_transition \
_(WAIT_FOR_INIT_ACK_TO_SYN, ACK, )*/

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 flags;
  union
  {
    u32 fin_num[VCDP_FLOW_F_B_N];
    u64 as_u64_0;
  };
  session_version_t version;
} vcdp_tcp_check_session_state_t;

typedef struct
{
  vcdp_tcp_check_session_state_t *state; /* vec indexed by session-index */
} vcdp_tcp_check_per_thread_data_t;

typedef struct
{
  vcdp_tcp_check_per_thread_data_t *ptd;
  u16 msg_id_base;
} vcdp_tcp_check_main_t;

extern vcdp_tcp_check_main_t vcdp_tcp;

format_function_t format_vcdp_tcp_check_session_flags;
format_function_t format_vcdp_tcp_check_session;
#endif /* __included_vcdp_tcp_check_h__ */
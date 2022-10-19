// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_tcp_check_h
#define included_vcdp_tcp_check_h

#include <vlib/vlib.h>
#include <vcdp/vcdp.h>
/* Convention: uppercase relates to responder lowercase to initiator */
#define foreach_vcdp_tcp_check_session_flag                                                                            \
  _(WAIT_FOR_RESP_SYN, 0, "S")                                                                                         \
  _(WAIT_FOR_INIT_ACK_TO_SYN, 1, "a")                                                                                  \
  _(WAIT_FOR_RESP_ACK_TO_SYN, 2, "A")                                                                                  \
  _(SEEN_FIN_INIT, 3, "f")                                                                                             \
  _(SEEN_FIN_RESP, 4, "F")                                                                                             \
  _(SEEN_ACK_TO_FIN_INIT, 5, "r")                                                                                      \
  _(SEEN_ACK_TO_FIN_RESP, 6, "R")                                                                                      \
  _(ESTABLISHED, 7, "U")                                                                                               \
  _(REMOVING, 8, "D")                                                                                                  \
  _(BLOCKED, 9, "X")

typedef enum {
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

typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
  u32 flags;
  union {
    u32 fin_num[VCDP_FLOW_F_B_N];
    u64 as_u64_0;
  };
  session_version_t version;
} vcdp_tcp_check_session_state_t;

typedef struct {
  vcdp_tcp_check_session_state_t *state; /* vec indexed by session-index */
} vcdp_tcp_check_per_thread_data_t;

typedef struct {
  vcdp_tcp_check_per_thread_data_t *ptd;
  u16 msg_id_base;
} vcdp_tcp_check_main_t;

extern vcdp_tcp_check_main_t vcdp_tcp;

format_function_t format_vcdp_tcp_check_session_flags;
u32
vcdp_table_format_insert_tcp_check_session(table_t *t, u32 n, vcdp_main_t *vcdp, u32 session_index,
                                           vcdp_session_t *session, vcdp_tcp_check_session_state_t *tcp_session);

#endif /* __included_vcdp_tcp_check_h__ */
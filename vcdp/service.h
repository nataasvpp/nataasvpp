// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_vcdp_service_h
#define included_vcdp_service_h
#include <vlib/vlib.h>
#include <vcdp/common.h>

typedef u8* (*format_service_fn)(u8 *s, u32 thread_index, u32 session_index);
typedef struct _vcdp_service_registration_t {
  struct _vcdp_service_registration_t *next;
  const char *node_name;
  char *icmp_error;
  u32 icmp_error_mask;
  char **runs_before;
  char **runs_after;
  u8 *index_in_bitmap;
  u32 *service_mask;
  u8 is_terminal;
  u8 is_tcp_specific;
  format_service_fn format_service;
} vcdp_service_registration_t;

typedef struct {
  vcdp_service_registration_t *next_service;
  vcdp_service_registration_t **services;
  uword *service_index_by_name;
} vcdp_service_main_t;

extern vcdp_service_main_t vcdp_service_main;

#define VCDP_SERVICE_DECLARE(x)                                                                                        \
  extern u8 vcdp_service_index_in_bitmap_##x;                                                                          \
  extern u32 vcdp_service_mask_##x;

#define VCDP_SERVICE_MASK(x)  vcdp_service_mask_##x
#define VCDP_SERVICE_INDEX(x) vcdp_service_index_in_bitmap_##x

#ifndef CLIB_MARCH_VARIANT
#define VCDP_SERVICE_DEFINE(x)                                                                                         \
  static vcdp_service_registration_t vcdp_service_registration_##x;                                                    \
  static void __vcdp_service_add_registration_##x(void) __attribute__((__constructor__));                              \
  u8 vcdp_service_index_in_bitmap_##x;                                                                                 \
  u32 vcdp_service_mask_##x;                                                                                           \
  static void __vcdp_service_add_registration_##x(void)                                                                \
  {                                                                                                                    \
    vcdp_service_main_t *sm = &vcdp_service_main;                                                                      \
    vcdp_service_registration_t *r = &vcdp_service_registration_##x;                                                   \
    r->next = sm->next_service;                                                                                        \
    sm->next_service = r;                                                                                              \
    r->index_in_bitmap = &vcdp_service_index_in_bitmap_##x;                                                            \
    r->service_mask = &vcdp_service_mask_##x;                                                                          \
  }                                                                                                                    \
  static vcdp_service_registration_t vcdp_service_registration_##x
#else
#define VCDP_SERVICE_DEFINE(x)                                                                                         \
  VCDP_SERVICE_DECLARE(x);                                                                                             \
  static vcdp_service_registration_t __clib_unused unused_vcdp_service_registration_##x

#endif

#define VCDP_SERVICES(...)                                                                                             \
  (char *[]) { __VA_ARGS__, 0 }

static_always_inline void
vcdp_next(vlib_buffer_t *b, u16 *next_index)
{
  u32 bmp = vcdp_buffer(b)->service_bitmap;
  u8 first = __builtin_ffs(bmp);
  ASSERT(first != 0);
  *next_index = (first - 1);
  vcdp_buffer(b)->service_bitmap ^= 1 << (first - 1);
}

void
vcdp_service_next_indices_init(vlib_main_t *vm, uword node_index);

#endif //__included_service_h__
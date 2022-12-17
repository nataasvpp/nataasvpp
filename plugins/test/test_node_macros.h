// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_test_node_macros_h
#define included_test_node_macros_h

/*
 * Always return the frame of generated packets
 */
#define vlib_frame_vector_args test_vlib_frame_vector_args
static inline void *test_vlib_frame_vector_args(vlib_frame_t *f) { return buffers_vector; }


/* Gather output packets */
#define vlib_buffer_enqueue_to_next test_vlib_buffer_enqueue_to_next
static inline void
test_vlib_buffer_enqueue_to_next(vlib_main_t *vm, vlib_node_runtime_t *node, u32 *buffers, u16 *nexts, uword count)
{
  vec_add(results_next, nexts, count);
  vec_add(results_bi, buffers, count);
}

#define vlib_get_buffers test_vlib_get_buffers
static inline void
test_vlib_get_buffers(vlib_main_t *vm, u32 *bi, vlib_buffer_t **b, int count)
{
  int i;
  for (i = 0; i < count; i++) {
    b[i] = (vlib_buffer_t *) &buffers[bi[i]];
  }
}

static inline vlib_buffer_t *
test_vlib_get_buffer(u32 bi)
{
  return (vlib_buffer_t *) &buffers[bi];
}
#endif
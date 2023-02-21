#ifndef __included_punt_h__
#define __included_punt_h__

typedef struct {
  ip4_address_t src;
  ip4_address_t dst;
} vcdp_punt_main_t;

extern vcdp_punt_main_t vcdp_punt_main;

#endif /* __included_punt_h__ */
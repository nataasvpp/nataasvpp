// SPDX-License-Identifier: Apache-2.0
/* DO NOT EDIT: automatically generated by test_genpackets.py */
/* clang-format off */
test_t tests_packets[] = {
  {
    .name = "da rewritten",
    .nsend = 28,
    .send = (char []){0x45,0x00,0x00,0x1c,0x00,0x01,0x00,0x00,0x40,0x11,0x74,0xcb,0x01,0x01,0x01,0x01,0x02,0x02,0x02,0x02,0x00,0x50,0x1a,0xd7,0x00,0x08,0xde,0xb1},
    .nexpect = 28,
    .expect = (char []){0x45,0x00,0x00,0x1c,0x00,0x01,0x00,0x00,0x40,0x11,0x74,0xc9,0x01,0x01,0x01,0x01,0x01,0x02,0x03,0x04,0x00,0x50,0x1a,0xd7,0x00,0x08,0xde,0xaf},
    .expect_next_index = 4242
  },
};
/* clang-format on */

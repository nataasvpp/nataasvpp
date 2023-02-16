// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vnet/plugin/plugin.h>

#define VCDP_PLUGIN_BUILD_VER "1.0"

VLIB_PLUGIN_REGISTER() = {
  .version = VCDP_PLUGIN_BUILD_VER,
  .description = "vCDP Plugin",
};

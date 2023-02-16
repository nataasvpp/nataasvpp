# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.


from deepdiff import DeepDiff

from .exceptions import VppConfigParsingError

##############################################################################


class VppCall:
    def __init__(self, caller):
        self.caller = caller


#####


class VcdpInterface(VppCall):
    def call(self, interface, obj, add):
        is_tunnel = obj.get("tunnel-headend", False)
        if is_tunnel:
            name = "vcdp_gateway_tunnel_enable_disable"
            params = {
                "sw_if_index": interface,
                "is_enable": add,
            }
            self.caller.call(name, params)

        tenant = obj.get("tenant", None)
        if tenant is not None:
            name = "vcdp_gateway_enable_disable"
            params = {"tenant_id": tenant, "sw_if_index": interface, "is_enable": add}
            self.caller.call(name, params)


#####


class VcdpTunnel(VppCall):
    def call(self, tunnel_id, obj, add):
        params = {}
        if add:
            name = "vcdp_tunnel_add"
            params = obj.copy()
            params["tunnel_id"] = tunnel_id
            params["tenant_id"] = params.pop("tenant")
            params["src_mac"] = params.pop("src-mac")
            params["dst_mac"] = params.pop("dst-mac")
            if obj["method"] == "vxlan-dummy-l2":
                params["method"] = 0
            else:
                params["method"] = 1
        else:
            name = "vcdp_tunnel_remove"
            params = dict(tunnel_id=tunnel_id)
        self.caller.call(name, params)


#####


class VcdpNat(VppCall):
    def call(self, nat_id, obj, add):
        name = "vcdp_nat_add" if add else "vcdp_nat_remove"
        params = dict(nat_id=nat_id)
        if add:
            params["addr"] = obj["pool-address"]
            params["n_addr"] = len(obj["pool-address"])
        self.caller.call(name, params)


#####


class VcdpTenant(VppCall):
    def __init__(self, caller):
        super().__init__(caller)
        self.dispatch = {
            "forward-services": self.service,
            "reverse-services": self.service,
            "nat-instance": self.nat_instance,
            "tcp-mss": self.tcp_mss,
        }

    def call(self, tenant_id, obj, add):
        tenant_id = int(tenant_id)

        name = "vcdp_tenant_add_del"
        params = {
            "tenant_id": tenant_id,
            "context_id": obj.get("context", 0),
            "is_add": add,
        }
        # On create, ensure the tenant is created first
        if add:
            self.caller.call(name, params)

        for key, val in obj.items():
            if key in self.dispatch:
                self.dispatch[key](key, tenant_id, val, add)

        # On delete, ensure the tenant is deleted last
        if not add:
            self.caller.call(name, params)

    def service(self, key, tenant_id, obj, is_add):
        if not is_add:
            return

        name = "vcdp_set_services"
        params = {
            "tenant_id": tenant_id,
            "dir": 0 if key == "forward-services" else 1,
            "services": [],
        }
        for srv in obj:
            service = dict(data=srv)
            params["services"].append(service)
        params["n_services"] = len(obj)
        self.caller.call(name, params)

    def nat_instance(self, _, tenant_id, nat_id, is_add):
        name = "vcdp_nat_bind_set_unset"
        params = {
            "tenant_id": tenant_id,
            "nat_id": nat_id,
            "is_set": is_add,
        }
        self.caller.call(name, params)

    def tcp_mss(self, _, tenant_id, mss, is_add):
        name = "vcdp_tcp_mss_enable_disable"
        params = {
            "tenant_id": tenant_id,
            "ip4_mss": mss,
            "is_enable": is_add,
        }
        self.caller.call(name, params)


##############################################################################


class VppConfigParser:

    # Top level sections of the json config, in the order they will be processed
    # For each section, provide the name and the parser class
    sections = (
        ("nats", VcdpNat),
        ("tenants", VcdpTenant),
        ("interfaces", VcdpInterface),
        ("tunnels", VcdpTunnel),
    )

    # Top level sections to ignore. These will exist in a running json config
    # and if that is used as the desired config (for example when restarting
    # the vpp process), we can safely just ignore them
    ignored_sections = [
        "boottime",
        "interface_list",
    ]

    def __init__(self, caller):
        self.sections = [section[0] for section in VppConfigParser.sections]
        self.parsers = {
            section: parser(caller) for section, parser in VppConfigParser.sections
        }

    def parse(self, desired, running):
        # pylint: disable=too-many-branches

        diff = DeepDiff(running, desired, view="tree")

        # If path length is 1, then missing root key.
        #   Do we allow configuration at root level?
        # If path length is 3, then individual field element is changed.
        #   Remove and add object at level 2.
        add_calls = {}
        del_calls = {}
        for changes in diff:
            for obj in diff[changes]:
                if changes == "dictionary_item_added":
                    node = obj.t2
                    add = True
                    calls = add_calls
                elif changes == "dictionary_item_removed":
                    node = obj.t1
                    add = False
                    calls = del_calls
                else:
                    raise VppConfigParsingError(f"Not implemented: {changes} {obj}")

                path = obj.path(output_format="list")
                if len(path) == 2 and path[0] in self.sections:
                    section = path[0]
                    key = path[1]
                    if section not in calls:
                        calls[section] = []
                    calls[section].append((key, node, add))
                else:
                    if path[0] not in self.ignored_sections:
                        raise VppConfigParsingError(
                            "NOT IMPLEMENTED YET", path, changes
                        )

        # Make the vpp api calls in specific order.

        # DELETE calls first, in reverse order of the defined sections (tunnels before nats...)
        for section in reversed(self.sections):
            if section in del_calls:
                for key, node, add in del_calls[section]:
                    self.parsers[section].call(key, node, add)

        # ADD calls second, in order of the defined sections (nats before tunnels...)
        for section in self.sections:
            if section in add_calls:
                for key, node, add in add_calls[section]:
                    self.parsers[section].call(key, node, add)


##############################################################################
# THE END

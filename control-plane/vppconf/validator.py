# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.


import json
import pkgutil

from jsonschema import validate, FormatChecker
from jsonschema.exceptions import ValidationError

from .exceptions import VppConfigValidationError

##############################################################################


class VppConfigValidator:
    def __init__(self):
        self.setup_schema()
        self.formatchecker = FormatChecker(["ipv4"])

    def setup_schema(self):
        schema_text = pkgutil.get_data(__package__, "schema.json")
        self.schema = json.loads(schema_text)

    def validate(self, instance):
        try:
            validate(instance, self.schema)
            self.formatchecker.check(instance, "ipv4")
        except ValidationError as exc:
            raise VppConfigValidationError(exc.message) from None

        # Validate that the internal references are correct

        nat_keys = instance["nats"].keys()
        tenant_keys = {int(k): k for k in instance["tenants"].keys()}

        for _, val in instance["tunnels"].items():
            tenant = val.get("tenant", None)
            if tenant and tenant not in tenant_keys:
                raise VppConfigValidationError(f"Tenant {tenant} is not defined")

        for _, val in instance["tenants"].items():
            nat_instance = val.get("nat-instance", None)
            if nat_instance and nat_instance not in nat_keys:
                raise VppConfigValidationError(
                    f"Nat instance {nat_instance} is not defined"
                )

        for _, val in instance["interfaces"].items():
            tenant = val.get("tenant", None)
            if tenant and tenant not in tenant_keys:
                raise VppConfigValidationError(f"Tenat {tenant} is not defined")

    def validate_file(self, filename):
        with open(filename, "r", encoding="utf-8") as file:
            instance = json.load(file)
        self.validate(instance)


##############################################################################
# THE END

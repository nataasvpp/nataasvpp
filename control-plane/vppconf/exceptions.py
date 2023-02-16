# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.


class VppControlPlaneError(Exception):
    """Base exception for vpp related errors"""


class VppCallerError(VppControlPlaneError):
    """Thrown when a VppCaller received an error or failure response from vpp"""


class VppConfigParsingError(VppControlPlaneError):
    """Thrown when a VppConfigParser cannot parse the configuration"""


class VppConfigValidationError(VppControlPlaneError):
    """Thrown if the vpp configuration cannot be validated"""


##############################################################################
# THE END

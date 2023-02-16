# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
# Copyright(c) 2022 Cisco Systems, Inc.

"""
Process desired configuration against current running configuration (may be 0).
The delta from the above should then be applied to VPP.
And the new running state is stored.

Input: desired configuration, running configuration
Output: Reprogrammed VPP, new running configuration
List of API commands to execute. Named tuple arguments.

"""

import argparse
import json
import logging
import time
import traceback  # pylint: disable=unused-import
from functools import wraps

import yaml
from yaml.loader import SafeLoader

try:
    import IPython  # pylint: disable=unused-import
except ImportError:
    pass

from vppconf.caller import VppAsyncBatchCaller, VppBatchCaller, VppNoopCaller
from vppconf.exceptions import VppControlPlaneError
from vppconf.parser import VppConfigParser

##############################################################################

# Create a logger
logger = logging.getLogger()
console_handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

performance = []


def timeit(func):
    """Timeit decorator"""

    @wraps(func)
    def timeit_wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        total_time = end_time - start_time
        performance.append({"func": func.__name__, "time": total_time})
        return result

    return timeit_wrapper


@timeit
def read_yamlfile(filename):
    """Open the file and load the file"""
    with open(filename, "r", encoding="utf-8") as yaml_file:
        data = yaml.load(yaml_file, Loader=SafeLoader)
    return data


@timeit
def read_jsonfile(filename):
    """Open the file and load the file"""
    with open(filename, "r", encoding="utf-8") as json_file:
        data = json.load(json_file)
    return data


def write_yamlfile(data, filename):
    """Write Python datastructure to YAML file"""
    with open(filename, "w", encoding="utf-8") as yaml_file:
        data = yaml.dump(data, yaml_file)


def write_jsonfile(data, filename):
    """Write Python datastructure to YAML file"""
    with open(filename, "w", encoding="utf-8") as json_file:
        json.dump(data, json_file, indent=4)


# little wrapper functions so we can @timeit the calls


@timeit
def parse_state(parser, desired, running):
    parser.parse(desired, running)


@timeit
def call_vpp(caller):
    caller.call_batch()


##############################################################################


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="VPP Configuration.")
    parser.add_argument("--desired-conf", dest="desired", help="Desired configuration")
    parser.add_argument(
        "--running-conf",
        dest="running",
        help="Current Running configuration",
    )
    parser.add_argument(
        "--new-running-conf",
        dest="new_running",
        help="New Running configuration",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes to running VPP instance",
    )
    parser.add_argument("--apidir", nargs="+", default=[])
    parser.add_argument("--log", help="Specify log level")
    parser.add_argument(
        "--async",
        dest="async_call",
        action="store_true",
        default=True,
        help="Make vpp api calls asynchronously (default)",
    )
    parser.add_argument(
        "--no-async",
        dest="async_call",
        action="store_false",
        help="Make vpp api call sychronously",
    )
    parser.add_argument("--packed-file", help="Apply changes via binary bulk API")

    args, unknownargs = parser.parse_known_args()
    if args.log:
        loglevel = getattr(logging, args.log.upper(), None)
        if not isinstance(loglevel, int):
            raise ValueError(f"Invalid log level: {loglevel}")
        logger.setLevel(loglevel)

    try:
        desired = read_jsonfile(args.desired)
    except json.decoder.JSONDecodeError:
        logger.error('Reading "%s" failed', args.desired)
        return 1

    if args.running:
        try:
            running = read_jsonfile(args.running)
        except json.decoder.JSONDecodeError:
            logger.error('Reading "%s" failed', args.running)
            return 1
    else:
        running = {"interfaces": {}, "tenants": {}, "nats": {}, "tunnels": {}}

    if args.apply and not args.new_running:
        parser.error(
            "Missing new running configuration option (--new-running-conf=<filename>)"
        )

    boottime = running.pop("boottime", None)
    interface_list = running.pop("interface_list", None)

    if args.apply:
        if args.async_call:
            caller_class = VppAsyncBatchCaller
        else:
            caller_class = VppBatchCaller
    else:
        caller_class = VppNoopCaller

    caller = caller_class(interface_list, apidir=args.apidir)
    if boottime and boottime != caller.current_boottime:
        logger.error(
            "Connecting to a different VPP instance than we have running state for"
        )
        return 1

    parser = VppConfigParser(caller)
    try:
        parse_state(parser, desired, running)
        call_vpp(caller)
    except VppControlPlaneError as exc:
        logger.error(
            "*** Programming VPP FAILED. VPP is left in an indeterminate state. %s\n",
            repr(exc),
        )
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(traceback.print_exc())
        return 1

    summary = caller.call_summary()
    logger.info(
        "API calls: %d/%d (%d failed)",
        summary["replies_received"],
        summary["calls_made"],
        summary["replies_failed"],
    )
    for p in performance:
        logger.info("%s: %.4fs", p["func"], p["time"])

    if summary["replies_failed"] > 0:
        logger.error("*** Programming VPP failed.")
        return 1

    # Dump new running configuration
    if args.apply:
        desired["boottime"] = boottime
        desired["interface_list"] = interface_list
        try:
            write_jsonfile(desired, args.new_running)
        except Exception as e:
            logger.error("Writing %s failed. %s", args.new_running, repr(e))
            return 1
    return 0


##############################################################################

if __name__ == "__main__":
    import sys

    sys.exit(main())

##############################################################################
# THE END

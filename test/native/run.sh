#!/bin/sh

pytest -s -v test/test_nat.py --vpp /home/otroan/src/vpp/build-root/install-vpp_debug-native/vpp/bin/vpp --config test/native/startup.conf

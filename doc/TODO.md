### Session dataplane
- [ ] Local host services. DHCP in session db
- [ ] Tunnels as part of main session database?
- [ ] Services ordering? E.g. a vector of u32s?
- [ ] Callback for session delete?
- [ ] Hide bihash lookup in tenant_id to tenant_idx lookup
- [ ] Hide tenant datastructure behind wrappers
- [ ] Add VRF support back
- [ ] Add more details to packet trace from vcdp-lookup (IP header)
- [x] show vcdp services command disappeared??
- [x] Policy node ahead of VCDP to handle sharing a single interface
- [ ] Check out2in packets if they match a pool address?
- [ ] show vcdp session <5-tuple>
- [ ] Fragment handling. Enable/Disable. Integrate with shallow reassembly / full reassembly.
- [ ] Timer using double linked lists as configurable alternative / compile time option


## Tunnels
Interface less tunnels infrastructure integrated with the session router.

- [ ] VXLAN-GPE ??
- [ ] Improve trace messages
- [ ] Stack of DPO from UDP encap
- [ ] Outer tunnel head-end full reassembly
- [ ] IPv6 encap / outer packet (if asked for)
- [ ] ICMP error for tunnel packet. E.g. PMTUD?

## Development environment
- [ ] clang-tidy

## Services

- [x] TCP MSS clamping
- [ ] Shallow reassembly and fragmentation
- [ ] Telemetry service

### NAT
- [ ] Copy with mask rewrite instead of individual fields?
- [ ] Update CLI
- [ ] Pool as DPO for hairpinning?
- [ ] ICMP Error handling
- [x] Non TCP/UDP handling
- [ ] Hairpinning
- [ ] - [ ] Send packet through NAT to myself via the tunnel. "BFD echo" style.
- [ ] Tests
	- [x] TCP, UDP, ICMP
	- [ ] ICMP errors
	- [ ] Fragments
	- [x] Other IP protocol

### TCP -lite state tracker
-[x] TCP lite service. Track TCP state like UDP

## Testing
### Isolated unit testing
- [ ] Multiworker
- [ ] Scale
- [ ] Improve isolated unit test infrastructure
- [ ] clang-tidy
- [ ] Coverage
- [ ] Multi-worker
- [ ] Performance

### Feature testing
- [ ] Test VCDP without NAT. Create session also creates secondary key
- [ ] Large and small packets
- [ ] TCP state machine
- [ ] ICMP error packets
- [ ] Non UDP/TCP/ICMP
- [ ] Outside interface in different VRF
- [ ] Tenants in different VRF
- [ ] Tunnels in different VRF
- [ ] Per tunnel counters both packets/bytes and errors

## Configuration
- [ ] YAML based configuration file format
- [ ] JSON schema for complete API
- [ ] Prototype Python configuration agent reading YAML/JSON injecting into API.
- [ ] Split setup-nat-cronsul to generate configuration in JSON file. And the actual configuration of Linux

A tunnel maps to a NAT instance
A native interface is 1:N NAT instances (based on session lookup)
An interface shares many NATs

A NAT instance has a single pool.
Can multiple NAT instances share a pool ==> Yes

### API
- [ ] Tunnels API
- [ ] NAT API
- [ ] VCDP API

### CLI
- [x] Merge show session-table and session-details
- [ ] Default service chain CLI
- [ ] unset cli
- [ ] - [ ] Fix pool CLI
- [x] Clear VCDP session tables command


## Telemetry
### Agent
- [ ] RUST based prometheus agent. Initially use C based POC code for stats gathering
- [ ] Only counters or logs and traces too?

### Counters
Should per-session counters exist or should they just be per-tenant counters?

Are NAT counters really part of just session counters?

- [ ]  Node drop counters
- [ ] Per-session counters
- [ ] Per-tenant counters
- [ ] NAT counters
	- [ ] Sessions per tenant

### Tracing
- [ ] Session tracing
- [x] Sessions snapshot -> Add documentation. Dump CRUD file.

## Documentation
- [ ] Update README in VCDP repo

## Tasks for Others
- [ ] /usr/lib/python3/dist-packages/setuptools/command/install.py:34: SetuptoolsDeprecationWarning: setup.py install is deprecated. Use build and pip and other standards-based tools.
- [ ] Performance tests of VCDP NATaaS

## MISC
- [x] Show session table also shows data from services. Function table to call
- [ ] Remove errors counters for normal traffic. expired / local
- [ ] Add error events to trace
- [x] TCP session creation state like UDP
- [ ] Handle NAT looping back via loopback interface. DPO for pool?
- [ ] Tunnel and handover multi-worker

## IP fragmentation

How to deal with services that need to see the transport header? TCP state tracking for example.
That cannot depend on shallow reassembly.
1. Bypass L4 specific services?
2. Require full reassembly
3. Check for fragment in each of the services?

How to integrate with shallow reassembly?
- Part of feature chain?
- Custom node, called as part of VCDP? Loop fragment and fragmented parts back into VCDP?

## NAT64

- [ ] vcdp-output is IPv4 only in it's TTL check
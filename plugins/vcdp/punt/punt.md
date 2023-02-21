# VCDP control-plane and data-plane separation

When VCDP runs in an integrated CP/DP mode, it has it's own NAT configuration and policy.

For CP/DP separation, VCDP only runs the data plane, and punts any packet where it doesn't have a session to the control plane. We use the VPP punt infrastructure for this.

## Implementation choices

### Option 1
On VCDP lookup miss, send the packet to the vcdp-punt node. This will extract the 5-tuple from the packet and create a new buffer with a "mapping request" that's sent across the punt backplane, via the punt unix domain socket to the control plane agent.
The original packet is dropped or buffered.

### Option 2
Same as above, but send the original packet to the control plane. And the control plane can parse the IP headers to find the 5-tuple. Small preamble protocol header. Perhaps signalling if this is a mapping request or a mapping refresh.

The control plane looks at the mapping request, finds a suitable NAT pool and sends a mapping response back to the dataplane over the punt socket. That is received by a new VCDP node that parses the set of mapping responses and programs the session table with the new entries.

### Option 3
The messages from VPP across the punt socket are uni-directional. The control plane agent uses the VPP binary API to add sessions when a new session is needed?
What about the NAT state required, will that be done via the API too?
The rewrite string?

### Timeouts

1. Static. Keep session until told by the control plane to remove it. Would require mapping refresh messages to the control plane.
2. Short timeout. Either send packet to control plane when it has timed out to get the session reinstated, or send refresh messages and control plane refreshes it.
3. Send message to control plane when detecting that session is disappearing. Seeing FIN flags.

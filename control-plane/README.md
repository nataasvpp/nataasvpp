# NATaaS VPP Control Plane

## Introduction

The current NATaaS configuration is represented in a JSON data structure. The data model is described in the NATaaS API (link). The VPP integration follow the model described RFC8342.

VPP is started with a startup configuration, that configures the static interfaces, proxy ARP etc.

The NATaaS/VPP datastore format is defined in the following schema (link). It's represented in JSON, and contains objects for tunnels, nats and interfaces. The tenant object is used to link tunnels and nats together.

The configuration pipeline is as follows:
 - *natcronsul* polls the central database for the instance configuration and writes that configuration to a candidate datastore JSON file (candidate.json)
 - *control-plane/vppconf.py* is run with the candidate datastore and the current running datastore files. It "compiles" the configuration files into VPP APIs, and calls VPP. On successful execution it saves the new running state into the running datastore file (running.json).

*vppconf.py* takes the new candidate configuration and the current running configuration as input and writes the new running configuration. The caller must ensure to keep track of these files.
*vppconf.py* finds the delta between the candidate and the running configurations and then compiles a list of VPP API calls to add or remove the required objects.

Currently only adds or removals of objects are supported. Modifications of existing objects will result in a failure.

## Configuration objects

### Tenants
A tenant is indexed on the tenant identifier (a 16 bit unsigned number).
A tenant provides the glue between tunnels and nats and the forward and reverse service chain used.

```
    "tenants": {
        "0": {
            "context": 0,
            "forward-services": [
                "vcdp-l4-lifecycle",
                "vcdp-nat-output"
            ],
            "reverse-services": [
                "vcdp-l4-lifecycle",
                "vcdp-tunnel-output"
            ],
            "nat-instance": "dd981ca2-9c35-4fab-836e-b9f8d8abbee2",
            flags: "no-create",
            tcp-mss: [ 1280, 1280 ]
        },
    }
```

An outside tenant has the 'no-create' flag set, which means if a packet arrives that does not match an existing session, it will be dropped.
The vcdp-bypass service can be used to forward packets through the normal forwarding path, bypassing VCDP for packets not matching existing sessions.
tcp-mss sets the TCP MSS clamping forward and reverse parameters if the service "vcdp-tcp-mss" is in the chain.

### Tunnels
A dictionary that is key'ed on the tunnel UUID. Specifies the source and destination IP addresses. If the tunnel method requires an inner Ethernet header, the src-mac and dst-mac fields can be specified. These are not used by VPP.

If the tunnel method includes a VNI, then that is used as the tenant idenfier, unless that is specified explicitly.

```
  "tunnels": {
        "8d5b5364-bf27-437b-ba08-ca903f7b2ac9": {
            "tenant": 531,
            "method": "vxlan-dummy-l2",
            "src": "192.168.0.1",
            "dst": "192.168.0.2",
            "dport": 1,
            "src-mac": "00:01:02:03:04:05",
            "dst-mac": "00:01:02:03:04:05"
        },
    }
```

Currently supported tunnel methods are "geneve-l3" and "vxlan-dummy-l2".

## Ordering constraints

The initial plan was to require that all objects existed before they are referenced when compiled to VPP API calls. It might be more convenient to support "dangling" references. E.g. to configure a tenant there are at least 4 different API calls. Set forward and reverse services, bind to NAT instance, configure MSS parameters and create the tenant itself.

### Interfaces
Interface configuration is how packets are injected into the session dataplane (VCDP). Packets can either come in on the native interface, where they are intercepted via the ip4-input feature arc. Or they are injected into VCDP from tunnel-decap. Tunnel decapsulation must also be enabled on the ingress interface.

```
    "interfaces": {
        "tap0": {
            "tenant": 1000,
        }
        "tap1": {
            "tunnel-headend": true,
        }
    },
```

### NATs
A NAT can be used by many tenants. It's only configuration at the moment is a list of outside IPv4 addresses.

```
    "nats": {
        "309546bd-8bed-4df4-ad56-f0da55db77d7": {
            "pool-address": [
                "123.123.123.123"
            ]
        },
    }
```

## Handling of failures

The control plane uses two data stores. The candidate datastore and the running datastore. The running data store is the control plane's view of the state in VPP.

If programming VPP fails, ie *vppconf.py* returns a value different from 0, then the running state of VPP is undefined. VPP then needs to be restarted and programmed again with the candidate configuration with a running configuration of null.

It's up to the application using the control plane to determine if it should roll back to an earlier revision of the candidate config, if e.g. a limit of number of NAT instances or some other error in the configuration causes VPP programming to fail.
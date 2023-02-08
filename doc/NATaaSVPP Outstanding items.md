## Testing

Automated testing is a fundamental to make a CI/CD pipeline function and the underpinnings of the VPP consumption model.

The diagram below shows the various types of tests. It's expected that all of these run per-patch. 

There is currently no resources allocated to working on the tests in the Integration box.

```mermaid
graph TD;
	subgraph Development
    UT[Unit Testing]-->FT[Feature Testing]
    end
    subgraph Integration
    FT-->PT[Performance tests]
    FT-->ST[Scale tests]
    FT-->VB[VPP Builder]
    VB-->IT[Integration tests]
    IT-->PPT[Pre-production tests]
    end
```

## Project plan

```mermaid
gantt
    title NATaaS/VPP project
    dateFormat  YYYY-MM-DD

    section Testing
     Unit Testing           :ut, 2022-10-01, 180d
     Feature Testing        :ft, 2023-01-01 , 60d
     Performance Testing    :pt  , after ft, 20d
     Scale Testing          :crit, st  , after ft, 20d
     Pre-Production Testing :crit, after ft, 2023-02-15  , 30d

    section Development
     Basic Functionality done    :milestone, m1, 2023-01-01  , 0d
     Multi-worker support : after telemetry, 14d
     ICMP error handling       :icmp, 2023-02-06, 6d
	 Hairpinning               :after icmp, 3d

    section New Features
      Telemetry service-chain node :telemetry, 2023-03-15, 7d
      Per-session bandwidth throttling :throttling, after telemetry, 7d

    section Control Plane
	  Additional API / features     : 3d

    section CPE
	  Automated CI/CD pipeline       :cicd, 2023-02-28, 5d
	
```


## Task list
### Development

- [ ] ICMP error handing
- [ ] Hairpinning
- [ ] VRFs
- [ ] Multiworker
- [ ] Counters
	- [ ] Data-model (split gauge / counter)
	- [ ] Per-tunnel instance
	- [ ] Per-tenant instance
	- [ ] Per protocol (from telemetry service)
- [ ] Telemetry service
	- [ ] Most active speaker
- [ ] Add more information to tracing
- [ ] Tool to make session tracing more convenient
- [ ] CLI
	- [ ] Clear session table
	- [ ] Merge show vcdp session-table and session-detail
	- [ ] Add unset commands (or remove configuration through CLI)
- [ ] Optimize tunnels by using midchains / UDP encap DPO
- [ ] Optimize NAT rewrite with AVX512 copy with mask
- [ ] Control-plane
	- [ ] Add additional APIs
	- [ ] Use Pydantic for data model
	- [ ] Consider loading configuration files directly from VPP
### Testing
#### Development
- [ ] Isolated unit tests (including per node performance and scale tests)
- [ ] Sanitizers: clang-tidy, valigrind
- [ ] Complete feature tests (make test)
	- [ ] ICMP error
	- [ ] PMTU
	- [ ] Fragments
	- [ ] Merge CPE and NATaaS tests
	- [ ] Multiple addresses in pool
	- [ ] VRFs

#### Integration
- [ ] Performance tests (modelled on frouter)
- [ ] Scale tests
- [ ] Pre-production and integration tests


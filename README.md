  <img src="https://www.softfire.eu/wp-content/uploads/SoftFIRE_Logo_Fireball-300x300.png" width="120"/>

  Copyright © 2016-2018 [SoftFIRE](https://www.softfire.eu/) and [TU Berlin](http://www.av.tu-berlin.de/next_generation_networks/).
  Licensed under [Apache v2 License](http://www.apache.org/licenses/LICENSE-2.0).

# Monitoring Manager

The Monitoring Manager provides proper resources to experimenters requiring monitoring service. For experimenters requiring monitoring services, the Monitoring Manager provides, via OpenBaton, the installation of an additional Virtual Machine pre-configured with Zabbix Server. All Virtual Machines requested by the experimenter will be installed with Zabbix Agent, per-configured to communicate with experimenter’s Zabbix Server. The experimenters receive full administrations rights of Zabbix Server, in order to be able to configure the server according the specific needs of the experimenter.

### Monitoring resource

The MonitoringResource node type is defined as follows:

```yaml
MonitoringResource:
  derived_from: eu.softfire.BaseResource
  description: "Defines the Zabbix monitoring resource requested"
  properties:
    testbed:
      type: string
      required: true
      description: "Location where to deploy the monitoring server"
    lan_name:
      type: string
      required: true
      description: "Openstack lan name where to deploy the monitoring server"
```

This node type has two properties:

* **testbed**: in case the experimenter requires deployment of VMs on more than one testbed is it possible to define on which testbed the Zabbix Server VM will be deployed

* **lan_name**: it possible to define on which Openstack lan the Zabbix Server VM will be deployed

## Technical Requirements

The Monitoring Manager requires Python 3.5 or higher.

## Installation and configuration


## Issue tracker

Issues and bug reports should be posted to the GitHub Issue Tracker of this project.

# What is SoftFIRE?

SoftFIRE provides a set of technologies for building a federated experimental platform aimed at the construction and experimentation of services and functionalities built on top of NFV and SDN technologies.
The platform is a loose federation of already existing testbed owned and operated by distinct organizations for purposes of research and development.

SoftFIRE has three main objectives: supporting interoperability, programming and security of the federated testbed.
Supporting the programmability of the platform is then a major goal and it is the focus of the SoftFIRE’s Second Open Call.

## Licensing and distribution
Copyright © [2016-2018] SoftFIRE project

Licensed under the Apache License, Version 2.0 (the "License");

you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


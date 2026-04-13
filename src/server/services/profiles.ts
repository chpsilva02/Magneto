import { Vendor, CommandProfile } from '../../shared/types.ts';

export const COMMAND_PROFILES: Record<Vendor, CommandProfile> = {
  cisco_ios: {
    l1: ['show lldp neighbors detail', 'show cdp neighbors detail'],
    l2: ['show spanning-tree', 'show mac address-table', 'show vlan'],
    l3: ['show ip route', 'show ip ospf neighbor', 'show ip bgp summary'],
    hardware: ['show version']
  },
  cisco_nxos: {
    l1: ['show lldp neighbors detail', 'show cdp neighbors detail'],
    l2: ['show spanning-tree', 'show mac address-table', 'show vlan'],
    l3: ['show ip route', 'show ip ospf neighbors', 'show bgp ipv4 unicast summary'],
    hardware: ['show version']
  },
  aruba_os: {
    l1: ['show lldp info remote-device detail'],
    l2: ['show spanning-tree', 'show mac-address', 'show vlan'],
    l3: ['show ip route', 'show ip ospf neighbor', 'show bgp summary'],
    hardware: ['show version']
  },
  hpe_comware: {
    l1: ['display lldp neighbor-information verbose'],
    l2: ['display stp', 'display mac-address', 'display vlan'],
    l3: ['display ip routing-table', 'display ospf peer', 'display bgp peer'],
    hardware: ['display version']
  },
  juniper_junos: {
    l1: ['show lldp neighbors'],
    l2: ['show spanning-tree bridge', 'show ethernet-switching table', 'show vlans'],
    l3: ['show route', 'show ospf neighbor', 'show bgp summary'],
    hardware: ['show version']
  },
  huawei_vrp: {
    l1: ['display lldp neighbor brief'],
    l2: ['display stp', 'display mac-address', 'display vlan'],
    l3: ['display ip routing-table', 'display ospf peer', 'display bgp peer'],
    hardware: ['display version']
  }
};

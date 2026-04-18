import { Vendor, CommandProfile } from '../../shared/types.ts';

export const COMMAND_PROFILES: Record<Vendor, CommandProfile> = {

  // ── Cisco IOS / IOS-XE ────────────────────────────────────────────────────
  cisco_ios: {
    l1:       ['show cdp neighbors detail', 'show lldp neighbors detail'],
    l2:       ['show spanning-tree', 'show spanning-tree detail', 'show etherchannel summary', 'show mac address-table', 'show vlan brief'],
    l3:       ['show ip route', 'show ip ospf neighbor', 'show ip bgp summary', 'show ip interface brief'],
    hardware: ['show version', 'show inventory', 'show running-config'],
  },

  // ── Cisco NX-OS ───────────────────────────────────────────────────────────
  cisco_nxos: {
    l1:       ['show cdp neighbors detail', 'show lldp neighbors detail'],
    l2:       ['show spanning-tree', 'show port-channel summary', 'show mac address-table', 'show vlan brief'],
    l3:       ['show ip route', 'show ip ospf neighbors', 'show bgp ipv4 unicast summary', 'show ip interface brief'],
    hardware: ['show version', 'show inventory', 'show running-config'],
  },

  // ── HP / HPE Aruba ────────────────────────────────────────────────────────
  aruba_os: {
    l1:       ['show lldp info remote-device detail', 'show cdp neighbors detail'],
    l2:       ['show spanning-tree', 'show lacp peer', 'show mac-address', 'show vlan'],
    l3:       ['show ip route', 'show ip ospf neighbor', 'show bgp summary', 'show ip interface'],
    hardware: ['show version', 'show system information'],
  },

  // ── HPE Comware (H3C) ─────────────────────────────────────────────────────
  hpe_comware: {
    l1:       ['display lldp neighbor-information verbose', 'display cdp neighbors detail'],
    l2:       ['display stp', 'display link-aggregation summary', 'display mac-address', 'display vlan'],
    l3:       ['display ip routing-table', 'display ospf peer', 'display bgp peer', 'display ip interface brief'],
    hardware: ['display version', 'display device manuinfo', 'display current-configuration'],
  },

  // ── Juniper JunOS ─────────────────────────────────────────────────────────
  juniper_junos: {
    l1:       ['show lldp neighbors detail', 'show lldp neighbors'],
    l2:       ['show spanning-tree bridge', 'show spanning-tree interface', 'show lacp interfaces', 'show ethernet-switching table', 'show vlans'],
    l3:       ['show route', 'show ospf neighbor detail', 'show bgp summary', 'show interfaces terse'],
    hardware: ['show version', 'show chassis hardware', 'show configuration'],
  },

  // ── Huawei VRP ────────────────────────────────────────────────────────────
  huawei_vrp: {
    l1:       ['display lldp neighbor brief', 'display lldp neighbor-information verbose'],
    l2:       ['display stp brief', 'display stp', 'display eth-trunk summary', 'display mac-address', 'display vlan'],
    l3:       ['display ip routing-table', 'display ospf peer', 'display bgp peer', 'display ip interface brief'],
    hardware: ['display version', 'display device manuinfo', 'display current-configuration'],
  },

  // ── Arista EOS ────────────────────────────────────────────────────────────
  arista_eos: {
    l1:       ['show lldp neighbors detail', 'show cdp neighbors detail'],
    l2:       ['show spanning-tree', 'show port-channel summary', 'show mac address-table', 'show vlan'],
    l3:       ['show ip route', 'show ip ospf neighbor', 'show bgp summary', 'show ip interface brief'],
    hardware: ['show version', 'show inventory', 'show running-config'],
  },

  // ── Dell OS10 / Dell EMC ─────────────────────────────────────────────────
  dell_os10: {
    l1:       ['show lldp neighbors detail', 'show cdp neighbors detail'],
    l2:       ['show spanning-tree', 'show port-channel', 'show mac address-table', 'show vlan'],
    l3:       ['show ip route', 'show ip ospf neighbor', 'show ip bgp summary', 'show ip interface'],
    hardware: ['show version', 'show system', 'show running-configuration'],
  },

  // ── Fortinet FortiOS ──────────────────────────────────────────────────────
  fortinet: {
    l1:       ['get system interface physical', 'diagnose lldp neighbors-summary'],
    l2:       ['get switch vlan list', 'get switch trunk list'],
    l3:       ['get router info routing-table all', 'get router info ospf neighbor', 'get router info bgp summary'],
    hardware: ['get system status', 'get hardware nic', 'show full-configuration system interface'],
  },

  // ── Palo Alto PAN-OS ──────────────────────────────────────────────────────
  paloalto: {
    l1:       ['show lldp neighbors all', 'show interface all'],
    l2:       ['show vlan all', 'show lacp aggregate-ethernet all'],
    l3:       ['show routing route', 'show routing protocol ospf neighbor', 'show routing protocol bgp peer'],
    hardware: ['show system info', 'show chassis inventory'],
  },

  // ── Extreme Networks (ExtremeXOS / EXOS) ─────────────────────────────────
  extreme: {
    l1:       ['show lldp neighbors detail', 'show cdp neighbors'],
    l2:       ['show stpd', 'show sharing', 'show fdb', 'show vlan'],
    l3:       ['show iproute', 'show ospf neighbor', 'show bgp neighbor', 'show ipconfig'],
    hardware: ['show version', 'show slot', 'show configuration'],
  },
};

export type Vendor = 'cisco_ios' | 'cisco_nxos' | 'aruba_os' | 'hpe_comware' | 'juniper_junos' | 'huawei_vrp';

export interface CommandProfile {
  l1: string[];
  l2: string[];
  l3: string[];
  hardware: string[];
}

export interface RouteEntry {
  destination: string;
  nextHop: string;
  interface: string;
  protocol: string;
}

export interface TopologyNode {
  id: string;
  hostname: string;
  ip: string;
  vendor: Vendor | 'unknown';
  hardware_model: string;
  os_version?: string;
  serial_number?: string;
  uptime?: string;
  mac_address?: string;
  role: 'core' | 'distribution' | 'access' | 'router' | 'firewall' | 'cloud' | 'unknown';
  x?: number;
  y?: number;
  isRoot?: boolean;
  routes?: RouteEntry[];
}

export interface TopologyLink {
  id: string;
  source: string;
  target: string;
  src_port: string;
  dst_port: string;
  layer: 'L1' | 'L2' | 'L3';
  protocol: 'lldp' | 'cdp' | 'stp' | 'ospf' | 'bgp' | 'static' | 'connected' | 'unknown';
  
  // Layer 1 specific
  speed?: string; // e.g., '10G', '1G', '100M'
  state?: string; // e.g., 'up/up'
  transceiver?: string; // e.g., 'SFP-10G-LR'
  
  // Layer 2 specific
  vlan?: string; // e.g., '10,20,30' or 'Trunk'
  stp_state?: string; // Legacy
  stp_role?: string; // Legacy
  src_stp_state?: string; // e.g., 'FWD', 'BLK'
  src_stp_role?: string; // e.g., 'Root', 'Desg', 'Altn'
  dst_stp_state?: string;
  dst_stp_role?: string;
  port_channel?: string; // e.g., 'Po1'
  
  // Layer 3 specific
  src_ip?: string; // Interface IP
  dst_ip?: string; // Neighbor Interface IP
  subnet?: string; // e.g., '/30'
  routing_area?: string; // e.g., 'Area 0' (OSPF)
  routing_as?: string; // e.g., 'AS 65001' (BGP)
  metric?: string; // Cost/Metric
  l3_routes?: {
    source: string;
    target: string;
    protocol: string;
    prefix: string;
  }[];
}

export interface TopologyData {
  nodes: TopologyNode[];
  links: TopologyLink[];
}

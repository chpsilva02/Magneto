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

  // ── L2 extensions (optional, set by L2 builder) ───────────────
  /** Instance IDs (e.g. "mst0", "vlan10") for which this node is STP root */
  stpRootForInstances?: string[];
  /** VLAN IDs (as strings) for which this node is STP root */
  stpRootForVlans?: string[];
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
  speed?: string;
  state?: string;
  transceiver?: string;

  // Layer 2 specific
  vlan?: string;
  stp_state?: string;  // Legacy
  stp_role?: string;   // Legacy
  src_stp_state?: string;
  src_stp_role?: string;
  dst_stp_state?: string;
  dst_stp_role?: string;
  port_channel?: string;

  // ── L2 extensions (optional, set by L2 builder) ───────────────
  /** Canonical bundle ID linking physical members to their logical link */
  logicalBundleId?: string;
  /** True when this link carries at least one blocked/discarding STP instance */
  isBlocked?: boolean;
  /** True when this link is on the STP root path */
  isRootPath?: boolean;
  /** VLANs carried on this link as an array */
  vlansCarried?: string[];

  // Layer 3 specific
  src_ip?: string;
  dst_ip?: string;
  subnet?: string;
  routing_area?: string;
  routing_as?: string;
  metric?: string;
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

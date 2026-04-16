import { applyLayout } from './src/server/services/layout.ts';
import { generateDrawioXml } from './src/server/services/drawio.ts';
import { TopologyData } from './src/shared/types.ts';
import { writeFileSync } from 'fs';

const topology: TopologyData = {
  nodes: [
    { id: 'MZ-DC-SR-30A', hostname: 'MZ-DC-SR-30A', ip: '10.222.128.13', vendor: 'cisco_ios', hardware_model: 'cisco WS-C6509', role: 'core' },
    { id: 'MZ-DC-SR-30B', hostname: 'MZ-DC-SR-30B', ip: '10.222.128.14', vendor: 'cisco_ios', hardware_model: 'cisco WS-C6509', role: 'core' },
    { id: 'AL-DC-SR-10B', hostname: 'AL-DC-SR-10B', ip: '10.221.32.5',   vendor: 'cisco_ios', hardware_model: 'cisco WS-C6506-E', role: 'distribution' },
    { id: 'MZ-DC-SR-10A', hostname: 'MZ-DC-SR-10A', ip: '10.199.75.65',  vendor: 'cisco_ios', hardware_model: 'cisco WS-C6506-E', role: 'distribution' },
    { id: 'MZ-DC-SR-10B', hostname: 'MZ-DC-SR-10B', ip: '10.199.75.101', vendor: 'cisco_ios', hardware_model: 'cisco WS-C6509',   role: 'distribution' },
    { id: 'AL-DC-FW-10A', hostname: 'AL-DC-FW-10A', ip: '10.221.32.34',  vendor: 'cisco_ios', hardware_model: 'cisco WS-C6513', role: 'firewall' },
    { id: 'AL-DC-FW-10B', hostname: 'AL-DC-FW-10B', ip: '10.221.32.38',  vendor: 'cisco_ios', hardware_model: 'cisco WS-C6513', role: 'firewall' },
    { id: 'AL-DC-SR-10A', hostname: 'AL-DC-SR-10A', ip: '10.221.32.5',   vendor: 'cisco_ios', hardware_model: 'cisco WS-C6506-E', role: 'access' },
    { id: 'AL-DC-SR-1A',  hostname: 'AL-DC-SR-1A',  ip: '10.221.32.13',  vendor: 'cisco_ios', hardware_model: 'cisco WS-C6509-E', role: 'access' },
    { id: 'AL-DC-SR-1B',  hostname: 'AL-DC-SR-1B',  ip: '10.221.32.21',  vendor: 'cisco_ios', hardware_model: 'cisco WS-C6509-E', role: 'access' },
    { id: 'AL-DC-SR-40A', hostname: 'AL-DC-SR-40A', ip: '10.195.75.242', vendor: 'cisco_ios', hardware_model: 'cisco WS-C6509-E', role: 'access' },
    { id: 'CT-NOC-SW-13A',hostname: 'CT-NOCSOC-SW-13A', ip: '10.197.148.51', vendor: 'cisco_ios', hardware_model: 'cisco WS-C4948', role: 'access' },
    { id: 'MZ-CT-RA-SW-1A',hostname: 'MZ-CT-RA-SW-1A', ip: '10.208.24.49', vendor: 'cisco_ios', hardware_model: 'cisco WS-C6509-E', role: 'access' },
    { id: 'MZ-CT-RA-SW-1B',hostname: 'MZ-CT-RA-SW-1B', ip: '10.208.24.51', vendor: 'cisco_ios', hardware_model: 'cisco WS-C6509-E', role: 'access' },
    { id: 'MZDCSAGLB001A',hostname: 'MZDCSAGLB001A', ip: '', vendor: 'cisco_ios', hardware_model: 'Unknown', role: 'access' },
    { id: 'MZDCSAGLB001B',hostname: 'MZDCSAGLB001B', ip: '', vendor: 'cisco_ios', hardware_model: 'Unknown', role: 'access' },
  ],
  links: [
    // Core interconnect — 4 parallel
    { id: 'l1_1', source: 'MZ-DC-SR-30A', target: 'MZ-DC-SR-30B', src_port: 'Gi1/45', dst_port: 'Gi1/45', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_2', source: 'MZ-DC-SR-30A', target: 'MZ-DC-SR-30B', src_port: 'Gi1/46', dst_port: 'Gi1/46', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_3', source: 'MZ-DC-SR-30A', target: 'MZ-DC-SR-30B', src_port: 'Gi1/47', dst_port: 'Gi1/47', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_4', source: 'MZ-DC-SR-30A', target: 'MZ-DC-SR-30B', src_port: 'Gi1/48', dst_port: 'Gi1/48', layer: 'L1', protocol: 'lldp' },
    // Core → Distribution — 2 parallel each
    { id: 'l1_5', source: 'MZ-DC-SR-30A', target: 'MZ-DC-SR-10A', src_port: 'Gi1/1', dst_port: 'Gi4/1', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_6', source: 'MZ-DC-SR-30A', target: 'MZ-DC-SR-10A', src_port: 'Gi1/2', dst_port: 'Gi4/2', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_7', source: 'MZ-DC-SR-30B', target: 'MZ-DC-SR-10A', src_port: 'Gi1/3', dst_port: 'Gi4/3', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_8', source: 'MZ-DC-SR-30B', target: 'MZ-DC-SR-10A', src_port: 'Gi1/4', dst_port: 'Gi4/4', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_9', source: 'MZ-DC-SR-30A', target: 'MZ-DC-SR-10B', src_port: 'Gi1/5', dst_port: 'Gi4/9', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_10',source: 'MZ-DC-SR-30B', target: 'MZ-DC-SR-10B', src_port: 'Gi1/7', dst_port: 'Gi4/11',layer: 'L1', protocol: 'lldp' },
    { id: 'l1_11',source: 'MZ-DC-SR-30A', target: 'AL-DC-SR-10B', src_port: 'Gi2/1', dst_port: 'Te1/1', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_12',source: 'MZ-DC-SR-30B', target: 'AL-DC-SR-10B', src_port: 'Gi2/2', dst_port: 'Te1/2', layer: 'L1', protocol: 'lldp' },
    // Distribution → Access — 4 parallel
    { id: 'l1_13',source: 'AL-DC-SR-10B', target: 'AL-DC-SR-10A', src_port: 'Te1/3', dst_port: 'Te1/3', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_14',source: 'AL-DC-SR-10B', target: 'AL-DC-SR-10A', src_port: 'Te1/4', dst_port: 'Te1/4', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_15',source: 'AL-DC-SR-10B', target: 'AL-DC-SR-10A', src_port: 'Te2/3', dst_port: 'Te2/3', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_16',source: 'AL-DC-SR-10B', target: 'AL-DC-SR-10A', src_port: 'Te2/4', dst_port: 'Te2/4', layer: 'L1', protocol: 'lldp' },
    // Firewall → Dist
    { id: 'l1_17',source: 'AL-DC-FW-10A', target: 'AL-DC-SR-10B', src_port: 'Te9/2', dst_port: 'Te2/1', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_18',source: 'AL-DC-FW-10B', target: 'AL-DC-SR-10B', src_port: 'Te9/2', dst_port: 'Te2/2', layer: 'L1', protocol: 'lldp' },
    // Dist → various access
    { id: 'l1_19',source: 'AL-DC-SR-10B', target: 'AL-DC-SR-1A',      src_port: 'Te1/1', dst_port: 'Gi1/1', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_20',source: 'AL-DC-SR-10B', target: 'AL-DC-SR-1B',      src_port: 'Te1/2', dst_port: 'Gi1/1', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_21',source: 'AL-DC-SR-10B', target: 'AL-DC-SR-40A',     src_port: 'Te3/1', dst_port: 'Gi1/1', layer: 'L1', protocol: 'lldp', speed: '10G' },
    { id: 'l1_22',source: 'AL-DC-SR-10B', target: 'AL-DC-SR-40A',     src_port: 'Te3/2', dst_port: 'Gi1/2', layer: 'L1', protocol: 'lldp', speed: '10G' },
    { id: 'l1_23',source: 'MZ-DC-SR-30B', target: 'CT-NOC-SW-13A',    src_port: 'Gi3/1', dst_port: 'Gi1/1', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_24',source: 'MZ-DC-SR-30A', target: 'MZ-CT-RA-SW-1A',  src_port: 'Gi3/2', dst_port: 'Gi1/1', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_25',source: 'MZ-DC-SR-30B', target: 'MZ-CT-RA-SW-1B',  src_port: 'Gi3/3', dst_port: 'Gi1/1', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_26',source: 'MZ-DC-SR-30A', target: 'MZDCSAGLB001A',   src_port: 'Gi4/1', dst_port: 'Gi1/1', layer: 'L1', protocol: 'lldp' },
    { id: 'l1_27',source: 'MZ-DC-SR-30B', target: 'MZDCSAGLB001B',   src_port: 'Gi4/2', dst_port: 'Gi1/1', layer: 'L1', protocol: 'lldp' },
    // L2 STP
    { id: 'l2_1',source: 'MZ-DC-SR-30A', target: 'MZ-DC-SR-30B', src_port: 'Gi1/45', dst_port: 'Gi1/45', layer: 'L2', protocol: 'stp', vlan: 'Trunk', src_stp_role: 'Desg', src_stp_state: 'FWD', dst_stp_role: 'Root', dst_stp_state: 'FWD' },
    { id: 'l2_2',source: 'MZ-DC-SR-30A', target: 'AL-DC-SR-10B', src_port: 'Gi2/1',  dst_port: 'Te1/1',  layer: 'L2', protocol: 'stp', vlan: 'Trunk', src_stp_role: 'Desg', src_stp_state: 'FWD', dst_stp_role: 'Root', dst_stp_state: 'FWD' },
    { id: 'l2_3',source: 'MZ-DC-SR-30B', target: 'AL-DC-SR-10B', src_port: 'Gi2/2',  dst_port: 'Te1/2',  layer: 'L2', protocol: 'stp', vlan: 'Trunk', src_stp_role: 'Altn', src_stp_state: 'BLK', dst_stp_role: 'Root', dst_stp_state: 'FWD' },
    // L3 OSPF
    { id: 'l3_1',source: 'MZ-DC-SR-30A', target: 'MZ-DC-SR-30B', src_port: 'Vlan10', dst_port: 'Vlan10', src_ip: '10.222.128.13', dst_ip: '10.222.128.14', layer: 'L3', protocol: 'ospf',
      l3_routes: [
        { source: 'MZ-DC-SR-30A', target: 'MZ-DC-SR-30B', protocol: 'ospf', prefix: '10.199.0.0/16' },
        { source: 'MZ-DC-SR-30B', target: 'MZ-DC-SR-30A', protocol: 'ospf', prefix: '10.221.0.0/16' },
      ]
    },
    { id: 'l3_2',source: 'MZ-DC-SR-30A', target: 'AL-DC-SR-10B', src_port: 'Vlan20', dst_port: 'Vlan20', src_ip: '10.222.128.1', dst_ip: '10.221.32.1', layer: 'L3', protocol: 'ospf',
      l3_routes: [{ source: 'MZ-DC-SR-30A', target: 'AL-DC-SR-10B', protocol: 'static', prefix: '10.221.32.0/24' }]
    },
  ],
};

const positioned = applyLayout(topology);
const xml = generateDrawioXml(positioned);
writeFileSync('/home/claude/topology_preview.drawio', xml);
console.log('OK — nodes:', positioned.nodes.length, '| links:', positioned.links.length);
positioned.nodes.forEach(n =>
  console.log(`  [${String(getRoleTier ? '' : '')}${n.role.padEnd(12)}]  ${n.hostname.padEnd(22)}  x=${n.x}  y=${n.y}`)
);

function getRoleTier(role: string): number {
  switch (role) {
    case 'cloud': return 0; case 'firewall': case 'router': return 1;
    case 'core': return 2; case 'distribution': return 3;
    case 'access': return 4; default: return 5;
  }
}

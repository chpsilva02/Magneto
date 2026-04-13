import { applyLayout } from './src/server/services/layout';
import { TopologyData } from './src/shared/types';

const data: TopologyData = {
  nodes: [
    { id: '1', hostname: 'R1', ip: '1.1.1.1', vendor: 'cisco_ios', hardware_model: 'ISR', role: 'core' },
    { id: '2', hostname: 'R2', ip: '2.2.2.2', vendor: 'cisco_ios', hardware_model: 'ISR', role: 'core' },
    { id: '3', hostname: 'R3', ip: '3.3.3.3', vendor: 'cisco_ios', hardware_model: 'ISR', role: 'core' },
  ],
  links: [
    { id: 'l1', source: '1', target: '2', src_port: 'g1', dst_port: 'g2', layer: 'L1', protocol: 'lldp' },
    { id: 'l2', source: '2', target: '3', src_port: 'g1', dst_port: 'g2', layer: 'L1', protocol: 'lldp' },
  ]
};

const result = applyLayout(data);
console.log(result.nodes.map(n => ({ id: n.id, x: n.x, y: n.y })));

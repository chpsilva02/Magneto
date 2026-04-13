import * as d3 from 'd3-force';
import { TopologyData, TopologyNode } from '../../shared/types.ts';

function getRoleLevel(role: string): number {
  switch (role) {
    case 'cloud': return 0;
    case 'firewall': return 1;
    case 'router': return 1;
    case 'core': return 2;
    case 'distribution': return 3;
    case 'access': return 4;
    default: return 5;
  }
}

export function applyLayout(topology: TopologyData): TopologyData {
  // Check if all nodes already have x and y defined (fixed layout)
  const hasFixedLayout = topology.nodes.every(n => n.x !== undefined && n.y !== undefined);
  if (hasFixedLayout) {
    return topology;
  }

  // Create nodes array for d3
  const nodes = topology.nodes.map(n => ({ ...n, id: n.id, x: 0, y: 0 }));
  
  // Create links array for d3
  const links = topology.links.map(l => ({
    source: l.source,
    target: l.target
  }));

  // Setup d3 force simulation (spring_layout equivalent)
  const simulation = d3.forceSimulation(nodes as d3.SimulationNodeDatum[])
    .force('link', d3.forceLink(links).id((d: any) => d.id).distance(150))
    .force('charge', d3.forceManyBody().strength(-3000)) // repel each other strongly
    .force('y', d3.forceY((d: any) => {
      const level = getRoleLevel(d.role);
      return 150 + level * 250;
    }).strength(1.5)) // Strong vertical constraint based on role
    .force('x', d3.forceX(600).strength(0.1)) // Weak horizontal centering
    .force('collide', d3.forceCollide().radius(120)) // prevent overlap
    .stop();

  // Run simulation synchronously to calculate positions mathematically
  // 300 ticks is usually enough for it to cool down and stabilize
  for (let i = 0; i < 300; ++i) {
    simulation.tick();
  }

  // Map positions back to topology nodes
  const positionedNodes = nodes.map(n => {
    return {
      ...topology.nodes.find(tn => tn.id === n.id)!,
      x: Math.round(n.x || 0),
      y: Math.round(n.y || 0)
    };
  });

  return {
    nodes: positionedNodes,
    links: topology.links
  };
}

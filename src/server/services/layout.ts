import * as d3 from 'd3-force';
import { TopologyData } from '../../shared/types';

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
    .force('link', d3.forceLink(links).id((d: any) => d.id).distance(200))
    .force('charge', d3.forceManyBody().strength(-1500)) // repel each other strongly
    .force('center', d3.forceCenter(500, 500))
    .force('collide', d3.forceCollide().radius(100)) // prevent overlap
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

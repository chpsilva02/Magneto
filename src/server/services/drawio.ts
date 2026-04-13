import { create } from 'xmlbuilder2';
import { TopologyData, TopologyNode, TopologyLink } from '../../shared/types.ts';
import { getDrawioShape } from './icons.ts';

function buildNodeLabel(node: TopologyNode): string {
  if (node.role === 'cloud') {
    return `<b>${node.hostname}</b>`;
  }
  let label = `<b>${node.hostname}</b>`;
  if (node.ip) label += `<br/>(${node.ip})`;
  if (node.hardware_model && node.hardware_model !== 'Unknown') label += `<br/>${node.hardware_model}`;
  if (node.os_version) label += `<br/><span style="color: #666666; font-size: 10px;">OS: ${node.os_version}</span>`;
  if (node.serial_number) label += `<br/><span style="color: #666666; font-size: 10px;">SN: ${node.serial_number}</span>`;
  if (node.uptime) label += `<br/><span style="color: #666666; font-size: 10px;">Up: ${node.uptime}</span>`;
  return label;
}

function buildLinkCenterLabel(link: TopologyLink, layer: string): string {
  let label = '';
  if (layer === 'L1') {
    if (link.speed) label += `<span style="color: #666666; font-size: 10px;">Speed: ${link.speed}</span><br/>`;
    if (link.state) label += `<span style="color: #666666; font-size: 10px;">State: ${link.state}</span><br/>`;
    if (link.transceiver) label += `<span style="color: #666666; font-size: 10px;">Tx: ${link.transceiver}</span>`;
  } else if (layer === 'L2') {
    // Removed verbose VLAN/STP text from center label as requested
    if (link.port_channel) label += `<span style="color: #666666; font-size: 10px;">Po: ${link.port_channel}</span>`;
  } else if (layer === 'L3') {
    if (link.l3_routes && link.l3_routes.length > 0) {
      const labels = link.l3_routes.map(r => {
        const protoName = r.protocol.toUpperCase();
        return `<span style="color: #005073; font-size: 11px; font-weight: bold;">${protoName} --&gt; ${r.prefix}</span>`;
      });
      label += labels.join('<br/>');
    } else if (link.protocol !== 'connected') {
      label += `<span style="color: #666666; font-size: 10px;">${link.protocol.toUpperCase()}</span>`;
    }
  }
  return label;
}

export function generateDrawioXml(topology: TopologyData): string {
  const root = create({ version: '1.0', encoding: 'UTF-8' })
    .ele('mxfile', { version: '21.6.8' });

  const layers = ['L1', 'L2', 'L3'];
  const layerNames = { 
    L1: 'Topologia Layer 1 (Física)', 
    L2: 'Topologia Layer 2 (Lógica)', 
    L3: 'Topologia Layer 3 (Roteamento)' 
  };

  layers.forEach((layer) => {
    const diagram = root.ele('diagram', { name: layerNames[layer as keyof typeof layerNames], id: `page_${layer}` });
    const mxGraphModel = diagram.ele('mxGraphModel', {
      dx: '1200', dy: '800', grid: '1', gridSize: '10', guides: '1', tooltips: '1', connect: '1', arrows: '1', fold: '1', page: '1', pageScale: '1', pageWidth: '1169', pageHeight: '827', math: '0', shadow: '0'
    });
    const rootCell = mxGraphModel.ele('root');
    rootCell.ele('mxCell', { id: `root_${layer}_0` });
    rootCell.ele('mxCell', { id: `root_${layer}_1`, parent: `root_${layer}_0` });

    // Add links for this layer
    const layerLinks = topology.links.filter(l => l.layer === layer);
    const layerNodeIds = new Set<string>();
    layerLinks.forEach(l => {
      layerNodeIds.add(l.source);
      layerNodeIds.add(l.target);
    });

    // Add nodes
    topology.nodes.forEach(node => {
      // Skip nodes that do not participate in this layer's links (unless there are no links at all)
      if (layerLinks.length > 0 && !layerNodeIds.has(node.id)) {
        return;
      }

      const shape = getDrawioShape(node.hardware_model, node.role);
      const vertex = rootCell.ele('mxCell', {
        id: `${layer}_node_${node.id}`,
        value: buildNodeLabel(node),
        style: `${shape}whiteSpace=wrap;html=1;verticalLabelPosition=bottom;verticalAlign=top;spacingTop=8;`,
        vertex: '1',
        parent: `root_${layer}_1`
      });
      vertex.ele('mxGeometry', {
        x: (node.x !== undefined ? node.x : 0).toString(),
        y: (node.y !== undefined ? node.y : 0).toString(),
        width: '60',
        height: '60',
        as: 'geometry'
      });

      if (layer === 'L2' && node.isRoot) {
        const rootLabel = rootCell.ele('mxCell', {
          id: `${layer}_node_${node.id}_root_label`,
          value: 'ROOT BRIDGE',
          style: 'text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontColor=#FF0000;fontStyle=1;fontSize=12;',
          vertex: '1',
          parent: `root_${layer}_1`
        });
        rootLabel.ele('mxGeometry', {
          x: (node.x !== undefined ? node.x - 20 : -20).toString(),
          y: (node.y !== undefined ? node.y - 25 : -25).toString(),
          width: '100',
          height: '20',
          as: 'geometry'
        });
      }

      if (layer === 'L3' && node.routes && node.routes.length > 0) {
        let tableHtml = `<table border="1" cellpadding="4" cellspacing="0" style="border-collapse: collapse; font-size: 10px; width: 100%; background-color: #ffffff;">`;
        tableHtml += `<tr><th colspan="3" style="background-color: #f0f0f0;">Routing Table</th></tr>`;
        tableHtml += `<tr><th>Destination</th><th>NextHop</th><th>Interface</th></tr>`;
        node.routes.forEach(r => {
          tableHtml += `<tr><td>${r.destination}</td><td>${r.nextHop}</td><td>${r.interface}</td></tr>`;
        });
        tableHtml += `</table>`;

        const tableNode = rootCell.ele('mxCell', {
          id: `${layer}_node_${node.id}_routes`,
          value: tableHtml,
          style: 'text;html=1;whiteSpace=wrap;overflow=hidden;rounded=0;shadow=1;',
          vertex: '1',
          parent: `root_${layer}_1`
        });
        tableNode.ele('mxGeometry', {
          x: (node.x !== undefined ? node.x - 100 : -100).toString(),
          y: (node.y !== undefined ? node.y - 120 : -120).toString(),
          width: '260',
          height: (node.routes.length * 20 + 40).toString(),
          as: 'geometry'
        });

        // Draw a line connecting the table to the router
        const tableEdge = rootCell.ele('mxCell', {
          id: `${layer}_node_${node.id}_routes_edge`,
          style: 'endArrow=none;html=1;rounded=0;strokeWidth=1;strokeColor=#888888;',
          edge: '1',
          parent: `root_${layer}_1`,
          source: `${layer}_node_${node.id}_routes`,
          target: `${layer}_node_${node.id}`
        });
        tableEdge.ele('mxGeometry', { relative: '1', as: 'geometry' });
      }
    });

    // Add links for this layer
    const linkCounts: Record<string, number> = {};
    const linkIndexMap: Record<string, number> = {};
    const nodeMap = new Map(topology.nodes.map(n => [n.id, n]));

    layerLinks.forEach(link => {
      const pair = [link.source, link.target].sort().join('_');
      linkCounts[pair] = (linkCounts[pair] || 0) + 1;
    });

    layerLinks.forEach(link => {
      const pair = [link.source, link.target].sort().join('_');
      linkIndexMap[link.id] = linkIndexMap[pair] || 0;
      linkIndexMap[pair] = (linkIndexMap[pair] || 0) + 1;
      
      const edgeId = `${layer}_link_${link.id}`;
      const centerLabel = buildLinkCenterLabel(link, layer);
      
      let edgeStyle = 'endArrow=none;html=1;rounded=0;strokeWidth=2;strokeColor=#444444;labelBackgroundColor=#ffffff;fontColor=#333333;fontSize=10;';
      
      const totalLinks = linkCounts[pair];
      const linkIndex = linkIndexMap[link.id];

      if (layer === 'L3' && link.l3_routes && link.l3_routes.length > 0) {
        let hasForward = false; // source -> target
        let hasBackward = false; // target -> source
        link.l3_routes.forEach(r => {
          if (r.source === link.source) hasForward = true;
          if (r.source === link.target) hasBackward = true;
        });

        if (hasForward && hasBackward) {
          edgeStyle = edgeStyle.replace('endArrow=none', 'endArrow=block;startArrow=block');
        } else if (hasForward) {
          edgeStyle = edgeStyle.replace('endArrow=none', 'endArrow=block');
        } else if (hasBackward) {
          edgeStyle = edgeStyle.replace('endArrow=none', 'startArrow=block');
        }
      }

      const edge = rootCell.ele('mxCell', {
        id: edgeId,
        value: centerLabel,
        style: edgeStyle,
        edge: '1',
        parent: `root_${layer}_1`,
        source: `${layer}_node_${link.source}`,
        target: `${layer}_node_${link.target}`
      });
      
      const geometry = edge.ele('mxGeometry', { relative: '1', as: 'geometry' });

      const nodeA = nodeMap.get(link.source);
      const nodeB = nodeMap.get(link.target);
      if (nodeA && nodeB) {
        const ax = nodeA.x || 0;
        const ay = nodeA.y || 0;
        const bx = nodeB.x || 0;
        const by = nodeB.y || 0;
        
        const dx = bx - ax;
        const dy = by - ay;
        
        let offset = 0.5;
        if (totalLinks > 1) {
          const step = 0.8 / totalLinks;
          offset = 0.1 + (step / 2) + (linkIndex * step);
        }

        let exitX = 0.5, exitY = 0.5, entryX = 0.5, entryY = 0.5;

        if (Math.abs(dx) > Math.abs(dy)) {
          // Horizontal alignment
          if (dx > 0) {
            exitX = 1; exitY = offset; entryX = 0; entryY = offset;
          } else {
            exitX = 0; exitY = offset; entryX = 1; entryY = offset;
          }
        } else {
          // Vertical alignment
          if (dy > 0) {
            exitX = offset; exitY = 1; entryX = offset; entryY = 0;
          } else {
            exitX = offset; exitY = 0; entryX = offset; entryY = 1;
          }
        }
        
        // Use orthogonal edge style to force straight lines that don't overlap in the middle
        edge.att('style', edgeStyle + `edgeStyle=orthogonalEdgeStyle;exitX=${exitX};exitY=${exitY};exitPerimeter=0;entryX=${entryX};entryY=${entryY};entryPerimeter=0;`);
      }

      const formatStpPort = (port: string, role?: string, state?: string) => {
        if (layer !== 'L2' || (!role && !state)) return port;
        
        let icon = '';
        if (state === 'FWD') icon = '🟢 ';
        else if (state === 'BLK' || state === 'Altn' || state === 'DIS') icon = '❌ ';
        else if (state) icon = '🟠 ';
        
        let roleStr = '';
        if (role === 'Desg') roleStr = 'DP';
        else if (role === 'Root') roleStr = 'RP';
        else if (role === 'Altn') roleStr = 'ALT';
        else if (role === 'Back') roleStr = 'BKP';
        else if (role) roleStr = role.toUpperCase();
        
        let label = `${icon}${port}`;
        if (roleStr) {
          label += `<br><font color="#FF0000"><b>${roleStr}</b></font>`;
        }
        return label;
      };

      // Source Port Label
      if (link.src_port || (layer === 'L3' && link.src_ip)) {
        let srcVal = link.src_port || '';
        if (layer === 'L3') {
          if (link.src_ip) {
            srcVal = srcVal ? `${srcVal}<br/>${link.src_ip}` : link.src_ip;
          }
        } else {
          srcVal = formatStpPort(link.src_port, link.src_stp_role, link.src_stp_state);
        }
        
        if (srcVal) {
          const srcLabel = rootCell.ele('mxCell', {
            id: `${edgeId}_src_label`,
            value: srcVal,
            style: 'edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];labelBackgroundColor=#ffffff;fontSize=11;fontColor=#333333;',
            vertex: '1',
            connectable: '0',
            parent: edgeId
          });
          srcLabel.ele('mxGeometry', { x: '-0.7', relative: '1', as: 'geometry' }).ele('mxPoint', { as: 'offset' });
        }
      }

      // Target Port Label
      if (link.dst_port || (layer === 'L3' && link.dst_ip)) {
        let dstVal = link.dst_port || '';
        if (layer === 'L3') {
          if (link.dst_ip) {
            dstVal = dstVal ? `${dstVal}<br/>${link.dst_ip}` : link.dst_ip;
          }
        } else {
          dstVal = formatStpPort(link.dst_port, link.dst_stp_role, link.dst_stp_state);
        }

        if (dstVal) {
          const dstLabel = rootCell.ele('mxCell', {
            id: `${edgeId}_dst_label`,
            value: dstVal,
            style: 'edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];labelBackgroundColor=#ffffff;fontSize=11;fontColor=#333333;',
            vertex: '1',
            connectable: '0',
            parent: edgeId
          });
          dstLabel.ele('mxGeometry', { x: '0.7', relative: '1', as: 'geometry' }).ele('mxPoint', { as: 'offset' });
        }
      }
    });
  });

  return root.end({ prettyPrint: true });
}

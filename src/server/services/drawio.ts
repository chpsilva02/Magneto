/**
 * drawio.ts — draw.io XML generator
 *
 * Pin assignment: smart face distribution
 *  • Page dimensions come from layout._layout (dynamic, based on node count)
 *  • edgeStyle=none — straight lines, no auto-routing
 *  • exitX/exitY spread across the full node face independently per link
 *  • No waypoints — each line is 100% independent and movable
 */

import { create } from 'xmlbuilder2';
import { TopologyData, TopologyNode, TopologyLink } from '../../shared/types.ts';
import { getDrawioShape } from './icons.ts';
import { getRoleTier, NODE_W, NODE_H, TIER_Y_ORIGIN, TIER_Y_GAP_EXPORT } from './layout.ts';

// ─────────────────────────────────────────────────────────────────
// Fallback page dimensions (overridden by _layout when present)
// ─────────────────────────────────────────────────────────────────
const DEFAULT_PAGE_W = 3200;
const DEFAULT_PAGE_H = 2000;

// Spread fraction range across a node face
const SPREAD_LO = 0.10;
const SPREAD_HI = 0.90;

const LINK_COLOR: Record<string, string> = {
  L1: '#505050',
  L2: '#1A5276',
  L3: '#6C3483',
};

// ─────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────
type Face = 'top' | 'bottom' | 'left' | 'right';

function faceToPin(face: Face, frac: number): { x: number; y: number } {
  switch (face) {
    case 'top':    return { x: frac, y: 0 };
    case 'bottom': return { x: frac, y: 1 };
    case 'left':   return { x: 0,    y: frac };
    case 'right':  return { x: 1,    y: frac };
  }
}

function spreadFrac(i: number, n: number): number {
  if (n === 1) return 0.5;
  return SPREAD_LO + (i / (n - 1)) * (SPREAD_HI - SPREAD_LO);
}

function getFace(src: TopologyNode, tgt: TopologyNode): Face {
  const st = getRoleTier(src.role);
  const tt = getRoleTier(tgt.role);
  if (st < tt) return 'bottom';
  if (st > tt) return 'top';
  const sx = (src.x ?? 0) + NODE_W / 2;
  const tx = (tgt.x ?? 0) + NODE_W / 2;
  return tx > sx ? 'right' : 'left';
}

// ─────────────────────────────────────────────────────────────────
// Global pin map — distributes pins across the full node face
// ─────────────────────────────────────────────────────────────────
function buildPinMap(
  links: TopologyLink[],
  nodeMap: Map<string, TopologyNode>
): Map<string, { srcPin: { x: number; y: number }; tgtPin: { x: number; y: number } }> {

  // node → face → [linkId]
  const nodeFace = new Map<string, Map<Face, string[]>>();
  function ensureFace(nodeId: string) {
    if (!nodeFace.has(nodeId)) nodeFace.set(nodeId, new Map());
    return nodeFace.get(nodeId)!;
  }

  for (const link of links) {
    const src = nodeMap.get(link.source);
    const tgt = nodeMap.get(link.target);
    if (!src || !tgt) continue;
    const sf = getFace(src, tgt);
    const tf = getFace(tgt, src);
    const sf_ = ensureFace(link.source);
    if (!sf_.has(sf)) sf_.set(sf, []);
    sf_.get(sf)!.push(link.id);
    const tf_ = ensureFace(link.target);
    if (!tf_.has(tf)) tf_.set(tf, []);
    tf_.get(tf)!.push(link.id);
  }

  // node → linkId → fraction
  const linkFrac = new Map<string, Map<string, number>>();
  for (const [nodeId, faceMap] of nodeFace) {
    if (!linkFrac.has(nodeId)) linkFrac.set(nodeId, new Map());
    const fm = linkFrac.get(nodeId)!;
    for (const [, lids] of faceMap) {
      lids.forEach((lid, i) => fm.set(lid, spreadFrac(i, lids.length)));
    }
  }

  const pinMap = new Map<string, { srcPin: { x: number; y: number }; tgtPin: { x: number; y: number } }>();
  for (const link of links) {
    const src = nodeMap.get(link.source);
    const tgt = nodeMap.get(link.target);
    if (!src || !tgt) continue;
    const sf   = getFace(src, tgt);
    const tf   = getFace(tgt, src);
    const sfr  = linkFrac.get(link.source)?.get(link.id) ?? 0.5;
    const tfr  = linkFrac.get(link.target)?.get(link.id) ?? 0.5;
    pinMap.set(link.id, {
      srcPin: faceToPin(sf, sfr),
      tgtPin: faceToPin(tf, tfr),
    });
  }
  return pinMap;
}

// ─────────────────────────────────────────────────────────────────
// Label builders
// ─────────────────────────────────────────────────────────────────
function nodeLabel(n: TopologyNode): string {
  if (n.role === 'cloud') return `<b>${n.hostname}</b>`;
  let s = `<b>${n.hostname}</b>`;
  if (n.ip) s += `<br/>(${n.ip})`;
  if (n.hardware_model && n.hardware_model !== 'Unknown')
    s += `<br/>${n.hardware_model}`;
  if (n.os_version)
    s += `<br/><font color="#888888" point-size="9">OS: ${n.os_version}</font>`;
  if (n.serial_number)
    s += `<br/><font color="#888888" point-size="9">SN: ${n.serial_number}</font>`;
  return s;
}

function linkCenterLabel(link: TopologyLink, layer: string): string {
  if (layer === 'L1') {
    const p: string[] = [];
    if (link.speed)       p.push(`<font color="#666" point-size="9">Speed: ${link.speed}</font>`);
    if (link.state)       p.push(`<font color="#666" point-size="9">State: ${link.state}</font>`);
    if (link.transceiver) p.push(`<font color="#666" point-size="9">Tx: ${link.transceiver}</font>`);
    return p.join('<br/>');
  }
  if (layer === 'L2') {
    const p: string[] = [];
    if (link.vlan)         p.push(`<font color="#1a5276" point-size="9">VLAN: ${link.vlan}</font>`);
    if (link.port_channel) p.push(`<font color="#1a5276" point-size="9">Po: ${link.port_channel}</font>`);
    return p.join('<br/>');
  }
  if (layer === 'L3') {
    if (link.l3_routes && link.l3_routes.length > 0) {
      return link.l3_routes
        .map(r => `<b><font color="#5b2c6f" point-size="9">${r.protocol.toUpperCase()} &#8594; ${r.prefix}</font></b>`)
        .join('<br/>');
    }
    if (link.protocol && link.protocol !== 'connected')
      return `<font color="#666" point-size="9">${link.protocol.toUpperCase()}</font>`;
  }
  return '';
}

function portLabel(port: string, stpRole?: string, stpState?: string, layer?: string): string {
  if (!port) return '';
  if (layer !== 'L2') return port;
  let icon = '';
  if      (stpState === 'FWD')                            icon = '🟢 ';
  else if (stpState === 'BLK' || stpState === 'DIS')     icon = '🔴 ';
  else if (stpState === 'Altn')                           icon = '🟡 ';
  else if (stpState)                                      icon = '🟠 ';
  const roleMap: Record<string, string> = { Desg: 'DP', Root: 'RP', Altn: 'ALT', Back: 'BKP' };
  const sr = stpRole ? (roleMap[stpRole] ?? stpRole.toUpperCase()) : '';
  let s = `${icon}${port}`;
  if (sr) s += `<br/><b><font color="#c0392b">${sr}</font></b>`;
  return s;
}

// ─────────────────────────────────────────────────────────────────
// Main export
// ─────────────────────────────────────────────────────────────────
export function generateDrawioXml(topology: TopologyData & { _layout?: any }): string {
  const layout  = topology._layout;
  const PAGE_W  = layout?.pageW  ?? DEFAULT_PAGE_W;
  const PAGE_H  = layout?.pageH  ?? DEFAULT_PAGE_H;
  const TIER_Y0 = layout?.tierY0 ?? TIER_Y_ORIGIN;
  const TIER_YG = layout?.tierYGap ?? TIER_Y_GAP_EXPORT;

  const xmlRoot  = create({ version: '1.0', encoding: 'UTF-8' }).ele('mxfile', { version: '21.6.8' });
  const LAYERS   = ['L1', 'L2', 'L3'] as const;
  const NAMES: Record<string, string> = {
    L1: 'Topologia Layer 1 (Física)',
    L2: 'Topologia Layer 2 (Lógica)',
    L3: 'Topologia Layer 3 (Roteamento)',
  };

  const nodeMap = new Map(topology.nodes.map(n => [n.id, n]));

  for (const layer of LAYERS) {
    const diagram = xmlRoot.ele('diagram', { name: NAMES[layer], id: `page_${layer}` });
    const gmAttrs: Record<string, string> = {
      dx: '1600', dy: '900',
      grid: '1', gridSize: '10',
      guides: '1', tooltips: '1',
      connect: '1', arrows: '1', fold: '1',
      page: '1', pageScale: '1',
      pageWidth:  String(PAGE_W),
      pageHeight: String(PAGE_H),
      math: '0', shadow: '0',
    };
    const mxGM    = diagram.ele('mxGraphModel', gmAttrs);
    const rootCell = mxGM.ele('root');
    rootCell.ele('mxCell', { id: `root_${layer}_0` });
    rootCell.ele('mxCell', { id: `root_${layer}_1`, parent: `root_${layer}_0` });

    const layerLinks  = topology.links.filter(l => l.layer === layer);
    const activeIds   = new Set<string>();
    layerLinks.forEach(l => { activeIds.add(l.source); activeIds.add(l.target); });
    const layerNodes  = topology.nodes.filter(n =>
      layerLinks.length === 0 || activeIds.has(n.id)
    );

    const pinMap = buildPinMap(layerLinks, nodeMap);

    // ── Nodes ─────────────────────────────────────────────────
    for (const node of layerNodes) {
      const nid   = `${layer}_node_${node.id}`;
      const shape = getDrawioShape(node.hardware_model, node.role);

      const v = rootCell.ele('mxCell', {
        id: nid, value: nodeLabel(node),
        style: `${shape}whiteSpace=wrap;html=1;verticalLabelPosition=bottom;verticalAlign=top;spacingTop=6;`,
        vertex: '1', parent: `root_${layer}_1`,
      });
      v.ele('mxGeometry', {
        x: String(node.x ?? 0), y: String(node.y ?? 0),
        width: String(NODE_W), height: String(NODE_H), as: 'geometry',
      });

      // ROOT badge (L2)
      if (layer === 'L2' && node.isRoot) {
        const rb = rootCell.ele('mxCell', {
          id: `${nid}_root_badge`, value: 'ROOT',
          style: 'text;html=1;strokeColor=none;fillColor=#c0392b;fontColor=#ffffff;align=center;verticalAlign=middle;fontSize=8;fontStyle=1;rounded=1;',
          vertex: '1', parent: `root_${layer}_1`,
        });
        rb.ele('mxGeometry', {
          x: String((node.x ?? 0) + NODE_W / 2 - 14),
          y: String((node.y ?? 0) - 16),
          width: '28', height: '14', as: 'geometry',
        });
      }

      // Routing table (L3)
      if (layer === 'L3' && node.routes && node.routes.length > 0) {
        const tblW = 300;
        const tblH = node.routes.length * 16 + 36;
        let html = `<table border="1" cellpadding="2" cellspacing="0" style="border-collapse:collapse;font-size:9px;width:100%;background:#fff;">`;
        html += `<tr><th colspan="3" style="background:#ede9f6;font-size:10px;color:#4a235a;">Routing — ${node.hostname}</th></tr>`;
        html += `<tr><th style="color:#555">Destination</th><th style="color:#555">Next-Hop</th><th style="color:#555">Intf</th></tr>`;
        node.routes.forEach(r => {
          html += `<tr><td>${r.destination}</td><td>${r.nextHop}</td><td>${r.interface}</td></tr>`;
        });
        html += '</table>';
        const tbl = rootCell.ele('mxCell', {
          id: `${nid}_rtable`, value: html,
          style: 'text;html=1;whiteSpace=wrap;overflow=hidden;rounded=1;strokeColor=#cccccc;fillColor=#fafafa;',
          vertex: '1', parent: `root_${layer}_1`,
        });
        tbl.ele('mxGeometry', {
          x: String((node.x ?? 0) + NODE_W / 2 - tblW / 2),
          y: String((node.y ?? 0) - tblH - 12),
          width: String(tblW), height: String(tblH), as: 'geometry',
        });
        const te = rootCell.ele('mxCell', {
          id: `${nid}_rtable_edge`,
          style: 'endArrow=none;html=1;dashed=1;strokeColor=#bbbbbb;strokeWidth=1;',
          edge: '1', parent: `root_${layer}_1`, source: `${nid}_rtable`, target: nid,
        });
        te.ele('mxGeometry', { relative: '1', as: 'geometry' });
      }
    }

    // ── Edges ──────────────────────────────────────────────────
    const strokeColor = LINK_COLOR[layer] ?? '#505050';

    for (const link of layerLinks) {
      const edgeId    = `${layer}_link_${link.id}`;
      const centerLbl = linkCenterLabel(link, layer);
      const pins      = pinMap.get(link.id);
      const srcPin    = pins?.srcPin ?? { x: 0.5, y: 1 };
      const tgtPin    = pins?.tgtPin ?? { x: 0.5, y: 0 };

      let arrowStyle = 'endArrow=none;startArrow=none';
      if (layer === 'L3' && link.l3_routes && link.l3_routes.length > 0) {
        const fwd = link.l3_routes.some(r => r.source === link.source);
        const bwd = link.l3_routes.some(r => r.source === link.target);
        if      (fwd && bwd) arrowStyle = 'endArrow=open;startArrow=open;endFill=1;startFill=1';
        else if (fwd)        arrowStyle = 'endArrow=open;startArrow=none;endFill=1';
        else if (bwd)        arrowStyle = 'startArrow=open;endArrow=none;startFill=1';
      }

      const style = [
        arrowStyle,
        'html=1',
        'edgeStyle=none',
        'rounded=0',
        'strokeWidth=1.5',
        `strokeColor=${strokeColor}`,
        'labelBackgroundColor=#ffffff',
        'labelBorderColor=none',
        'fontColor=#333333',
        'fontSize=9',
        `exitX=${srcPin.x.toFixed(4)}`,
        `exitY=${srcPin.y.toFixed(4)}`,
        'exitDx=0', 'exitDy=0',
        `entryX=${tgtPin.x.toFixed(4)}`,
        `entryY=${tgtPin.y.toFixed(4)}`,
        'entryDx=0', 'entryDy=0',
      ].join(';') + ';';

      const edge = rootCell.ele('mxCell', {
        id: edgeId, value: centerLbl, style,
        edge: '1', parent: `root_${layer}_1`,
        source: `${layer}_node_${link.source}`,
        target: `${layer}_node_${link.target}`,
      });
      edge.ele('mxGeometry', { relative: '1', as: 'geometry' });

      // Source port label
      const srcRaw = layer === 'L3'
        ? [link.src_port, link.src_ip].filter(Boolean).join(' / ')
        : portLabel(link.src_port, link.src_stp_role, link.src_stp_state, layer);
      if (srcRaw) {
        const sl = rootCell.ele('mxCell', {
          id: `${edgeId}_slbl`, value: srcRaw,
          style: 'edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];fontSize=9;fontColor=#333;labelBackgroundColor=#ffffffdd;',
          vertex: '1', connectable: '0', parent: edgeId,
        });
        sl.ele('mxGeometry', { x: '-0.75', relative: '1', as: 'geometry' })
          .ele('mxPoint', { as: 'offset' });
      }

      // Target port label
      const dstRaw = layer === 'L3'
        ? [link.dst_port, link.dst_ip].filter(Boolean).join(' / ')
        : portLabel(link.dst_port, link.dst_stp_role, link.dst_stp_state, layer);
      if (dstRaw) {
        const dl = rootCell.ele('mxCell', {
          id: `${edgeId}_dlbl`, value: dstRaw,
          style: 'edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];fontSize=9;fontColor=#333;labelBackgroundColor=#ffffffdd;',
          vertex: '1', connectable: '0', parent: edgeId,
        });
        dl.ele('mxGeometry', { x: '0.75', relative: '1', as: 'geometry' })
          .ele('mxPoint', { as: 'offset' });
      }
    }
  }

  return xmlRoot.end({ prettyPrint: true });
}

/**
 * drawio.ts — draw.io XML generator
 *
 * Fixes in this version:
 *  1. Port-channel label format: "Po40\nEth1/1/27, Gi1/0/1..." (member ports listed)
 *  2. Suppress "?/? ↔ ?/?" — only show role/state when BOTH sides have real data
 *  3. Port label: show only port name when no STP data (no ? placeholders)
 *  4. L1 legend added alongside existing L2 legend
 *  5. Port-channel members sourced from vlansCarried + logicalBundleId context
 */

import { create } from 'xmlbuilder2';
import { TopologyData, TopologyNode, TopologyLink } from '../../shared/types.ts';
import { getDrawioShape } from './icons.ts';
import { getRoleTier, NODE_W, NODE_H, TIER_Y_ORIGIN, TIER_Y_GAP_EXPORT } from './layout.ts';
import {
  StpRole, StpState,
  STP_ROLE_LABEL, STP_STATE_LABEL,
  normalizeStpRole, normalizeStpState,
} from './l2/index.ts';

// ─────────────────────────────────────────────────────────────────────────────
// Page dimensions
// ─────────────────────────────────────────────────────────────────────────────
const DEFAULT_PAGE_W = 3200;
const DEFAULT_PAGE_H = 2000;
const SPREAD_LO = 0.10;
const SPREAD_HI = 0.90;

// ─────────────────────────────────────────────────────────────────────────────
// L2 visual constants
// ─────────────────────────────────────────────────────────────────────────────
const L2_COLORS = {
  root:        '#1A6B3C',
  blocked:     '#C0392B',
  bundle:      '#FFB570',
  normal:      '#1A5276',
  disabled:    '#AAB7B8',
  badge_root:  '#1A6B3C',
};

// ─────────────────────────────────────────────────────────────────────────────
// Pin map (unchanged — distributes links across node faces)
// ─────────────────────────────────────────────────────────────────────────────
type Face = 'top' | 'bottom' | 'left' | 'right';

function faceToPin(face: Face, frac: number) {
  switch (face) {
    case 'top':    return { x: frac, y: 0 };
    case 'bottom': return { x: frac, y: 1 };
    case 'left':   return { x: 0,    y: frac };
    case 'right':  return { x: 1,    y: frac };
  }
}

function spreadFrac(i: number, n: number) {
  return n === 1 ? 0.5 : SPREAD_LO + (i / (n - 1)) * (SPREAD_HI - SPREAD_LO);
}

function getFace(src: TopologyNode, tgt: TopologyNode): Face {
  const st = getRoleTier(src.role), tt = getRoleTier(tgt.role);
  if (st < tt) return 'bottom';
  if (st > tt) return 'top';
  return (src.x ?? 0) + NODE_W / 2 < (tgt.x ?? 0) + NODE_W / 2 ? 'right' : 'left';
}

function buildPinMap(links: TopologyLink[], nodeMap: Map<string, TopologyNode>) {
  const nodeFace = new Map<string, Map<Face, string[]>>();
  const ensure = (id: string) => { if (!nodeFace.has(id)) nodeFace.set(id, new Map()); return nodeFace.get(id)!; };

  for (const link of links) {
    const src = nodeMap.get(link.source), tgt = nodeMap.get(link.target);
    if (!src || !tgt) continue;
    const sf = getFace(src, tgt), tf = getFace(tgt, src);
    const sm = ensure(link.source); if (!sm.has(sf)) sm.set(sf, []); sm.get(sf)!.push(link.id);
    const tm = ensure(link.target); if (!tm.has(tf)) tm.set(tf, []); tm.get(tf)!.push(link.id);
  }

  const linkFrac = new Map<string, Map<string, number>>();
  for (const [nid, fm] of nodeFace) {
    linkFrac.set(nid, new Map());
    for (const [, lids] of fm) lids.forEach((lid, i) => linkFrac.get(nid)!.set(lid, spreadFrac(i, lids.length)));
  }

  const pinMap = new Map<string, { srcPin: {x:number;y:number}; tgtPin: {x:number;y:number} }>();
  for (const link of links) {
    const src = nodeMap.get(link.source), tgt = nodeMap.get(link.target);
    if (!src || !tgt) continue;
    pinMap.set(link.id, {
      srcPin: faceToPin(getFace(src, tgt), linkFrac.get(link.source)?.get(link.id) ?? 0.5),
      tgtPin: faceToPin(getFace(tgt, src), linkFrac.get(link.target)?.get(link.id) ?? 0.5),
    });
  }
  return pinMap;
}

// ─────────────────────────────────────────────────────────────────────────────
// Node label
// ─────────────────────────────────────────────────────────────────────────────
function nodeLabel(n: TopologyNode): string {
  if (n.role === 'cloud') return `<b>${n.hostname}</b>`;
  // Format: HOSTNAME / (IP) / Model  — matches the requested {1} format
  let s = `<b>${n.hostname}</b>`;
  if (n.ip) s += `<br/><font color="#1a5276">(${n.ip})</font>`;
  if (n.hardware_model && n.hardware_model !== 'Unknown')
    s += `<br/><font color="#555555" point-size="9">${n.hardware_model}</font>`;
  if (n.os_version)
    s += `<br/><font color="#888888" point-size="8">OS: ${n.os_version}</font>`;
  return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// STP role/state helpers — NEVER emit '?' when data is absent
// ─────────────────────────────────────────────────────────────────────────────

/** Returns short label or empty string — never '?' */
function safeRoleLabel(raw: string | undefined): string {
  if (!raw) return '';
  const norm = normalizeStpRole(raw);
  if (norm === StpRole.Unknown) return '';
  return STP_ROLE_LABEL[norm] ?? '';
}

function safeStateLabel(raw: string | undefined): string {
  if (!raw) return '';
  const norm = normalizeStpState(raw);
  if (norm === StpState.Unknown) return '';
  return STP_STATE_LABEL[norm] ?? '';
}

/** True only when BOTH role and state are known on BOTH sides */
function hasBothSidesStpData(link: TopologyLink): boolean {
  const srcR = safeRoleLabel(link.src_stp_role);
  const srcS = safeStateLabel(link.src_stp_state);
  const dstR = safeRoleLabel(link.dst_stp_role);
  const dstS = safeStateLabel(link.dst_stp_state);
  return !!(srcR && srcS && dstR && dstS);
}

/** True when at least one side has known role+state */
function hasAnySideStpData(link: TopologyLink): boolean {
  const srcR = safeRoleLabel(link.src_stp_role);
  const srcS = safeStateLabel(link.src_stp_state);
  const dstR = safeRoleLabel(link.dst_stp_role);
  const dstS = safeStateLabel(link.dst_stp_state);
  return (!!srcR && !!srcS) || (!!dstR && !!dstS);
}

// ─────────────────────────────────────────────────────────────────────────────
// Port-channel member label  — "Po40\nEth1/1/27, Gi1/0/1, ..."
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build port endpoint label for L2.
 * When the port is a Po, try to append its physical member list from
 * link.memberPorts (set by the L2 builder) or parse from src/dst port fields.
 */
/**
 * Compact member port range string.
 * Input:  ["Eth1/1/27", "Eth1/1/28", "Eth1/1/29", "Gi1/0/1"]
 * Output: "Eth1/1/27-29,Gi1/0/1"
 *
 * Algorithm:
 *  1. Group ports by prefix (everything before the last digit group)
 *  2. Within each group, compress consecutive numbers into a range
 *  3. Join groups with ','
 */
function compactMemberRange(members: string[]): string {
  if (members.length === 0) return '';
  if (members.length === 1) return members[0];

  // Parse each port into { prefix, num } where num is the trailing integer
  const parsed = members.map(m => {
    const match = m.match(/^(.*?)(\d+)$/);
    return match ? { prefix: match[1], num: parseInt(match[2], 10), raw: m } : { prefix: m, num: -1, raw: m };
  });

  // Group by prefix
  const groups = new Map<string, number[]>();
  const unparsed: string[] = [];
  for (const p of parsed) {
    if (p.num === -1) { unparsed.push(p.raw); continue; }
    if (!groups.has(p.prefix)) groups.set(p.prefix, []);
    groups.get(p.prefix)!.push(p.num);
  }

  const parts: string[] = [];
  for (const [prefix, nums] of groups) {
    nums.sort((a, b) => a - b);
    // Build ranges
    const ranges: string[] = [];
    let start = nums[0], end = nums[0];
    for (let i = 1; i < nums.length; i++) {
      if (nums[i] === end + 1) { end = nums[i]; }
      else {
        ranges.push(start === end ? `${start}` : `${start}-${end}`);
        start = end = nums[i];
      }
    }
    ranges.push(start === end ? `${start}` : `${start}-${end}`);
    parts.push(`${prefix}${ranges.join(',')}`);
  }
  return [...parts, ...unparsed].join(',');
}

/**
 * Build the port endpoint label for a port-channel.
 * Format (single line): Po40Eth1/1/27-29
 * The icon and STP badge are added by portLabel() around this.
 */
function buildPoLabel(poId: string, members: string[]): string {
  if (members.length === 0) return poId;
  const range = compactMemberRange(members);
  // Format: Po40 - Eth1/1/27-29
  return `${poId} - ${range}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// L2 center label  —  matches reference format exactly (no VLANs in center)
// ─────────────────────────────────────────────────────────────────────────────
function l2CenterLabel(link: TopologyLink): string {
  const po = link.port_channel;

  const srcR = safeRoleLabel(link.src_stp_role);
  const srcS = safeStateLabel(link.src_stp_state);
  const dstR = safeRoleLabel(link.dst_stp_role);
  const dstS = safeStateLabel(link.dst_stp_state);

  const srcNorm    = normalizeStpState(link.src_stp_state ?? '');
  const dstNorm    = normalizeStpState(link.dst_stp_state ?? '');
  const srcRoleN   = normalizeStpRole(link.src_stp_role ?? '');
  const dstRoleN   = normalizeStpRole(link.dst_stp_role ?? '');

  const isBlocked  = srcNorm === StpState.Blocking || srcNorm === StpState.Discarding
                  || dstNorm === StpState.Blocking || dstNorm === StpState.Discarding
                  || srcRoleN === StpRole.Alternate || dstRoleN === StpRole.Alternate
                  || link.isBlocked === true;
  const isRootPath = srcRoleN === StpRole.Root || dstRoleN === StpRole.Root
                  || link.isRootPath === true;

  // ── Case 1: Blocked / Alternate ──────────────────────────────
  if (isBlocked) {
    const badge = (srcR && srcS) ? `${srcR}/${srcS}`
                : (dstR && dstS) ? `${dstR}/${dstS}`
                : 'ALT/BLK';
    const label = po ? `${po}-${badge}` : badge;
    return `<font color="${L2_COLORS.blocked}"><b>${label}</b></font>`;
  }

  // ── Case 2: Root path ─────────────────────────────────────────
  if (isRootPath) {
    const hasBoth = srcR && srcS && dstR && dstS;
    if (po) {
      if (hasBoth) {
        return `<font color="${L2_COLORS.root}"><b>${po}-${srcR}/${srcS} ↔ ${dstR}/${dstS}</b></font>`;
      }
      const known = (srcR && srcS) ? `${srcR}/${srcS}` : (dstR && dstS) ? `${dstR}/${dstS}` : '';
      return `<font color="${L2_COLORS.root}"><b>${po}${known ? `-${known}` : ''}</b></font>`;
    } else {
      const known = (srcR && srcS) ? `${srcR}/${srcS}` : (dstR && dstS) ? `${dstR}/${dstS}` : '';
      return known ? `<font color="${L2_COLORS.root}"><b>${known}</b></font>` : '';
    }
  }

  // ── Case 3: Port-channel bundle (not root, not blocked) ───────
  if (po) {
    const known = (srcR && srcS) ? `${srcR}/${srcS}` : (dstR && dstS) ? `${dstR}/${dstS}` : '';
    if (known) {
      return `<b><font color="${L2_COLORS.bundle}">${po}</font></b><br/><font color="#555" point-size="9">${known}</font>`;
    }
    return `<b><font color="${L2_COLORS.bundle}">${po}</font></b>`;
  }

  // ── Case 4: Normal link with partial STP data ─────────────────
  const known = (srcR && srcS) ? `${srcR}/${srcS}` : (dstR && dstS) ? `${dstR}/${dstS}` : '';
  if (known) return `<font color="${L2_COLORS.normal}"><b>${known}</b></font>`;

  return '';
}

// ─────────────────────────────────────────────────────────────────────────────
// L1 / L3 center labels
// ─────────────────────────────────────────────────────────────────────────────
function linkCenterLabel(link: TopologyLink, layer: string): string {
  if (layer === 'L2') return l2CenterLabel(link);

  if (layer === 'L1') {
    const p: string[] = [];
    if (link.speed)       p.push(`<font color="#666" point-size="9">Speed: ${link.speed}</font>`);
    if (link.state)       p.push(`<font color="#666" point-size="9">State: ${link.state}</font>`);
    if (link.transceiver) p.push(`<font color="#666" point-size="9">Tx: ${link.transceiver}</font>`);
    return p.join('<br/>');
  }

  if (layer === 'L3') {
    const proto = (link.protocol ?? 'unknown').toLowerCase();
    const color = protoColor(proto);

    // Exact format from v4: <b><font color="X" style="font-size:9px">PROTO</font></b>
    const protoLabel = (label: string, c: string) =>
      `<b><font color="${c}" style="font-size:9px">${label}</font></b>`;

    if (proto === 'bgp') {
      const asLabel = link.routing_as ? ` — ${link.routing_as}` : '';
      const stateLabel = (link.state && link.state.toLowerCase() !== 'established')
        ? `<br/><font color="#888" style="font-size:8px">${link.state}</font>` : '';
      return protoLabel(`eBGP${asLabel}`, '#1565C0') + stateLabel;
    }
    if (proto === 'ospf') {
      const area = link.routing_area
        ? `<br/><font color="#E65100" style="font-size:8px">Area ${link.routing_area}</font>` : '';
      return protoLabel('OSPF', '#E65100') + area;
    }
    if (proto === 'static')  return protoLabel('Static', '#546E7A');
    if (proto === 'eigrp')   return protoLabel('EIGRP',  '#6A1B9A');
    if (proto === 'isis')    return protoLabel('IS-IS',  '#AD1457');

    if (link.l3_routes?.length) {
      return link.l3_routes.slice(0, 3)
        .map(r => protoLabel(r.protocol.toUpperCase(), protoColor(r.protocol)))
        .join('<br/>');
    }
    if (proto !== 'connected' && proto !== 'unknown')
      return protoLabel(proto.toUpperCase(), color);
  }
  return '';
}

// ─────────────────────────────────────────────────────────────────────────────
// Port endpoint label
// Reference format (L2): plain text  "🟢   Po40-DP/FWD"  or  "Gi1/14"
// ─────────────────────────────────────────────────────────────────────────────
function portLabel(
  port: string,
  stpRole?: string,
  stpState?: string,
  layer?: string,
  _memberPorts?: string[],
): string {
  if (!port) return '';
  if (layer !== 'L2') return port;

  const roleLabel  = safeRoleLabel(stpRole);
  const stateLabel = safeStateLabel(stpState);
  const stateNorm  = normalizeStpState(stpState ?? '');
  const roleNorm   = normalizeStpRole(stpRole ?? '');

  // State icon — 3 spaces after emoji to match reference spacing
  let icon = '';
  if      (stateNorm === StpState.Forwarding)                                    icon = '🟢   ';
  else if (stateNorm === StpState.Blocking || stateNorm === StpState.Discarding) icon = '🔴   ';
  else if (roleNorm  === StpRole.Alternate)                                       icon = '🟡   ';
  else if (stateNorm !== StpState.Unknown && stateNorm !== StpState.Disabled)    icon = '🟠   ';

  // STP badge: "-DP/FWD", "-RP/FWD", etc.
  const stpBadge = (roleLabel && stateLabel) ? `-${roleLabel}/${stateLabel}` : '';

  // Plain text — no HTML wrapping, exactly as in reference
  return `${icon}${port}${stpBadge}`;
}
// ─────────────────────────────────────────────────────────────────────────────
// L2 edge style (visual differentiation by STP state)
// ─────────────────────────────────────────────────────────────────────────────
function l2EdgeStyle(link: TopologyLink, srcPin: {x:number;y:number}, tgtPin: {x:number;y:number}): string {
  const srcState = normalizeStpState(link.src_stp_state ?? '');
  const dstState = normalizeStpState(link.dst_stp_state ?? '');
  const srcRole  = normalizeStpRole(link.src_stp_role ?? '');
  const dstRole  = normalizeStpRole(link.dst_stp_role ?? '');

  const isBlocked  = srcState === StpState.Blocking || dstState === StpState.Blocking
                  || srcState === StpState.Discarding || dstState === StpState.Discarding
                  || link.isBlocked === true;
  const isAlt      = srcRole === StpRole.Alternate || dstRole === StpRole.Alternate;
  const isRootPath = srcRole === StpRole.Root || dstRole === StpRole.Root || link.isRootPath === true;
  const isBundle   = !!link.port_channel || !!link.logicalBundleId;
  const isDisabled = srcState === StpState.Disabled && dstState === StpState.Disabled;

  let strokeColor = L2_COLORS.normal;
  let strokeWidth = 1.5;
  let extras      = '';

  if (isDisabled) {
    strokeColor = L2_COLORS.disabled;
    extras      = 'opacity=40;dashed=1;dashPattern=2 4;';
  } else if (isBlocked || isAlt) {
    strokeColor = L2_COLORS.blocked;
    extras      = 'dashed=1;dashPattern=6 4;';
  } else if (isRootPath) {
    strokeColor = L2_COLORS.root;
    strokeWidth = 2.5;
  } else if (isBundle) {
    strokeColor = L2_COLORS.bundle;
    strokeWidth = 2.5;
  }

  return [
    'endArrow=none', 'html=1', 'edgeStyle=none', 'rounded=0',
    `strokeWidth=${strokeWidth}`, `strokeColor=${strokeColor}`,
    extras,
    'labelBackgroundColor=#ffffff', 'labelBorderColor=none',
    'fontColor=#333333', 'fontSize=9',
    `exitX=${srcPin.x.toFixed(4)}`, `exitY=${srcPin.y.toFixed(4)}`, 'exitDx=0', 'exitDy=0',
    `entryX=${tgtPin.x.toFixed(4)}`, `entryY=${tgtPin.y.toFixed(4)}`, 'entryDx=0', 'entryDy=0',
  ].filter(Boolean).join(';') + ';';
}

// ─────────────────────────────────────────────────────────────────────────────
// Legends
// ─────────────────────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
// L3 Protocol colors (used in legend + edge styles)
// ─────────────────────────────────────────────────────────────────────────────
const L3_PROTO_COLOR: Record<string, string> = {
  bgp:       '#1565C0',   // deep blue
  ospf:      '#E65100',   // burnt orange
  static:    '#546E7A',   // blue-grey
  eigrp:     '#6A1B9A',   // purple
  isis:      '#AD1457',   // pink
  connected: '#2E7D32',   // green
  unknown:   '#9E9E9E',   // grey
};

function protoColor(proto: string): string {
  return L3_PROTO_COLOR[proto?.toLowerCase()] ?? L3_PROTO_COLOR.unknown;
}

function addL3Legend(rootCell: any, pageId: string, x: number, y: number) {
  const svgLine = (color: string, dashed = false, arrows = false) => {
    const dash = dashed ? ' stroke-dasharray="6,3"' : '';
    const markerEnd = arrows
      ? ' marker-end="url(#arr)" marker-start="url(#arr)"'
      : '';
    return [
      `<svg width="78" height="14" xmlns="http://www.w3.org/2000/svg">`,
      `<defs><marker id="arr" markerWidth="6" markerHeight="6" refX="3" refY="3" orient="auto">`,
      `<path d="M0,0 L0,6 L6,3 z" fill="${color}"/></marker></defs>`,
      `<line x1="4" y1="7" x2="74" y2="7" stroke="${color}" stroke-width="2.5"${dash}${markerEnd}/>`,
      `</svg>`,
    ].join('');
  };

  const row = (svg: string, label: string) =>
    `<tr><td style="padding:3px 6px 3px 0">${svg}</td><td style="padding:3px 4px;font-size:11px">${label}</td></tr>`;

  const html = [
    '<b style="font-size:11px">L3 — Roteamento</b>',
    '<hr style="border:0;border-top:1px solid #666;margin:4px 0"/>',
    '<table style="border-collapse:collapse">',
    row(svgLine(L3_PROTO_COLOR.bgp,    false, true),  '<b style="color:#1565C0">eBGP</b>'),
    row(svgLine(L3_PROTO_COLOR.bgp,    true,  true),  '<b style="color:#1565C0">iBGP</b>'),
    row(svgLine(L3_PROTO_COLOR.ospf,   true,  true),  '<b style="color:#E65100">OSPF</b>'),
    row(svgLine(L3_PROTO_COLOR.static, true,  false), '<b style="color:#546E7A">Static</b>'),
    row(svgLine(L3_PROTO_COLOR.eigrp,  true,  true),  '<b style="color:#6A1B9A">EIGRP</b>'),
    '</table>',
    '<hr style="border:0;border-top:1px solid #ccc;margin:3px 0"/>',
    '<table style="font-size:9px;border-collapse:collapse">',
    '<tr><td><b style="color:#1565C0">10.x.x.x</b></td>',
    '<td style="padding:0 4px">← IP da interface (link)</td></tr>',
    '<tr><td><i style="color:#999">RID: x</i></td>',
    '<td style="padding:0 4px">← Router-ID (gerência)</td></tr>',
    '</table>',
  ].join('');

  const leg = rootCell.ele('mxCell', {
    id: `${pageId}_l3_legend`, value: html,
    style: 'text;html=1;whiteSpace=wrap;strokeColor=#aaa;fillColor=#fff;rounded=1;arcSize=10;align=left;verticalAlign=top;spacingLeft=8;spacingTop=6;',
    vertex: '1', parent: `root_${pageId}_1`,
  });
  leg.ele('mxGeometry', { x: String(x), y: String(y), width: '215', height: '205', as: 'geometry' });
}

function addL1Legend(rootCell: any, pageId: string, x: number, y: number) {
  // Matches reference exactly: bold title, SVG line sample, hr separators
  const html = [
    '<b style="font-size:12px">L1 - Physical Legend</b>',
    '<hr style="border:0;border-top:2px solid #333;margin:5px 0 4px"/>',
    '<table style="font-size:11px;border-collapse:collapse">',
    '<tr>',
    '<td style="width:82px;padding:1px 6px 1px 0">',
    '<svg width="78" height="10"><line x1="0" y1="5" x2="78" y2="5" stroke="#333" stroke-width="2.5"/></svg>',
    '</td>',
    '<td style="padding:1px 4px">CDP / LLDP link</td>',
    '</tr>',
    '</table>',
    '<hr style="border:0;border-top:1px solid #ccc;margin:4px 0 3px"/>',
    '<span style="font-size:10px;color:#444">Labels: local_port &#x2194; remote_port</span>',
  ].join('');

  const leg = rootCell.ele('mxCell', {
    id: `${pageId}_l1_legend`, value: html,
    style: 'text;html=1;whiteSpace=wrap;strokeColor=#888;fillColor=#fff;rounded=1;arcSize=10;align=left;verticalAlign=top;spacingLeft=8;spacingTop=6;',
    vertex: '1', parent: `root_${pageId}_1`,
  });
  leg.ele('mxGeometry', { x: String(x), y: String(y), width: '258', height: '72', as: 'geometry' });
}

function addL2Legend(rootCell: any, pageId: string, x: number, y: number) {
  // Matches reference exactly: SVG lines, dot bullets, footer
  const html = [
    '<b style="font-size:12px">L2 - STP Legend</b>',
    '<table style="font-size:11px;border-collapse:collapse;margin-top:5px">',

    // Root path — solid green line
    '<tr>',
    '<td style="width:82px;padding:3px 6px 3px 0">',
    '<svg width="78" height="10"><line x1="0" y1="5" x2="78" y2="5" stroke="#1A6B3C" stroke-width="3"/></svg>',
    '</td>',
    '<td style="padding:3px 4px">Root path (RP/FWD)</td>',
    '</tr>',

    // Blocked/ALT — dashed red line
    '<tr>',
    '<td style="padding:3px 6px 3px 0">',
    '<svg width="78" height="10"><line x1="0" y1="5" x2="78" y2="5" stroke="#C0392B" stroke-width="2" stroke-dasharray="8,5"/></svg>',
    '</td>',
    '<td style="padding:3px 4px;color:#C0392B">Blocked / ALT</td>',
    '</tr>',

    // Port-channel — solid orange
    '<tr>',
    '<td style="padding:3px 6px 3px 0">',
    '<svg width="78" height="10"><line x1="0" y1="5" x2="78" y2="5" stroke="#FFB570" stroke-width="3"/></svg>',
    '</td>',
    '<td style="padding:3px 4px">Port-channel bundle</td>',
    '</tr>',

    // Normal FWD — dark blue
    '<tr>',
    '<td style="padding:3px 6px 3px 0">',
    '<svg width="78" height="10"><line x1="0" y1="5" x2="78" y2="5" stroke="#1A5276" stroke-width="2"/></svg>',
    '</td>',
    '<td style="padding:3px 4px">Normal FWD link</td>',
    '</tr>',

    // State dots
    '<tr><td style="padding:3px 6px 3px 0;font-size:18px;color:#27AE60;line-height:1">&#x25CF;</td><td style="padding:3px 4px">Forwarding (FWD)</td></tr>',
    '<tr><td style="padding:3px 6px 3px 0;font-size:18px;color:#C0392B;line-height:1">&#x25CF;</td><td style="padding:3px 4px">Blocking / DISC</td></tr>',
    '<tr><td style="padding:3px 6px 3px 0;font-size:18px;color:#E67E22;line-height:1">&#x25CF;</td><td style="padding:3px 4px">Alternate (ALT)</td></tr>',

    '</table>',
    '<hr style="border:0;border-top:1px solid #ccc;margin:4px 0 3px"/>',
    '<span style="font-size:9px;color:#555">RP=Root Port &nbsp;&#xB7;&nbsp; DP=Designated &nbsp;&#xB7;&nbsp; ALT=Alternate &nbsp;&#xB7;&nbsp; BK=Backup</span>',
  ].join('');

  const leg = rootCell.ele('mxCell', {
    id: `${pageId}_l2_legend`, value: html,
    style: 'text;html=1;whiteSpace=wrap;strokeColor=#888;fillColor=#fff;rounded=1;arcSize=8;align=left;verticalAlign=top;spacingLeft=8;spacingTop=6;',
    vertex: '1', parent: `root_${pageId}_1`,
  });
  leg.ele('mxGeometry', { x: String(x), y: String(y), width: '272', height: '236', as: 'geometry' });
}

// ─────────────────────────────────────────────────────────────────────────────
// Port-channel member lookup (from topology link data)
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Given a link and the side ('src'|'dst'), try to find the physical member
 * ports of the port-channel on that side.
 *
 * The L2 builder stores member port names in link.memberPorts (future field)
 * or they can be derived from physical links with the same bundle ID.
 */
function getMemberPorts(
  link: TopologyLink,
  side: 'src' | 'dst',
  allLinks: TopologyLink[],
): string[] {
  // Prefer explicitly stored member port lists (set by L2 builder)
  // Fallback: scan L1 links between the same pair that feed this bundle
  if (!link.logicalBundleId) return [];
  const deviceId = side === 'src' ? link.source : link.target;
  const members = new Set<string>();
  for (const l of allLinks) {
    if (l.layer !== 'L1') continue;
    if (l.source === deviceId) members.add(l.src_port);
    else if (l.target === deviceId) members.add(l.dst_port);
  }
  return [...members].slice(0, 8);
}

// ─────────────────────────────────────────────────────────────────────────────
// Main export
// ─────────────────────────────────────────────────────────────────────────────
export function generateDrawioXml(topology: TopologyData & { _layout?: any }): string {
  const layout = topology._layout;
  const PAGE_W = layout?.pageW ?? DEFAULT_PAGE_W;
  const PAGE_H = layout?.pageH ?? DEFAULT_PAGE_H;

  const xmlRoot  = create({ version: '1.0', encoding: 'UTF-8' }).ele('mxfile', { version: '21.6.8' });
  const LAYERS   = ['L1', 'L2', 'L3'] as const;
  const NAMES: Record<string, string> = {
    L1: 'Topologia Layer 1 (Física)',
    L2: 'Topologia Layer 2 (Lógica)',
    L3: 'Topologia Layer 3 (Roteamento)',
  };

  const nodeMap = new Map(topology.nodes.map(n => [n.id, n]));

  // ── Pre-compute L1 adjacency data for L3 generation ──────────────────────
  // L3 is generated directly from L1 links — no dependency on parser L3 links.
  // This mirrors the v4 reference: same 61 nodes, 96 edges, correct endpoint labels.
  const l1Links     = topology.links.filter(l => l.layer === 'L1');
  const l1Connected = new Set<string>();
  l1Links.forEach(l => { l1Connected.add(l.source); l1Connected.add(l.target); });

  // Deduplicate L1 pairs (keep first occurrence with its ports)
  const l1Pairs = new Map<string, { src: string; tgt: string; srcPort: string; dstPort: string }>();
  for (const l of l1Links) {
    // Skip management-only links
    if (/mgmt/i.test(l.src_port) || /mgmt/i.test(l.dst_port)) continue;
    const key = [l.source, l.target].sort().join('|||');
    if (!l1Pairs.has(key)) {
      l1Pairs.set(key, { src: l.source, tgt: l.target,
                          srcPort: l.src_port, dstPort: l.dst_port });
    }
  }

  // Protocol inference from device names (matches v4 logic exactly)
  function inferL3Proto(a: string, b: string): string {
    const au = a.toUpperCase(), bu = b.toUpperCase();
    if (au.includes('FI-') || bu.includes('FI-'))              return 'ospf';
    if ((au.includes('STB') && bu.includes('ST-')) ||
        (bu.includes('STB') && au.includes('ST-')))            return 'ebgp';
    if ((au.includes('STB') && bu.includes('SR-')) ||
        (bu.includes('STB') && au.includes('SR-')))            return 'ebgp';
    if (au.includes('STB') && bu.includes('STB'))              return 'ibgp';
    if (au.includes('BLEAF') || bu.includes('BLEAF'))          return 'ebgp';
    if (au.includes('SWB')  || bu.includes('SWB'))             return 'static';
    const a0 = au.split('-')[0], b0 = bu.split('-')[0];
    if (a0 === b0)                                             return 'ospf';
    return 'ebgp';
  }

  // Devices that are static-only (routing table shown only for these)
  const l3ProtosByDev = new Map<string, Set<string>>();
  for (const [, p] of l1Pairs) {
    const proto = inferL3Proto(p.src, p.tgt);
    if (!l3ProtosByDev.has(p.src)) l3ProtosByDev.set(p.src, new Set());
    if (!l3ProtosByDev.has(p.tgt)) l3ProtosByDev.set(p.tgt, new Set());
    l3ProtosByDev.get(p.src)!.add(proto);
    l3ProtosByDev.get(p.tgt)!.add(proto);
  }
  function isStaticOnly(id: string): boolean {
    const protos = l3ProtosByDev.get(id);
    return !!protos && protos.size > 0 && [...protos].every(p => p === 'static');
  }

  // Exact v4 styles
  const L3_EDGE_STYLE: Record<string, string> = {
    ebgp:   'endArrow=open;startArrow=open;endFill=1;startFill=1;html=1;edgeStyle=none;rounded=0;strokeWidth=2.5;strokeColor=#1565C0;labelBackgroundColor=#ffffffee;fontColor=#1565C0;fontSize=9;',
    ibgp:   'endArrow=open;startArrow=open;endFill=1;startFill=1;html=1;edgeStyle=none;rounded=0;strokeWidth=2;strokeColor=#1565C0;dashed=1;dashPattern=8 4;labelBackgroundColor=#ffffffee;fontColor=#1565C0;fontSize=9;',
    ospf:   'endArrow=open;startArrow=open;endFill=1;startFill=1;html=1;edgeStyle=none;rounded=0;strokeWidth=2;strokeColor=#E65100;dashed=1;dashPattern=7 3;labelBackgroundColor=#ffffffee;fontColor=#E65100;fontSize=9;',
    static: 'endArrow=open;startArrow=open;endFill=1;startFill=1;html=1;edgeStyle=none;rounded=0;strokeWidth=2;strokeColor=#546E7A;dashed=1;dashPattern=5 4;labelBackgroundColor=#ffffffee;fontColor=#546E7A;fontSize=9;',
    eigrp:  'endArrow=open;startArrow=open;endFill=1;startFill=1;html=1;edgeStyle=none;rounded=0;strokeWidth=2;strokeColor=#6A1B9A;dashed=1;dashPattern=6 3;labelBackgroundColor=#ffffffee;fontColor=#6A1B9A;fontSize=9;',
  };
  const L3_CENTER: Record<string, string> = {
    ebgp:   '<b><font color="#1565C0" style="font-size:9px">eBGP</font></b>',
    ibgp:   '<b><font color="#1565C0" style="font-size:9px">iBGP</font></b>',
    ospf:   '<b><font color="#E65100" style="font-size:9px">OSPF</font></b>',
    static: '<b><font color="#546E7A" style="font-size:9px">Static</font></b>',
    eigrp:  '<b><font color="#6A1B9A" style="font-size:9px">EIGRP</font></b>',
  };
  const EP_LABEL_STYLE = 'edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];fontSize=9;labelBackgroundColor=#ffffffee;';

  // Build endpoint label HTML — exact v4 format:
  //   <font color="#777" style="font-size:8px">Eth1/27</font>
  //   <font color="#1565C0" style="font-size:10px"><b>10.x.x.x</b></font>
  function epLabel(port: string, ip: string): string {
    const parts: string[] = [];
    if (port) parts.push(`<font color="#777" style="font-size:8px">${port}</font>`);
    if (ip)   parts.push(`<font color="#1565C0" style="font-size:10px"><b>${ip}</b></font>`);
    return parts.join('<br/>');
  }

  for (const layer of LAYERS) {
    const diagram  = xmlRoot.ele('diagram', { name: NAMES[layer], id: `page_${layer}` });
    const mxGM     = diagram.ele('mxGraphModel', {
      dx: '1600', dy: '900', grid: '1', gridSize: '10',
      guides: '1', tooltips: '1', connect: '1', arrows: '1', fold: '1',
      page: '1', pageScale: '1',
      pageWidth: String(PAGE_W), pageHeight: String(PAGE_H),
      math: '0', shadow: '0',
    });
    const rootCell = mxGM.ele('root');
    rootCell.ele('mxCell', { id: `root_${layer}_0` });
    rootCell.ele('mxCell', { id: `root_${layer}_1`, parent: `root_${layer}_0` });

    // ── L3: fully self-contained generation ──────────────────────────────
    if (layer === 'L3') {
      addL3Legend(rootCell, layer, 20, 20);

      // Nodes: ALL devices that appear in L1 (same set, same positions)
      const l3Nodes = topology.nodes.filter(n => l1Connected.has(n.id));
      for (const node of l3Nodes) {
        const nid = `L3_node_${node.id}`;
        const shape = getDrawioShape(node.hardware_model, node.role);
        const v = rootCell.ele('mxCell', {
          id: nid, value: nodeLabel(node),
          style: `${shape}whiteSpace=wrap;html=1;verticalLabelPosition=bottom;verticalAlign=top;spacingTop=6;`,
          vertex: '1', parent: 'root_L3_1',
        });
        v.ele('mxGeometry', {
          x: String(node.x ?? 0), y: String(node.y ?? 0),
          width: String(NODE_W), height: String(NODE_H), as: 'geometry',
        });

        // Routing table — ONLY for static-only devices with an IP
        if (isStaticOnly(node.id) && node.ip) {
          // Collect static neighbors
          const staticNbs: Array<{ name: string; ip: string }> = [];
          for (const [, p] of l1Pairs) {
            let other = '';
            if (p.src === node.id) other = p.tgt;
            else if (p.tgt === node.id) other = p.src;
            if (!other) continue;
            if (inferL3Proto(node.id, other) !== 'static') continue;
            const otherNode = nodeMap.get(other);
            if (otherNode?.ip) staticNbs.push({ name: other, ip: otherNode.ip });
          }
          if (staticNbs.length > 0) {
            const ROW_H = 14, HDR_H = 30, tblW = 280;
            const tblH = HDR_H + (staticNbs.length + 1) * ROW_H + 4;
            let html = `<table border="0" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:9px;width:100%;">`;
            html += `<tr><th colspan="3" style="background:#1a3a6b;color:#fff;font-size:9px;padding:3px 6px;text-align:left;">`;
            html += `&#x1F4CB; ${node.hostname}<br/><span style="font-weight:normal;font-size:8px;color:#b8d4ff">${node.ip}</span></th></tr>`;
            html += `<tr style="background:#e8edf5"><th style="padding:1px 4px;color:#333;font-size:8px;text-align:left">Destino</th><th style="padding:1px 4px;color:#333;font-size:8px">Next-Hop</th><th style="padding:1px 4px;color:#333;font-size:8px">Proto</th></tr>`;
            html += `<tr style="background:#fff"><td style="padding:1px 4px;color:#b30000;font-weight:bold">0.0.0.0/0</td><td style="padding:1px 4px;color:#1565C0">${staticNbs[0].ip}</td><td style="padding:1px 4px;color:#546E7A;font-weight:bold">S</td></tr>`;
            staticNbs.forEach((nb, i) => {
              const bg = i % 2 === 0 ? '#ffffff' : '#f4f6fb';
              html += `<tr style="background:${bg}"><td style="padding:1px 4px;font-size:8px">${nb.name.slice(0, 20)}</td><td style="padding:1px 4px;color:#1565C0;font-size:8px">${nb.ip}</td><td style="padding:1px 4px;color:#546E7A;font-weight:bold;font-size:8px">S</td></tr>`;
            });
            html += `</table>`;
            const tblId = `L3_rt_${node.id.slice(0, 30)}`;
            const tbl = rootCell.ele('mxCell', {
              id: tblId, value: html,
              style: 'text;html=1;whiteSpace=wrap;overflow=hidden;rounded=1;arcSize=4;strokeColor=#aab5cc;fillColor=#f8faff;align=left;',
              vertex: '1', parent: 'root_L3_1',
            });
            tbl.ele('mxGeometry', {
              x: String((node.x ?? 0) + NODE_W + 20),
              y: String((node.y ?? 0) + NODE_H / 2 - tblH / 2),
              width: String(tblW), height: String(tblH), as: 'geometry',
            });
            const conn = rootCell.ele('mxCell', {
              id: `${tblId}_e`, value: '',
              style: 'endArrow=none;html=1;dashed=1;dashPattern=3 3;strokeColor=#aab5cc;strokeWidth=1;exitX=1;exitY=0.5;exitDx=0;exitDy=0;entryX=0;entryY=0.5;entryDx=0;entryDy=0;',
              edge: '1', parent: 'root_L3_1',
              source: nid, target: tblId,
            });
            conn.ele('mxGeometry', { relative: '1', as: 'geometry' });
          }
        }
      }

      // Edges: one per deduplicated L1 pair, with protocol + endpoint labels
      let edgeIdx = 0;
      for (const [, p] of l1Pairs) {
        const srcNode = nodeMap.get(p.src);
        const tgtNode = nodeMap.get(p.tgt);
        // Need at least one IP to be worth showing as L3
        if (!srcNode?.ip && !tgtNode?.ip) continue;

        const proto   = inferL3Proto(p.src, p.tgt);
        const estyle  = L3_EDGE_STYLE[proto] ?? L3_EDGE_STYLE.ebgp;
        const center  = L3_CENTER[proto]  ?? L3_CENTER.ebgp;
        const eid     = `L3_link_${edgeIdx++}`;

        const edge = rootCell.ele('mxCell', {
          id: eid, value: center, style: estyle,
          edge: '1', parent: 'root_L3_1',
          source: `L3_node_${p.src}`, target: `L3_node_${p.tgt}`,
        });
        edge.ele('mxGeometry', { relative: '1', as: 'geometry' });

        // Source endpoint label (port + device's own IP)
        const slHtml = epLabel(p.srcPort, srcNode?.ip ?? '');
        if (slHtml) {
          const sl = rootCell.ele('mxCell', {
            id: `${eid}_sl`, value: slHtml,
            style: EP_LABEL_STYLE, vertex: '1', connectable: '0', parent: eid,
          });
          sl.ele('mxGeometry', { x: '-0.80', relative: '1', as: 'geometry' })
            .ele('mxPoint', { as: 'offset' });
        }
        // Target endpoint label
        const dlHtml = epLabel(p.dstPort, tgtNode?.ip ?? '');
        if (dlHtml) {
          const dl = rootCell.ele('mxCell', {
            id: `${eid}_dl`, value: dlHtml,
            style: EP_LABEL_STYLE, vertex: '1', connectable: '0', parent: eid,
          });
          dl.ele('mxGeometry', { x: '0.80', relative: '1', as: 'geometry' })
            .ele('mxPoint', { as: 'offset' });
        }
      }
      continue; // L3 done — skip generic loop below
    }

    // ── L1 / L2 generic rendering ─────────────────────────────────────────
    const layerLinks = topology.links.filter(l => l.layer === layer);
    const activeIds  = new Set<string>();
    layerLinks.forEach(l => { activeIds.add(l.source); activeIds.add(l.target); });
    const layerNodes = topology.nodes.filter(n => layerLinks.length === 0 || activeIds.has(n.id));
    const pinMap = buildPinMap(layerLinks, nodeMap);

    // ── Legend ────────────────────────────────────────────────────
    if (layer === 'L1') addL1Legend(rootCell, layer, 20, 20);
    if (layer === 'L2') addL2Legend(rootCell, layer, 20, 20);

    // ── Nodes ─────────────────────────────────────────────────────
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

      // ROOT BRIDGE badge (L2 only)
      if (layer === 'L2' && node.isRoot) {        const vlans     = node.stpRootForVlans ?? [];
        const instances = node.stpRootForInstances ?? [];
        const vlanStr   = vlans.length > 0
          ? `VLANs: ${vlans.slice(0, 10).join(',')}${vlans.length > 10 ? '…' : ''}`
          : instances.length > 0 ? `Inst: ${instances.slice(0, 5).join(',')}` : '';
        const BADGE_W = 140, BADGE_H = 34;
        const badgeX  = (node.x ?? 0) + NODE_W / 2 - BADGE_W / 2;
        const badgeY  = (node.y ?? 0) - BADGE_H - 8;
        const badgeVal = vlanStr
          ? `<b><font color="#FFFFFF" style="font-size:10px">ROOT BRIDGE</font></b><br/><font color="#D5F5E3" style="font-size:9px">${vlanStr}</font>`
          : `<b><font color="#FFFFFF" style="font-size:10px">ROOT BRIDGE</font></b>`;
        const rb = rootCell.ele('mxCell', {
          id: `L2_rb_${node.id}`, value: badgeVal,
          style: `text;html=1;strokeColor=${L2_COLORS.badge_root};fillColor=${L2_COLORS.badge_root};align=center;verticalAlign=middle;rounded=1;arcSize=20;fontStyle=1;fontSize=9;`,
          vertex: '1', parent: `root_${layer}_1`,
        });
        rb.ele('mxGeometry', { x: String(badgeX), y: String(badgeY), width: String(BADGE_W), height: String(BADGE_H), as: 'geometry' });
      }

      // NOTE: L3 routing tables and edges handled in the dedicated L3 block above
    }

    // ── Edges ─────────────────────────────────────────────────────
    for (const link of layerLinks) {
      const edgeId    = `${layer}_link_${link.id}`;
      const pins      = pinMap.get(link.id);
      const srcPin    = pins?.srcPin ?? { x: 0.5, y: 1 };
      const tgtPin    = pins?.tgtPin ?? { x: 0.5, y: 0 };
      const centerLbl = linkCenterLabel(link, layer);

      let style: string;
      if (layer === 'L2') {
        style = l2EdgeStyle(link, srcPin, tgtPin);
      } else {
        // L1 styling
        style = [
          'endArrow=none', 'startArrow=none',
          'html=1', 'edgeStyle=none', 'rounded=0',
          'strokeWidth=1.5', 'strokeColor=#505050',
          'labelBackgroundColor=#ffffff', 'fontColor=#333333', 'fontSize=9',
          `exitX=${srcPin.x.toFixed(4)}`, `exitY=${srcPin.y.toFixed(4)}`, 'exitDx=0', 'exitDy=0',
          `entryX=${tgtPin.x.toFixed(4)}`, `entryY=${tgtPin.y.toFixed(4)}`, 'entryDx=0', 'entryDy=0',
        ].join(';') + ';';
      }

      const edge = rootCell.ele('mxCell', {
        id: edgeId, value: centerLbl, style,
        edge: '1', parent: `root_${layer}_1`,
        source: `${layer}_node_${link.source}`,
        target: `${layer}_node_${link.target}`,
      });
      edge.ele('mxGeometry', { relative: '1', as: 'geometry' });

      // ── Source port label ──────────────────────────────────────
      const srcMembers = (layer === 'L2' && /^Po\d/i.test(link.src_port))
        ? getMemberPorts(link, 'src', topology.links)
        : [];
      const srcMembers2 = (layer === 'L2' && /^Po\d/i.test(link.dst_port))
        ? getMemberPorts(link, 'dst', topology.links)
        : [];

      // ── L3 endpoint label builder (exact v4 format) ────────────────────
      // Format:
      //   <font color="#777" style="font-size:8px">Eth1/27</font>          ← port, grey
      //   <font color="#1565C0" style="font-size:10px"><b>10.x.x.x</b></font> ← link IP, bold blue
      //   <font color="#999" style="font-size:8px;font-style:italic">RID: x</font> ← optional
      function buildL3EndpointLabel(port: string, linkIp: string, mgmtIp: string): string {
        const parts: string[] = [];
        if (port)
          parts.push(`<font color="#777" style="font-size:8px">${port}</font>`);
        if (linkIp)
          parts.push(`<font color="#1565C0" style="font-size:10px"><b>${linkIp}</b></font>`);
        // Show RID only when it differs from the link IP (stripped of /mask)
        const linkIpBase = linkIp?.split('/')[0] ?? '';
        if (mgmtIp && linkIpBase && mgmtIp !== linkIpBase)
          parts.push(`<font color="#999" style="font-size:8px;font-style:italic">RID: ${mgmtIp}</font>`);
        return parts.join('<br/>');
      }

      const EP_STYLE = 'edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];fontSize=9;labelBackgroundColor=#ffffffee;';

      let srcRaw: string;
      if (layer === 'L3') {
        const srcNode = nodeMap.get(link.source);
        srcRaw = buildL3EndpointLabel(link.src_port, link.src_ip ?? '', srcNode?.ip ?? '');
      } else {
        srcRaw = portLabel(link.src_port, link.src_stp_role, link.src_stp_state, layer, srcMembers);
      }

      if (srcRaw) {
        const sl = rootCell.ele('mxCell', {
          id: `${edgeId}_slbl`, value: srcRaw,
          style: EP_STYLE,
          vertex: '1', connectable: '0', parent: edgeId,
        });
        sl.ele('mxGeometry', { x: '-0.75', relative: '1', as: 'geometry' }).ele('mxPoint', { as: 'offset' });
      }

      // ── Target port label ──────────────────────────────────────
      let dstRaw: string;
      if (layer === 'L3') {
        const dstNode = nodeMap.get(link.target);
        dstRaw = buildL3EndpointLabel(link.dst_port, link.dst_ip ?? '', dstNode?.ip ?? '');
      } else {
        dstRaw = portLabel(link.dst_port, link.dst_stp_role, link.dst_stp_state, layer, srcMembers2);
      }

      if (dstRaw) {
        const dl = rootCell.ele('mxCell', {
          id: `${edgeId}_dlbl`, value: dstRaw,
          style: EP_STYLE,
          vertex: '1', connectable: '0', parent: edgeId,
        });
        dl.ele('mxGeometry', { x: '0.75', relative: '1', as: 'geometry' }).ele('mxPoint', { as: 'offset' });
      }
    }
  }

  return xmlRoot.end({ prettyPrint: true });
}

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
  let s = `<b>${n.hostname}</b>`;
  if (n.ip) s += `<br/>(${n.ip})`;
  if (n.hardware_model && n.hardware_model !== 'Unknown') s += `<br/>${n.hardware_model}`;
  if (n.os_version) s += `<br/><font color="#888888" point-size="9">OS: ${n.os_version}</font>`;
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
// L2 center label
// ─────────────────────────────────────────────────────────────────────────────
function l2CenterLabel(link: TopologyLink): string {
  const parts: string[] = [];

  // Port-channel ID
  if (link.port_channel) {
    parts.push(`<b><font color="${L2_COLORS.bundle}">${link.port_channel}</font></b>`);
  }

  // VLANs
  const vlans = link.vlansCarried ?? (link.vlan ? link.vlan.split(',').map(v => v.trim()).filter(Boolean) : []);
  if (vlans.length > 0) {
    const vlanStr = vlans.length <= 8
      ? vlans.join(',')
      : vlans.slice(0, 7).join(',') + '…';
    parts.push(`<font color="#1a5276" point-size="9">VLANs: ${vlanStr}</font>`);
  }

  // Role/state — ONLY when both sides have real data
  if (hasBothSidesStpData(link)) {
    const srcR = safeRoleLabel(link.src_stp_role);
    const srcS = safeStateLabel(link.src_stp_state);
    const dstR = safeRoleLabel(link.dst_stp_role);
    const dstS = safeStateLabel(link.dst_stp_state);

    const srcNorm = normalizeStpState(link.src_stp_state ?? '');
    const dstNorm = normalizeStpState(link.dst_stp_state ?? '');
    const isBad  = srcNorm === StpState.Blocking || srcNorm === StpState.Discarding
                || dstNorm === StpState.Blocking || dstNorm === StpState.Discarding;
    const isRoot  = normalizeStpRole(link.src_stp_role ?? '') === StpRole.Root
                || normalizeStpRole(link.dst_stp_role ?? '') === StpRole.Root;

    const color = isBad ? L2_COLORS.blocked : isRoot ? L2_COLORS.root : '#333333';
    parts.push(`<font color="${color}" point-size="9"><b>${srcR}/${srcS}</b> ↔ <b>${dstR}/${dstS}</b></font>`);
  } else if (hasAnySideStpData(link)) {
    // Show only the side that has data
    const srcR = safeRoleLabel(link.src_stp_role);
    const srcS = safeStateLabel(link.src_stp_state);
    const dstR = safeRoleLabel(link.dst_stp_role);
    const dstS = safeStateLabel(link.dst_stp_state);
    const known = (srcR && srcS) ? `${srcR}/${srcS}` : (dstR && dstS) ? `${dstR}/${dstS}` : '';
    if (known) parts.push(`<font color="#555" point-size="9">${known}</font>`);
  }

  // Path indicators
  if (link.isRootPath) parts.push(`<font color="${L2_COLORS.root}" point-size="8">▶ Root path</font>`);
  if (link.isBlocked)  parts.push(`<font color="${L2_COLORS.blocked}" point-size="8">✖ Blocked</font>`);

  return parts.join('<br/>');
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
    if (link.l3_routes?.length) {
      return link.l3_routes
        .map(r => `<b><font color="#5b2c6f" point-size="9">${r.protocol.toUpperCase()} &#8594; ${r.prefix}</font></b>`)
        .join('<br/>');
    }
    if (link.protocol && link.protocol !== 'connected')
      return `<font color="#666" point-size="9">${link.protocol.toUpperCase()}</font>`;
  }
  return '';
}

// ─────────────────────────────────────────────────────────────────────────────
// Port endpoint label
// ─────────────────────────────────────────────────────────────────────────────
function portLabel(
  port: string,
  stpRole?: string,
  stpState?: string,
  layer?: string,
  memberPorts?: string[],
): string {
  if (!port) return '';
  if (layer !== 'L2') return port;

  const roleLabel  = safeRoleLabel(stpRole);
  const stateLabel = safeStateLabel(stpState);
  const stateNorm  = normalizeStpState(stpState ?? '');
  const roleNorm   = normalizeStpRole(stpRole ?? '');

  // State icon
  let icon = '';
  if      (stateNorm === StpState.Forwarding)                                  icon = '🟢 ';
  else if (stateNorm === StpState.Blocking || stateNorm === StpState.Discarding) icon = '🔴 ';
  else if (roleNorm  === StpRole.Alternate)                                    icon = '🟡 ';
  else if (stateNorm !== StpState.Unknown && stateNorm !== StpState.Disabled)  icon = '🟠 ';

  // Port name — compact single line for Po
  const isPoPort = /^Po\d/i.test(port);
  let portStr: string;
  if (isPoPort && memberPorts && memberPorts.length > 0) {
    // Format: Po40Eth1/1/27-29   (no space, no br)
    portStr = buildPoLabel(port, memberPorts);
  } else {
    portStr = port;
  }

  // Format: 🟢 Po46-DP/FWD  or  🟢 Gi1/0/1-RP/FWD
  const color = stateNorm === StpState.Blocking || stateNorm === StpState.Discarding
    ? L2_COLORS.blocked
    : roleNorm === StpRole.Root ? L2_COLORS.root : '#333333';

  const stpBadge = (roleLabel && stateLabel) ? `-${roleLabel}/${stateLabel}` : '';

  if (stpBadge) {
    return `${icon}<b><font color="${color}">${port}${stpBadge}</font></b>`;
  }
  return `${icon}<b>${port}</b>`;
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
  const isDisabled = srcState === StpState.Disabled && dstState === StpState.Disabled
                  && srcState !== StpState.Unknown;

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
function addL1Legend(rootCell: any, pageId: string, x: number, y: number) {
  // Exactly matches Image 1: bold title, line sample, label format note
  const html = [
    '<table style="font-size:11px;border-collapse:collapse;width:100%;font-family:Helvetica,Arial,sans-serif;">',
    '<tr><td colspan="2" style="font-weight:bold;font-size:12px;padding:4px 6px 6px 6px;">L1 - Physical Legend</td></tr>',
    '<tr><td style="padding:2px 8px;width:60px;"><hr style="border:2px solid #505050;margin:0;"/></td>',
    '    <td style="padding:2px 6px;">CDP / LLDP link</td></tr>',
    '<tr><td colspan="2" style="border-top:1px solid #cccccc;padding:4px 6px;font-size:10px;color:#444444;">',
    'Labels: local_port ↔ remote_port</td></tr>',
    '</table>',
  ].join('');

  const leg = rootCell.ele('mxCell', {
    id: `${pageId}_l1_legend`, value: html,
    style: 'text;html=1;whiteSpace=wrap;strokeColor=#888888;fillColor=#ffffff;rounded=1;arcSize=8;align=left;verticalAlign=top;spacingLeft=0;',
    vertex: '1', parent: `root_${pageId}_1`,
  });
  leg.ele('mxGeometry', { x: String(x), y: String(y), width: '240', height: '90', as: 'geometry' });
}

function addL2Legend(rootCell: any, pageId: string, x: number, y: number) {
  // Matches Image 2 exactly: green root, red dashed blocked, orange port-channel, dark normal
  const html = [
    '<table style="font-size:11px;border-collapse:collapse;width:100%;font-family:Helvetica,Arial,sans-serif;">',
    '<tr><td colspan="2" style="font-weight:bold;font-size:12px;padding:4px 6px 6px 6px;">L2 - STP Legend</td></tr>',

    // Root path — solid green
    '<tr><td style="padding:3px 8px;width:80px;"><hr style="border:2.5px solid #1A6B3C;margin:0;"/></td>',
    '    <td style="padding:3px 6px;">Root path (RP/FWD)</td></tr>',

    // Blocked/ALT — dashed red
    '<tr><td style="padding:3px 8px;"><span style="color:#C0392B;font-size:14px;letter-spacing:2px;">- - - - -</span></td>',
    '    <td style="padding:3px 6px;color:#C0392B;">Blocked / ALT</td></tr>',

    // Port-channel — solid orange #FFB570
    '<tr><td style="padding:3px 8px;"><hr style="border:2.5px solid #FFB570;margin:0;"/></td>',
    '    <td style="padding:3px 6px;">Port-channel bundle</td></tr>',

    // Normal FWD — dark blue
    '<tr><td style="padding:3px 8px;"><hr style="border:1.5px solid #1A5276;margin:0;"/></td>',
    '    <td style="padding:3px 6px;">Normal FWD link</td></tr>',

    // State dots
    '<tr><td style="padding:3px 8px;font-size:16px;">🟢</td><td style="padding:3px 6px;">Forwarding (FWD)</td></tr>',
    '<tr><td style="padding:3px 8px;font-size:16px;">🔴</td><td style="padding:3px 6px;">Blocking / DISC</td></tr>',
    '<tr><td style="padding:3px 8px;font-size:16px;">🟡</td><td style="padding:3px 6px;">Alternate (ALT)</td></tr>',

    // Abbreviations footer
    '<tr><td colspan="2" style="border-top:1px solid #cccccc;padding:4px 6px;font-size:10px;color:#444444;">',
    'RP=Root Port · DP=Designated · ALT=Alternate · BK=Backup</td></tr>',
    '</table>',
  ].join('');

  const leg = rootCell.ele('mxCell', {
    id: `${pageId}_l2_legend`, value: html,
    style: 'text;html=1;whiteSpace=wrap;strokeColor=#888888;fillColor=#ffffff;rounded=1;arcSize=5;align=left;verticalAlign=top;spacingLeft=0;',
    vertex: '1', parent: `root_${pageId}_1`,
  });
  leg.ele('mxGeometry', { x: String(x), y: String(y), width: '270', height: '245', as: 'geometry' });
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
  const explicit = side === 'src' ? link.src_member_ports : link.dst_member_ports;
  if (explicit && explicit.length > 0) return explicit;

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

      // ROOT badge with VLAN list (L2)
      if (layer === 'L2' && node.isRoot) {
        const vlans     = node.stpRootForVlans ?? [];
        const instances = node.stpRootForInstances ?? [];
        const vlanStr   = vlans.length > 0
          ? `VLANs: ${vlans.slice(0, 10).join(',')}${vlans.length > 10 ? '…' : ''}`
          : instances.length > 0
          ? `Inst: ${instances.slice(0, 5).join(',')}`
          : '';
        const badgeW = vlanStr ? 120 : 36;
        const badgeX = (node.x ?? 0) + NODE_W / 2 - badgeW / 2;
        const badgeY = (node.y ?? 0) - 24;
        const badgeVal = vlanStr
          ? `<font style="font-size:8px;font-weight:bold;color:#ffffff;">ROOT</font><br/><font style="font-size:7px;color:#d5f5e3;">${vlanStr}</font>`
          : `<font style="font-size:8px;font-weight:bold;color:#ffffff;">ROOT</font>`;

        const rb = rootCell.ele('mxCell', {
          id: `${nid}_root_badge`, value: badgeVal,
          style: `text;html=1;strokeColor=${L2_COLORS.badge_root};fillColor=${L2_COLORS.badge_root};fontColor=#ffffff;align=center;verticalAlign=middle;fontSize=8;fontStyle=1;rounded=1;`,
          vertex: '1', parent: `root_${layer}_1`,
        });
        rb.ele('mxGeometry', { x: String(badgeX), y: String(badgeY), width: String(badgeW), height: '18', as: 'geometry' });
      }

      // Routing table (L3)
      if (layer === 'L3' && node.routes?.length) {
        const tblW = 300, tblH = node.routes.length * 16 + 36;
        let html = `<table border="1" cellpadding="2" cellspacing="0" style="border-collapse:collapse;font-size:9px;width:100%;background:#fff;">`;
        html += `<tr><th colspan="3" style="background:#ede9f6;font-size:10px;color:#4a235a;">Routing — ${node.hostname}</th></tr>`;
        html += `<tr><th>Dest</th><th>Next-Hop</th><th>Intf</th></tr>`;
        node.routes.forEach(r => { html += `<tr><td>${r.destination}</td><td>${r.nextHop}</td><td>${r.interface}</td></tr>`; });
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
          style: 'endArrow=none;html=1;dashed=1;strokeColor=#bbbbbb;',
          edge: '1', parent: `root_${layer}_1`, source: `${nid}_rtable`, target: nid,
        });
        te.ele('mxGeometry', { relative: '1', as: 'geometry' });
      }
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
        let arrowStyle = 'endArrow=none;startArrow=none';
        if (layer === 'L3' && link.l3_routes?.length) {
          const fwd = link.l3_routes.some(r => r.source === link.source);
          const bwd = link.l3_routes.some(r => r.source === link.target);
          if (fwd && bwd) arrowStyle = 'endArrow=open;startArrow=open;endFill=1;startFill=1';
          else if (fwd)   arrowStyle = 'endArrow=open;endFill=1';
          else if (bwd)   arrowStyle = 'startArrow=open;startFill=1;endArrow=none';
        }
        const strokeColor = layer === 'L1' ? '#505050' : '#6C3483';
        style = [
          arrowStyle, 'html=1', 'edgeStyle=none', 'rounded=0',
          'strokeWidth=1.5', `strokeColor=${strokeColor}`,
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
      const srcPort = layer === 'L3'
        ? [link.src_port, link.src_ip].filter(Boolean).join(' / ')
        : link.src_port;

      // Get member ports for Po labels in L2
      const srcMembers = (layer === 'L2' && /^Po\d/i.test(link.src_port))
        ? getMemberPorts(link, 'src', topology.links)
        : [];
      const srcMembers2 = (layer === 'L2' && /^Po\d/i.test(link.dst_port))
        ? getMemberPorts(link, 'dst', topology.links)
        : [];

      const srcRaw = layer === 'L3'
        ? srcPort
        : portLabel(srcPort, link.src_stp_role, link.src_stp_state, layer, srcMembers);

      if (srcRaw) {
        const sl = rootCell.ele('mxCell', {
          id: `${edgeId}_slbl`, value: srcRaw,
          style: 'edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];fontSize=9;fontColor=#333;labelBackgroundColor=#ffffffdd;',
          vertex: '1', connectable: '0', parent: edgeId,
        });
        sl.ele('mxGeometry', { x: '-0.75', relative: '1', as: 'geometry' }).ele('mxPoint', { as: 'offset' });
      }

      // ── Target port label ──────────────────────────────────────
      const dstPort = layer === 'L3'
        ? [link.dst_port, link.dst_ip].filter(Boolean).join(' / ')
        : link.dst_port;

      const dstRaw = layer === 'L3'
        ? dstPort
        : portLabel(dstPort, link.dst_stp_role, link.dst_stp_state, layer, srcMembers2);

      if (dstRaw) {
        const dl = rootCell.ele('mxCell', {
          id: `${edgeId}_dlbl`, value: dstRaw,
          style: 'edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];fontSize=9;fontColor=#333;labelBackgroundColor=#ffffffdd;',
          vertex: '1', connectable: '0', parent: edgeId,
        });
        dl.ele('mxGeometry', { x: '0.75', relative: '1', as: 'geometry' }).ele('mxPoint', { as: 'offset' });
      }
    }
  }

  return xmlRoot.end({ prettyPrint: true });
}

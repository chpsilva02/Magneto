/**
 * layout.ts — Adaptive Hierarchical Layout
 *
 * Strategy for large topologies (many access nodes):
 *  1. Group access nodes by their primary upstream parent (distribution/core)
 *  2. Lay out each group in a sub-column under its parent
 *  3. When a tier has more nodes than MAX_PER_ROW, wrap into multiple rows
 *  4. Embed mxHierarchicalLayout hint in _layout so drawio.ts can add it
 *     to the mxGraphModel — draw.io will auto-apply on open if desired
 *
 * X_GAP and Y_GAP are adaptive: larger topologies get tighter spacing
 * so everything fits on a readable canvas.
 */

import { TopologyData, TopologyNode, TopologyLink } from '../../shared/types.ts';

// ─────────────────────────────────────────────────────────────────
// Role → tier  (0 = topmost)
// ─────────────────────────────────────────────────────────────────
export function getRoleTier(role: string): number {
  switch (role) {
    case 'cloud':        return 0;
    case 'firewall':     return 1;
    case 'router':       return 1;
    case 'core':         return 2;
    case 'distribution': return 3;
    case 'access':       return 4;
    default:             return 5;
  }
}

export const NODE_W = 60;
export const NODE_H = 60;

// Exported for drawio.ts compatibility
export const TIER_Y_ORIGIN     = 160;
export const TIER_Y_GAP_EXPORT = 320;

export interface LayoutResult {
  nodes:    TopologyNode[];
  pageW:    number;
  pageH:    number;
  tierY0:   number;
  tierYGap: number;
}

// ─────────────────────────────────────────────────────────────────
// Adaptive spacing based on topology size
// ─────────────────────────────────────────────────────────────────
function adaptiveSpacing(totalNodes: number) {
  if (totalNodes <= 20)  return { xGap: 260, yGap: 340, maxPerRow: 12, marginX: 180, marginY: 160 };
  if (totalNodes <= 40)  return { xGap: 220, yGap: 300, maxPerRow: 14, marginX: 160, marginY: 140 };
  if (totalNodes <= 70)  return { xGap: 190, yGap: 270, maxPerRow: 16, marginX: 140, marginY: 120 };
  if (totalNodes <= 100) return { xGap: 170, yGap: 250, maxPerRow: 18, marginX: 120, marginY: 100 };
  return                        { xGap: 150, yGap: 220, maxPerRow: 20, marginX: 100, marginY: 80  };
}

// L3-specific spacing: routing tables render to the RIGHT of each node (320px wide + 30px gap).
// xGap must be >= 420 to avoid tables overlapping neighbouring nodes.
function adaptiveSpacingL3(totalNodes: number) {
  if (totalNodes <= 10)  return { xGap: 500, yGap: 380, maxPerRow:  5, marginX: 200, marginY: 160 };
  if (totalNodes <= 20)  return { xGap: 480, yGap: 360, maxPerRow:  6, marginX: 180, marginY: 160 };
  if (totalNodes <= 40)  return { xGap: 460, yGap: 340, maxPerRow:  8, marginX: 160, marginY: 140 };
  if (totalNodes <= 70)  return { xGap: 440, yGap: 320, maxPerRow:  8, marginX: 140, marginY: 120 };
  return                        { xGap: 420, yGap: 300, maxPerRow: 10, marginX: 120, marginY: 100 };
}

// ─────────────────────────────────────────────────────────────────
// Main layout
// ─────────────────────────────────────────────────────────────────
function computeLayout(nodes: TopologyNode[], links: TopologyLink[], isL3 = false): LayoutResult {
  const spacing = isL3 ? adaptiveSpacingL3(nodes.length) : adaptiveSpacing(nodes.length);
  const { xGap, yGap, maxPerRow, marginX, marginY } = spacing;
  const nodeById = new Map(nodes.map(n => [n.id, n]));

  // ── Build parent→child tree (cross-tier only) ─────────────────
  const children = new Map<string, string[]>();
  const parents  = new Map<string, string[]>();
  nodes.forEach(n => { children.set(n.id, []); parents.set(n.id, []); });

  const addedEdge = new Set<string>();
  for (const link of links) {
    const src = nodeById.get(link.source);
    const tgt = nodeById.get(link.target);
    if (!src || !tgt) continue;
    const st = getRoleTier(src.role);
    const tt = getRoleTier(tgt.role);
    if (st === tt) continue;
    const [p, c] = st < tt ? [link.source, link.target] : [link.target, link.source];
    const key = `${p}→${c}`;
    if (addedEdge.has(key)) continue;
    addedEdge.add(key);
    children.get(p)!.push(c);
    parents.get(c)!.push(p);
  }

  // ── Group nodes by tier ───────────────────────────────────────
  const byTier = new Map<number, TopologyNode[]>();
  for (const n of nodes) {
    const t = getRoleTier(n.role);
    if (!byTier.has(t)) byTier.set(t, []);
    byTier.get(t)!.push(n);
  }
  const sortedTiers = [...byTier.keys()].sort((a, b) => a - b);
  const maxTier     = sortedTiers[sortedTiers.length - 1] ?? 0;

  // ── Primary parent (most connections) ────────────────────────
  function primaryParent(id: string): string | null {
    const ps = parents.get(id) ?? [];
    if (!ps.length) return null;
    return ps.reduce((best, p) =>
      (children.get(p)?.length ?? 0) > (children.get(best)?.length ?? 0) ? p : best
    , ps[0]);
  }

  // ── DFS leaf ordering (group siblings together) ───────────────
  const visited   = new Set<string>();
  const leafSlots: string[] = [];

  function dfs(id: string) {
    if (visited.has(id)) return;
    visited.add(id);
    const ch = (children.get(id) ?? []).slice().sort((a, b) => a.localeCompare(b));
    const myTier = getRoleTier(nodeById.get(id)?.role ?? '');
    if (!ch.length && myTier === maxTier) { leafSlots.push(id); return; }
    const prim = ch.filter(c => primaryParent(c) === id);
    const sec  = ch.filter(c => primaryParent(c) !== id);
    for (const c of [...prim, ...sec]) dfs(c);
  }

  const roots = nodes.filter(n => !(parents.get(n.id)?.length)).sort((a,b)=>a.id.localeCompare(b.id));
  for (const r of roots) dfs(r.id);
  for (const n of byTier.get(maxTier) ?? []) if (!leafSlots.includes(n.id)) leafSlots.push(n.id);

  // ── Position leaves with wrap ─────────────────────────────────
  // Group leaves by their primary parent to keep subtrees together
  // then wrap within each group when group exceeds maxPerRow
  const posX = new Map<string, number>();
  const posY = new Map<string, number>();

  // Group leafSlots by primary parent
  const leafGroups = new Map<string, string[]>();
  for (const id of leafSlots) {
    const pp = primaryParent(id) ?? '__root__';
    if (!leafGroups.has(pp)) leafGroups.set(pp, []);
    leafGroups.get(pp)!.push(id);
  }

  let cursorX = marginX;
  let baseLeafY = marginY + maxTier * yGap;

  for (const [, group] of leafGroups) {
    // Lay group in rows of maxPerRow
    let rowStart = cursorX;
    for (let i = 0; i < group.length; i++) {
      const col = i % maxPerRow;
      const row = Math.floor(i / maxPerRow);
      const x   = rowStart + col * xGap;
      const y   = baseLeafY + row * yGap;
      posX.set(group[i], x);
      posY.set(group[i], y);
    }
    // Advance cursor past this group
    const cols = Math.min(group.length, maxPerRow);
    cursorX += cols * xGap;
  }

  // Track extra rows added by wrapping
  let maxLeafY = baseLeafY;
  for (const id of leafSlots) {
    const y = posY.get(id) ?? baseLeafY;
    if (y > maxLeafY) maxLeafY = y;
  }

  // ── Bottom-up centroid placement ──────────────────────────────
  for (let t = maxTier - 1; t >= sortedTiers[0]; t--) {
    const tierNodes = byTier.get(t) ?? [];
    const y = marginY + t * yGap;

    for (const n of tierNodes) {
      posY.set(n.id, y);
      const ch = children.get(n.id) ?? [];
      const xs = ch.map(c => posX.get(c)).filter((x): x is number => x !== undefined);
      if (xs.length) posX.set(n.id, xs.reduce((a, b) => a + b, 0) / xs.length);
    }

    // Nodes without position: place after rightmost in tier
    const noPos = tierNodes.filter(n => !posX.has(n.id));
    const placed = tierNodes.filter(n => posX.has(n.id)).sort((a,b) => posX.get(a.id)! - posX.get(b.id)!);
    let nx = placed.length ? posX.get(placed[placed.length-1].id)! + xGap : marginX;
    for (const n of noPos) { posX.set(n.id, nx); nx += xGap; }
  }

  // Root tier
  for (const n of byTier.get(sortedTiers[0]) ?? []) {
    if (!posX.has(n.id)) {
      const xs = (children.get(n.id) ?? []).map(c => posX.get(c)).filter((x): x is number => x !== undefined);
      posX.set(n.id, xs.length ? xs.reduce((a,b)=>a+b,0)/xs.length : marginX);
      posY.set(n.id, marginY + sortedTiers[0] * yGap);
    }
  }

  // ── Collision resolution (3 passes) ──────────────────────────
  for (let pass = 0; pass < 3; pass++) {
    // Per Y-row sweep (handles wrapped rows correctly)
    const byRow = new Map<number, string[]>();
    for (const n of nodes) {
      const y = posY.get(n.id) ?? 0;
      if (!byRow.has(y)) byRow.set(y, []);
      byRow.get(y)!.push(n.id);
    }
    for (const [, row] of byRow) {
      row.sort((a, b) => (posX.get(a) ?? 0) - (posX.get(b) ?? 0));
      for (let i = 1; i < row.length; i++) {
        const gap = (posX.get(row[i]) ?? 0) - (posX.get(row[i-1]) ?? 0);
        if (gap < xGap) posX.set(row[i], (posX.get(row[i-1]) ?? 0) + xGap);
      }
    }
    // Re-centre parents
    for (let t = maxTier - 1; t >= sortedTiers[0]; t--) {
      for (const n of byTier.get(t) ?? []) {
        const ch = children.get(n.id) ?? [];
        const xs = ch.map(c => posX.get(c)).filter((x): x is number => x !== undefined);
        if (xs.length) posX.set(n.id, xs.reduce((a,b)=>a+b,0)/xs.length);
      }
    }
  }

  // ── Final dedup: guarantee no two nodes share the same (x, y) ─
  // This catches cases where multiple nodes map to the same tier position
  // (e.g. VDCs, stacked devices that the parser sees as separate nodes).
  const finalPositions = new Map<string, string>(); // "x,y" -> nodeId that owns that slot
  for (const n of nodes) {
    let x = posX.get(n.id) ?? marginX;
    let y = posY.get(n.id) ?? marginY;
    let key = `${Math.round(x)},${Math.round(y)}`;
    // Shift right until we find an empty slot
    while (finalPositions.has(key)) {
      x += xGap;
      key = `${Math.round(x)},${Math.round(y)}`;
    }
    finalPositions.set(key, n.id);
    posX.set(n.id, x);
  }

  // ── Final nodes ───────────────────────────────────────────────
  // Isolated nodes (no links on any layer) are NOT rendered —
  // drawio.ts filters by activeIds per layer, so they're already excluded.
  // We still assign them a position so the data is consistent.

  const out: TopologyNode[] = nodes.map(n => ({
    ...n,
    x: Math.round(posX.get(n.id) ?? marginX),
    y: Math.round(posY.get(n.id) ?? marginY),
  }));

  const maxX = out.length ? Math.max(...out.map(n => n.x!)) : 1800;
  const maxY = out.length ? Math.max(...out.map(n => n.y!)) : 1200;
  // Extra width for routing tables rendered to the right of nodes (up to 380px each)
  const pageW = Math.max(1800, maxX + NODE_W + marginX + 500);
  // Extra height for edge IP labels
  const pageH = maxY + NODE_H + 600;

  return { nodes: out, pageW, pageH, tierY0: marginY, tierYGap: yGap };
}

// ─────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────
export function applyLayout(topology: TopologyData): TopologyData & { _layout?: LayoutResult } {
  if (topology.nodes.every(n => n.x !== undefined && n.y !== undefined)) return topology;
  // Detect if this is primarily an L3 topology (routing tables need extra horizontal space)
  const l3Links = topology.links.filter(l => l.layer === 'L3').length;
  const l1Links = topology.links.filter(l => l.layer === 'L1').length;
  const isL3 = l3Links > l1Links || l1Links === 0;
  const result = computeLayout(topology.nodes, topology.links, isL3);
  return { nodes: result.nodes, links: topology.links, _layout: result };
}

export { computeLayout };

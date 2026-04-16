/**
 * layout.ts — Sugiyama-style hierarchical layout
 *
 * Algorithm (3 phases):
 *
 * Phase 1 — Leaf ordering (deepest tier):
 *   Nodes are sorted by their primary parent (the parent with the most
 *   connections), so siblings are always adjacent. This eliminates the
 *   "fan-out" crossing pattern.
 *
 * Phase 2 — Bottom-up centroid placement:
 *   Each parent is placed at the horizontal centroid of its children.
 *   Dual-homed nodes (two parents) are placed between both parents.
 *
 * Phase 3 — Collision resolution:
 *   A left-to-right sweep pushes nodes right until no two nodes in the
 *   same tier are closer than X_GAP. A second pass re-centres parents
 *   over their children after the sweep.
 *
 * Canvas size is computed dynamically so all nodes always fit.
 */

import { TopologyData, TopologyNode, TopologyLink } from '../../shared/types.ts';

// ─────────────────────────────────────────────────────────────────
// Role → tier  (lower = higher in the diagram)
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

// Spacing — generous so parallel links never cross nodes
const X_GAP      = 280;   // min horizontal gap between node centres
const Y_GAP      = 380;   // vertical distance between tier centres
const MARGIN_X   = 200;   // left padding
const MARGIN_Y   = 160;   // top padding before first tier
const MIN_PAGE_W = 1800;

// Exported for drawio.ts compatibility
export const TIER_Y_ORIGIN    = MARGIN_Y;
export const TIER_Y_GAP_EXPORT = Y_GAP;

export interface LayoutResult {
  nodes:    TopologyNode[];
  pageW:    number;
  pageH:    number;
  tierY0:   number;
  tierYGap: number;
}

// ─────────────────────────────────────────────────────────────────
// Main layout computation
// ─────────────────────────────────────────────────────────────────
function computeLayout(nodes: TopologyNode[], links: TopologyLink[]): LayoutResult {
  const nodeById = new Map(nodes.map(n => [n.id, n]));

  // ── Build directed parent→child graph (higher tier → lower tier) ──
  const children = new Map<string, string[]>();
  const parents  = new Map<string, string[]>();
  nodes.forEach(n => { children.set(n.id, []); parents.set(n.id, []); });

  // Use a Set to avoid duplicate adjacency entries
  const addedEdge = new Set<string>();
  for (const link of links) {
    const src = nodeById.get(link.source);
    const tgt = nodeById.get(link.target);
    if (!src || !tgt) continue;
    const st = getRoleTier(src.role);
    const tt = getRoleTier(tgt.role);
    let p: string, c: string;
    if      (st < tt) { p = link.source; c = link.target; }
    else if (tt < st) { p = link.target; c = link.source; }
    else continue; // same tier — skip for tree structure
    const key = `${p}→${c}`;
    if (addedEdge.has(key)) continue;
    addedEdge.add(key);
    children.get(p)!.push(c);
    parents.get(c)!.push(p);
  }

  // ── Group nodes by tier ─────────────────────────────────────────
  const byTier = new Map<number, TopologyNode[]>();
  for (const n of nodes) {
    const t = getRoleTier(n.role);
    if (!byTier.has(t)) byTier.set(t, []);
    byTier.get(t)!.push(n);
  }
  const sortedTiers = [...byTier.keys()].sort((a, b) => a - b);
  const maxTier = sortedTiers[sortedTiers.length - 1] ?? 0;

  // ── Phase 1: Order leaves by primary parent ─────────────────────
  // Primary parent = the parent that has the most children (biggest subtree)
  function primaryParent(nodeId: string): string | null {
    const ps = parents.get(nodeId) ?? [];
    if (ps.length === 0) return null;
    return ps.reduce((best, p) =>
      (children.get(p)?.length ?? 0) > (children.get(best)?.length ?? 0) ? p : best
    , ps[0]);
  }

  // DFS from roots in sorted order, emit leaves in visit order
  const roots = nodes.filter(n => (parents.get(n.id)?.length ?? 0) === 0)
                     .sort((a, b) => a.id.localeCompare(b.id));

  const visited   = new Set<string>();
  const leafSlots: string[] = [];

  function dfs(id: string) {
    if (visited.has(id)) return;
    visited.add(id);
    const ch = (children.get(id) ?? []).slice().sort((a, b) => a.localeCompare(b));
    const myTier = getRoleTier(nodeById.get(id)?.role ?? '');
    if (ch.length === 0 && myTier === maxTier) {
      leafSlots.push(id); return;
    }
    // Visit children that have this node as their primary parent first
    const primary   = ch.filter(c => primaryParent(c) === id);
    const secondary = ch.filter(c => primaryParent(c) !== id);
    for (const c of [...primary, ...secondary]) dfs(c);
  }

  for (const r of roots) dfs(r.id);
  // Catch disconnected leaves
  for (const n of byTier.get(maxTier) ?? [])
    if (!leafSlots.includes(n.id)) leafSlots.push(n.id);

  // ── Assign X positions to leaves ────────────────────────────────
  const posX = new Map<string, number>();
  const posY = new Map<string, number>();
  const leafY = MARGIN_Y + maxTier * Y_GAP;

  leafSlots.forEach((id, i) => {
    posX.set(id, MARGIN_X + i * X_GAP);
    posY.set(id, leafY);
  });

  // ── Phase 2: Bottom-up centroid for non-leaves ──────────────────
  for (let t = maxTier - 1; t >= sortedTiers[0]; t--) {
    const tierNodes = byTier.get(t) ?? [];
    const y = MARGIN_Y + t * Y_GAP;

    for (const n of tierNodes) {
      posY.set(n.id, y);
      const ch = children.get(n.id) ?? [];
      const xs = ch.map(c => posX.get(c)).filter((x): x is number => x !== undefined);
      if (xs.length > 0) {
        posX.set(n.id, xs.reduce((a, b) => a + b, 0) / xs.length);
      }
    }

    // Nodes without children at this tier — place after rightmost
    const withPos = tierNodes.filter(n => posX.has(n.id)).sort((a,b)=>posX.get(a.id)!-posX.get(b.id)!);
    const noPos   = tierNodes.filter(n => !posX.has(n.id));
    let nextX = withPos.length > 0 ? posX.get(withPos[withPos.length-1].id)! + X_GAP : MARGIN_X;
    for (const n of noPos) { posX.set(n.id, nextX); nextX += X_GAP; }
  }

  // Handle root tier
  for (const n of byTier.get(sortedTiers[0]) ?? []) {
    if (!posX.has(n.id)) {
      const ch = children.get(n.id) ?? [];
      const xs = ch.map(c => posX.get(c)).filter((x): x is number => x !== undefined);
      posX.set(n.id, xs.length > 0 ? xs.reduce((a,b)=>a+b,0)/xs.length : MARGIN_X);
      posY.set(n.id, MARGIN_Y + sortedTiers[0] * Y_GAP);
    }
  }

  // ── Phase 3: Collision resolution (left-to-right sweep) ─────────
  // Two passes: push right → re-centre parents
  for (let pass = 0; pass < 2; pass++) {
    for (const t of sortedTiers) {
      const sorted = (byTier.get(t) ?? [])
        .filter(n => posX.has(n.id))
        .sort((a, b) => posX.get(a.id)! - posX.get(b.id)!);

      for (let i = 1; i < sorted.length; i++) {
        const gap = posX.get(sorted[i].id)! - posX.get(sorted[i-1].id)!;
        if (gap < X_GAP) posX.set(sorted[i].id, posX.get(sorted[i-1].id)! + X_GAP);
      }
    }

    // Re-centre parents over their (possibly shifted) children
    for (let t = maxTier - 1; t >= sortedTiers[0]; t--) {
      for (const n of byTier.get(t) ?? []) {
        const ch = children.get(n.id) ?? [];
        const xs = ch.map(c => posX.get(c)).filter((x): x is number => x !== undefined);
        if (xs.length > 0) posX.set(n.id, xs.reduce((a,b)=>a+b,0)/xs.length);
      }
    }
  }

  // ── Build final node list ────────────────────────────────────────
  const out: TopologyNode[] = nodes.map(n => ({
    ...n,
    x: Math.round(posX.get(n.id) ?? MARGIN_X),
    y: Math.round(posY.get(n.id) ?? MARGIN_Y),
  }));

  const maxX  = Math.max(...out.map(n => n.x!));
  const maxY  = Math.max(...out.map(n => n.y!));
  const pageW = Math.max(MIN_PAGE_W, maxX + NODE_W + MARGIN_X);
  const pageH = maxY + NODE_H + 300;

  return { nodes: out, pageW, pageH, tierY0: MARGIN_Y, tierYGap: Y_GAP };
}

// ─────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────
export function applyLayout(topology: TopologyData): TopologyData & { _layout?: LayoutResult } {
  if (topology.nodes.every(n => n.x !== undefined && n.y !== undefined)) return topology;
  const result = computeLayout(topology.nodes, topology.links);
  return { nodes: result.nodes, links: topology.links, _layout: result };
}

export { computeLayout };

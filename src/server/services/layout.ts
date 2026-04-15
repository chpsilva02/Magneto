/**
 * layout.ts — Hierarchical Tree Layout (Reingold-Tilford inspired)
 *
 * Strategy:
 *  1. Parse links to build parent→child relationships based on tier order
 *  2. Assign leaf nodes (tier 4) evenly spaced slots left-to-right,
 *     grouped by their parent so siblings stay together
 *  3. Position each parent node at the horizontal centroid of its children
 *  4. Canvas width and height computed dynamically from actual content
 *
 * This eliminates diagonal fan-out by ensuring every parent is centred
 * directly above its subtree — exactly the pattern in the VDI reference.
 */

import { TopologyData, TopologyNode, TopologyLink } from '../../shared/types.ts';

// ─────────────────────────────────────────────────────────────────
// Role → tier (0 = topmost)
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

// ─────────────────────────────────────────────────────────────────
// Exported constants
// ─────────────────────────────────────────────────────────────────
export const NODE_W = 60;
export const NODE_H = 60;

// Layout spacing
const X_GAP      = 240;   // horizontal distance between node centres
const Y_GAP      = 340;   // vertical distance between tier centres
const MARGIN_TOP = 160;   // top margin before tier 0 / first tier
const MARGIN_X   = 180;   // left margin
const MIN_PAGE_W = 1600;

// Exported for drawio.ts (backwards compat)
export const TIER_Y_ORIGIN   = MARGIN_TOP;
export const TIER_Y_GAP_EXPORT = Y_GAP;

// ─────────────────────────────────────────────────────────────────
// Layout result type
// ─────────────────────────────────────────────────────────────────
export interface LayoutResult {
  nodes:    TopologyNode[];
  pageW:    number;
  pageH:    number;
  tierY0:   number;
  tierYGap: number;
}

// ─────────────────────────────────────────────────────────────────
// Core algorithm
// ─────────────────────────────────────────────────────────────────
function computeLayout(nodes: TopologyNode[], links: TopologyLink[]): LayoutResult {
  const nodeById = new Map(nodes.map(n => [n.id, n]));

  // ── Build adjacency: parent → children (higher tier → lower tier) ──
  const children = new Map<string, Set<string>>();
  const parents  = new Map<string, Set<string>>();
  nodes.forEach(n => { children.set(n.id, new Set()); parents.set(n.id, new Set()); });

  for (const link of links) {
    const src = nodeById.get(link.source);
    const tgt = nodeById.get(link.target);
    if (!src || !tgt) continue;
    const st = getRoleTier(src.role);
    const tt = getRoleTier(tgt.role);
    if (st < tt) {
      children.get(link.source)?.add(link.target);
      parents.get(link.target)?.add(link.source);
    } else if (tt < st) {
      children.get(link.target)?.add(link.source);
      parents.get(link.source)?.add(link.target);
    }
  }

  // ── Group nodes by tier ──────────────────────────────────────────
  const byTier = new Map<number, TopologyNode[]>();
  for (const n of nodes) {
    const t = getRoleTier(n.role);
    if (!byTier.has(t)) byTier.set(t, []);
    byTier.get(t)!.push(n);
  }
  const sortedTiers = [...byTier.keys()].sort((a, b) => a - b);
  const maxTier     = sortedTiers[sortedTiers.length - 1] ?? 0;

  // ── Assign X slots to the deepest tier (leaves) ─────────────────
  // Sort leaves by grouping siblings together.
  // Algorithm: BFS from roots, visit leaves in DFS order per subtree.
  const posX = new Map<string, number>();
  const posY = new Map<string, number>();

  // Find roots: nodes with no parents
  const roots = nodes.filter(n => (parents.get(n.id)?.size ?? 0) === 0);

  // DFS to collect leaf order
  const visited    = new Set<string>();
  const leafSlots: string[] = [];

  function dfs(id: string) {
    if (visited.has(id)) return;
    visited.add(id);
    const ch = [...(children.get(id) ?? [])];
    // Sort children by their tier (deepest last), then by id for determinism
    ch.sort((a, b) => {
      const ta = getRoleTier(nodeById.get(a)?.role ?? '');
      const tb = getRoleTier(nodeById.get(b)?.role ?? '');
      if (ta !== tb) return ta - tb;
      return a.localeCompare(b);
    });
    const isLeaf = ch.every(c => (children.get(c)?.size ?? 0) === 0);
    if (ch.length === 0 || isLeaf) {
      // This node's children are leaves — add them in order
      for (const c of ch) {
        if (!visited.has(c)) { visited.add(c); leafSlots.push(c); }
      }
      // If node itself is a leaf (no children at all)
      if (ch.length === 0 && getRoleTier(nodeById.get(id)?.role ?? '') === maxTier) {
        if (!leafSlots.includes(id)) leafSlots.push(id);
      }
    } else {
      for (const c of ch) dfs(c);
    }
  }

  // Sort roots by id for determinism
  roots.sort((a, b) => a.id.localeCompare(b.id));
  for (const root of roots) dfs(root.id);

  // Any leaf not yet visited (disconnected)
  for (const n of byTier.get(maxTier) ?? []) {
    if (!leafSlots.includes(n.id)) leafSlots.push(n.id);
  }

  // Assign X to leaves
  const leafY = MARGIN_TOP + maxTier * Y_GAP;
  leafSlots.forEach((id, i) => {
    posX.set(id, MARGIN_X + i * X_GAP);
    posY.set(id, leafY);
  });

  // ── Bottom-up: position each non-leaf at centroid of its children ─
  for (let t = maxTier - 1; t >= sortedTiers[0]; t--) {
    const tierNodes = byTier.get(t) ?? [];
    const y = MARGIN_TOP + t * Y_GAP;
    for (const n of tierNodes) {
      posY.set(n.id, y);
    }
    // Compute X from children
    for (const n of tierNodes) {
      const ch = [...(children.get(n.id) ?? [])];
      const childXs = ch.map(c => posX.get(c)).filter((x): x is number => x !== undefined);
      if (childXs.length > 0) {
        posX.set(n.id, childXs.reduce((a, b) => a + b, 0) / childXs.length);
      }
    }
    // Nodes with no children yet — place them after the others
    const noPos = tierNodes.filter(n => !posX.has(n.id));
    const withPos = tierNodes.filter(n => posX.has(n.id)).sort((a, b) => posX.get(a.id)! - posX.get(b.id)!);
    let nextX = (withPos.length > 0 ? Math.max(...withPos.map(n => posX.get(n.id)!)) + X_GAP : MARGIN_X);
    for (const n of noPos) {
      posX.set(n.id, nextX); nextX += X_GAP;
    }
  }

  // Nodes at tier 0 or above not yet positioned (roots)
  for (const n of byTier.get(sortedTiers[0]) ?? []) {
    if (!posX.has(n.id)) {
      const ch = [...(children.get(n.id) ?? [])];
      const childXs = ch.map(c => posX.get(c)).filter((x): x is number => x !== undefined);
      posX.set(n.id, childXs.length > 0 ? childXs.reduce((a, b) => a + b, 0) / childXs.length : MARGIN_X);
      posY.set(n.id, MARGIN_TOP + sortedTiers[0] * Y_GAP);
    }
  }

  // ── Resolve collisions within the same tier ──────────────────────
  // After centroid placement, nodes in the same tier can overlap.
  // Simple sweep: scan left-to-right and push right if needed.
  for (const t of sortedTiers) {
    const tierNodes = (byTier.get(t) ?? [])
      .filter(n => posX.has(n.id))
      .sort((a, b) => posX.get(a.id)! - posX.get(b.id)!);

    for (let i = 1; i < tierNodes.length; i++) {
      const prev = tierNodes[i - 1];
      const curr = tierNodes[i];
      const gap  = posX.get(curr.id)! - posX.get(prev.id)!;
      if (gap < X_GAP) {
        posX.set(curr.id, posX.get(prev.id)! + X_GAP);
      }
    }
  }

  // ── Build positioned nodes ────────────────────────────────────────
  const out: TopologyNode[] = nodes.map(n => ({
    ...n,
    x: Math.round(posX.get(n.id) ?? MARGIN_X),
    y: Math.round(posY.get(n.id) ?? MARGIN_TOP),
  }));

  // ── Canvas dimensions ─────────────────────────────────────────────
  const maxX  = Math.max(...out.map(n => n.x!)) + NODE_W;
  const maxY  = Math.max(...out.map(n => n.y!)) + NODE_H;
  const pageW = Math.max(MIN_PAGE_W, maxX + MARGIN_X);
  const pageH = maxY + 300;

  return { nodes: out, pageW, pageH, tierY0: MARGIN_TOP, tierYGap: Y_GAP };
}

// ─────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────
export function applyLayout(topology: TopologyData): TopologyData & { _layout?: LayoutResult } {
  if (topology.nodes.every(n => n.x !== undefined && n.y !== undefined)) {
    return topology;
  }
  const result = computeLayout(topology.nodes, topology.links);
  return { nodes: result.nodes, links: topology.links, _layout: result };
}

export { computeLayout };

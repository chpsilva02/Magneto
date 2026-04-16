/**
 * stp-normalizer.ts
 *
 * Pure functions that convert raw strings from device output
 * into the canonical StpRole / StpState enums.
 *
 * Zero external dependencies — easy to unit-test in isolation.
 */

import { StpRole, StpState, StpVariant } from './l2.types.ts';

// ─────────────────────────────────────────────────────────────────────────────
// Role normalisation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Maps every known raw role string to StpRole.
 * Handles Cisco IOS, IOS-XE, NX-OS, Juniper, Huawei and HP variants.
 * Keys are lower-cased before lookup to avoid duplicates.
 */
const RAW_ROLE_MAP: Record<string, StpRole> = {
  // Cisco IOS / IOS-XE
  'root':               StpRole.Root,
  'desg':               StpRole.Designated,
  'designated':         StpRole.Designated,
  'altn':               StpRole.Alternate,
  'alternate':          StpRole.Alternate,
  'back':               StpRole.Backup,
  'backup':             StpRole.Backup,
  'mstr':               StpRole.Master,
  'master':             StpRole.Master,
  'disabled':           StpRole.Disabled,
  'none':               StpRole.Unknown,
  // Cisco NX-OS
  'shr':                StpRole.Designated,   // Shared — treated as Designated
  // Juniper
  'root-port':          StpRole.Root,
  'designated-port':    StpRole.Designated,
  'alternate-port':     StpRole.Alternate,
  'backup-port':        StpRole.Backup,
  // Huawei VRP
  'desi':               StpRole.Designated,
  'alte':               StpRole.Alternate,
  'mast':               StpRole.Master,
  'disa':               StpRole.Disabled,
};

/**
 * Normalise a raw role string.
 * Returns StpRole.Unknown for anything unrecognised.
 */
export function normalizeStpRole(raw: string): StpRole {
  if (!raw) return StpRole.Unknown;
  return RAW_ROLE_MAP[raw.trim().toLowerCase()] ?? StpRole.Unknown;
}

// ─────────────────────────────────────────────────────────────────────────────
// State normalisation
// ─────────────────────────────────────────────────────────────────────────────

/** Keys are lower-cased before lookup */
const RAW_STATE_MAP: Record<string, StpState> = {
  'fwd':        StpState.Forwarding,
  'forwarding': StpState.Forwarding,
  'blk':        StpState.Blocking,
  'blocking':   StpState.Blocking,
  'disc':       StpState.Discarding,
  'discarding': StpState.Discarding,
  'lrn':        StpState.Learning,
  'learning':   StpState.Learning,
  'lis':        StpState.Listening,
  'listening':  StpState.Listening,
  'dis':        StpState.Disabled,
  'disabled':   StpState.Disabled,
  'bkn':        StpState.Broken,
  'broken':     StpState.Broken,
  // Some IOS versions print role as state in condensed tables
  'altn':       StpState.Blocking,
};

/**
 * Normalise a raw state string.
 * Returns StpState.Unknown for anything unrecognised.
 */
export function normalizeStpState(raw: string): StpState {
  if (!raw) return StpState.Unknown;
  return RAW_STATE_MAP[raw.trim().toLowerCase()] ?? StpState.Unknown;
}

// ─────────────────────────────────────────────────────────────────────────────
// Variant detection
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Detect the STP variant from a block of text (e.g. a show spanning-tree output).
 */
export function detectStpVariant(block: string): StpVariant {
  const b = block.toLowerCase();
  if (b.includes('mstp') || b.includes('mst'))              return StpVariant.MSTP;
  if (b.includes('rapid-pvst') || b.includes('rapid pvst')) return StpVariant.RPVSTP;
  if (b.includes('pvst') || b.includes('per-vlan'))         return StpVariant.PVSTP;
  if (b.includes('rstp') || b.includes('rapid'))            return StpVariant.RSTP;
  if (b.includes('spanning-tree') || b.includes('spanning tree')) return StpVariant.STP;
  return StpVariant.Unknown;
}

// ─────────────────────────────────────────────────────────────────────────────
// Dominant state computation
// ─────────────────────────────────────────────────────────────────────────────

/** Priority order: lower index = more disruptive */
const STATE_PRIORITY: StpState[] = [
  StpState.Broken,
  StpState.Disabled,
  StpState.Blocking,
  StpState.Discarding,
  StpState.Listening,
  StpState.Learning,
  StpState.Forwarding,
  StpState.Unknown,
];

/**
 * Return the "worst" state from a pair of endpoint states.
 * A link is only truly forwarding if BOTH sides forward.
 */
export function dominantState(a: StpState, b: StpState): StpState {
  const ia = STATE_PRIORITY.indexOf(a);
  const ib = STATE_PRIORITY.indexOf(b);
  return ia <= ib ? a : b;
}

// ─────────────────────────────────────────────────────────────────────────────
// Instance ID normalisation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build a canonical instance ID string.
 *
 * Examples:
 *   "vlan 10"    → "vlan10"
 *   "VLAN0010"   → "vlan10"
 *   "MST 0"      → "mst0"
 *   "instance 2" → "mst2"
 */
export function normalizeInstanceId(raw: string): string {
  if (!raw) return 'unknown';
  const s = raw.trim().toLowerCase().replace(/\s+/g, '');
  const vlanMatch = s.match(/^vlan0*(\d+)$/);
  if (vlanMatch) return `vlan${vlanMatch[1]}`;
  const mstMatch = s.match(/^(?:mst|mstp|instance)0*(\d+)$/);
  if (mstMatch) return `mst${mstMatch[1]}`;
  return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// Bridge priority parsing
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Parse a bridge priority from a string like "32769" or "32768 (32768 sysid 1)".
 */
export function parseBridgePriority(raw: string): number | undefined {
  if (!raw) return undefined;
  const m = raw.trim().match(/^(\d+)/);
  return m ? parseInt(m[1], 10) : undefined;
}

/**
 * Extract the MAC address from a bridge ID string.
 * Bridge IDs look like: "32769 aabb.cc00.0100" or "8001.aabb.cc00.0100"
 */
export function extractMacFromBridgeId(bridgeId: string): string | undefined {
  if (!bridgeId) return undefined;
  const m = bridgeId.match(/([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})/i);
  return m ? m[1].toLowerCase() : undefined;
}

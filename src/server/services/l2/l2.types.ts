/**
 * l2.types.ts
 *
 * Canonical types and enums for the L2 topology layer.
 * All STP, Port-channel and logical link modelling lives here.
 *
 * Design principles:
 *  - Enums for every normalised value so callers get compile-time safety
 *  - Raw strings preserved alongside enums for debugging / evidence
 *  - Optional fields throughout so partial data never crashes the pipeline
 *  - No circular imports — this file has zero imports from the project
 */

// ─────────────────────────────────────────────────────────────────────────────
// STP Roles
// ─────────────────────────────────────────────────────────────────────────────

export enum StpRole {
  Root        = 'root',
  Designated  = 'designated',
  Alternate   = 'alternate',
  Backup      = 'backup',
  Master      = 'master',   // MST regional root port
  Disabled    = 'disabled',
  Unknown     = 'unknown',
}

/** Short display labels used in Draw.io badges */
export const STP_ROLE_LABEL: Record<StpRole, string> = {
  [StpRole.Root]:       'RP',
  [StpRole.Designated]: 'DP',
  [StpRole.Alternate]:  'ALT',
  [StpRole.Backup]:     'BK',
  [StpRole.Master]:     'MST',
  [StpRole.Disabled]:   'DIS',
  [StpRole.Unknown]:    '?',
};

// ─────────────────────────────────────────────────────────────────────────────
// STP States
// ─────────────────────────────────────────────────────────────────────────────

export enum StpState {
  Forwarding  = 'forwarding',
  Blocking    = 'blocking',
  Discarding  = 'discarding',  // RSTP equivalent of blocking
  Learning    = 'learning',
  Listening   = 'listening',
  Disabled    = 'disabled',
  Broken      = 'broken',
  Unknown     = 'unknown',
}

/** Short display labels used in Draw.io badges */
export const STP_STATE_LABEL: Record<StpState, string> = {
  [StpState.Forwarding]:  'FWD',
  [StpState.Blocking]:    'BLK',
  [StpState.Discarding]:  'DISC',
  [StpState.Learning]:    'LRN',
  [StpState.Listening]:   'LIS',
  [StpState.Disabled]:    'DIS',
  [StpState.Broken]:      'BKN',
  [StpState.Unknown]:     '?',
};

// ─────────────────────────────────────────────────────────────────────────────
// STP Protocol variant
// ─────────────────────────────────────────────────────────────────────────────

export enum StpVariant {
  STP   = 'stp',
  RSTP  = 'rstp',
  MSTP  = 'mstp',
  PVSTP = 'pvst+',
  RPVSTP = 'rapid-pvst+',
  Unknown = 'unknown',
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-port STP record (one per port per instance/VLAN)
// ─────────────────────────────────────────────────────────────────────────────

export interface StpPortRecord {
  /** Device that owns this port */
  deviceId:               string;

  /** Normalised interface name, e.g. "Gi1/0/1" */
  interfaceName:          string;

  /** STP instance identifier — "vlan10", "mst0", etc. */
  instanceId:             string;

  /** VLAN number, if applicable (PVST+/Rapid-PVST+) */
  vlanId?:                string;

  /** MST instance number, if applicable */
  mstInstanceId?:         string;

  /** Normalised role */
  role:                   StpRole;

  /** Normalised state */
  state:                  StpState;

  /** Raw role string from device output, e.g. "Desg", "Root" */
  rawRole:                string;

  /** Raw state string from device output, e.g. "FWD", "BLK" */
  rawState:               string;

  /** Port-channel this interface belongs to, if any, e.g. "Po1" */
  portChannelId?:         string;

  /** True when this interface is a LAG member */
  memberOfPortChannel:    boolean;

  /** STP port cost */
  cost?:                  number;

  /** STP port priority (0-255) */
  priority?:              number;

  /** STP port number (internal numbering) */
  portNumber?:            number;

  /** Command / section that provided this data */
  evidenceSource:         string;

  /** 0-1 confidence: 1 = from detailed show output, 0.5 = from brief table */
  confidenceScore:        number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-instance STP root record
// ─────────────────────────────────────────────────────────────────────────────

export interface StpRootRecord {
  /** Device that reported this root information */
  reportingDeviceId:      string;

  /** Same as StpPortRecord.instanceId */
  instanceId:             string;

  vlanId?:                string;
  mstInstanceId?:         string;

  /** Bridge ID of the root, e.g. "8001.aabb.cc00.0100" */
  rootBridgeId?:          string;

  /** MAC portion of the root bridge ID */
  rootMac?:               string;

  /** Priority portion of the root bridge ID */
  rootPriority?:          number;

  /**
   * Device ID resolved from rootMac/rootBridgeId via the node map.
   * Populated by the builder, not the parser.
   */
  rootDeviceId?:          string;

  /** True if the reporting device itself is the root for this instance */
  localDeviceIsRoot:      boolean;

  evidenceSource:         string;
  confidenceScore:        number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Port-channel / EtherChannel / LAG
// ─────────────────────────────────────────────────────────────────────────────

export enum PortChannelProtocol {
  LACP    = 'lacp',
  PAgP    = 'pagp',
  Static  = 'static',  // "on"
  Unknown = 'unknown',
}

export interface PortChannelMember {
  /** Normalised physical interface name, e.g. "Gi1/0/1" */
  interfaceName:   string;

  /** LACP / PAgP mode: active|passive|desirable|auto|on */
  mode?:           string;

  /** True if the member is currently bundled and passing traffic */
  isActive?:       boolean;

  /** Raw flags from "show etherchannel summary", e.g. "P", "D", "I" */
  rawFlags?:       string;
}

export interface PortChannelRecord {
  deviceId:           string;

  /** Normalised Po ID, e.g. "Po1" */
  portChannelId:      string;

  protocol:           PortChannelProtocol;

  members:            PortChannelMember[];

  /** "up" | "down" | "unknown" */
  operationalStatus?: string;

  evidenceSource:     string;
}

// ─────────────────────────────────────────────────────────────────────────────
// L2 logical link (output of the L2 builder)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Represents a single logical L2 adjacency between two devices.
 * May be backed by a physical link or a port-channel bundle.
 */
export interface L2LogicalLink {
  id:                   string;
  sourceDevice:         string;
  targetDevice:         string;

  /** Logical interface at source side — could be Po or physical */
  sourcePort:           string;
  /** Logical interface at target side */
  targetPort:           string;

  /** Port-channel ID at source, if applicable */
  sourcePortChannel?:   string;
  /** Port-channel ID at target, if applicable */
  targetPortChannel?:   string;

  /**
   * Canonical bundle ID.
   * For port-channels: "sourceDevice:Po1--targetDevice:Po2"
   * For plain links:   "sourceDevice:Gi1/0/1--targetDevice:Gi1/0/2"
   */
  logicalBundleId:      string;

  /** Underlying physical link IDs that make up this logical link */
  memberLinkIds:        string[];

  /** Physical member port names at source side (for Po label rendering) */
  srcMemberPorts?:      string[];

  /** Physical member port names at target side (for Po label rendering) */
  dstMemberPorts?:      string[];

  /** VLANs carried on this link, e.g. ["10","20","30"] */
  vlans:                string[];

  /** STP instance IDs with data for this link */
  stpInstanceIds:       string[];

  /** Dominant STP role at source side (across all instances) */
  sourceRole:           StpRole;
  /** Dominant STP state at source side */
  sourceState:          StpState;

  /** Dominant STP role at target side */
  targetRole:           StpRole;
  /** Dominant STP state at target side */
  targetState:          StpState;

  /**
   * Dominant state of the link overall.
   * "forwarding" only if BOTH sides forward.
   * "blocking" if either side blocks.
   * "discarding" if either side discards.
   */
  dominantState:        StpState;

  /** True if this link is on the root path (RP/FWD on at least one side) */
  isRootPath:           boolean;

  /** True if this link carries at least one blocked/discarding instance */
  isBlocked:            boolean;

  /** True if source or target has an alternate-port role */
  isAlternatePath:      boolean;

  /** True if this is a bundle (port-channel) link */
  isBundle:             boolean;

  /** Number of active member links for bundles */
  activeMemberCount?:   number;

  /** 0-1 overall confidence for this link record */
  confidenceScore:      number;
}

// ─────────────────────────────────────────────────────────────────────────────
// L2 view — full topology snapshot fed to the renderer
// ─────────────────────────────────────────────────────────────────────────────

export interface L2TopologyView {
  /** All discovered STP port records, indexed by deviceId+interfaceName+instanceId */
  stpPorts:       StpPortRecord[];

  /** All discovered root records, indexed by reportingDeviceId+instanceId */
  stpRoots:       StpRootRecord[];

  /** All discovered port-channels, indexed by deviceId+portChannelId */
  portChannels:   PortChannelRecord[];

  /** Consolidated logical links ready for rendering */
  logicalLinks:   L2LogicalLink[];

  /**
   * Map of deviceId → set of instanceIds for which that device is root.
   * Built by the builder, consumed by the renderer for root badges.
   */
  rootByDevice:   Map<string, Set<string>>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Render view — what the Draw.io renderer consumes for a single link
// ─────────────────────────────────────────────────────────────────────────────

export interface L2LinkView {
  link:           L2LogicalLink;

  /** Short label for source endpoint, e.g. "Po1\nRP/FWD" */
  sourceLabelShort:  string;
  /** Short label for target endpoint */
  targetLabelShort:  string;

  /** Centre label, e.g. "VLANs 10,20,30\nRP/FWD ↔ DP/FWD" */
  centerLabel:       string;

  /** Draw.io edge style string */
  edgeStyle:         string;

  /** Hex colour for this link */
  strokeColor:       string;

  /** Stroke width in px */
  strokeWidth:       number;

  /** True for dashed style */
  dashed:            boolean;

  /** 0-1 opacity */
  opacity:           number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Extended TopologyNode fields (additive — no breaking change)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extra L2-related fields that will be merged into TopologyNode at runtime.
 * Declared here so the rest of the L2 module can reference them with types.
 */
export interface TopologyNodeL2Extensions {
  /** Instance IDs for which this device is STP root */
  stpRootForInstances?: string[];

  /** VLAN IDs (as strings) for which this device is STP root */
  stpRootForVlans?: string[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Extended TopologyLink fields (additive — no breaking change)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extra L2-related fields that will be merged into TopologyLink at runtime.
 */
export interface TopologyLinkL2Extensions {
  /** Logical bundle this link belongs to */
  logicalBundleId?: string;

  /** Source-side normalised STP role */
  srcStpRoleNorm?: StpRole;

  /** Source-side normalised STP state */
  srcStpStateNorm?: StpState;

  /** Target-side normalised STP role */
  dstStpRoleNorm?: StpRole;

  /** Target-side normalised STP state */
  dstStpStateNorm?: StpState;

  /** True when link is part of a blocked/alternate path */
  isBlocked?: boolean;

  /** True when link is on the root path */
  isRootPath?: boolean;

  /** VLANs carried (comma-separated string or array) */
  vlansCarried?: string[];

  /** Physical ports that are members of the src-side port-channel */
  src_member_ports?: string[];

  /** Physical ports that are members of the dst-side port-channel */
  dst_member_ports?: string[];
}

/**
 * l2-topology.builder.ts
 *
 * Consolidates raw STP and Port-channel data into a clean L2TopologyView
 * ready for the renderer.
 *
 * Responsibilities:
 *  1. Merge StpPortRecord entries per port (multi-VLAN → dominant state)
 *  2. Resolve port-channel membership (logical Po vs physical members)
 *  3. Correlate STP data with L1 physical links
 *  4. Build L2LogicalLink objects with all visual metadata
 *  5. Resolve rootDeviceId from rootMac → nodeId mapping
 *  6. Populate node.stpRootForVlans / stpRootForInstances
 */

import {
  StpPortRecord, StpRootRecord, StpRole, StpState,
  PortChannelRecord, L2LogicalLink, L2TopologyView,
  dominantState,
} from '../l2/index.ts';
import { TopologyNode, TopologyLink } from '../../../shared/types.ts';

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

export interface L2BuilderInput {
  nodes:         TopologyNode[];
  physicalLinks: TopologyLink[];      // L1 links
  stpPorts:      StpPortRecord[];
  stpRoots:      StpRootRecord[];
  portChannels:  PortChannelRecord[];
}

export function buildL2TopologyView(input: L2BuilderInput): L2TopologyView {
  const { nodes, physicalLinks, stpPorts, stpRoots, portChannels } = input;

  // ── Step 1: Build lookup maps ────────────────────────────────
  const nodeByHostname = new Map(nodes.map(n => [n.hostname.toLowerCase(), n]));
  const nodeById       = new Map(nodes.map(n => [n.id, n]));

  // mac → nodeId for root resolution
  const macToNodeId = new Map<string, string>();
  for (const n of nodes) {
    if (n.mac_address) macToNodeId.set(n.mac_address.toLowerCase(), n.id);
    // Also try to match by hostname patterns in bridge IDs
  }

  // ── Step 2: Resolve root device IDs and enrich nodes ────────
  const rootByDevice = new Map<string, Set<string>>();

  for (const root of stpRoots) {
    // Mark reporting device as root for its instances
    if (root.localDeviceIsRoot) {
      if (!rootByDevice.has(root.reportingDeviceId)) {
        rootByDevice.set(root.reportingDeviceId, new Set());
      }
      rootByDevice.get(root.reportingDeviceId)!.add(root.instanceId);

      // Enrich node
      const node = nodeByHostname.get(root.reportingDeviceId.toLowerCase())
                ?? nodeById.get(root.reportingDeviceId);
      if (node) {
        node.isRoot = true;
        if (!node.stpRootForInstances) node.stpRootForInstances = [];
        if (!node.stpRootForVlans)     node.stpRootForVlans = [];
        if (!node.stpRootForInstances.includes(root.instanceId)) {
          node.stpRootForInstances.push(root.instanceId);
        }
        if (root.vlanId && !node.stpRootForVlans.includes(root.vlanId)) {
          node.stpRootForVlans.push(root.vlanId);
        }
      }
    }

    // Try to resolve rootDeviceId from MAC
    if (root.rootMac) {
      const resolvedId = macToNodeId.get(root.rootMac);
      if (resolvedId) root.rootDeviceId = resolvedId;
    }
  }

  // ── Step 3: Build per-device port-channel membership lookup ──
  // portChannelByDevice[deviceId][physicalPort] = portChannelId
  const portChannelByDevice = new Map<string, Map<string, string>>();
  for (const pc of portChannels) {
    if (!portChannelByDevice.has(pc.deviceId)) {
      portChannelByDevice.set(pc.deviceId, new Map());
    }
    const m = portChannelByDevice.get(pc.deviceId)!;
    for (const member of pc.members) {
      m.set(member.interfaceName, pc.portChannelId);
    }
  }

  // ── Step 4: Build STP port index ─────────────────────────────
  // key: deviceId::interfaceName  → all records (multi-VLAN)
  const stpPortIndex = new Map<string, StpPortRecord[]>();
  for (const sp of stpPorts) {
    const key = `${sp.deviceId}::${sp.interfaceName}`;
    if (!stpPortIndex.has(key)) stpPortIndex.set(key, []);
    stpPortIndex.get(key)!.push(sp);
  }

  // ── Step 5: Build L2 logical links from L1 physical links ────
  const logicalLinks: L2LogicalLink[] = [];
  // Track which L1 links have been absorbed into a bundle
  const absorbedL1Ids = new Set<string>();
  // Bundle key → L2LogicalLink
  const bundleMap = new Map<string, L2LogicalLink>();

  let linkCounter = 1;

  for (const l1 of physicalLinks) {
    if (l1.layer !== 'L1') continue;

    // Resolve port-channel on each side
    const srcPo = resolvePortChannel(l1.source, l1.src_port, portChannelByDevice);
    const dstPo = resolvePortChannel(l1.target, l1.dst_port, portChannelByDevice);

    // Logical port to use for this link
    const logicalSrcPort = srcPo ?? l1.src_port;
    const logicalDstPort = dstPo ?? l1.dst_port;

    // Bundle ID: stable regardless of direction
    const [devA, portA, devB, portB] = l1.source < l1.target
      ? [l1.source, logicalSrcPort, l1.target, logicalDstPort]
      : [l1.target, logicalDstPort, l1.source, logicalSrcPort];
    const bundleId = `${devA}:${portA}--${devB}:${portB}`;

    // STP data for each side
    const srcStp = getDominantStpRecord(l1.source, logicalSrcPort, stpPortIndex);
    const dstStp = getDominantStpRecord(l1.target, logicalDstPort, stpPortIndex);

    const srcRole  = srcStp?.role  ?? StpRole.Unknown;
    const srcState = srcStp?.state ?? StpState.Unknown;
    const dstRole  = dstStp?.role  ?? StpRole.Unknown;
    const dstState = dstStp?.state ?? StpState.Unknown;
    const dom      = dominantState(srcState, dstState);

    const isBlocked = dom === StpState.Blocking || dom === StpState.Discarding
                    || srcRole === StpRole.Alternate || dstRole === StpRole.Alternate;
    const isRoot    = (srcRole === StpRole.Root || dstRole === StpRole.Root)
                    && (srcState === StpState.Forwarding || dstState === StpState.Forwarding);
    const isAlt     = srcRole === StpRole.Alternate || dstRole === StpRole.Alternate;

    // Collect VLANs from STP records
    const vlans = collectVlans(l1.source, logicalSrcPort, stpPortIndex);

    if (bundleMap.has(bundleId)) {
      // Absorb into existing bundle
      const existing = bundleMap.get(bundleId)!;
      existing.memberLinkIds.push(l1.id);
      existing.activeMemberCount = (existing.activeMemberCount ?? 0) + 1;
      // Merge VLANs
      for (const v of vlans) {
        if (!existing.vlans.includes(v)) existing.vlans.push(v);
      }
      absorbedL1Ids.add(l1.id);
      continue;
    }

    // Collect physical member ports for each side's port-channel
    const srcMembers = srcPo
      ? portChannels
          .filter(pc => pc.deviceId === l1.source && pc.portChannelId === srcPo)
          .flatMap(pc => pc.members.map(m => m.interfaceName))
      : [];
    const dstMembers = dstPo
      ? portChannels
          .filter(pc => pc.deviceId === l1.target && pc.portChannelId === dstPo)
          .flatMap(pc => pc.members.map(m => m.interfaceName))
      : [];

    const ll: L2LogicalLink = {
      id:                `l2_logical_${linkCounter++}`,
      sourceDevice:      l1.source,
      targetDevice:      l1.target,
      sourcePort:        logicalSrcPort,
      targetPort:        logicalDstPort,
      sourcePortChannel: srcPo,
      targetPortChannel: dstPo,
      logicalBundleId:   bundleId,
      memberLinkIds:     [l1.id],
      srcMemberPorts:    srcMembers,
      dstMemberPorts:    dstMembers,
      vlans,
      stpInstanceIds:    collectInstances(l1.source, logicalSrcPort, stpPortIndex),
      sourceRole:        srcRole,
      sourceState:       srcState,
      targetRole:        dstRole,
      targetState:       dstState,
      dominantState:     dom,
      isRootPath:        isRoot,
      isBlocked,
      isAlternatePath:   isAlt,
      isBundle:          !!(srcPo || dstPo),
      activeMemberCount: 1,
      confidenceScore:   srcStp ? srcStp.confidenceScore : 0.5,
    };

    bundleMap.set(bundleId, ll);
    logicalLinks.push(ll);
    absorbedL1Ids.add(l1.id);
  }

  return { stpPorts, stpRoots, portChannels, logicalLinks, rootByDevice };
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function resolvePortChannel(
  deviceId: string,
  port: string,
  pcByDevice: Map<string, Map<string, string>>,
): string | undefined {
  // If the port is already a Po, return it directly
  if (/^Po\d/i.test(port)) return port;
  return pcByDevice.get(deviceId)?.get(port);
}

/**
 * Get the dominant STP record for a given device+port.
 * "Dominant" = the record with the worst/most significant state.
 * Priority: Blocking > Discarding > Alternate > Forwarding
 */
function getDominantStpRecord(
  deviceId: string,
  port: string,
  index: Map<string, StpPortRecord[]>,
): StpPortRecord | undefined {
  const records = index.get(`${deviceId}::${port}`) ?? [];
  if (records.length === 0) return undefined;
  return records.reduce((best, cur) => {
    const bState = best.state;
    const cState = cur.state;
    // Prefer blocking/alternate over forwarding
    const stateScore = (s: StpState) =>
      s === StpState.Blocking || s === StpState.Discarding ? 3
      : s === StpState.Unknown ? 2
      : s === StpState.Forwarding ? 1 : 0;
    return stateScore(cState) > stateScore(bState) ? cur : best;
  });
}

function collectVlans(
  deviceId: string,
  port: string,
  index: Map<string, StpPortRecord[]>,
): string[] {
  const records = index.get(`${deviceId}::${port}`) ?? [];
  const vlans = new Set<string>();
  for (const r of records) {
    if (r.vlanId) vlans.add(r.vlanId);
  }
  return [...vlans].sort((a, b) => parseInt(a) - parseInt(b));
}

function collectInstances(
  deviceId: string,
  port: string,
  index: Map<string, StpPortRecord[]>,
): string[] {
  const records = index.get(`${deviceId}::${port}`) ?? [];
  return [...new Set(records.map(r => r.instanceId))];
}

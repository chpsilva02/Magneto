/**
 * stp.parser.ts
 *
 * Parses raw spanning-tree output blocks from Cisco IOS/IOS-XE/NX-OS.
 * Supports:
 *   - show spanning-tree
 *   - show spanning-tree vlan X
 *   - show spanning-tree detail
 *   - show spanning-tree summary
 *   - PVST+, Rapid-PVST+, MST
 *
 * Returns StpPortRecord[] and StpRootRecord[] — one record per
 * port per VLAN/instance, preserving full per-VLAN detail.
 */

import {
  StpPortRecord, StpRootRecord, StpRole, StpState,
  normalizeStpRole, normalizeStpState,
  normalizeInstanceId, parseBridgePriority, extractMacFromBridgeId,
  detectStpVariant,
} from '../l2/index.ts';
import { normalizePort } from './port-utils.ts';

// ─────────────────────────────────────────────────────────────────────────────
// Regex patterns for different IOS output formats
// ─────────────────────────────────────────────────────────────────────────────

// Header: "VLAN0010" or "VLAN 10" or "Spanning tree instance 0"
const RE_VLAN_HEADER   = /^(?:VLAN|VLAN\s*)0*(\d+)/im;
const RE_MST_HEADER    = /^(?:MST|Spanning tree instance)\s*0*(\d+)/im;

// "This bridge is the root"
const RE_IS_ROOT       = /this bridge is the root/i;

// Root info line: "Root ID  Priority 32768 Address aabb.cc00.0100"
const RE_ROOT_PRIORITY = /(?:root\s+id\s+)?priority\s+(\d+)/i;
const RE_ROOT_ADDRESS  = /address\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})/i;

// Port table line (Cisco IOS brief format):
// "Gi1/0/1           Root FWD 4      128.1   P2p"
// "Po1               Desg FWD 4      128.65  P2p"
const RE_PORT_BRIEF =
  /^([A-Za-z][A-Za-z0-9\/\.\-]+)\s+(Root|Desg|Altn|Back|Mstr|Shr|None|Bkup)\s+(FWD|BLK|LRN|LIS|BKN|DIS|DISC)\s+(\d+)/im;

// Port cost + priority: "128.1" → priority=128, portNum=1
const RE_PORT_COST_PRIO = /(\d+)\s+(\d+\.\d+)\s/;

// ─────────────────────────────────────────────────────────────────────────────
// Main parser
// ─────────────────────────────────────────────────────────────────────────────

export interface StpParseResult {
  ports: StpPortRecord[];
  roots: StpRootRecord[];
}

export function parseStpBlock(
  hostname: string,
  blockData: string,
  evidenceSource = 'show spanning-tree',
): StpParseResult {
  const ports: StpPortRecord[] = [];
  const roots: StpRootRecord[] = [];

  // Split into per-VLAN/per-instance sub-blocks.
  // Cisco IOS separates VLAN blocks with "VLAN0001" header lines.
  const subBlocks = splitIntoStpInstances(blockData);

  for (const sub of subBlocks) {
    const { instanceId, vlanId, mstInstanceId } = detectInstance(sub);
    if (!instanceId) continue;

    // ── Root detection ─────────────────────────────────────────
    const localIsRoot = RE_IS_ROOT.test(sub);
    const rootPrioMatch = sub.match(RE_ROOT_PRIORITY);
    const rootAddrMatch = sub.match(RE_ROOT_ADDRESS);

    const rootRecord: StpRootRecord = {
      reportingDeviceId:  hostname,
      instanceId,
      vlanId,
      mstInstanceId,
      localDeviceIsRoot:  localIsRoot,
      rootPriority:       rootPrioMatch ? parseBridgePriority(rootPrioMatch[1]) : undefined,
      rootMac:            rootAddrMatch ? rootAddrMatch[1].toLowerCase() : undefined,
      evidenceSource,
      confidenceScore:    localIsRoot ? 1.0 : (rootAddrMatch ? 0.9 : 0.5),
    };
    if (rootRecord.rootMac) {
      rootRecord.rootBridgeId = rootRecord.rootPriority
        ? `${rootRecord.rootPriority} ${rootRecord.rootMac}`
        : rootRecord.rootMac;
    }
    roots.push(rootRecord);

    // ── Port records ───────────────────────────────────────────
    const portRecords = parsePortLines(sub, hostname, instanceId, vlanId, mstInstanceId, evidenceSource);
    ports.push(...portRecords);
  }

  return { ports, roots };
}

// ─────────────────────────────────────────────────────────────────────────────
// Split raw block into per-VLAN/instance sections
// ─────────────────────────────────────────────────────────────────────────────

function splitIntoStpInstances(raw: string): string[] {
  // Try to split on "VLAN0010" / "MST 0" header lines
  const chunks = raw.split(
    /(?=\bVLAN\s*0*\d+\b|\bMST\s+\d+\b|\bSpanning tree instance\s+\d+\b)/i,
  );
  // Filter out empty / header-only chunks
  return chunks.filter(c => c.trim().length > 20);
}

// ─────────────────────────────────────────────────────────────────────────────
// Detect instance/VLAN from a sub-block header
// ─────────────────────────────────────────────────────────────────────────────

interface InstanceInfo {
  instanceId:    string;
  vlanId?:       string;
  mstInstanceId?: string;
}

function detectInstance(block: string): InstanceInfo {
  const vlanMatch = block.match(/^VLAN\s*0*(\d+)/im);
  if (vlanMatch) {
    const v = vlanMatch[1];
    return { instanceId: `vlan${v}`, vlanId: v };
  }
  const mstMatch = block.match(/^(?:MST|Spanning tree instance)\s*0*(\d+)/im);
  if (mstMatch) {
    const m = mstMatch[1];
    return { instanceId: `mst${m}`, mstInstanceId: m };
  }
  return { instanceId: '' };
}

// ─────────────────────────────────────────────────────────────────────────────
// Parse individual port lines within a sub-block
// ─────────────────────────────────────────────────────────────────────────────

function parsePortLines(
  block: string,
  hostname: string,
  instanceId: string,
  vlanId: string | undefined,
  mstInstanceId: string | undefined,
  evidenceSource: string,
): StpPortRecord[] {
  const records: StpPortRecord[] = [];
  const lines = block.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('---') || trimmed.startsWith('Port')) continue;

    // Brief format: "Gi1/0/1  Root FWD 4  128.1  P2p"
    const briefMatch = trimmed.match(
      /^([A-Za-z][A-Za-z0-9\/\.\-]+)\s+(Root|Desg|Altn|Back|Mstr|Shr|None|Bkup|Mast)\s+(FWD|BLK|LRN|LIS|BKN|DIS|DISC)\s+(\d+)/i,
    );
    if (briefMatch) {
      const rawPort = briefMatch[1];
      const rawRole  = briefMatch[2];
      const rawState = briefMatch[3];
      const cost     = parseInt(briefMatch[4], 10);

      // Extract priority.portNum if present after cost
      let priority: number | undefined;
      let portNumber: number | undefined;
      const prioMatch = trimmed.match(/\d+\s+(\d+)\.(\d+)\s/);
      if (prioMatch) {
        priority   = parseInt(prioMatch[1], 10);
        portNumber = parseInt(prioMatch[2], 10);
      }

      const interfaceName = normalizePort(rawPort);

      records.push({
        deviceId:            hostname,
        interfaceName,
        instanceId,
        vlanId,
        mstInstanceId,
        role:                normalizeStpRole(rawRole),
        state:               normalizeStpState(rawState),
        rawRole,
        rawState,
        memberOfPortChannel: /^Po\d/i.test(interfaceName),
        portChannelId:       /^Po\d/i.test(interfaceName) ? interfaceName : undefined,
        cost:                isNaN(cost) ? undefined : cost,
        priority,
        portNumber,
        evidenceSource,
        confidenceScore:     0.95,
      });
      continue;
    }

    // Detail format: "Port X (GigabitEthernet1/0/1) of VLAN... is ..."
    const detailMatch = trimmed.match(/Port\s+\d+\s+\(([^)]+)\)\s+of\s+\S+\s+is\s+(\w+)/i);
    if (detailMatch) {
      const rawPort  = detailMatch[1];
      const rawState = detailMatch[2];
      const interfaceName = normalizePort(rawPort);
      // Role comes on subsequent lines — emit with Unknown role for now
      records.push({
        deviceId:            hostname,
        interfaceName,
        instanceId,
        vlanId,
        mstInstanceId,
        role:                StpRole.Unknown,
        state:               normalizeStpState(rawState),
        rawRole:             '',
        rawState,
        memberOfPortChannel: /^Po\d/i.test(interfaceName),
        portChannelId:       /^Po\d/i.test(interfaceName) ? interfaceName : undefined,
        evidenceSource,
        confidenceScore:     0.7,
      });
    }
  }

  return records;
}

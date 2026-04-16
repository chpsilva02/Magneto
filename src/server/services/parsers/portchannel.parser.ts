/**
 * portchannel.parser.ts
 *
 * Parses raw EtherChannel / LAG output from Cisco IOS/IOS-XE/NX-OS.
 * Supports:
 *   - show etherchannel summary
 *   - show port-channel summary
 *   - show lacp neighbor
 *   - channel-group config blocks
 */

import {
  PortChannelRecord, PortChannelProtocol, PortChannelMember,
} from '../l2/index.ts';
import { normalizePort } from './port-utils.ts';

// ─────────────────────────────────────────────────────────────────────────────
// show etherchannel summary / show port-channel summary
//
// Example output:
//   Number of channel-groups in use: 2
//   Group  Port-channel  Protocol  Ports
//   ------+-------------+---------+-----------------------------------------------
//   1      Po1(SU)       LACP      Gi1/0/1(P)   Gi1/0/2(P)
//   2      Po2(SU)       PAgP      Gi1/0/3(D)
// ─────────────────────────────────────────────────────────────────────────────

// Matches a group line with port-channel and optional protocol
const RE_ECHAN_LINE =
  /^\s*(\d+)\s+(Po\d+)\s*\([^)]*\)\s*(LACP|PAgP|Static|-|None)?\s*(.*)/i;

// Flag chars: P=bundled, D=not-bundled, I=stand-alone, s=suspended
const RE_MEMBER_WITH_FLAGS =
  /([A-Za-z][A-Za-z0-9\/\.\-]+)\s*\(([PpDdIissSuUhH]*)\)/g;

export function parsePortChannelSummary(
  hostname: string,
  blockData: string,
  evidenceSource = 'show etherchannel summary',
): PortChannelRecord[] {
  const records: PortChannelRecord[] = [];
  const lines = blockData.split('\n');

  for (const line of lines) {
    const m = line.match(RE_ECHAN_LINE);
    if (!m) continue;

    const poId    = m[2];           // e.g. "Po1"
    const protoRaw = (m[3] || '').trim().toLowerCase();
    const rest    = m[4] || '';

    const protocol = protoRaw === 'lacp'   ? PortChannelProtocol.LACP
                   : protoRaw === 'pagp'   ? PortChannelProtocol.PAgP
                   : protoRaw === 'static' || protoRaw === '-' ? PortChannelProtocol.Static
                   : PortChannelProtocol.Unknown;

    const members: PortChannelMember[] = [];
    let match: RegExpExecArray | null;
    RE_MEMBER_WITH_FLAGS.lastIndex = 0;
    while ((match = RE_MEMBER_WITH_FLAGS.exec(rest)) !== null) {
      const rawFlags = match[2].toUpperCase();
      members.push({
        interfaceName: normalizePort(match[1]),
        rawFlags,
        isActive: rawFlags.includes('P'), // P = in-port-channel (bundled)
      });
    }

    // Determine overall status from Po flags
    const poFlags = line.match(/Po\d+\(([^)]+)\)/i)?.[1]?.toUpperCase() ?? '';
    const operStatus = poFlags.includes('U') ? 'up'
                     : poFlags.includes('D') ? 'down'
                     : 'unknown';

    records.push({
      deviceId:          hostname,
      portChannelId:     normalizePort(poId),
      protocol,
      members,
      operationalStatus: operStatus,
      evidenceSource,
    });
  }

  return records;
}

// ─────────────────────────────────────────────────────────────────────────────
// show lacp neighbor
//
// Example:
//   Channel group 1 neighbors
//     Partner's information:
//       GigabitEthernet1/0/1
//         Partner System ID: aabb.cc00.0200
// ─────────────────────────────────────────────────────────────────────────────

export function parseLacpNeighbor(
  hostname: string,
  blockData: string,
): PortChannelRecord[] {
  const records: PortChannelRecord[] = [];
  const groupBlocks = blockData.split(/(?=Channel group \d+)/i);

  for (const block of groupBlocks) {
    const groupMatch = block.match(/Channel group (\d+)/i);
    if (!groupMatch) continue;
    const poId = `Po${groupMatch[1]}`;

    const members: PortChannelMember[] = [];
    const intfMatches = [...block.matchAll(/^\s+((?:Gi|Te|Fa|Hu|Fo|Eth)[^\s]+)/gim)];
    for (const im of intfMatches) {
      members.push({
        interfaceName: normalizePort(im[1]),
        isActive:      true,
      });
    }

    records.push({
      deviceId:          hostname,
      portChannelId:     poId,
      protocol:          PortChannelProtocol.LACP,
      members,
      operationalStatus: 'up',
      evidenceSource:    'show lacp neighbor',
    });
  }

  return records;
}

// ─────────────────────────────────────────────────────────────────────────────
// channel-group config block
//
// Looks for lines like:
//   channel-group 1 mode active
// inside interface blocks.
// ─────────────────────────────────────────────────────────────────────────────

export function parseChannelGroupConfig(
  hostname: string,
  blockData: string,
): PortChannelRecord[] {
  const records: PortChannelRecord[] = [];
  // Map groupId → PortChannelRecord
  const groupMap = new Map<string, PortChannelRecord>();

  // Split into interface config blocks
  const intfBlocks = blockData.split(/(?=^interface\s)/im);
  for (const block of intfBlocks) {
    const intfMatch = block.match(/^interface\s+([^\r\n]+)/im);
    if (!intfMatch) continue;
    const rawIntf = intfMatch[1].trim();
    // Skip port-channel interfaces themselves
    if (/^port-channel/i.test(rawIntf)) continue;

    const cgMatch = block.match(/channel-group\s+(\d+)\s+mode\s+(\w+)/i);
    if (!cgMatch) continue;

    const groupId = cgMatch[1];
    const mode    = cgMatch[2].toLowerCase();
    const poId    = `Po${groupId}`;

    const protocol = mode === 'active' || mode === 'passive' ? PortChannelProtocol.LACP
                   : mode === 'desirable' || mode === 'auto' ? PortChannelProtocol.PAgP
                   : PortChannelProtocol.Static;

    if (!groupMap.has(groupId)) {
      groupMap.set(groupId, {
        deviceId:          hostname,
        portChannelId:     poId,
        protocol,
        members:           [],
        operationalStatus: 'unknown',
        evidenceSource:    'interface config',
      });
    }

    groupMap.get(groupId)!.members.push({
      interfaceName: normalizePort(rawIntf),
      mode,
      isActive:      true,
    });
  }

  return [...groupMap.values()];
}

// ─────────────────────────────────────────────────────────────────────────────
// Merge PortChannelRecords for the same device+portChannelId
// ─────────────────────────────────────────────────────────────────────────────

export function mergePortChannels(
  records: PortChannelRecord[],
): PortChannelRecord[] {
  const map = new Map<string, PortChannelRecord>();

  for (const r of records) {
    const key = `${r.deviceId}::${r.portChannelId}`;
    if (!map.has(key)) {
      map.set(key, { ...r, members: [...r.members] });
      continue;
    }
    const existing = map.get(key)!;
    // Merge members (avoid duplicates)
    for (const m of r.members) {
      if (!existing.members.find(em => em.interfaceName === m.interfaceName)) {
        existing.members.push(m);
      }
    }
    // Higher confidence source wins
    if (r.protocol !== PortChannelProtocol.Unknown) existing.protocol = r.protocol;
    if (r.operationalStatus === 'up') existing.operationalStatus = 'up';
  }

  return [...map.values()];
}

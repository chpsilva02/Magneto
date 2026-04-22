/**
 * device-info.parser.ts  — Multi-vendor device metadata extractor
 *
 * Extracts: Hostname · Management IP · Hardware Model · Serial · OS Version
 *
 * Vendors with deep coverage:
 *   Cisco IOS / IOS-XE / NX-OS
 *   Juniper JunOS  (set-style, braces-style, show terse, chassis hardware)
 *   HP/HPE Aruba   (ArubaOS-Switch ProCurve + ArubaOS-CX)
 *   Huawei VRP     (display version, display device manuinfo, Vlanif)
 *   HPE Comware/H3C (Comware 7.x, Vlan-interface, display manuinfo)
 *   Arista EOS · Dell OS10 · Fortinet · Palo Alto · Extreme Networks
 *
 * Management IP priority (lower = better):
 *   1  Interface description contains mgmt keyword (gerencia/mgmt/management/oob…)
 *   2  Loopback0 / lo0
 *   3  Any Loopback
 *   4  Management / Mgmt / fxp0 / me0 interface (OOB mgmt)
 *   5  Vlan1 / Vlanif1 / Vlan-interface1
 *   6  Other Vlan SVI / IRB
 *   7  ArubaOS-CX "interface mgmt" ip static
 *   8  Palo Alto / Fortinet dedicated mgmt
 *  10  Physical interface (last resort)
 */

export interface DeviceInfo {
  hostname?:      string;
  managementIp?:  string;
  mgmtInterface?: string;
  hardwareModel?: string;
  serialNumber?:  string;
  osVersion?:     string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const MGMT_DESC_KEYWORDS = [
  'gerencia', 'gerência', 'gerenciamento',
  'mgmt', 'management', 'oob', 'out-of-band',
  'acesso', 'admin', 'controle', 'gestao', 'gestão',
  'noc', 'monitoramento', 'monitor',
];

const BAD_MODEL = /^(unknown|unspecified|n\/a|not[\s_]specified|private[\-_]config|none|chassis|processor|memory|flash|software|version|ios|nx-os|junos|comware|vrp|cisco[\s_]ios|eos|pan-os|fortios|exos|dell[\s_]emc)/i;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function isUsableIp(ip: string): boolean {
  if (!ip) return false;
  if (ip.startsWith('169.254.')) return false;
  if (ip.startsWith('127.'))     return false;
  if (ip === '0.0.0.0')         return false;
  if (ip.startsWith('255.'))    return false;
  if (ip.startsWith('0.'))      return false;
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
}

function cleanModel(raw: string): string {
  if (!raw) return '';
  const m = raw.trim()
    .replace(/\s+/g, ' ')
    .replace(/,.*$/, '')
    .replace(/\s+(cisco|systems|networks|technologies|inc\.?|co\.,?\s*ltd\.?)$/i, '')
    .replace(/^["'`]|["'`]$/g, '')
    .trim();
  if (BAD_MODEL.test(m) || m.length < 3) return '';
  return m;
}

function hasMgmtKeyword(desc: string, name: string): boolean {
  const d = (desc ?? '').toLowerCase();
  const n = (name ?? '').toLowerCase();
  return MGMT_DESC_KEYWORDS.some(k => d.includes(k) || n.includes(k));
}

function ifacePriority(name: string, description: string): number {
  const n = (name ?? '').toLowerCase();
  const hasMgmt = hasMgmtKeyword(description, name);
  if (hasMgmt)                                    return 1;
  if (/^loopback0$/i.test(name))                  return 2;
  if (/^loopback/i.test(name))                   return 3;
  // Juniper OOB: fxp0, me0, em0
  if (/^(fxp0|me0|me1|em0|em1)$/i.test(name))    return 4;
  // Generic management interface names
  if (/^(mgmt|management|mgmteth|oob|eth0|ma\d)/i.test(n)) return 4;
  // Vlan 1 SVI (all vendors)
  if (/^(vlan1|vl1|vlanif1|vlan-interface1|irb\.1|irb\.0)$/i.test(n)) return 5;
  // Other Vlan SVIs
  if (/^(vlan|vl|vlanif|vlan-interface|irb)\d+$/i.test(n)) return 6;
  if (/^irb\.\d+$/i.test(n))                     return 6;
  // ArubaOS-CX mgmt interface
  if (/^mgmt$/i.test(n))                          return 7;
  // Physical interfaces — lowest priority
  if (/^(gi|ge|te|xe|et|fa|eth|hu|fo|twe|\d+\/)/i.test(n)) return 10;
  return 8;
}

export interface IfaceRecord {
  name: string; ip: string; description: string; priority: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// IP Extraction — covers all vendor formats
// ─────────────────────────────────────────────────────────────────────────────

export function parseInterfaceIps(block: string): IfaceRecord[] {
  const records: IfaceRecord[] = [];
  const seenIps = new Set<string>();

  function add(name: string, ip: string, desc = '') {
    if (!isUsableIp(ip) || seenIps.has(ip)) return;
    seenIps.add(ip);
    records.push({ name: name.trim(), ip, description: desc.trim(), priority: ifacePriority(name, desc) });
  }

  // ══════════════════════════════════════════════════════════════════════════
  // A — Cisco IOS / IOS-XE / Arista / Dell / ArubaOS-CX
  //     "interface Vlan100\n description Gerencia\n ip address 10.x.x.x 255.x"
  // ══════════════════════════════════════════════════════════════════════════
  {
    const blocks = block.split(/(?=^interface\s)/im);
    for (const ib of blocks) {
      const nm = ib.match(/^interface\s+([^\r\n]+)/im);
      if (!nm) continue;
      const ifName = nm[1].trim();
      const desc   = ib.match(/^\s+description\s+([^\r\n]+)/im)?.[1] ?? '';
      // "ip address X.X.X.X 255.x" or "ip address X.X.X.X/N" or "ip static X/N"
      const ipM = ib.match(/^\s+ip(?:v4)?\s+address\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:\s+[0-9]|\/\d)/im)
               ?? ib.match(/^\s+ip\s+static\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\/\d+/im)
               ?? ib.match(/^\s+ipv4\s+address\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\/\d+/im);
      if (ipM) add(ifName, ipM[1], desc);
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // B — Huawei VRP  "interface Vlanif100 / ip address X.X.X.X 255.x"
  //     VRP uses "Vlanif" (not "Vlan") and "GigabitEthernet0/0/1" format
  // ══════════════════════════════════════════════════════════════════════════
  {
    const blocks = block.split(/(?=^interface\s)/im);
    for (const ib of blocks) {
      const nm = ib.match(/^interface\s+(Vlanif\d+|LoopBack\d+|NULL\d+|GigabitEthernet[\d\/]+|XGigabitEthernet[\d\/]+|Eth-Trunk\d+|MEth[\d\/]+)/im);
      if (!nm) continue;
      const ifName = nm[1].trim();
      const desc   = ib.match(/^\s+description\s+([^\r\n]+)/im)?.[1] ?? '';
      // VRP: "ip address X.X.X.X 255.x.x.x" or "ip address X.X.X.X 24"
      const ipM = ib.match(/^\s+ip\s+address\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+(?:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|\d{1,2})/im);
      if (ipM) add(ifName, ipM[1], desc);
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // C — HPE Comware / H3C  "interface Vlan-interface100 / ip address X 255"
  // ══════════════════════════════════════════════════════════════════════════
  {
    const blocks = block.split(/(?=^interface\s)/im);
    for (const ib of blocks) {
      const nm = ib.match(/^interface\s+(Vlan-interface\d+|LoopBack\d+|GigabitEthernet[\d\/]+|Ten-GigabitEthernet[\d\/]+|M-GigabitEthernet[\d\/]+)/im);
      if (!nm) continue;
      const ifName = nm[1].trim();
      const desc   = ib.match(/^\s+description\s+([^\r\n]+)/im)?.[1] ?? '';
      const ipM = ib.match(/^\s+ip\s+address\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+[0-9]/im);
      if (ipM) add(ifName, ipM[1], desc);
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // D — Juniper JunOS braces style
  //     interfaces { irb { unit 100 { description "Gerencia"; family inet { address 10.x/24; } } } }
  // ══════════════════════════════════════════════════════════════════════════
  {
    // Parse "family inet { address X.X.X.X/N; }" blocks
    const inetPat = /interfaces\s*\{[^}]*?(\w[\w\.\-]+)\s*\{[^}]*?unit\s+(\d+)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}/gs;
    let m: RegExpExecArray | null;
    while ((m = inetPat.exec(block)) !== null) {
      const ifBase = m[1]; const unit = m[2]; const body = m[3];
      const descM  = body.match(/description\s+"?([^";\r\n]+)/i);
      const addrM  = body.match(/address\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\/\d+/i);
      if (addrM) add(`${ifBase}.${unit}`, addrM[1], descM?.[1] ?? '');
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // E — Juniper JunOS set-style flat config
  //     "set interfaces irb unit 100 family inet address 10.x/24"
  //     "set interfaces irb unit 100 description Gerencia"
  // ══════════════════════════════════════════════════════════════════════════
  {
    const addrLines = [...block.matchAll(/^set\s+interfaces\s+(\S+)\s+unit\s+(\d+)\s+family\s+inet\s+address\s+([0-9.]+)\/\d+/gim)];
    for (const m of addrLines) {
      const ifName = `${m[1]}.${m[2]}`;
      const ip     = m[3];
      // Look for description on same interface
      const descPat = new RegExp(`set\\s+interfaces\\s+${m[1]}\\s+unit\\s+${m[2]}\\s+description\\s+"?([^"\\r\\n]+)`, 'im');
      const desc    = block.match(descPat)?.[1] ?? '';
      add(ifName, ip, desc);
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // F — Juniper "show interfaces terse" output table
  //     "irb.100   up  up  inet  10.10.100.1/24"
  //     "fxp0      up  up  inet  192.168.1.1/24"
  // ══════════════════════════════════════════════════════════════════════════
  {
    const tersePat = /^([A-Za-z][\w\.\-\/]+)\s+up\s+up\s+inet\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\/\d+/gim;
    let m: RegExpExecArray | null;
    while ((m = tersePat.exec(block)) !== null) add(m[1], m[2], '');
  }

  // ══════════════════════════════════════════════════════════════════════════
  // G — Huawei "display ip interface brief" table
  //     "Vlanif100   up   up   10.215.233.27"
  // ══════════════════════════════════════════════════════════════════════════
  {
    const vrpBriefPat = /^(Vlanif\d+|LoopBack\d+|MEth[\d\/]+)\s+up\s+up\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/gim;
    let m: RegExpExecArray | null;
    while ((m = vrpBriefPat.exec(block)) !== null) add(m[1], m[2], '');
  }

  // ══════════════════════════════════════════════════════════════════════════
  // H — HPE Comware "display ip interface brief" table
  //     "Vlan-interface100   up   up   10.215.233.27"
  // ══════════════════════════════════════════════════════════════════════════
  {
    const comwareBriefPat = /^(Vlan-interface\d+|LoopBack\d+|M-GigabitEthernet[\d\/]+)\s+up\s+up\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/gim;
    let m: RegExpExecArray | null;
    while ((m = comwareBriefPat.exec(block)) !== null) add(m[1], m[2], '');
  }

  // ══════════════════════════════════════════════════════════════════════════
  // I — HP Aruba ArubaOS-Switch (ProCurve) VLAN IP table
  //     " 100  | 10.215.233.27   | 255.255.255.0"
  // Strategy: find default gateway, pick the VLAN in same /24 subnet as gateway
  //           If no gateway match, use VLAN with lowest ID that has routable IP
  // ══════════════════════════════════════════════════════════════════════════
  {
    const gwM = block.match(/IP\s+Default\s+Gateway\s*:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i)
             ?? block.match(/Default\s+Gateway\s*:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i);
    const gwPrefix = gwM ? gwM[1].split('.').slice(0,3).join('.') : null;

    const procurvePat = /^\s*(\d+)\s*\|\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*\|/gim;
    const vlanEntries: Array<{id:string; ip:string}> = [];
    let m: RegExpExecArray | null;
    while ((m = procurvePat.exec(block)) !== null) {
      const vlanId = m[1]; const ip = m[2];
      vlanEntries.push({ id: vlanId, ip });
    }

    // Pick mgmt VLAN: same subnet as gateway > lowest vlan id
    let mgmtEntry = gwPrefix
      ? vlanEntries.find(e => e.ip.split('.').slice(0,3).join('.') === gwPrefix)
      : null;
    if (!mgmtEntry && vlanEntries.length > 0) {
      // No gateway clue — sort by VLAN id, prefer non-192.168 / non-1 VLANs
      vlanEntries.sort((a,b) => {
        const aIsDefault = a.ip.startsWith('192.168.') || a.id === '1';
        const bIsDefault = b.ip.startsWith('192.168.') || b.id === '1';
        if (aIsDefault !== bIsDefault) return aIsDefault ? 1 : -1;
        return parseInt(a.id) - parseInt(b.id);
      });
      mgmtEntry = vlanEntries[0];
    }

    // Add all VLAN IPs; mgmt one gets 'management' description for priority boost
    for (const e of vlanEntries) {
      const isMgmt = mgmtEntry && e.id === mgmtEntry.id;
      add(`VLAN${e.id}`, e.ip, isMgmt ? 'management' : (e.id === '1' ? 'vlan1' : ''));
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // J — ArubaOS-CX "show interface mgmt" output
  //     "IPv4 address/subnet-mask : 10.20.30.40/24"
  // ══════════════════════════════════════════════════════════════════════════
  {
    const cxMgmtPat = /IPv4\s+address\/subnet-mask\s*:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\/\d+/i;
    const m = block.match(cxMgmtPat);
    if (m) add('mgmt', m[1], 'management');
  }

  // ══════════════════════════════════════════════════════════════════════════
  // K — Cisco IOS "show interfaces" style — "Internet address is X.X.X.X/N"
  // ══════════════════════════════════════════════════════════════════════════
  {
    const showIntfPat = /^([A-Za-z][A-Za-z0-9\/\.\-]+)\s+is\s+(?:up|down|administratively\s+down)/gim;
    const indices: Array<{idx: number; name: string}> = [];
    let m: RegExpExecArray | null;
    while ((m = showIntfPat.exec(block)) !== null) indices.push({ idx: m.index, name: m[1] });
    for (let i = 0; i < indices.length; i++) {
      const seg  = block.slice(indices[i].idx, indices[i+1]?.idx ?? block.length);
      const ipM  = seg.match(/Internet address is ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\/\d+/i);
      const dscM = seg.match(/Description:\s*([^\r\n]+)/i);
      if (ipM) add(indices[i].name, ipM[1], dscM?.[1] ?? '');
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // L — Cisco "show ip interface brief" table
  //     "Vlan100  10.0.0.1  YES manual up  up"
  // ══════════════════════════════════════════════════════════════════════════
  {
    const briefPat = /^([A-Za-z][A-Za-z0-9\/\.\-]+)\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+YES/gim;
    let m: RegExpExecArray | null;
    while ((m = briefPat.exec(block)) !== null) add(m[1], m[2], '');
  }

  // ══════════════════════════════════════════════════════════════════════════
  // M — NX-OS / Arista inline "ip address X.X.X.X/N"
  // ══════════════════════════════════════════════════════════════════════════
  {
    const nxPat = /ip address ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\/\d+/gi;
    let m: RegExpExecArray | null;
    while ((m = nxPat.exec(block)) !== null) {
      const before = block.slice(Math.max(0, m.index - 500), m.index);
      const ifM    = before.match(/interface\s+(\S[^\r\n]+)\s*$/i);
      const descM  = before.match(/description\s+([^\r\n]+)\s*$/i);
      add(ifM?.[1]?.trim() ?? 'unknown', m[1], descM?.[1] ?? '');
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // N — Fortinet "set ip X.X.X.X mask" inside config system interface
  // ══════════════════════════════════════════════════════════════════════════
  {
    const fortiPat = /set\s+ip\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+[0-9.]+/gi;
    let m: RegExpExecArray | null;
    while ((m = fortiPat.exec(block)) !== null) {
      const before = block.slice(Math.max(0, m.index - 400), m.index);
      const aliasM = before.match(/set\s+(?:alias|name)\s+"?([^"\r\n]+)/i)
                  ?? before.match(/edit\s+"?([^"\r\n]+)/i);
      add(aliasM?.[1]?.trim() ?? 'port', m[1], aliasM?.[1] ?? '');
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // O — Palo Alto "show system info"  ip-address: X.X.X.X
  // ══════════════════════════════════════════════════════════════════════════
  {
    const paloM = block.match(/ip-address\s*:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i)
               ?? block.match(/Management\s+IP\s*:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i);
    if (paloM) add('management', paloM[1], 'management');
  }

  // ══════════════════════════════════════════════════════════════════════════
  // P — Extreme Networks "VLAN: Mgmt  IP addr: 10.x/24"
  // ══════════════════════════════════════════════════════════════════════════
  {
    const xPat = /VLAN:\s+(\S+)\s+IP\s+addr:\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\/\d+/gi;
    let m: RegExpExecArray | null;
    while ((m = xPat.exec(block)) !== null) add(m[1], m[2], m[1]);
  }

  records.sort((a, b) => a.priority - b.priority);
  return records;
}

export function extractManagementIp(block: string): { ip: string; iface: string } | undefined {
  const recs = parseInterfaceIps(block);
  if (!recs.length) return undefined;
  return { ip: recs[0].ip, iface: recs[0].name };
}

// ─────────────────────────────────────────────────────────────────────────────
// Hostname
// ─────────────────────────────────────────────────────────────────────────────

export function extractHostname(block: string): string | undefined {
  // Cisco / Arista / Dell / ArubaOS-CX
  const m1 = block.match(/^hostname\s+(\S+)/im);
  if (m1) return m1[1].trim();

  // Huawei VRP / HPE Comware / H3C
  const m2 = block.match(/^sysname\s+(\S+)/im);
  if (m2) return m2[1].trim();

  // Juniper JunOS  "host-name qfx-leaf-01;"
  const m3 = block.match(/^(?:set\s+system\s+)?host-name\s+(\S+?)\s*;?$/im);
  if (m3) return m3[1].trim();

  // Fortinet  "set hostname FW-01"
  const m4 = block.match(/set\s+hostname\s+(\S+)/i);
  if (m4) return m4[1].trim();

  // Juniper show version  "Hostname: qfx-leaf-01"
  const m5 = block.match(/^Hostname:\s*(\S+)/im);
  if (m5) return m5[1].trim().split('.')[0];

  // HP Aruba AOS-Switch  "SWITCH_1#" prompt
  const m6 = block.match(/^([A-Za-z0-9][A-Za-z0-9_\-\.]{2,})[#>]\s*(?:show|display|get|diagnose|$)/im);
  if (m6) return m6[1].trim();

  // LLDP System Name (all vendors)
  const m7 = block.match(/System\s+[Nn]ame\s*[:=]\s*(\S+)/i);
  if (m7) return m7[1].trim().split('.')[0];

  // Palo Alto  "Hostname:  PA-FW-01"
  const m8 = block.match(/^Hostname\s*:\s*(\S+)/im);
  if (m8) return m8[1].trim();

  // Huawei VRP / HPE Comware prompt  "<HW-S5720-CORE>display"
  const m9 = block.match(/^<([A-Za-z0-9][A-Za-z0-9_\-\.]{2,})>/im);
  if (m9) return m9[1].trim();

  return undefined;
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardware Model
// ─────────────────────────────────────────────────────────────────────────────

export function extractHardwareModel(block: string): string | undefined {

  // ── Cisco: show inventory PID (highest confidence) ──────────────────────
  const pidM = block.match(/^NAME:\s*"(?:Chassis|Switch|[^"]{0,30})"\s*,.*\nPID:\s*([A-Za-z0-9][\w\-]+)/im)
            ?? block.match(/PID:\s*([A-Za-z0-9][\w\-]+)/i);
  if (pidM) { const v = cleanModel(pidM[1]); if (v) return v; }

  // ── Cisco show version ──────────────────────────────────────────────────
  const ciscoV = block.match(/[Cc]isco\s+(WS-C[\w\-]+|WS-CBS[\w\-]+|CBS\d[\w\-]+|C\d{4}[\w\-]+|N\d[Kk][\w\-]+|Nexus[\s\-]?\d[\w\-]+|ASR\d[\w\-]+|ISR\d[\w\-]+|FPR\d[\w\-]+|AIR-[\w\-]+)/i)
             ?? block.match(/\b(WS-C[\w\-]+|WS-CBS[\w\-]+|CBS\d[\w\-]+|C\d{4}[\w\-]+|N9[Kk][\w\-]+|N7[Kk][\w\-]+|N5[Kk][\w\-]+|N3[Kk][\w\-]+|ASR\d{4}[\w\-]+|ISR\d{4}[\w\-]+|FPR\d{4}[\w\-]+)\b/i);
  if (ciscoV) { const v = cleanModel(ciscoV[1]); if (v) return v; }

  // ── Juniper: show version "Model: qfx5120-32c" ──────────────────────────
  const juniperModel = block.match(/^Model:\s*([\w\-]+)/im);
  if (juniperModel) { const v = cleanModel(juniperModel[1]); if (v) return v; }
  // show chassis hardware "QFX5120-32C"
  const juniperChassis = block.match(/Chassis\s+[\w\-]+\s+[\w\-]+\s+[\w\-]+\s+((?:EX|QFX|MX|SRX|ACX|PTX|OCX)\d[\w\-]+)/i)
                      ?? block.match(/\b(EX\d{4}[\w\-]+|QFX\d{4}[\w\-]+|MX\d{2,}[\w\-]+|SRX\d{3,}[\w\-]+|ACX\d{4}[\w\-]+|PTX\d{4}[\w\-]+)\b/i);
  if (juniperChassis) { const v = cleanModel(juniperChassis[1]); if (v) return v; }

  // ── Huawei VRP: display device manuinfo / display version ───────────────
  // "DEVICE_NAME     : S5720-52X-SI-AC"
  const huaweiName = block.match(/DEVICE_NAME\s*:\s*([A-Za-z0-9][\w\-]+)/i);
  if (huaweiName) { const v = cleanModel(huaweiName[1]); if (v) return v; }
  // "HUAWEI S5720-52X-SI-AC" in display version
  const huaweiVer = block.match(/^HUAWEI\s+([\w\-]+)/im)
                 ?? block.match(/\b(S\d{4}[\w\-]+|CE\d{4,}[\w\-]+|NE\d{2,}[\w\-]+|AR\d{3,}[\w\-]+|USG\d{4,}[\w\-]+|AntiDDoS[\w\-]+)\b/i);
  if (huaweiVer) { const v = cleanModel(huaweiVer[1]); if (v) return v; }

  // ── HPE Comware / H3C: display version / display device manuinfo ────────
  // "H3C S5560X-54C-EI uptime is..."  or  "DEVICE_NAME : S5560X-54C-EI"
  const comwareName = block.match(/DEVICE_NAME\s*:\s*([A-Za-z0-9][\w\-]+)/i)
                   ?? block.match(/^(?:H3C|HPE)\s+([\w\-]+)\s+uptime/im)
                   ?? block.match(/Product\s+(?:name|model)\s*:\s*([A-Za-z0-9][\w\-\s]+?)(?:\r|\n)/i);
  if (comwareName) { const v = cleanModel(comwareName[1]); if (v) return v; }
  const comwareModel = block.match(/\b(S\d{4}X?[\w\-]+|MSR\d{2,}[\w\-]+|A-MSR[\w\-]+)\b/i);
  if (comwareModel) { const v = cleanModel(comwareModel[1]); if (v) return v; }

  // ── HP Aruba ArubaOS-Switch (ProCurve) ──────────────────────────────────
  // "HP J9850A Switch 5406R zl2"  or  "Switch Model : 5406R zl2"
  const arubaSwitch = block.match(/HP\s+J\d{4}[A-Z]\s+Switch\s+([\w\-]+)/i)
                   ?? block.match(/(?:Switch|System)\s+Model\s*:\s*([\w\-]+)/i);
  if (arubaSwitch) { const v = cleanModel(arubaSwitch[1]); if (v) return v; }

  // ── HP Aruba ArubaOS-CX ─────────────────────────────────────────────────
  // "Switch Model  : 6300M"
  const arubaModel = block.match(/Switch\s+Model\s*:\s*([\w\-]+)/i)
                  ?? block.match(/\b(Aruba[\s\-][\w\-]+|6[123]\d{2}[A-Z]?[\w\-]*)\b/i);
  if (arubaModel) { const v = cleanModel(arubaModel[1]); if (v) return v; }

  // ── Arista EOS ──────────────────────────────────────────────────────────
  const aristaM = block.match(/Arista\s+(DCS-[\w\-]+|CCS-[\w\-]+)/i)
               ?? block.match(/\b(DCS-[\w\-]+|CCS-[\w\-]+)\b/i);
  if (aristaM) { const v = cleanModel(aristaM[1]); if (v) return v; }

  // ── Dell OS10 ────────────────────────────────────────────────────────────
  const dellM = block.match(/System\s+Type\s*:\s*([A-Za-z0-9][\w\-\s]+?)(?:\r|\n)/i)
             ?? block.match(/\b(S\d{4}[A-Z][\w\-]+|Z\d{4}[\w\-]+|PowerSwitch[\s\-][\w\-]+)\b/i);
  if (dellM) { const v = cleanModel(dellM[1]); if (v) return v; }

  // ── Fortinet ─────────────────────────────────────────────────────────────
  const fortiM = block.match(/(?:Platform|Model)\s*:\s*(FortiGate[\s\-][\w\-]+)/i)
              ?? block.match(/Version:\s*(FortiGate[\w\-]+)/i)
              ?? block.match(/\b(FortiGate-[\w\-]+|FGT-[\w\-]+)\b/i);
  if (fortiM) { const v = cleanModel(fortiM[1]); if (v) return v; }

  // ── Palo Alto ────────────────────────────────────────────────────────────
  const paloM = block.match(/^model\s*:\s*(PA-[\w\-]+)/im)
             ?? block.match(/\b(PA-\d{3,}[\w\-]+|VM-\d{3}[\w\-]+)\b/i);
  if (paloM) { const v = cleanModel(paloM[1]); if (v) return v; }

  // ── Extreme Networks ─────────────────────────────────────────────────────
  const extremeM = block.match(/\b(X\d{3}[A-Z]?-\d{2}[\w\-]+|Summit[\s\-][\w\-]+|BlackDiamond[\s\-][\w\-]+)\b/i);
  if (extremeM) { const v = cleanModel(extremeM[1]); if (v) return v; }

  // ── Generic fallbacks ────────────────────────────────────────────────────
  const hwFallback = block.match(/Hardware\s*[:=]\s*([A-Za-z0-9][\w\-]+)/i)
                  ?? block.match(/Model\s+(?:number|name|id)?\s*[:=]\s*([A-Za-z0-9][\w\-]+)/i)
                  ?? block.match(/Platform:\s*([A-Za-z0-9][\w\-\s]{3,30}?)(?:,|\r|\n)/i);
  if (hwFallback) { const v = cleanModel(hwFallback[1]); if (v) return v; }

  return undefined;
}

// ─────────────────────────────────────────────────────────────────────────────
// Serial Number
// ─────────────────────────────────────────────────────────────────────────────

export function extractSerialNumber(block: string): string | undefined {
  return (
    block.match(/^SN:\s*([A-Za-z0-9]{6,20})/im)?.[1]
    ?? block.match(/DEVICE_SERIAL_NUMBER\s*:\s*([A-Za-z0-9]{6,25})/i)?.[1]
    ?? block.match(/[Ss]erial\s*[Nn]umber\s*[:=]\s*([A-Za-z0-9]{6,20})/i)?.[1]
    ?? block.match(/[Ss]ystem\s+[Ss]erial\s+[Nn]umber\s*[:=]\s*([A-Za-z0-9]{6,20})/i)?.[1]
    ?? block.match(/[Cc]hassis\s+[Ss]erial\s*(?:[Nn]umber)?\s*:\s*([A-Za-z0-9]{6,20})/i)?.[1]
    // Juniper: show chassis hardware "Serial number: WT3719380058"
    ?? block.match(/^\s+Serial\s+number\s*:\s*([A-Za-z0-9]{6,20})/im)?.[1]
  )?.trim();
}

// ─────────────────────────────────────────────────────────────────────────────
// OS Version
// ─────────────────────────────────────────────────────────────────────────────

export function extractOsVersion(block: string): string | undefined {
  // Cisco IOS / IOS-XE
  const iosM = block.match(/Cisco IOS[^,\r\n]*,?\s*Version\s+([^\s,\r\n]+)/i);
  if (iosM) return iosM[1].trim();

  // Cisco NX-OS
  const nxM = block.match(/(?:NXOS|NX-OS|system):\s*version\s+([^\s\r\n]+)/i);
  if (nxM) return nxM[1].trim();

  // Juniper JunOS  "Junos: 21.2R3.5"
  const junosM = block.match(/^Junos:\s*([^\s\r\n]+)/im)
              ?? block.match(/JUNOS\s+([\d\.R\-S]+)/i);
  if (junosM) return junosM[1].trim();

  // Huawei VRP  "VRP (R) software, Version 5.170 (S5720 V200R011C10SPC600)"
  const vrpM = block.match(/VRP\s*\(R\)\s*software,\s*Version\s+([\S]+)\s+\(([^)]+)\)/i)
            ?? block.match(/Versatile Routing Platform.*?Version\s+([^\s\r\n]+)/i);
  if (vrpM) return `${vrpM[1]} (${vrpM[2] ?? ''})`.replace(/\(\)$/, '').trim();

  // HPE Comware  "Comware Software, Version 7.1.070, Release 3208"
  const comwareV = block.match(/Comware\s+Software,\s*Version\s+([^\s,\r\n]+)/i);
  if (comwareV) return comwareV[1].trim();

  // HP Aruba ArubaOS-Switch  "Software revision: WB.16.10.0022"
  const arubaV = block.match(/Software\s+revision\s*:\s*([^\s\r\n]+)/i)
              ?? block.match(/Version\s+:\s*(FL\.\S+|[A-Z]{2}\.\d+\S*)/i);
  if (arubaV) return arubaV[1].trim();

  // Arista EOS
  const aristaV = block.match(/EOS\s+version\s+([^\s\r\n]+)/i)
               ?? block.match(/Arista[^\r\n]*?(\d+\.\d+\.\d+[^\s,]*)/i);
  if (aristaV) return aristaV[1].trim();

  // Fortinet
  const fortiV = block.match(/Version:\s*FortiGate\S*\s+(v[\d\.]+[^\s\r\n]*)/i)
              ?? block.match(/FortiOS\s+v([\d\.]+)/i);
  if (fortiV) return fortiV[1].trim();

  // Palo Alto
  const paloV = block.match(/sw-version\s*:\s*([^\s\r\n]+)/i);
  if (paloV) return paloV[1].trim();

  // Generic
  const genV = block.match(/Version\s+(\d+[\.\d\(\)A-Za-z\-]+)/i);
  if (genV) return genV[1].trim();

  return undefined;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main entry
// ─────────────────────────────────────────────────────────────────────────────

export function extractDeviceInfo(block: string): DeviceInfo {
  const mgmt = extractManagementIp(block);
  return {
    hostname:      extractHostname(block),
    managementIp:  mgmt?.ip,
    mgmtInterface: mgmt?.iface,
    hardwareModel: extractHardwareModel(block),
    serialNumber:  extractSerialNumber(block),
    osVersion:     extractOsVersion(block),
  };
}

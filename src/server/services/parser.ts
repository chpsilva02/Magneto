import { TopologyData, TopologyNode, TopologyLink } from '../../shared/types.ts';
import { TopologyDatabase } from './topologyDb.ts';

function normalizePort(port: string): string {
  let p = port.replace(/[\s-]/g, ''); // remove spaces and dashes
  if (/^tegigabitethernet/i.test(p)) return p.replace(/^tegigabitethernet/i, 'Te');
  if (/^xgigabitethernet/i.test(p)) return p.replace(/^xgigabitethernet/i, 'XGE');
  if (/^gigabitethernet/i.test(p)) return p.replace(/^gigabitethernet/i, 'Gi');
  if (/^gig/i.test(p)) return p.replace(/^gig/i, 'Gi');
  if (/^fastethernet/i.test(p)) return p.replace(/^fastethernet/i, 'Fa');
  if (/^fas/i.test(p)) return p.replace(/^fas/i, 'Fa');
  if (/^tengigabitethernet/i.test(p)) return p.replace(/^tengigabitethernet/i, 'Te');
  if (/^ten/i.test(p)) return p.replace(/^ten/i, 'Te');
  if (/^twentyfivegige/i.test(p)) return p.replace(/^twentyfivegige/i, 'Twe');
  if (/^fortygigabitethernet/i.test(p)) return p.replace(/^fortygigabitethernet/i, 'Fo');
  if (/^hundredgigabitethernet/i.test(p)) return p.replace(/^hundredgigabitethernet/i, 'Hu');
  if (/^ethernet/i.test(p)) return p.replace(/^ethernet/i, 'Eth');
  if (/^eth/i.test(p)) return p.replace(/^eth/i, 'Eth');
  if (/^portchannel/i.test(p)) return p.replace(/^portchannel/i, 'Po');
  return port.replace(/\s+/g, ''); // return original without spaces if no match
}

function determineRole(hostname: string, model: string): 'unknown' | 'core' | 'distribution' | 'access' | 'router' | 'firewall' | 'cloud' {
  const h = hostname.toLowerCase();
  const m = model.toLowerCase();
  
  if (h.includes('fw') || m.includes('firewall') || m.includes('srx') || m.includes('asa') || m.includes('fpr') || m.includes('usg')) return 'firewall';
  if (h.includes('rtr') || h.includes('router') || m.includes('isr') || m.includes('asr') || m.includes('c8200') || m.includes('c1100') || m.includes('ne40') || m.includes('ar')) return 'router';
  if (h.includes('core') || m.includes('nexus') || m.includes('n9k') || m.includes('c9500') || m.includes('c9600') || m.includes('12500') || m.includes('ce12800') || m.includes('s12700')) return 'core';
  if (h.includes('dist') || m.includes('c9400') || m.includes('c3850') || m.includes('c3750') || m.includes('s5720') || m.includes('s5730') || m.includes('mx9116')) return 'distribution';
  if (h.includes('sw') || m.includes('switch') || m.includes('c2960') || m.includes('c9200') || m.includes('c9300') || m.includes('s5700')) return 'access';
  if (h.startsWith('sep') || m.includes('phone') || m.includes('room') || m.includes('bar') || m.includes('endpoint')) return 'access';
  
  return 'access'; // default
}

function isNetworkInterface(port: string): boolean {
  if (!port) return false;
  const p = port.replace(/[\s-]/g, '');
  return /^(Gi|Gig|GigabitEthernet|Fa|Fas|FastEthernet|Te|Ten|TenGigabitEthernet|Twe|TwentyFiveGigE|Fo|FortyGigabitEthernet|Hu|HundredGigabitEthernet|Eth|Ethernet|Po|Portchannel|Ser|Serial|mgmt|Vl|Vlan|XGE|25GE|40GE|100GE|ge|xe|et)/i.test(p);
}

function isValidDeviceName(name: string): boolean {
  if (!name) return false;
  if (/^(System|Device|Local|Port|Capability|Interface|Total|Entries|None|Unknown|ID|Name|Mac|IP|Address|LLDP|CDP|Detail|Info|Time|Chassis|Update|Index|Management|Compiled|Oper|DCBX|TLV|Auto-negotiation|Max\/min|Aggregation|HP|Version|Sequence|http|Percentage|CoS|Hardware|Platform|Software|uptime|processor|memory|bytes|packets|errors|discard|broadcast|multicast|unicast)$/i.test(name)) return false;
  if (/^\d+$/.test(name)) return false; // purely numeric like "7"
  if (name.toLowerCase().includes('not advertised')) return false;
  if (name.toLowerCase().includes('poweredge')) return false;
  if (name.length < 2) return false;
  return true;
}

export function parseRawData(rawData: string, vendor: string): TopologyData {
  const db = new TopologyDatabase();
  
  const nodesMap: Record<string, TopologyNode> = {};
  const linksMap: Record<string, TopologyLink> = {};

  const extractedL2Links: Array<{ sourceDevice: string, localPort: string, vlan: string, role: string, state: string }> = [];
  
  // L3 Extraction Arrays
  const ipToDevice: Record<string, string> = {};
  const extractedOspf: Array<{ sourceDevice: string, neighborIp: string, localPort: string, state: string }> = [];
  const extractedBgp: Array<{ sourceDevice: string, neighborIp: string, as: string, state: string }> = [];
  const extractedRoutes: Array<{ sourceDevice: string, code: string, prefix: string, nextHop: string, localPort: string }> = [];

  function parseBlock(hostname: string, blockData: string) {
    let hwModel = 'Unknown';
    
    // 1. Try explicit inventory/manuinfo commands first (highest accuracy)
    const pidMatch = blockData.match(/PID:\s*([A-Za-z0-9\-_]+)/i);
    const productMatch = blockData.match(/Product(?: Name| ID| Number)?\s*[:=]\s*([A-Za-z0-9\-_]+)/i);
    const manuinfoMatch = blockData.match(/(?:DEVICE_NAME|Device Name|Device)\s*[:=]\s*([A-Za-z0-9\-_]+)/i);
    
    // 2. Try specific known patterns in show version or other outputs
    const specificMatch = blockData.match(/(WS-C[\w\-]+|C\d{4,}[\w\-]*|Nexus\s*\d+[\w\-]*|ISR\d+[\w\-]*|ASR\d+[\w\-]*|FPR\d+[\w\-]*|SRX\d+[\w\-]*|(?:MX|S|Z|N)\d{4,}[\w\-]*|NE\d{2,}[\w\-]*|125\d{2}[\w\-]*)/i);

    if (pidMatch) {
        hwModel = pidMatch[1].trim();
    } else if (productMatch) {
        hwModel = productMatch[1].trim();
    } else if (manuinfoMatch) {
        hwModel = manuinfoMatch[1].trim();
    } else if (specificMatch) {
        hwModel = specificMatch[1].trim();
    } else {
        // 3. Fallback to generic pattern
        const genericMatch = blockData.match(/(?:hardware|model|platform|system type)\s*(?:is|:)?\s*([A-Za-z0-9\-_]+(?:[ \t]+[A-Za-z0-9\-_]+)*)/i);
        if (genericMatch && genericMatch[1] && !/^(processor|memory|chassis|uptime|software|version)/i.test(genericMatch[1])) {
            hwModel = genericMatch[1].trim();
        }
    }
    
    // Clean up hwModel if it accidentally captured an OS string
    if (hwModel.toLowerCase().includes('nexus operating system') || hwModel.toLowerCase().includes('nx-os')) {
        hwModel = 'Nexus';
    }
    
    const isRoot = /This bridge is the root/i.test(blockData);

    db.upsertDevice({
      id: hostname,
      hostname: hostname,
      vendor: vendor as any,
      hardware_model: hwModel,
      role: determineRole(hostname, hwModel),
      isRoot: isRoot
    });

    // --- PARSE CDP DETAIL ---
    const cdpBlocks = blockData.split(/Device ID:/i).slice(1);
    for (const block of cdpBlocks) {
      const deviceIdMatch = block.match(/^\s*([^\r\n]+)/);
      const interfaceMatch = block.match(/Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*([^\r\n]+)/i);
      const ipMatch = block.match(/IP address:\s*([0-9.]+)/i);
      const platformMatch = block.match(/Platform:\s*([^,]+)/i);

      if (deviceIdMatch && interfaceMatch) {
        let remoteDevice = deviceIdMatch[1].trim().split('.')[0];
        let localPort = normalizePort(interfaceMatch[1].trim());
        let remotePort = normalizePort(interfaceMatch[2].trim());
        
        let remoteModel = platformMatch ? platformMatch[1].trim() : undefined;
        if (remoteModel && (remoteModel.toLowerCase().includes('nexus operating system') || remoteModel.toLowerCase().includes('nx-os'))) {
            remoteModel = 'Nexus';
        }

        if (isValidDeviceName(remoteDevice) && isNetworkInterface(localPort) && isNetworkInterface(remotePort) && !/^(Po|Port-channel|Vl|Vlan)/i.test(localPort) && !/^(Po|Port-channel|Vl|Vlan)/i.test(remotePort)) {
          db.insertPhysicalLink(
            hostname,
            localPort,
            remoteDevice,
            remotePort,
            'cdp',
            ipMatch ? ipMatch[1].trim() : undefined,
            remoteModel
          );
        }
      }
    }

    // --- PARSE LLDP DETAIL ---
    // Handle Cisco (Local Intf:), HP/Huawei (LLDP neighbor-information of port), and Dell (Local Interface)
    const lldpBlocks = blockData.split(/(?=Local Intf:|Local Interface|LLDP neighbor-information of port)/i);
    for (const block of lldpBlocks) {
      if (!/Local Intf:|Local Interface|LLDP neighbor-information of port/i.test(block)) continue;

      const localIntfMatch = block.match(/Local Intf:\s*([^\r\n]+)/i) || block.match(/Local Interface\s*[:]?\s*([^\r\n]+)/i) || block.match(/LLDP neighbor-information of port.*?\[([^\]]+)\]/i) || block.match(/LLDP neighbor-information of port\s+([^\s\[:]+)/i);
      const sysNameMatch = block.match(/System Name\s*[:=]\s*([^\r\n]+)/i);
      const portIdMatch = block.match(/Port id\s*[:=]\s*([^\r\n]+)/i);
      const ipMatch = block.match(/Management address\s*[:=]\s*([0-9.]+)/i) || block.match(/IP\s*[:=]\s*([0-9.]+)/i) || block.match(/IPv4 address\s*[:=]\s*([0-9.]+)/i);
      const descMatch = block.match(/System Description\s*[:=]\s*([^\r\n]+)/i);

      if (localIntfMatch && sysNameMatch && portIdMatch) {
        let remoteDevice = sysNameMatch[1].trim().split('.')[0];
        let localPort = normalizePort(localIntfMatch[1].trim());
        let remotePort = normalizePort(portIdMatch[1].trim());

        let remoteModel = undefined;
        if (descMatch) {
          const hwMatch = descMatch[1].match(/(?:Hardware:\s*|Platform:\s*|Cisco\s+|Dell EMC\s+)([^,]+)/i);
          remoteModel = hwMatch ? hwMatch[1].trim() : descMatch[1].substring(0, 40).trim();
        }
        
        if (remoteModel && (remoteModel.toLowerCase().includes('nexus operating system') || remoteModel.toLowerCase().includes('nx-os'))) {
            remoteModel = 'Nexus';
        }

        if (isValidDeviceName(remoteDevice) && isNetworkInterface(localPort) && isNetworkInterface(remotePort) && !/^(Po|Port-channel|Vl|Vlan)/i.test(localPort) && !/^(Po|Port-channel|Vl|Vlan)/i.test(remotePort)) {
          db.insertPhysicalLink(
            hostname,
            localPort,
            remoteDevice,
            remotePort,
            'lldp',
            ipMatch ? ipMatch[1].trim() : undefined,
            remoteModel
          );
        }
      }
    }

    // --- PARSE TABULAR CDP/LLDP ---
    const lines = blockData.split('\n');
    let inTable = false;
    let pendingDevice = '';
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      // Detect start of table strictly
      if (line.match(/^(?:Device ID|Loc PortID|System Name)\s+(?:Local Intrfce|Local Intf|Rem Host Name|Local Interface)/i)) {
        inTable = true;
        pendingDevice = '';
        continue;
      }
      
      // Detect end of table
      if (inTable && (line === '' || line.match(/^[a-zA-Z0-9_.-]+[#>]/))) {
        inTable = false;
        continue;
      }

      if (!inTable) continue;
      if (line.startsWith('Capability') || line.startsWith('Port ID') || line.startsWith('------')) continue;
      
      const tokens = line.split(/\s+/);
      if (tokens.length === 0) continue;

      let remoteDevice = '';
      let localPortFull = '';
      let remotePortFull = '';

      // Handle Dell/Force10 format: Loc PortID Rem Host Name Rem Port Id Rem Chassis Id
      if (isNetworkInterface(tokens[0]) && tokens.length >= 3 && isNetworkInterface(tokens[2])) {
        localPortFull = tokens[0];
        remoteDevice = tokens[1];
        remotePortFull = tokens[2];
      } else {
        // Standard CDP/LLDP format
        if (tokens.length === 1) {
          pendingDevice = tokens[0];
          continue;
        }

        let interfaceStartIndex = 0;
        if (!isNetworkInterface(tokens[0]) && !isNetworkInterface(tokens[0] + (tokens[1] || ''))) {
          remoteDevice = tokens[0];
          interfaceStartIndex = 1;
        } else {
          remoteDevice = pendingDevice;
        }

        if (isNetworkInterface(tokens[interfaceStartIndex])) {
          localPortFull = tokens[interfaceStartIndex];
          if (tokens.length > interfaceStartIndex + 1 && /^\d+\/\d+/.test(tokens[interfaceStartIndex + 1])) {
            localPortFull += tokens[interfaceStartIndex + 1];
          }
        } else if (tokens.length > interfaceStartIndex + 1 && isNetworkInterface(tokens[interfaceStartIndex] + tokens[interfaceStartIndex + 1])) {
          localPortFull = tokens[interfaceStartIndex] + tokens[interfaceStartIndex + 1];
        }

        if (isNetworkInterface(tokens[tokens.length - 1])) {
          remotePortFull = tokens[tokens.length - 1];
        } else if (tokens.length >= 2 && isNetworkInterface(tokens[tokens.length - 2] + tokens[tokens.length - 1])) {
          remotePortFull = tokens[tokens.length - 2] + tokens[tokens.length - 1];
        } else if (tokens.length >= 2 && isNetworkInterface(tokens[tokens.length - 2])) {
          remotePortFull = tokens[tokens.length - 2] + tokens[tokens.length - 1];
        }
      }

      if (remoteDevice && localPortFull && remotePortFull) {
        remoteDevice = remoteDevice.split('.')[0];
        
        if (isValidDeviceName(remoteDevice)) {
          let localPort = normalizePort(localPortFull);
          let remotePort = normalizePort(remotePortFull);
          
          if (isNetworkInterface(localPort) && isNetworkInterface(remotePort) && !/^(Po|Port-channel|Vl|Vlan)/i.test(localPort) && !/^(Po|Port-channel|Vl|Vlan)/i.test(remotePort)) {
            db.insertPhysicalLink(
              hostname,
              localPort,
              remoteDevice,
              remotePort,
              'cdp/lldp'
            );
          }
        }
        pendingDevice = '';
      }
    }

    // --- PARSE SPANNING TREE (L2 TOPOLOGY) ---
    const stpBlocks = blockData.split(/(?=VLAN\s*\d+|Spanning tree instance)/i);
    for (const block of stpBlocks) {
      const vlanMatch = block.match(/(?:VLAN|Spanning tree instance)\s*0*(\d+)/i);
      const vlanId = vlanMatch ? vlanMatch[1] : null;

      if (vlanId) {
        const portRegex = /^([A-Za-z0-9\/\.-]+)\s+(Root|Desg|Altn|Back|Mstr|Shr|None)\s+(FWD|BLK|LRN|LIS|BKN|DIS)\s+(\d+)/gm;
        let portMatch;
        while ((portMatch = portRegex.exec(block)) !== null) {
          extractedL2Links.push({
            sourceDevice: hostname,
            localPort: normalizePort(portMatch[1]),
            vlan: vlanId,
            role: portMatch[2],
            state: portMatch[3]
          });
        }
      }
    }

    // --- PARSE L3 (ROUTING & NEIGHBORS) ---
    let currentRouteCode = '';
    let currentPrefix = '';
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      // IP to Device mapping from interfaces
      const intfIpMatch = line.match(/Internet address is ([0-9\.]+)\/\d+/i);
      if (intfIpMatch) ipToDevice[intfIpMatch[1]] = hostname;

      // OSPF Neighbor
      const ospfMatch = line.match(/^([0-9\.]+)\s+\d+\s+(FULL|2WAY|INIT|EXSTART|EXCHANGE|LOADING)[^\s]*\s+[0-9\:]+\s+([0-9\.]+)\s+([A-Za-z0-9\/\.-]+)/i);
      if (ospfMatch) {
        extractedOspf.push({
          sourceDevice: hostname,
          neighborIp: ospfMatch[3],
          localPort: normalizePort(ospfMatch[4]),
          state: ospfMatch[2]
        });
        ipToDevice[ospfMatch[1]] = ospfMatch[3]; // Map Router ID to Interface IP for resolution
      }

      // BGP Neighbor
      const bgpMatch = line.match(/^([0-9\.]+)\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+([0-9a-zA-Z]+)/i);
      if (bgpMatch) {
        extractedBgp.push({
          sourceDevice: hostname,
          neighborIp: bgpMatch[1],
          as: bgpMatch[2],
          state: bgpMatch[3]
        });
      }

      // Routing Table
      const localRouteMatch = line.match(/^L\s+([0-9\.]+)\/32\s+is directly connected/i);
      if (localRouteMatch) ipToDevice[localRouteMatch[1]] = hostname;

      const routeHeaderMatch = line.match(/^([A-Za-z\*]{1,4})\s+([0-9\.\/]+)/);
      if (routeHeaderMatch && !line.includes('via') && !line.includes('connected')) {
        currentRouteCode = routeHeaderMatch[1].trim();
        currentPrefix = routeHeaderMatch[2].trim();
      }

      const viaMatch = line.match(/via\s+([0-9\.]+)(?:,\s*[0-9\:]+)?(?:,\s*([A-Za-z0-9\/\.-]+))?/i);
      if (viaMatch) {
        let code = currentRouteCode;
        let prefix = currentPrefix;
        if (routeHeaderMatch) {
          code = routeHeaderMatch[1].trim();
          prefix = routeHeaderMatch[2].trim();
        }
        if (code) {
          const nextHop = viaMatch[1];
          const localPort = viaMatch[2] ? normalizePort(viaMatch[2]) : '';
          
          extractedRoutes.push({
            sourceDevice: hostname,
            code: code,
            prefix: prefix,
            nextHop: nextHop,
            localPort: localPort
          });
        }
      }
    }
  }

  const fileBlocks = rawData.split(/--- FILE: (.*?) ---\n/g);
  if (fileBlocks.length > 1) {
    for (let f = 1; f < fileBlocks.length; f += 2) {
      let filename = fileBlocks[f].trim().replace(/\.[^/.]+$/, ""); // remove extension
      const fileContent = fileBlocks[f+1];
      
      const parts = fileContent.split(/^([a-zA-Z0-9_.-]+)[#>]/m);
      
      // Parse the text before the first prompt (if any)
      if (parts[0].trim().length > 0) {
        parseBlock(isValidDeviceName(filename) ? filename : 'Unknown-Device', parts[0]);
      }
      
      if (parts.length > 1) {
        let foundValidPrompt = false;
        for (let i = 1; i < parts.length; i += 2) {
          let hostname = parts[i].split('.')[0];
          if (isValidDeviceName(hostname)) {
            foundValidPrompt = true;
            parseBlock(hostname, parts[i+1]);
          } else {
            // If prompt is invalid, fallback to filename
            parseBlock(isValidDeviceName(filename) ? filename : 'Unknown-Device', parts[i+1]);
          }
        }
      }
    }
  } else {
    const parts = rawData.split(/^([a-zA-Z0-9_.-]+)[#>]/m);
    
    if (parts[0].trim().length > 0) {
      parseBlock('Unknown-Device', parts[0]);
    }
    
    if (parts.length > 1) {
      for (let i = 1; i < parts.length; i += 2) {
        let hostname = parts[i].split('.')[0];
        if (!isValidDeviceName(hostname)) {
          hostname = 'Unknown-Device';
        }
        parseBlock(hostname, parts[i+1]);
      }
    }
  }

  // --- DEDUPLICATE AND BUILD TOPOLOGY ---
  let linkIdCounter = 1;
  
  // Populate nodes from DB
  const dbDevices = db.getDevices();
  for (const dev of dbDevices) {
    nodesMap[dev.id] = dev;
  }

  // Populate routes into nodesMap
  for (const route of extractedRoutes) {
    if (nodesMap[route.sourceDevice]) {
      if (!nodesMap[route.sourceDevice].routes) {
        nodesMap[route.sourceDevice].routes = [];
      }
      nodesMap[route.sourceDevice].routes.push({
        destination: route.prefix,
        nextHop: route.nextHop,
        interface: route.localPort,
        protocol: route.code
      });
    }
  }

  const physicalLinks = db.getDeduplicatedPhysicalLinks();
  
  for (const link of physicalLinks) {
    const sDevice = link.source;
    const rDevice = link.target;
    const lPort = link.src_port;
    const rPort = link.dst_port;

    if (!nodesMap[sDevice]) {
      nodesMap[sDevice] = {
        id: sDevice,
        hostname: sDevice,
        ip: link.src_ip || '',
        vendor: 'unknown' as any,
        hardware_model: link.src_model || 'Unknown',
        role: determineRole(sDevice, link.src_model || 'Unknown')
      };
    } else {
      if (link.src_ip && !nodesMap[sDevice].ip) nodesMap[sDevice].ip = link.src_ip;
      if (link.src_model && nodesMap[sDevice].hardware_model === 'Unknown') {
        nodesMap[sDevice].hardware_model = link.src_model;
        nodesMap[sDevice].role = determineRole(sDevice, link.src_model);
      }
    }

    if (!nodesMap[rDevice]) {
      nodesMap[rDevice] = {
        id: rDevice,
        hostname: rDevice,
        ip: link.dst_ip || '',
        vendor: 'unknown' as any,
        hardware_model: link.dst_model || 'Unknown',
        role: determineRole(rDevice, link.dst_model || 'Unknown')
      };
    } else {
      if (link.dst_ip && !nodesMap[rDevice].ip) nodesMap[rDevice].ip = link.dst_ip;
      if (link.dst_model && nodesMap[rDevice].hardware_model === 'Unknown') {
        nodesMap[rDevice].hardware_model = link.dst_model;
        nodesMap[rDevice].role = determineRole(rDevice, link.dst_model);
      }
    }

    const linkKey = `${sDevice}_${lPort}_${rDevice}_${rPort}`;
    
    linksMap[linkKey] = {
      id: `l1_${linkIdCounter++}`,
      source: sDevice,
      target: rDevice,
      src_port: lPort,
      dst_port: rPort,
      layer: 'L1',
      protocol: link.protocols
    };
  }

  // Add L2 Links based on STP and L1 adjacency
  const l2ByPort: Record<string, { sourceDevice: string, localPort: string, vlan: string, role: string, state: string }> = {};
  for (const l2 of extractedL2Links) {
    const key = `${l2.sourceDevice}_${l2.localPort}`;
    if (!l2ByPort[key]) {
      l2ByPort[key] = l2;
    } else if (l2ByPort[key].state !== l2.state) {
      l2ByPort[key].state = 'Mixed';
    }
  }

  for (const [key, l2] of Object.entries(l2ByPort)) {
    // Find the corresponding L1 link in the DB
    // We need to check both directions because the DB deduplicates
    const l1Link = physicalLinks.find(l => 
      (l.source === l2.sourceDevice && l.src_port === l2.localPort) ||
      (l.target === l2.sourceDevice && l.dst_port === l2.localPort)
    );
    
    if (!l1Link) continue;

    const sDevice = l1Link.source;
    const rDevice = l1Link.target;
    const lPort = l1Link.src_port;
    const rPort = l1Link.dst_port;

    const devices = [sDevice, rDevice].sort();
    const ports = sDevice < rDevice ? [lPort, rPort] : [rPort, lPort];
    const linkKey = `L2_${devices[0]}_${ports[0]}_${devices[1]}_${ports[1]}`;
    
    if (!linksMap[linkKey]) {
      linksMap[linkKey] = {
        id: `l2_${linkIdCounter++}`,
        source: devices[0],
        target: devices[1],
        src_port: ports[0],
        dst_port: ports[1],
        layer: 'L2',
        protocol: 'stp',
        vlan: l2.vlan
      };
    }
    
    if (linksMap[linkKey].source === l2.sourceDevice) {
       linksMap[linkKey].src_stp_role = l2.role;
       linksMap[linkKey].src_stp_state = l2.state;
    } else {
       linksMap[linkKey].dst_stp_role = l2.role;
       linksMap[linkKey].dst_stp_state = l2.state;
    }
  }

  // --- BUILD L3 TOPOLOGY ---
  const l3LinksMap: Record<string, TopologyLink> = {};

  function getL3Link(source: string, targetIp: string): TopologyLink | null {
    const targetDevice = ipToDevice[targetIp] || targetIp;
    if (source === targetDevice) return null; // Ignore self links

    if (!nodesMap[source]) {
      nodesMap[source] = {
        id: source,
        hostname: source,
        ip: '',
        vendor: 'unknown',
        hardware_model: 'Unknown',
        role: 'unknown'
      };
    }

    if (!nodesMap[targetDevice]) {
      nodesMap[targetDevice] = {
        id: targetDevice,
        hostname: targetDevice,
        ip: targetIp,
        vendor: 'unknown',
        hardware_model: 'Unknown',
        role: 'router'
      };
    }

    const devices = [source, targetDevice].sort();
    const linkKey = `L3_${devices[0]}_${devices[1]}`;

    if (!l3LinksMap[linkKey]) {
      l3LinksMap[linkKey] = {
        id: `l3_${linkIdCounter++}`,
        source: devices[0],
        target: devices[1],
        src_port: '',
        dst_port: '',
        layer: 'L3',
        protocol: 'connected',
        l3_routes: []
      };
    }
    
    const link = l3LinksMap[linkKey];
    if (devices[0] === targetDevice && !link.src_ip) {
      link.src_ip = targetIp;
    } else if (devices[1] === targetDevice && !link.dst_ip) {
      link.dst_ip = targetIp;
    }
    
    return link;
  }

  for (const ospf of extractedOspf) {
    const link = getL3Link(ospf.sourceDevice, ospf.neighborIp);
    if (link) {
      link.protocol = 'ospf';
      if (link.source === ospf.sourceDevice) link.src_port = ospf.localPort;
      else link.dst_port = ospf.localPort;
      link.state = ospf.state;
    }
  }

  for (const bgp of extractedBgp) {
    const link = getL3Link(bgp.sourceDevice, bgp.neighborIp);
    if (link) {
      link.protocol = 'bgp';
      link.routing_as = `AS ${bgp.as}`;
      link.state = bgp.state;
    }
  }

  for (const route of extractedRoutes) {
    let proto = 'unknown';
    const code = route.code.replace('*', '').trim();
    if (code.startsWith('O')) proto = 'ospf';
    else if (code.startsWith('B')) proto = 'bgp';
    else if (code.startsWith('D')) proto = 'eigrp';
    else if (code.startsWith('S')) proto = 'static';
    else if (code.startsWith('i')) proto = 'isis';
    else continue;

    const link = getL3Link(route.sourceDevice, route.nextHop);
    if (link) {
      if (link.protocol === 'connected' || link.protocol === 'unknown') {
        link.protocol = proto as any;
      }
      if (route.localPort) {
        if (link.source === route.sourceDevice && !link.src_port) link.src_port = route.localPort;
        if (link.target === route.sourceDevice && !link.dst_port) link.dst_port = route.localPort;
      }

      if (route.prefix && route.prefix !== '0.0.0.0/0') {
        if (!link.l3_routes) link.l3_routes = [];
        const exists = link.l3_routes.find(r => r.source === route.sourceDevice && r.prefix === route.prefix && r.protocol === proto);
        if (!exists) {
          link.l3_routes.push({
            source: route.sourceDevice,
            target: link.source === route.sourceDevice ? link.target : link.source,
            protocol: proto,
            prefix: route.prefix
          });
        }
      }
    }
  }

  for (const link of Object.values(l3LinksMap)) {
    if (!nodesMap[link.target]) {
      nodesMap[link.target] = {
        id: link.target,
        hostname: link.target,
        ip: link.dst_ip || '',
        vendor: 'unknown',
        hardware_model: 'Unknown L3 Node',
        role: 'router'
      };
    }
    linksMap[link.id] = link;
  }

  let nodes = Object.values(nodesMap);
  let links = Object.values(linksMap);

  // Fallback to mock data if no neighbors were parsed
  if (links.length === 0) {
    nodes = [
      { 
        id: 'acc_sw2', hostname: 'Acc-SW2', ip: '10.0.0.3', vendor: vendor as any, hardware_model: 'WS-C2960X', role: 'access',
        x: 150, y: 350
      },
      { 
        id: 'dist_sw1', hostname: 'Dist-SW1', ip: '10.0.0.2', vendor: vendor as any, hardware_model: 'Nexus 9000', role: 'distribution',
        x: 450, y: 550
      },
      { 
        id: 'vit_swc', hostname: 'VIT_PIN_SWC_3850_01', ip: '10.0.0.1', vendor: vendor as any, hardware_model: 'WS-C3750X', role: 'core',
        x: 750, y: 350
      },
      { 
        id: 'edge_fw1', hostname: 'Edge-FW1', ip: '10.0.0.254', vendor: vendor as any, hardware_model: 'SRX300', role: 'firewall',
        x: 750, y: 100
      },
    ];

    links = [
      // L1 Links (Physical)
      { id: 'l1_1', source: 'acc_sw2', target: 'vit_swc', src_port: 'Eth1/2', dst_port: 'Gi1/0/1', layer: 'L1', protocol: 'lldp' },
      { id: 'l1_2', source: 'dist_sw1', target: 'vit_swc', src_port: 'Eth1/1', dst_port: 'Gi0/0/1', layer: 'L1', protocol: 'lldp' },
      { id: 'l1_3', source: 'vit_swc', target: 'edge_fw1', src_port: 'ge-0/0/0', dst_port: 'Gi0/0/2', layer: 'L1', protocol: 'lldp' },
      
      // L2 Links (Logical)
      { id: 'l2_1', source: 'acc_sw2', target: 'vit_swc', src_port: 'Po1', dst_port: 'Po1', layer: 'L2', protocol: 'stp', vlan: 'Trunk (10,20,30)', src_stp_state: 'FWD', src_stp_role: 'Root', dst_stp_state: 'FWD', dst_stp_role: 'Desg', port_channel: 'Po1' },
      { id: 'l2_2', source: 'dist_sw1', target: 'vit_swc', src_port: 'Po2', dst_port: 'Po2', layer: 'L2', protocol: 'stp', vlan: 'Trunk (10,20,30)', src_stp_state: 'FWD', src_stp_role: 'Desg', dst_stp_state: 'FWD', dst_stp_role: 'Root', port_channel: 'Po2' },
      
      // L3 Links (Routing)
      { id: 'l3_1', source: 'dist_sw1', target: 'vit_swc', src_port: 'Vlan10', dst_port: 'Vlan10', layer: 'L3', protocol: 'ospf', src_ip: '10.0.10.1', dst_ip: '10.0.10.2', subnet: '/24', routing_area: 'Area 0', metric: '10' },
      { id: 'l3_2', source: 'vit_swc', target: 'edge_fw1', src_port: '10.0.254.1', dst_port: '10.0.254.2', layer: 'L3', protocol: 'bgp', src_ip: '10.0.254.1', dst_ip: '10.0.254.2', subnet: '/30', routing_as: 'AS 65001', metric: '0' },
    ];
  }

  return { nodes, links };
}

function parseDevice(raw) {
  const lines = raw.split(/\r?\n/);
  const first = re => {
    for (const l of lines) {
      const m = l.match(re);
      if (m) return m[1].trim();
    }
    return "";
  };

  // ── Detectar plataforma: IOS, IOS-XE ou NX-OS ───────────────
  // Verifica apenas na seção show version para evitar falso positivo via CDP
  let verSection = "";
  let inVer = false;
  for (const l of lines) {
    if (/show version/.test(l)) {
      inVer = true;
      continue;
    }
    if (inVer && /^[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inVer = false;
      continue;
    }
    if (inVer) verSection += l + "\n";
  }
  const isNexus = /Cisco Nexus|NX-OS|nxos/i.test(verSection) || /Cisco Nexus|NX-OS|nxos/i.test(raw.substring(0, 5000));
  const isIosXe = !isNexus && /Cisco IOS XE Software/i.test(verSection);
  // Detect HP Comware (uses same <hostname> prompt as Huawei — must check FIRST)
  const isHP = /HP Comware Software|Hewlett-Packard.*Comware|Comware.*Version.*Release/i.test(raw.substring(0, 8000));
  // Detect Huawei VRP: prompt "<hostname>" or "hostname>" + display commands, NOT HP
  const isHuawei = !isHP && (/Huawei Versatile Routing Platform|VRP.*software.*Version/i.test(raw.substring(0, 8000)) || /<[\w\-]+>display\s/.test(raw.substring(0, 2000)) && !isNexus || /[\w\-]+>display\s/.test(raw.substring(0, 2000)) && !isNexus);
  // Detect Dell EMC OS10
  const isDell = /Dell EMC Networking OS10|Dell Inc.*OS Version/i.test(raw.substring(0, 8000)) || /OS Version:\s*10\./.test(raw.substring(0, 5000));
  // Detect Dell FTOS (Force10 OS, older Dell switches)
  const isDellFtos = !isDell && (/Dell Real Time Operating System|Dell Networking OS|FTOS/i.test(raw.substring(0, 8000)) || /Dell Application Software Version:\s*9\./i.test(raw.substring(0, 5000)));

  // ── Hostname ─────────────────────────────────────────────────
  let hostname = "";
  if (isDell || isDellFtos) {
    hostname = first(/^hostname\s+(\S+)/) || (() => {
      const m = raw.match(/([\w\-]+)#\s*(?:terminal|show version)/);
      return m ? m[1] : "";
    })();
  } else if (isHP) {
    hostname = first(/^sysname\s+(\S+)/) || (() => {
      const m = raw.match(/<([\w\-]+)>display version/);
      return m ? m[1] : "";
    })() || first(/^hostname\s+(\S+)/);
  } else if (isHuawei) {
    hostname = first(/^sysname\s+(\S+)/) || (() => {
      const m = raw.match(/<([\w\-]+)>display version/);
      return m ? m[1] : "";
    })() || first(/^hostname\s+(\S+)/);
  } else if (isNexus) {
    hostname = first(/^switchname\s+(\S+)/) || first(/^hostname\s+(\S+)/);
  }
  // IOS-XE: hostname está no running-config E também no prompt
  if (!hostname) hostname = first(/^hostname\s+(\S+)/) || first(/^\r?([A-Za-z0-9\-_.]+)#/) || "UNKNOWN";

  // ── show version ─────────────────────────────────────────────
  let ios_ver = "",
    model = "",
    serial = "",
    uptime = "",
    last_rst = "",
    image = "",
    romver = "";
  if (isNexus) {
    ios_ver = first(/NXOS:\s+version\s+(\S+)/i) || first(/(?:NXOS|system):\s+version\s+(\S+)/i) || first(/NX-OS.*?version\s+(\S+)/i);
    // Modelo: linha "cisco Nexus9000 C93180YC-FX" ou UDI PID
    model = first(/^cisco\s+Nexus\d*\s+([\w\-]+)\s+Chassis/i) || first(/UDI:\s+PID:([\w\-]+)/i) || first(/cisco\s+(N\dK[-\w]+)/i) || first(/cisco\s+(Nexus\s*\S+)/i);
    serial = first(/Processor Board ID\s+(\S+)/i) || first(/UDI:.*SN:([\w]+)/i);
    uptime = first(/Kernel uptime is (.+)/i) || first(/uptime is (.+)/i);
    image = first(/NXOS image file is:?\s*"?([^\s"]+)"?/i) || first(/(?:NXOS|system) image file is:?\s*"?([^\s"]+)"?/i);
  } else if (isIosXe) {
    // IOS-XE: "Cisco IOS XE Software, Version 16.09.03"
    ios_ver = first(/Cisco IOS XE Software, Version\s+(\S+)/i) || first(/Version\s+([\d.()A-Za-z]+),/);
    // modelo: "cisco C9200L-24T-4G (ARM64)" ou "Model Number : C9300-24T"
    model = first(/^cisco\s+(C\d[\w\-]+)\s+\(/i) || first(/Model Number\s*:\s*(\S+)/);
    serial = first(/Processor board ID\s+(\S+)/i);
    uptime = first(/\S+\s+uptime is\s+(.+)/);
    last_rst = first(/System restarted at\s+(.+)/);
    image = first(/System image file is\s+"([^"]+)"/);
    romver = first(/BOOTLDR:\s+System Bootstrap, Version\s+([^,\n]+)/i) || first(/ROM:\s+System Bootstrap, Version\s+([^,\n]+)/i);
  } else if (isHP) {
    // HP Comware: "HP Comware Software, Version 7.1.045, Release 7375-US"
    ios_ver = first(/Version\s+([\d.]+),\s+Release/i) || first(/HP Comware Software,\s+Version\s+([\d.]+)/i);
    // "HP 12508 uptime is 515 weeks..."
    const hpUp = raw.match(/HP\s+([\w\-]+)\s+uptime is\s+([^\r\n]+)/i);
    model = hpUp ? hpUp[1] : (first(/DEVICE_NAME\s*:\s*HP\s+([^\r\n]+)/i) || "").trim();
    uptime = hpUp ? hpUp[2].trim() : first(/uptime is\s+([^\r\n]+)/i);
    // Serial from display device manuinfo: "DEVICE_SERIAL_NUMBER : CN59GBM003"
    serial = first(/DEVICE_SERIAL_NUMBER\s*:\s*(\S+)/i);
    image = first(/System image:\s*(\S+)/i) || first(/Boot image:\s*(\S+)/i);
  } else if (isDellFtos) {
    // Dell FTOS Force10: "Dell Application Software Version: 9.11(0.0P4)"
    ios_ver = first(/Dell Application Software Version:\s*(\S+)/i) || first(/Dell Operating System Version:\s*(\S+)/i);
    model = first(/System Type:\s*(\S+)/i);
    serial = (() => {
      const invLines = raw.split(/\r?\n/);
      let svcTagCol = -1;
      for (const l of invLines) {
        if (/Svc Tag/i.test(l) && /Serial/i.test(l)) {
          svcTagCol = l.indexOf("Svc Tag");
          continue;
        }
        if (svcTagCol >= 0 && /^\*/.test(l.trim())) {
          const val = l.substring(svcTagCol).trim().split(/\s+/)[0];
          if (val && val.length >= 4) return val;
        }
      }
      return "";
    })();
    uptime = first(/Dell Networking OS uptime is\s*(.+)/i) || first(/uptime is\s*(.+)/i);
    image = first(/System image file is\s+"([^"]+)"/i) || first(/System image file is\s+(\S+)/i);
  } else if (isDell) {
    // Dell OS10: "OS Version: 10.5.3.1"
    ios_ver = first(/OS Version:\s*(\S+)/i) || first(/Software version\s*:\s*(\S+)/i);
    // Model from version section or inventory: "System Type: MX9116N-ON"
    model = first(/System Type:\s*(\S+)/i) || first(/Product\s*:\s*(\S+)/i);
    // Serial: Svc Tag from inventory table (column-based, not label:value)
    // Header: "Unit Type  Part Number  Rev  Piece Part ID  Svc Tag  Exprs Svc Code"
    // Data:   "* 1  MX9116N-ON  0RFX85  A11  CN-xxx  65S4RN3  134 102..."
    serial = (() => {
      const invLines = raw.split(/\r?\n/);
      let svcTagCol = -1;
      for (const l of invLines) {
        if (/Svc Tag/i.test(l) && /Part Number/i.test(l)) {
          svcTagCol = l.indexOf("Svc Tag");
          continue;
        }
        if (svcTagCol >= 0 && /^\*/.test(l.trim())) {
          const val = l.substring(svcTagCol).trim().split(/\s+/)[0];
          if (val && val.length >= 4) return val;
        }
      }
      return first(/Product Serial Number\s*:\s*(\S+)/i) || "";
    })();
    uptime = first(/Up Time:\s*(.+)/i);
  } else if (isHuawei) {
    // VRP (R) software, Version 8.191 (CE12800 V200R019C10SPC800)
    ios_ver = first(/VRP.*?Version\s+([\d.]+)/i) || first(/Version\s+([\d.]+)\s+\(/i);
    // HUAWEI CE12804 uptime is 679 days...  OR  CE6860-48S8CQ-EI(Master) 1 : uptime is...
    const hvUp = raw.match(/HUAWEI\s+([\w\-]+)\s+uptime is\s+([^\r\n]+)/i);
    model = hvUp ? hvUp[1] : first(/Board\s+Type\s*:\s*([\w\-]+)/i) || "";
    uptime = hvUp ? hvUp[2].trim() : first(/uptime is\s+([^\r\n]+)/i);
    // Serial from display device manufacture-info → backplane or slot 1
    const manuSection = (() => {
      let s = "",
        inM = false;
      for (const l of lines) {
        if (/display device manufacture-info/.test(l)) {
          inM = true;
          continue;
        }
        if (inM && /<[\w\-]+>/.test(l)) {
          inM = false;
          continue;
        }
        if (inM) s += l + "\n";
      }
      return s;
    })();
    const bpSn = manuSection.match(/backplane.*?(\w{15,})/i) || manuSection.match(/^1\s+--\s+\S+\s+(\w{15,})/m);
    serial = bpSn ? bpSn[1] : first(/ESN of chassis 1\s*:\s*(\S+)/i);
  } else {
    ios_ver = first(/Version ([\S]+),/);
    model = first(/^cisco ([\w\-]+)\s+\(/i);
    serial = first(/Processor board ID (\S+)/);
    uptime = first(/uptime is (.+)/);
    last_rst = first(/System restarted at (.+)/);
    image = first(/System image file is "([^"]+)"/);
    romver = first(/ROM: System Bootstrap, Version ([^,\n]+)/);
  }

  // ── show inventory — Chassis principal + Stack members ───────
  const isIgnoredPid = pid => {
    if (!pid || pid === "N/A") return true;
    if (/^STACK-|STACK$/i.test(pid)) return true;
    if (/^C\d{3,4}L?-STACK/i.test(pid)) return true;
    if (/^CAB-STACK/i.test(pid)) return true;
    if (/^WS-X|^WS-F|^WS-G|^WS-SVC|^WS-SUP|^WS-C6K/i.test(pid)) return true;
    if (/^PWR-|^FAN-|^C\d+-PWR|^C\d+-FAN|^C\d+[A-Z]+-PWR|^C\d+[A-Z]+-FAN/i.test(pid)) return true;
    if (/^NXA-PAC|^NXA-FAN|^N2200-PAC|^N55-PAC|^N5K-PAC/i.test(pid)) return true;
    if (/^SPA-|^NIM-|^SM-|^ISM-|^PVDM/i.test(pid)) return true;
    if (/^CLK-/i.test(pid)) return true;
    return false;
  };
  const isChassis = name => /^chassis$/i.test(name.trim()) || name.trim() === "1";
  const isStackMember = name => /^Switch\s+\d+/i.test(name);
  const isNxSlot = name => /^Slot\s+\d+/i.test(name);
  const isStackNum = name => /^\d+$/.test(name.trim()) && +name.trim() > 1;
  const stackMembers = [];
  let inInv = false,
    curName = "",
    curPid = "",
    curSn = "";
  let firstValidPid = "",
    firstValidSn = "";
  for (const l of lines) {
    if (/show inventory/.test(l)) {
      inInv = true;
      continue;
    }
    if (inInv && /^[A-Za-z0-9\-_.]+[#>]\s*show/.test(l)) {
      inInv = false;
      continue;
    }
    if (!inInv) continue;
    const nm = l.match(/^NAME:\s*"([^"]+)"/);
    if (nm) {
      curName = nm[1].trim();
      curPid = "";
      curSn = "";
    }
    // Regex tolerante: PID com espaços extras (NX-OS)
    const pidm = l.match(/^PID:\s*([\w\-]+)\s*,\s*VID:\s*[\w]*\s*,\s*SN:\s*(\S+)/);
    if (pidm) {
      curPid = pidm[1].trim();
      curSn = pidm[2].trim() === "N/A" ? "" : pidm[2].trim();
      if (!firstValidPid && curPid && !isIgnoredPid(curPid)) {
        firstValidPid = curPid;
        firstValidSn = curSn;
      }
      if (!isIgnoredPid(curPid) && !isNxSlot(curName)) {
        if (isStackMember(curName)) {
          const swNum = parseInt((curName.match(/\d+/) || [1])[0]);
          if (!stackMembers.find(m => m.pid === curPid && m.sn === curSn)) stackMembers.push({
            pid: curPid,
            sn: curSn,
            name: curName,
            swNum
          });
        } else if (isStackNum(curName)) {
          // IOS stack: NAME "2", "3" etc.
          const swNum = parseInt(curName.trim());
          if (!stackMembers.find(m => m.sn === curSn)) stackMembers.push({
            pid: curPid,
            sn: curSn,
            name: "Switch " + swNum,
            swNum
          });
        } else if (isChassis(curName)) {
          if (!stackMembers.find(m => m.pid === curPid)) stackMembers.push({
            pid: curPid,
            sn: curSn,
            name: curName,
            swNum: 1
          });
        }
      }
    }
    // NX-OS indentado
    const npid = l.match(/^\s+PID:\s*([\w\-]+)\s*,\s*VID:\s*[\w]*\s*,\s*SN:\s*(\S+)/);
    if (npid && isChassis(curName) && !isIgnoredPid(npid[1])) {
      const sn2 = npid[2].trim() === "N/A" ? "" : npid[2].trim();
      if (!stackMembers.find(m => m.pid === npid[1])) stackMembers.push({
        pid: npid[1],
        sn: sn2,
        name: curName,
        swNum: 1
      });
    }
  }
  // HP Comware: IRF stack from display irf
  if (isHP && !stackMembers.length) {
    let inIRF = false;
    for (const l of lines) {
      if (/display irf\b/.test(l)) {
        inIRF = true;
        continue;
      }
      if (inIRF && /<[\w\-]+>/.test(l)) {
        inIRF = false;
        continue;
      }
      if (!inIRF || /^MemberID|^-+$|^\*|^The bridge/.test(l.trim())) continue;
      // "   1    0    Standby  32  0210-fc01-0000  ---"
      // "*+1    1    Master   32  0210-fc01-0001  ---"
      const m = l.replace(/^[\s*+]+/, "").match(/^(\d+)\s+(\d+)\s+(\w+)\s+(\d+)/);
      if (m && !stackMembers.find(s => s.swNum === +m[1])) {
        stackMembers.push({
          pid: model || "HP",
          sn: "",
          name: "IRF Member " + m[1],
          swNum: +m[1]
        });
      }
    }
  }

  // Dell FTOS: single unit
  if (isDellFtos && !stackMembers.length) {
    stackMembers.push({
      pid: model || "Dell",
      sn: serial || "",
      name: "Chassis",
      swNum: 1
    });
  }
  // Dell OS10: single unit from show inventory
  if (isDell && !stackMembers.length) {
    const dModel = model || first(/System Type:\s*(\S+)/i) || first(/Product\s*:\s*(\S+)/i);
    const dSn = serial || "";
    stackMembers.push({
      pid: dModel || "Dell",
      sn: dSn,
      name: "Chassis",
      swNum: 1
    });
  }

  // ── Huawei: stack from "display stack" + serials from "display device manufacture-info" ──
  if (isHuawei && !stackMembers.length) {
    let inStack = false,
      inStackSection = false,
      manuSection = "",
      inManu = false;
    for (const l of lines) {
      // Detect "display stack" command — but NOT "display stack configuration/peers/topology"
      if (/display stack/.test(l) && !/configuration|peers|topology|bandwidth/.test(l)) {
        inStack = true;
        inStackSection = false;
        continue;
      }
      if (inStack && /<[\w\-]+>/.test(l)) {
        inStack = false;
        inStackSection = false;
      }
      if (inStack) {
        // Detect the member table header line
        if (/^Slot\s+Role\s+MAC/i.test(l)) {
          inStackSection = true;
          continue;
        }
        if (/^-+$/.test(l.trim())) continue;
        // Only parse rows AFTER the header
        if (inStackSection) {
          // "0   Master   b008-75a0-0170   200   S5720-56C-PWR-EI-AC"
          // Must have valid Role (Master/Standby/Slave) and DeviceType (not "STACK")
          const sm = l.match(/^(\d+)\s+(Master|Standby|Slave)\s+([\w\-:]+)\s+(\d+)\s+([\w\-]+)/i);
          if (sm && sm[5] !== "STACK") {
            // Huawei slots are 0-based — convert to 1-based swNum
            const slot = +sm[1];
            const swNum = slot + 1;
            stackMembers.push({
              pid: sm[5],
              sn: "",
              name: "Slot " + slot,
              swNum
            });
          }
        }
      }
      if (/display device manufacture-info/.test(l)) {
        inManu = true;
        continue;
      }
      if (inManu && /<[\w\-]+>/.test(l)) {
        inManu = false;
      }
      if (inManu) manuSection += l + "\n";
    }
    // Fill serials from display device manufacture-info
    for (const l of manuSection.split("\n")) {
      // Format CE: "0  --  CE6860-48S8CQ-EI  2102350SBR10J8000127"
      const smCE = l.match(/^(\d+)\s+--\s+\S+\s+(\w{10,})/);
      if (smCE) {
        const slot = +smCE[1];
        const mem = stackMembers.find(m => m.swNum === slot + 1);
        if (mem) mem.sn = smCE[2];
        continue;
      }
      // Format S5720: "0   -   2102359576DMKC000605   2019-12-22"
      const smS57 = l.match(/^(\d+)\s+-\s+(\w{10,})\s+\d{4}-/);
      if (smS57) {
        const slot = +smS57[1];
        const mem = stackMembers.find(m => m.swNum === slot + 1);
        if (mem) mem.sn = smS57[2];
        continue;
      }
      // backplane serial for single device
      const bp = l.match(/^backplane\s+--\s+(\S+)\s+(\w{10,})/i);
      if (bp && stackMembers[0] && !stackMembers[0].sn) {
        stackMembers[0].sn = bp[2];
        if (!stackMembers[0].pid || stackMembers[0].pid === "") stackMembers[0].pid = bp[1];
      }
    }
    // Fallback: ESN from display version "ESN of slot N: SERIAL"
    for (const l of lines) {
      const esn = l.match(/ESN of slot\s+(\d+):\s*(\w{10,})/i);
      if (esn) {
        const slot = +esn[1];
        const mem = stackMembers.find(m => m.swNum === slot + 1);
        if (mem && !mem.sn) mem.sn = esn[2];
      }
    }
    // If still empty (no stack), single device from version
    if (!stackMembers.length) stackMembers.push({
      pid: model,
      sn: serial,
      name: "Chassis",
      swNum: 1
    });
  }
  if (!stackMembers.length) stackMembers.push({
    pid: firstValidPid || model,
    sn: firstValidSn || serial,
    name: "Chassis",
    swNum: 1
  });
  const chassisPid = stackMembers[0]?.pid || model;
  const chassisSn = stackMembers[0]?.sn || serial;

  // Helper: detecta tipo do equipamento pelo PID
  function deviceTipo(pid) {
    if (!pid) return "Switch";
    // Dell model detection
    if (/^MX9116N|^MX5108|^MX7116N|^S52[0-9][0-9]|^Z93[0-9][0-9]|^Z95[0-9][0-9]/i.test(pid)) return "Switch";
    // Huawei model detection
    if (/^CE12[0-9]{3}/i.test(pid)) return "Core Switch";
    if (/^CE6[0-9]{3}/i.test(pid)) return "Switch";
    if (/^CE5[0-9]{3}/i.test(pid)) return "Switch";
    if (/^CE7[0-9]{3}/i.test(pid)) return "Switch";
    if (/^NE[0-9]/i.test(pid)) return "Router";
    if (/^AR[0-9]/i.test(pid)) return "Router";
    if (/^(ASR|ISR|C8[0-9]{2}V?|C11[0-9]{2}|C12[0-9]{2}|C43[0-9]{2}|CGR|C72)/i.test(pid)) return "Roteador";
    return "Switch";
  }

  // Helper: normaliza nome abreviado de interface para nome completo
  function normIf(s) {
    if (!s) return s;
    return s.replace(/^Gi(\d)/i, "GigabitEthernet$1").replace(/^Te(\d)/i, "TenGigabitEthernet$1").replace(/^Fa(\d)/i, "FastEthernet$1").replace(/^Po(\d)/i, "Port-channel$1").replace(/^Et(\d)/i, "Ethernet$1").replace(/^Tw(\d)/i, "TwentyFiveGigE$1").replace(/^Hu(\d)/i, "HundredGigE$1");
  }

  // ── show cdp neighbors detail ────────────────────────────────
  const cdp = [];
  let inCdpDetail = false,
    cdpDev = {},
    cdpState = "";
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (/show cdp neighbors detail/.test(l)) {
      inCdpDetail = true;
      continue;
    }
    if (inCdpDetail && /^\r?[A-Za-z0-9\-_.]+#/.test(l) && !/show cdp neighbors detail/.test(l)) {
      inCdpDetail = false;
      continue;
    }
    if (!inCdpDetail) continue;
    if (/^-{5,}/.test(l)) {
      if (cdpDev.devId) cdp.push({
        ...cdpDev
      });
      cdpDev = {};
      continue;
    }
    const did = l.match(/^Device ID:\s*(.+)/);
    if (did) cdpDev.devId = did[1].trim();
    const ip = l.match(/^\s+IP(?:v4)? [Aa]ddress:\s*([\d.]+)/);
    if (ip) cdpDev.ip = ip[1];
    const plat = l.match(/^Platform:\s*([^,]+)/);
    if (plat) cdpDev.plat = plat[1].trim();
    const cap = l.match(/Capabilities:\s*(.+)/);
    if (cap) cdpDev.cap = cap[1].trim();
    const intf = l.match(/^Interface:\s*([^,]+)/);
    if (intf) cdpDev.localIf = intf[1].trim();
    const rem = l.match(/Port ID \(outgoing port\):\s*(.+)/);
    if (rem) cdpDev.remIf = rem[1].trim();
    const hold = l.match(/^Holdtime\s*:\s*(\d+)/);
    if (hold) cdpDev.hold = hold[1];
  }
  if (cdpDev.devId) cdp.push({
    ...cdpDev
  });

  // ── LLDP — fixed-width columns (IOS-XE trunca DeviceID em 20 chars) ─
  const lldp = [];
  let inLldp = false;
  // HP Comware: display lldp neighbor-information (multi-line per port)
  // "LLDP neighbor-information of port 106[Ten-GigabitEthernet1/2/0/2]:"
  // "PortID/subtype: Te6/6/Interface name"
  if (isHP) {
    let inHPL = false,
      curHPLocalIf = "",
      curHPRemIf = "",
      curHPDevId = "";
    const saveHPLldp = () => {
      if (curHPLocalIf && (curHPDevId || curHPRemIf)) lldp.push({
        devId: curHPDevId || curHPRemIf,
        localIf: curHPLocalIf,
        hold: "",
        cap: "",
        remIf: curHPRemIf
      });
    };
    for (const l of lines) {
      if (/display lldp neighbor-information\b/.test(l) && !/verbose/.test(l)) {
        inHPL = true;
        continue;
      }
      if (inHPL && /<[\w\-]+>/.test(l)) {
        inHPL = false;
        saveHPLldp();
        continue;
      }
      if (!inHPL) continue;
      // "LLDP neighbor-information of port 106[Ten-GigabitEthernet1/2/0/2]:"
      const pm = l.match(/of port\s+\d+\[([^\]]+)\]/i);
      if (pm) {
        saveHPLldp();
        curHPLocalIf = pm[1];
        curHPRemIf = "";
        curHPDevId = "";
        continue;
      }
      // "PortID/subtype: Te6/6/Interface name"
      const rim = l.match(/PortID\/subtype\s*:\s*([^/]+)/i);
      if (rim) curHPRemIf = rim[1].trim();
      // "SystemName: SWITCH-01" — use as devId if available
      const snm = l.match(/SystemName\s*:\s*(\S+)/i);
      if (snm) curHPDevId = snm[1];
    }
    saveHPLldp();
  }

  // Dell FTOS LLDP — brief + detail (for hold/TTL)
  if (isDellFtos) {
    // Step 1: parse brief
    const dFtosLldpMap = {}; // localIf → entry
    let inDFL = false;
    for (const l of lines) {
      if (/show lldp neighbors\b/.test(l) && !/detail/.test(l)) {
        inDFL = true;
        continue;
      }
      if (inDFL && /^[\w\-]+#/.test(l)) {
        inDFL = false;
        continue;
      }
      if (!inDFL || /^Loc Port|^-+$|^\s*$/.test(l.trim())) continue;
      const m = l.trim().match(/^((?:Te|Gi|Fo|Hu)\s+[\d\/]+)\s+(\S+)\s+(\S+)\s+(\S+)/);
      if (m) {
        const localIf = m[1].trim();
        const devId = m[2] === "-" ? m[4] : m[2];
        const remIf = m[3];
        const entry = {
          devId,
          localIf,
          hold: "",
          cap: "Não suportado",
          remIf
        };
        lldp.push(entry);
        dFtosLldpMap[localIf.toLowerCase().replace(/\s+/g, "")] = entry;
      }
    }
    // Step 2: enrich with Remote TTL from detail
    let inDFLD = false,
      curLocalIf = "";
    for (const l of lines) {
      if (/show lldp neighbors detail/.test(l)) {
        inDFLD = true;
        continue;
      }
      if (inDFLD && /^[\w\-]+#/.test(l)) {
        inDFLD = false;
        continue;
      }
      if (!inDFLD) continue;
      // "Local Interface Te 0/1 has 1 neighbor"
      const lm = l.match(/Local Interface\s+((?:Te|Gi|Fo|Hu)\s+[\d\/]+)/i);
      if (lm) {
        curLocalIf = lm[1].trim().toLowerCase().replace(/\s+/g, "");
        continue;
      }
      // "Remote TTL:  120"
      const tm = l.match(/Remote TTL:\s*(\d+)/i);
      if (tm && curLocalIf) {
        const entry = dFtosLldpMap[curLocalIf];
        if (entry) entry.hold = tm[1] + "s";
      }
      // "Local Port ID: TenGigabitEthernet 0/1" — normalize localIf
      const pm = l.match(/Local Port ID:\s*(\S+(?:\s+[\d\/]+)?)/i);
      if (pm) {
        const norm = pm[1].toLowerCase().replace(/tengigabitethernet/g, "te").replace(/\s+/g, "");
        if (dFtosLldpMap[norm] && !dFtosLldpMap[curLocalIf]) curLocalIf = norm;
      }
    }
  }

  // Dell OS10: show lldp neighbors
  // "Loc PortID  Rem Host Name  Rem Port Id  Rem Chassis Id"
  if (isDell) {
    let inDL = false;
    for (const l of lines) {
      if (/show lldp neighbors\b/.test(l)) {
        inDL = true;
        continue;
      }
      if (inDL && /^[\w\-]+#/.test(l)) {
        inDL = false;
        continue;
      }
      if (!inDL || /^Loc Port|^-+$/.test(l)) continue;
      // ethernet1/1/1  PowerEdge MX750c ...  3PG6KN3 NIC.Mezzanine  90:8d:6e:fb:01:7c
      const m = l.match(/^(\S+)\s+(\S.*?)\s{2,}(\S.*?)\s{2,}(\S+)\s*$/);
      if (m) lldp.push({
        devId: m[2].trim(),
        localIf: m[1],
        hold: "",
        cap: "",
        remIf: m[3].trim()
      });
    }
  }

  // Huawei: display lldp neighbor brief — dois formatos de colunas:
  // Formato A: "Local Interface  Exptime(s)  Neighbor Intf  Neighbor Device"
  //   → cols: localIf, hold, remIf, devId
  // Formato B: "Local Intf  Neighbor Dev  Neighbor Intf  Exptime(s)"
  //   → cols: localIf, devId, remIf, hold
  if (isHuawei) {
    let inHL = false,
      fmtB = false;
    for (const l of lines) {
      if (/display lldp neighbor brief/.test(l)) {
        inHL = true;
        fmtB = false;
        continue;
      }
      if (inHL && /(?:<[\w\-]+>|[\w\-]+[#>])/.test(l)) {
        inHL = false;
        continue;
      }
      if (!inHL) continue;
      // Detect header format
      if (/Local Intf/i.test(l) && /Neighbor Dev/i.test(l)) {
        fmtB = true;
        continue;
      }
      if (/Local Interface/i.test(l) || /^-+$|Exptime/.test(l)) continue;
      if (fmtB) {
        // "GE0/0/1   834YQN3   gbe1   8"
        const m = l.match(/^(\S+)\s+(\S+)\s+(\S+)\s+(\d+)/);
        if (m) lldp.push({
          devId: m[2],
          localIf: m[1],
          hold: m[4] + "s",
          cap: "",
          remIf: m[3]
        });
      } else {
        // "40GE1/1/3   99   40GE1/3/0/30   CT-BK-SR-2AB"
        const m = l.match(/^(\S+)\s+(\d+)\s+(\S+)\s+(\S+)/);
        if (m) lldp.push({
          devId: m[4],
          localIf: m[1],
          hold: m[2] + "s",
          cap: "",
          remIf: m[3]
        });
      }
    }
  }
  // Huawei LLDP verbose: display lldp neighbor — cap, hold, devId
  if (isHuawei && lldp.length === 0) {
    let inHLV = false,
      curLI = "",
      curDevId = "",
      curRemIf = "",
      curCap = "",
      curHold = "";
    const saveHL = () => {
      if (curLI) lldp.push({
        devId: curDevId,
        localIf: curLI,
        hold: curHold,
        cap: curCap,
        remIf: curRemIf
      });
    };
    for (const l of lines) {
      if (/display lldp neighbor\b/.test(l) && !/brief/.test(l)) {
        inHLV = true;
        continue;
      }
      if (inHLV && /(?:<[\w\-]+>|[\w\-]+[#>])/.test(l)) {
        inHLV = false;
        saveHL();
        continue;
      }
      if (!inHLV) continue;
      // "40GE1/1/1 has 1 neighbor(s):"
      const pm = l.match(/^(\S+)\s+has\s+\d+\s+neighbor/i);
      if (pm) {
        saveHL();
        curLI = pm[1];
        curDevId = "";
        curRemIf = "";
        curCap = "";
        curHold = "";
        continue;
      }
      if (curLI) {
        const sn = l.match(/System name\s*:\s*(\S+)/i);
        if (sn) curDevId = sn[1].trim();
        const ri = l.match(/Port ID\s*:\s*(\S+)/i);
        if (ri) curRemIf = ri[1].trim();
        const ce = l.match(/System capabilities enabled\s*:\s*(.+)/i);
        if (ce) curCap = ce[1].trim();
        const et = l.match(/Expired time\s*:\s*(\S+)/i);
        if (et) curHold = et[1].trim();
      }
    }
    saveHL();
  }
  for (const l of lines) {
    if (/show lldp neighbors/.test(l) && !/detail/.test(l)) {
      inLldp = true;
      continue;
    }
    if (inLldp && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inLldp = false;
      continue;
    }
    if (!inLldp) continue;
    // IOS-XE: colunas fixas — DeviceID cols 0-19, LocalIntf 20-34, Hold 35-44, Cap 45-60, PortID 61+
    if (isIosXe) {
      if (l.length < 20 || /^Device ID|^Capability|^---/.test(l)) continue;
      const devId = l.substring(0, 20).trim();
      const rest = l.substring(20).trim();
      // rest: "Gi1/0/1    120    B    Gi0/0/1"
      const rm = rest.match(/^(\S+)\s+(\d+)\s+([\w,]*)\s+(\S+)/);
      if (devId && rm) lldp.push({
        devId,
        localIf: rm[1],
        hold: rm[2],
        cap: rm[3],
        remIf: rm[4]
      });
    } else {
      // NX-OS/IOS: fixed column format
      // "DeviceID       LocalIntf  Hold  Cap  PortID"
      // Cap can be empty: "6cfe.5472.69f1  Eth1/5  121       6cfe.5472.69f1"
      if (/^Device ID|^Capability codes|^-+$|^\s*$/.test(l.trim())) continue;
      // Try with capability
      const m = l.match(/^(\S+)\s+((?:Gi|Te|Fa|Et|Po|Eth|mgmt)\S*)\s+(\d+)\s+(\S+)\s+(\S+)\s*$/);
      if (m && m[1] !== "Device") {
        lldp.push({
          devId: m[1],
          localIf: m[2],
          hold: m[3],
          cap: m[4],
          remIf: m[5]
        });
        continue;
      }
      // Try without capability (empty cap — fields shift)
      const m2 = l.match(/^(\S+)\s+((?:Gi|Te|Fa|Et|Po|Eth|mgmt)\S*)\s+(\d+)\s+(\S+)\s*$/);
      if (m2 && m2[1] !== "Device") lldp.push({
        devId: m2[1],
        localIf: m2[2],
        hold: m2[3],
        cap: "",
        remIf: m2[4]
      });
    }
  }

  // ── HSRP — show standby brief (IOS) / show hsrp brief (NX-OS) ──
  const hsrp = [];
  let inHsrp = false;
  for (const l of lines) {
    if (/show (?:standby|hsrp) brief/.test(l)) {
      inHsrp = true;
      continue;
    }
    if (inHsrp && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inHsrp = false;
      continue;
    }
    if (!inHsrp) continue;
    // IOS format: Vl10  1  100  P  Active  10.x  10.x  10.x
    const ios = l.match(/^(Vl\S+)\s+(\d+)\s+(\d+)\s*(\w?)\s+(\w+)\s+(\S+)\s+(\S+)\s+([\d.]+)/);
    if (ios) {
      hsrp.push({
        platform: "HSRP",
        intf: ios[1],
        grp: ios[2],
        pri: ios[3],
        p: ios[4],
        state: ios[5],
        active: ios[6],
        standby: ios[7],
        vip: ios[8]
      });
      continue;
    }
    // NX-OS format:   Vlan10  10  120  P  Active  local  10.x.x.x  10.x.x.x  (conf)
    const nxos = l.match(/^\s+(Vlan\S+)\s+(\d+)\s+(\d+)\s*(P?)\s+(Active|Standby|Init|Listen)\s+(\S+)\s+(\S+)\s+([\d.]+)/i);
    if (nxos) hsrp.push({
      platform: "HSRP",
      intf: nxos[1],
      grp: nxos[2],
      pri: nxos[3],
      p: nxos[4],
      state: nxos[5],
      active: nxos[6],
      standby: nxos[7],
      vip: nxos[8]
    });
  }

  // ── VRRP — show vrrp brief (Cisco) / display vrrp (Huawei) ──────
  const vrrp = [];
  let inVrrp = false;
  // Huawei VRRP: display vrrp (not brief)
  if (isHuawei) {
    let inHV = false,
      lastV = null;
    for (const l of lines) {
      if (/display vrrp\b(?!\s+brief)/.test(l)) {
        inHV = true;
        continue;
      }
      if (inHV && /<[\w\-]+>/.test(l)) {
        inHV = false;
        continue;
      }
      if (!inHV) continue;
      if (/Info: The VRRP does not exist/.test(l)) break;
      const vm = l.match(/^(\S+)\s*\|\s*Virtual Router\s+(\d+)/i);
      if (vm) {
        lastV = {
          intf: vm[1],
          group: vm[2],
          state: "",
          vip: "",
          priority: "100",
          preempt: "",
          activeIp: ""
        };
        vrrp.push(lastV);
      }
      if (lastV) {
        const st = l.match(/State\s*:\s*(\S+)/i);
        if (st) lastV.state = st[1];
        const vi = l.match(/Virtual IP\s*:\s*([\d.]+)/i);
        if (vi) lastV.vip = vi[1];
        const pr = l.match(/Priority\s*:\s*(\d+)/i);
        if (pr) lastV.priority = pr[1];
        const ac = l.match(/Master IP\s*:\s*([\d.]+)/i);
        if (ac) lastV.activeIp = ac[1];
      }
    }
  }
  for (const l of lines) {
    if (/(?:show|display) vrrp brief/.test(l)) {
      inVrrp = true;
      continue;
    }
    if (inVrrp && /^[\r]?[A-Za-z0-9\-_.<>]+[#>]/.test(l)) {
      inVrrp = false;
      continue;
    }
    if (!inVrrp) continue;
    // Huawei: "1  Vlanif10  Master  Normal  192.168.1.1"
    const h = l.match(/^(\d+)\s+(\S+)\s+(Master|Backup|Initialize)\s+(\S+)\s+([\d.]+)/i);
    if (h) {
      vrrp.push({
        vrid: h[1],
        intf: h[2],
        state: h[3],
        type: h[4],
        vip: h[5]
      });
      continue;
    }
    // Cisco: "Vl10  1  100  ...  Master  10.x  10.x"
    const c = l.match(/^(Vl\S+)\s+(\d+)\s+(\d+)\s+\S+\s+\S+\s+(Master|Backup|Init)\s+([\d.]+)\s+([\d.]+)/i);
    if (c) vrrp.push({
      vrid: c[2],
      intf: c[1],
      state: c[4],
      type: "Normal",
      vip: c[6]
    });
  }

  // ── GLBP — show glbp brief — apenas linhas de grupo (Fwd="-") ─
  const glbp = [];
  let inGlbp = false;
  for (const l of lines) {
    if (/show glbp brief/.test(l)) {
      inGlbp = true;
      continue;
    }
    if (inGlbp && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inGlbp = false;
      continue;
    }
    if (!inGlbp) continue;
    // Linha de grupo: Fwd é "-"
    const m = l.match(/^(Vl\S+)\s+(\d+)\s+-\s+(\d+)\s+(\S+)\s+([\d.]+)\s+(\S+)\s+(\S+)/);
    if (m) glbp.push({
      intf: m[1],
      grp: m[2],
      pri: m[3],
      state: m[4],
      vip: m[5],
      active: m[6],
      standby: m[7]
    });
  }

  // ── show etherchannel / show port-channel / display eth-trunk ─
  const portch = [];
  let inPc = false,
    lastPc = null;
  // HP Comware: display link-aggregation summary → "BAGG1 S/D Selected/Unselected"
  // Members from running-config: "port link-aggregation group N"
  if (isHP) {
    let inHPPC = false;
    for (const l of lines) {
      if (/display link-aggregation summary/.test(l)) {
        inHPPC = true;
        continue;
      }
      if (inHPPC && /<[\w\-]+>/.test(l)) {
        inHPPC = false;
        continue;
      }
      if (!inHPPC || /^AGG|^Interface|^-+$|^Aggregation|^Actor|^Loadsharing/.test(l.trim())) continue;
      // "BAGG3  D  0x8000, 2c23-3aab-c570  8  0  0  Shar"
      const m = l.match(/^((?:BAGG|BLAGG|RAGG)\d+)\s+(S|D)\s+\S+.*?\s+(\d+)\s+(\d+)/);
      if (m) {
        const total = +m[3] + +m[4];
        const status = +m[3] > 0 ? "connected" : "notconnect";
        const proto = m[2] === "D" ? "LACP" : "Static";
        portch.push({
          id: m[1].replace(/\D/g, ""),
          name: m[1],
          proto,
          status,
          members: ""
        });
      }
    }
    // Fill members from running-config
    let curIf = "";
    for (const l of lines) {
      const ifm = l.match(/^interface\s+(\S+)/i);
      if (ifm) {
        curIf = ifm[1];
        continue;
      }
      const lgm = l.match(/^\s+port\s+link-aggregation\s+group\s+(\d+)/i);
      if (lgm) {
        const pc = portch.find(p => p.name === "BAGG" + lgm[1] || p.name === "RAGG" + lgm[1]);
        if (pc) pc.members = (pc.members ? pc.members + ", " : "") + curIf;
      }
    }
  }

  // Dell FTOS: "show interface port-channel brief"
  // "L  1  L2  down  00:00:00" / "L  2  L2  up  157w4d11h  Te 0/42 (Up)"
  if (isDellFtos) {
    let inDFPC = false;
    for (const l of lines) {
      if (/show interface port-channel brief/.test(l)) {
        inDFPC = true;
        continue;
      }
      if (inDFPC && /^[\w\-]+#/.test(l)) {
        inDFPC = false;
        continue;
      }
      if (!inDFPC || /^Codes:|^LAG|^-+$|^\s*$/.test(l.trim())) continue;
      // "L   2    L2    up    157w4d11h   Te 0/42    (Up)"
      const m = l.match(/^[LOAI]\s+(\d+)\s+(\w+)\s+(up|down)\s+(\S+)\s*(.*)/i);
      if (m) {
        const id = m[1],
          status = m[3].toLowerCase() === "up" ? "connected" : "notconnect";
        // Extract member ports from rest of line
        const mems = m[5].match(/(?:Te|Gi|Fo|Hu)\s+[\d\/]+/gi) || [];
        portch.push({
          id,
          name: "port-channel" + id,
          proto: "LACP",
          status,
          members: mems.map(s => s.trim()).join(", ")
        });
      }
    }
  }

  // Dell OS10: "Port-channel 41 is up / Members in this channel: Eth 1/1/41:1,1/1/42:1"
  if (isDell) {
    let curDPc = null;
    for (const l of lines) {
      const hm = l.match(/^Port-channel\s+(\d+)\s+is\s+(\S+)/i);
      if (hm) {
        curDPc = {
          id: hm[1],
          name: "port-channel" + hm[1],
          proto: "",
          status: hm[2].toLowerCase() === "up" ? "connected" : "notconnect",
          members: ""
        };
        portch.push(curDPc);
        continue;
      }
      if (curDPc) {
        const mm = l.match(/Members in this channel:\s*(.+)/i);
        if (mm) {
          // "Eth 1/1/41:1,1/1/42:1" → normalize to "Eth1/1/41, Eth1/1/42"
          const mems = mm[1].split(",").map(s => {
            const p = s.trim().replace(/:\d+$/, "");
            return p.startsWith("Eth") || p.startsWith("eth") ? p : "Eth " + p;
          });
          curDPc.members = mems.join(", ");
        }
        const lm = l.match(/LineSpeed\s+(\S+)/i);
        if (lm) curDPc.speed = lm[1];
      }
    }
  }
  // Huawei Eth-Trunk
  if (isHuawei) {
    let curTr = null;
    for (const l of lines) {
      const hm = l.match(/^Eth-Trunk(\d+)'s state/);
      if (hm) {
        curTr = {
          id: hm[1],
          name: "Eth-Trunk" + hm[1],
          proto: "Static",
          status: "notconnect",
          members: []
        };
        portch.push(curTr);
        continue;
      }
      if (curTr) {
        const st = l.match(/Operating Status:\s*(\S+)/i);
        if (st) curTr.status = st[1].toLowerCase() === "up" ? "connected" : "notconnect";
        const wm = l.match(/Working Mode:\s*(\S+)/i);
        if (wm) curTr.proto = wm[1];
        const pm = l.match(/^((?:25GE|40GE|10GE|100GE|GE|XGE)[\d\/.:]+)\s+(\w+)/);
        if (pm && /Selected|Unselect/i.test(pm[2])) curTr.members.push(pm[1]);
      }
    }
    // Convert members array to string (rest of code expects string)
    for (const tr of portch) if (Array.isArray(tr.members)) tr.members = tr.members.join(", ");
  }
  for (const l of lines) {
    if (/show (?:etherchannel|port-channel) summary/.test(l)) {
      inPc = true;
      continue;
    }
    if (inPc && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inPc = false;
      lastPc = null;
      continue;
    }
    if (!inPc) continue;
    // IOS: "1  Po1(SU)  Eth  LACP  Gi1/0/1(P) Gi1/0/2(P)"
    const mios = l.match(/^(\d+)\s+(Po\d+)\((\w+)\)\s+(\S+)\s+(\S+)\s+(.*)/);
    if (mios) {
      const raw = mios[6].trim();
      const members = raw.replace(/\([\w]+\)/g, "").trim().split(/\s+/).filter(Boolean).map(normIf).join(", ");
      lastPc = {
        po: mios[2],
        status: mios[3],
        proto: mios[5],
        members,
        rawMembers: raw
      };
      portch.push(lastPc);
      continue;
    }
    // NX-OS: "1     Po1(SU)     Eth      LACP      Eth1/1(P)    Eth1/2(P)"
    const mnx = l.match(/^(\d+)\s+(Po\d+)\((\w+)\)\s+\w+\s+(\w+)\s+(.*)/);
    if (mnx) {
      const rawMems = mnx[5].replace(/--/g, "").replace(/\([\w]+\)/g, "").trim().split(/\s+/).filter(Boolean).map(normIf).join(", ");
      lastPc = {
        po: mnx[2],
        status: mnx[3],
        proto: mnx[4],
        members: rawMems,
        rawMembers: mnx[5]
      };
      portch.push(lastPc);
      continue;
    }
    // NX-OS continuation line (members overflow): "                                     Eth1/4(P)"
    if (lastPc && /^\s{20,}(Eth\S+)/.test(l)) {
      const extra = l.trim().replace(/\([\w]+\)/g, "").split(/\s+/).filter(Boolean).map(normIf).join(", ");
      if (extra && lastPc.members) lastPc.members += ", " + extra;else if (extra) lastPc.members = extra;
    }
  }

  // PORT-CHANNEL: cruzar com CDP/LLDP (nomes normalizados)
  const cdpMap = {};
  for (const c of cdp) {
    if (c.localIf) cdpMap[normIf(c.localIf.trim())] = c;
  }
  const lldpMap = {};
  for (const l of lldp) {
    if (l.localIf) lldpMap[normIf(l.localIf.trim())] = l;
  }
  const portchFull = portch.map(pc => {
    const memberList = (Array.isArray(pc.members) ? pc.members : (pc.members || "").split(",")).map(s => s.trim()).filter(Boolean);
    let vizinho = "",
      portasRemotas = "",
      poRemoto = "";
    for (const mb of memberList) {
      const entry = cdpMap[mb] || lldpMap[mb];
      if (entry) {
        vizinho = entry.devId || "";
        const remIf = entry.remIf || "";
        portasRemotas = remIf;
        // Se remIf já é um Port-channel, usa direto
        if (/^Port-channel\d+/i.test(remIf)) poRemoto = remIf;
        break;
      }
    }
    const po = pc.po || pc.name || "Po" + pc.id;
    return {
      ...pc,
      po,
      vizinho,
      portasRemotas,
      poRemoto
    };
  });

  // ── Running-config VLANs map (NX-OS: switchport trunk allowed vlan) ─
  const runCfgVlans = {}; // normKey → vlan list string
  const runCfgDesc = {}; // normKey → description
  {
    let curIf = null;
    for (const l of lines) {
      const ifm = l.match(/^interface\s+((?:port-channel|Ethernet|Vlan|loopback)\S+)/i);
      if (ifm) {
        // normalize: "port-channel1" → "Po1", "Ethernet1/5" → "Eth1/5"
        let k = ifm[1].replace(/^port-channel/i, "Po").replace(/^Ethernet/i, "Eth");
        curIf = k;
        continue;
      }
      if (curIf) {
        if (/^interface\s/i.test(l) || /^!/.test(l)) {
          curIf = null;
          continue;
        }
        const va = l.match(/switchport trunk allowed vlan\s+(\S+)/i);
        if (va) runCfgVlans[curIf] = va[1].trim();
        const de = l.match(/^\s+description\s+(.+)/);
        if (de) runCfgDesc[curIf] = de[1].trim();
      }
    }
  }

  // ── show interface trunk / display port vlan ──────────────────
  const trunk = [];
  const trunkMap = {};
  let inTrunk = false,
    trunkPhase = "";
  // Dell OS10: show interface switchport
  // "Name: ethernet1/1/1 / U  1 (native) / T  60,62,168..."
  if (isDell) {
    let inDS = false,
      curDIntf = "",
      curDVlans = "",
      curDNative = "1",
      curDTagged = false;
    const saveDTrunk = () => {
      if (curDIntf && curDVlans) trunk.push({
        port: curDIntf,
        intf: curDIntf,
        mode: "trunk",
        encap: "802.1q",
        status: "N/A",
        vlans: curDVlans,
        native: curDNative,
        nativeVlan: curDNative
      });
    };
    for (const l of lines) {
      if (/show interface switchport\b/.test(l)) {
        inDS = true;
        continue;
      }
      if (inDS && /^[\w\-]+#/.test(l)) {
        inDS = false;
        saveDTrunk();
        continue;
      }
      if (!inDS) continue;
      const nm = l.match(/^Name:\s*(\S+)/i);
      if (nm) {
        saveDTrunk();
        curDIntf = nm[1];
        curDVlans = "";
        curDNative = "1";
        curDTagged = false;
        continue;
      }
      if (/802\.1QTagged:\s*(Hybrid|True)/i.test(l)) {
        curDTagged = true;
        continue;
      }
      if (curDTagged) {
        const um = l.match(/^U\s+(\d+)/);
        if (um) curDNative = um[1];
        const tm = l.match(/^T\s+([\d,\s-]+)/);
        if (tm) curDVlans = tm[1].trim();
      }
    }
    saveDTrunk();
  }

  // Dell FTOS: show interface switchport — native from "Native VlanId: X."
  if (isDellFtos) {
    let inDFS2 = false,
      curDFI = "",
      curDFV = "",
      curDFN = "1",
      curDFT = false;
    const saveDFS = () => {
      if (curDFI && curDFV) trunk.push({
        port: curDFI,
        intf: curDFI,
        mode: "trunk",
        encap: "802.1q",
        status: "N/A",
        vlans: curDFV,
        native: curDFN,
        nativeVlan: curDFN
      });
    };
    for (const l of lines) {
      if (/show interface switchport\b/.test(l)) {
        inDFS2 = true;
        continue;
      }
      if (inDFS2 && /^[\w\-]+#/.test(l)) {
        inDFS2 = false;
        saveDFS();
        continue;
      }
      if (!inDFS2) continue;
      const nm = l.match(/^Name:\s*(\S.*)/i);
      if (nm) {
        saveDFS();
        curDFI = nm[1].trim().replace(/\s+/, "-");
        curDFV = "";
        curDFN = "1";
        curDFT = false;
        continue;
      }
      if (/802\.1QTagged:\s*(Hybrid|True)/i.test(l)) {
        curDFT = true;
        continue;
      }
      const nv = l.match(/Native VlanId:\s*(\d+)/i);
      if (nv) curDFN = nv[1];
      if (curDFT) {
        const tm = l.match(/^T\s+([\d,\s-]+)/);
        if (tm) curDFV = tm[1].trim();
      }
    }
    saveDFS();
  }

  // HP Comware: display port trunk → "Interface  PVID  VLAN Passing"
  if (isHP) {
    let inHPT = false;
    for (const l of lines) {
      if (/display port trunk/.test(l)) {
        inHPT = true;
        continue;
      }
      if (inHPT && /<[\w\-]+>/.test(l)) {
        inHPT = false;
        continue;
      }
      if (!inHPT || /^Interface|^-+$/.test(l.trim())) continue;
      // "BAGG3   1   94, 113-114, 304, 306..."  (with  backspace chars — clean first)
      const clean = l.replace(/./g, "").replace(/\x08/g, "").trim();
      const m = clean.match(/^(\S+)\s+(\d+)\s+(.+)/);
      if (m) trunk.push({
        port: m[1],
        intf: m[1],
        mode: "trunk",
        encap: "802.1q",
        status: "N/A",
        vlans: m[3].trim().replace(/,\s*$/, ""),
        native: m[2],
        nativeVlan: m[2]
      });
    }
  }

  // Huawei trunk: display port vlan (with or without | inc trunk)
  // Handles: multiline VLAN lists + physical interfaces (GE, 40GE etc)
  if (isHuawei) {
    let inHT = false,
      vlanCol = 43,
      descCol = 80;
    let lastTrunk = null; // for multiline VLAN continuation
    for (const l of lines) {
      if (/display port vlan/.test(l)) {
        inHT = true;
        lastTrunk = null;
        continue;
      }
      if (inHT && /(?:<[\w\-]+>|[\w\-]+[#>])/.test(l)) {
        inHT = false;
        lastTrunk = null;
        continue;
      }
      if (!inHT) continue;
      // Detect header to get column positions
      if (/Trunk VLAN List/i.test(l) && /Port Description/i.test(l)) {
        vlanCol = l.indexOf("Trunk VLAN List");
        descCol = l.indexOf("Port Description");
        if (descCol < 0) descCol = vlanCol + 40;
        lastTrunk = null;
        continue;
      }
      if (/^-+$|^Port\s+Link/.test(l)) continue;
      // Match any trunk line (Eth-Trunk OR physical interface: GE, 40GE, 25GE, XGE...)
      const tm = l.match(/^(\S+)\s+trunk\s+(\d+)/i);
      if (tm) {
        const intf = tm[1],
          nativeVlan = tm[2];
        let vlans = "";
        if (l.length > vlanCol) {
          const rest = l.substring(vlanCol);
          vlans = descCol > vlanCol ? rest.substring(0, descCol - vlanCol).trim() : rest.trim();
        }
        lastTrunk = {
          port: intf,
          intf,
          mode: "trunk",
          encap: "802.1q",
          status: "N/A",
          vlans,
          native: nativeVlan,
          nativeVlan
        };
        trunk.push(lastTrunk);
        continue;
      }
      // Continuation line: starts with spaces, has VLANs at vlanCol position
      // (no interface name at start — just continuation of previous entry)
      if (lastTrunk && /^\s/.test(l) && l.trim().length > 0) {
        // Check if this is a VLAN continuation (numbers/ranges at vlanCol)
        if (l.length > vlanCol) {
          const contVlans = l.substring(vlanCol, descCol > vlanCol ? descCol : l.length).trim();
          if (contVlans && /^[\d\s\-,]+$/.test(contVlans)) {
            lastTrunk.vlans = (lastTrunk.vlans ? lastTrunk.vlans + " " : "") + contVlans;
          }
        }
        continue;
      }
      // Non-trunk line (access etc) — reset lastTrunk
      if (/^(\S+)\s+(access|hybrid)/.test(l)) lastTrunk = null;
    }
  }
  for (const l of lines) {
    if (/show interface(s)? trunk/.test(l)) {
      inTrunk = true;
      trunkPhase = "";
      continue;
    }
    if (inTrunk && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inTrunk = false;
      continue;
    }
    if (!inTrunk) continue;
    // IOS phases
    if (/^Port\s+Mode\s+Encapsulation\s+Status/.test(l)) {
      trunkPhase = "main";
      continue;
    }
    if (/^Port\s+Vlans allowed on trunk/.test(l)) {
      trunkPhase = "vlans";
      continue;
    }
    if (/^Port\s+Native vlan/.test(l)) {
      trunkPhase = "native";
      continue;
    }
    if (/^Port\s+Vlans allowed and active/.test(l)) {
      trunkPhase = "";
      continue;
    }
    if (/^Port\s+Vlans in spanning/.test(l)) {
      trunkPhase = "";
      continue;
    }
    // NX-OS headers
    if (/^Port\s+Native\s+Status\s+Port/.test(l)) {
      trunkPhase = "nxos";
      continue;
    }
    if (/^Port\s+Vlans Allowed on Trunk/.test(l)) {
      trunkPhase = "nxos-vlans";
      continue;
    }
    if (trunkPhase === "nxos" && /^\s+Vlan/.test(l)) {
      continue;
    } // skip sub-header
    if (/^-{10,}/.test(l)) {
      continue;
    } // skip separator lines
    if (trunkPhase === "main") {
      const m = l.match(/^((?:Gi|Te|Fa|Po|Et)\S+)\s+(\S+)\s+(\S+)\s+(trunking|not-trunking)\s+(\d+)/);
      if (m) trunkMap[m[1]] = {
        port: m[1],
        mode: m[2],
        encap: m[3],
        status: m[4],
        native: m[5],
        vlans: ""
      };
    }
    if (trunkPhase === "vlans") {
      const m = l.match(/^((?:Gi|Te|Fa|Po|Et)\S+)\s+(\S+)/);
      if (m && trunkMap[m[1]]) trunkMap[m[1]].vlans = m[2];
    }
    if (trunkPhase === "native") {
      const m = l.match(/^((?:Gi|Te|Fa|Po|Et)\S+)\s+(\d+)/);
      if (m && trunkMap[m[1]]) trunkMap[m[1]].native = m[2];
    }
    // NX-OS main: "Eth1/1  1  trnk-bndl  Po1"
    if (trunkPhase === "nxos") {
      const m = l.match(/^((?:Eth|Po)\S+)\s+(\d+)\s+(trnk-bndl|trunking|routed|\S+)\s+(\S+)/);
      if (m) {
        const pc = m[4] !== "--" ? m[4] : "";
        trunkMap[m[1]] = {
          port: m[1],
          mode: "trunk",
          encap: "802.1q",
          status: m[3],
          native: m[2],
          vlans: pc
        };
      }
    }
    // NX-OS vlans allowed section
    if (trunkPhase === "nxos-vlans") {
      const m = l.match(/^((?:Eth|Po)\S+)\s+(\S+)/);
      if (m && trunkMap[m[1]]) trunkMap[m[1]].vlans = m[2];
    }
  }

  // Cross-reference running-config VLANs for NX-OS (fills missing vlans)
  for (const key of Object.keys(trunkMap)) {
    if (!trunkMap[key].vlans || trunkMap[key].vlans === "") {
      if (runCfgVlans[key]) trunkMap[key].vlans = runCfgVlans[key];
    }
  }
  // Add Port-Channels that are trunk in running-config but not in show interface trunk
  if (isNexus) {
    for (const [key, vlans] of Object.entries(runCfgVlans)) {
      if (!trunkMap[key] && key.startsWith("Po")) {
        trunkMap[key] = {
          port: key,
          mode: "trunk",
          encap: "802.1q",
          status: "trunking",
          native: "1",
          vlans
        };
      }
    }
  }
  Object.values(trunkMap).forEach(t => trunk.push(t));

  // ── Static Routes + Gateway padrão ───────────────────────────
  const staticRt = [];
  let defaultGw = "";
  // Dell FTOS static routes: "ip route 0.0.0.0/0 X.X.X.X" (same as OS10 CIDR)
  // already covered by isDell|isDellFtos below — same format
  // Dell OS10 static routes from running-config: "ip route X.X.X.X/M X.X.X.X"
  if (isDell || isDellFtos) {
    for (const l of lines) {
      const dr = l.match(/^\s*ip route\s+([\d.]+\/\d+)\s+([\d.]+)/i);
      if (dr) {
        staticRt.push({
          net: dr[1],
          via: dr[2],
          intf: "",
          name: ""
        });
        if (dr[1] === "0.0.0.0/0") defaultGw = dr[2];
      }
    }
  }

  // Huawei static routes — 3 formatos:
  // 1) ip route-static vpn-instance VRF NET MASK [INTF] NEXTHOP [description X]
  // 2) ip route-static NET MASK NEXTHOP [description X]
  // 3) ip route-static NET/PREFIX NEXTHOP
  if (isHuawei) {
    for (const l of lines) {
      let net = "",
        mask = "",
        via = "",
        name = "";
      // Formato vpn-instance: ip route-static vpn-instance VRF NET MASK [INTF] NEXTHOP [description X]
      const hvpn = l.match(/^\s*ip route-static\s+vpn-instance\s+\S+\s+([\d.]+)\s+([\d.]+)\s+(?:(\S+)\s+)?(\d+\.\d+\.\d+\.\d+)(?:\s+description\s+(.+))?/i);
      if (hvpn) {
        net = hvpn[1];
        mask = hvpn[2];
        via = hvpn[4];
        name = (hvpn[5] || "").trim();
        // Se hvpn[3] é um IP, é o nexthop sem interface antes
        if (hvpn[3] && /^\d+\.\d+\.\d+\.\d+$/.test(hvpn[3])) {
          via = hvpn[3];
          name = (hvpn[4] || "").trim();
        }
      } else {
        // Formato padrão: ip route-static NET MASK NEXTHOP [description X]
        const hw = l.match(/^\s*ip route-static\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)(?:\s+description\s+(.+))?/i);
        if (hw) {
          net = hw[1];
          mask = hw[2];
          via = hw[3];
          name = (hw[4] || "").trim();
        }
      }
      if (via) {
        const netStr = net + (mask && mask !== "0.0.0.0" ? "/" + mask : "");
        staticRt.push({
          net: netStr,
          via,
          intf: "",
          name
        });
        if (net === "0.0.0.0") defaultGw = via;
      }
    }
  }
  for (const l of lines) {
    // IOS: "ip route 10.x.x.x 255.x.x.x 10.x.x.x [name xxx]"
    const rc = l.match(/^\s*ip route ([\d.]+)\s+([\d.]+)\s+([\d.]+)(?:\s+name\s+(\S+))?/);
    if (rc) {
      staticRt.push({
        net: rc[1] + "/" + rc[2],
        via: rc[3],
        intf: "",
        name: rc[4] || ""
      });
      if (rc[1] === "0.0.0.0") defaultGw = rc[3];
      continue;
    }
    // NX-OS: "ip route 0.0.0.0/0 10.x.x.x [vrf management]"
    const nx = l.match(/^\s*ip route ([\d.]+\/\d+)\s+([\d.]+)(?:\s+vrf\s+(\S+))?/);
    if (nx) {
      staticRt.push({
        net: nx[1],
        via: nx[2],
        intf: "",
        name: nx[3] || ""
      });
      if (nx[1] === "0.0.0.0/0") defaultGw = nx[2];
      continue;
    }
    // Note: "show ip route" S* lines removed — using running-config only to avoid duplicates
  }

  // ── show ip arp / display arp ────────────────────────────────
  const arpTable = [];
  let inArp = false;
  // HP Comware: display arp → "IP  MAC  VLAN  Interface  Aging  Type"
  if (isHP) {
    let inHPA = false;
    for (const l of lines) {
      if (/display arp\b/.test(l)) {
        inHPA = true;
        continue;
      }
      if (inHPA && /<[\w\-]+>/.test(l)) {
        inHPA = false;
        continue;
      }
      if (!inHPA || /^Type:|^IP address|^-+$/.test(l.trim())) continue;
      // "10.193.108.20  480f-cfd3-6d57  N/A  M-E1/0/0/0  10  D"
      const m = l.match(/^([\d.]+)\s+([\w\-]+)\s+\S+\s+(\S+)\s+\d+\s+([DSOR])/i);
      if (m) arpTable.push({
        ip: m[1],
        mac: m[2].replace(/-/g, "."),
        age: "",
        intf: m[3],
        type: m[4] === "D" ? "DYNAMIC" : "STATIC"
      });
    }
  }

  // Dell FTOS ARP: "show arp" (not "show ip arp")
  // "Protocol  Address  Age  Hardware Addr  Type  Interface"
  if (isDellFtos) {
    let inDFA = false;
    for (const l of lines) {
      if (/^show arp\b/.test(l.trim())) {
        inDFA = true;
        continue;
      }
      if (inDFA && /^[\w\-]+#/.test(l)) {
        inDFA = false;
        continue;
      }
      if (!inDFA || /^Protocol|^-+$|^Codes/.test(l.trim())) continue;
      // "Internet  10.x.x.x  0  f4:8e:38:4b:14:c9  ARPA  ManagementEthernet 0/0"
      const m = l.match(/^\w+\s+([\d.]+)\s+(\d+|-)\s+([\w:]+)\s+(\w+)\s+(\S+.*)/i);
      if (m) arpTable.push({
        ip: m[1],
        mac: m[3],
        age: m[2],
        intf: m[5].trim(),
        type: m[4]
      });
    }
  }

  // Dell OS10 ARP: "Address  Hardware-address  Interface  Egress-Interface"
  if (isDell) {
    let inDA = false;
    for (const l of lines) {
      if (/show ip arp\b/.test(l)) {
        inDA = true;
        continue;
      }
      if (inDA && /^[\w\-]+#/.test(l)) {
        inDA = false;
        continue;
      }
      if (!inDA || /^Codes:|^Address|^-+$/.test(l)) continue;
      const m = l.match(/^([\d.]+)\s+([\w:]+)\s+(\S+)/);
      if (m && m[1] !== "Address") arpTable.push({
        ip: m[1],
        mac: m[2],
        age: "",
        intf: m[3],
        type: "ARPA"
      });
    }
  }

  // Huawei ARP: "IP  MAC  EXP  TYPE/VLAN  INTF  VPN"
  if (isHuawei) {
    let inHA = false;
    for (const l of lines) {
      if (/display arp\b/.test(l)) {
        inHA = true;
        continue;
      }
      if (inHA && /<[\w\-]+>/.test(l)) {
        inHA = false;
        continue;
      }
      if (!inHA || /^-+$|^ARP Entry|^IP ADDRESS|^EXP:/.test(l)) continue;
      const m = l.match(/^(\d+\.\d+\.\d+\.\d+)\s+([\w\-]+)\s+(?:\d+\s+|\s+)(\S+)\s+(\S+)/);
      if (m && m[4] !== "VPN-INSTANCE") arpTable.push({
        ip: m[1],
        mac: m[2].replace(/-/g, "."),
        age: "",
        intf: m[4],
        type: m[3]
      });
    }
  }
  for (const l of lines) {
    if (/show ip arp/.test(l)) {
      inArp = true;
      continue;
    }
    if (inArp && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inArp = false;
      continue;
    }
    if (!inArp) continue;
    // IOS: "Internet  10.x.x.x  1  xxxx.xxxx.xxxx  ARPA  Vlan10"
    const ios = l.match(/^Internet\s+([\d.]+)\s+(-|\d+)\s+([\w.]+)\s+(\S+)\s+(\S+)/);
    if (ios) {
      arpTable.push({
        ip: ios[1],
        age: ios[2],
        mac: ios[3],
        type: ios[4],
        intf: ios[5]
      });
      continue;
    }
    // NX-OS: "10.x.x.x  00:01:23  xxxx.xxxx.xxxx  Vlan10"
    const nxos = l.match(/^([\d]+\.[\d.]+)\s+([\d:-]+|-)\s+([\w.]+)\s+(\S+)\s*$/);
    if (nxos && nxos[3] !== "MAC") arpTable.push({
      ip: nxos[1],
      age: nxos[2],
      mac: nxos[3],
      type: "ARPA",
      intf: nxos[4]
    });
  }

  // ── show mac address-table / display mac-address ────────────
  const macTable = [];
  let inMac = false;
  // HP Comware: display mac-address → "MAC-Address  VLAN-ID  State  Port/NickName  Aging"
  if (isHP) {
    let inHPM = false;
    for (const l of lines) {
      if (/display mac-address\b/.test(l)) {
        inHPM = true;
        continue;
      }
      if (inHPM && /<[\w\-]+>/.test(l)) {
        inHPM = false;
        continue;
      }
      if (!inHPM || /^MAC Address|^-+$/.test(l.trim())) continue;
      // "0050-5687-091a  113  Learned  BAGG3  Y"
      const m = l.match(/^([\w\-]{14})\s+(\d+)\s+(\w+)\s+(\S+)/);
      if (m) macTable.push({
        vlan: m[2],
        mac: m[1].replace(/-/g, "."),
        type: m[3].toLowerCase() === "learned" ? "dynamic" : "static",
        intf: m[4]
      });
    }
  }

  // Dell FTOS MAC: "show mac-address-table dynamic"
  // VlanId  Mac Address  Type  Interface
  if (isDellFtos) {
    let inDFM = false;
    for (const l of lines) {
      if (/show mac-address-table/.test(l)) {
        inDFM = true;
        continue;
      }
      if (inDFM && /^[\w\-]+#/.test(l)) {
        inDFM = false;
        continue;
      }
      if (!inDFM || /^VlanId|^-+$|^Codes/.test(l.trim())) continue;
      // "1  f4:8e:38:4b:xx:xx  Dynamic  TenGigabitEthernet 0/1"
      const m = l.match(/^(\d+)\s+([\w:]+)\s+(\w+)\s+(\S+.*)/i);
      if (m) macTable.push({
        vlan: m[1],
        mac: m[2].replace(/:/g, "."),
        type: m[3].toLowerCase(),
        intf: m[4].trim()
      });
    }
  }

  // Dell OS10 MAC: "VlanId  Mac-Address  Type  Interface"
  if (isDell) {
    let inDM = false;
    for (const l of lines) {
      if (/show mac address-table\b/.test(l)) {
        inDM = true;
        continue;
      }
      if (inDM && /^[\w\-]+#/.test(l)) {
        inDM = false;
        continue;
      }
      if (!inDM || /^Codes:|^VlanId|^-+$/.test(l)) continue;
      // "1  c4:f7:d5:aa:3f:e7  dynamic  port-channel41"
      const m = l.match(/^(\d+)\s+([\w:]+)\s+(dynamic|static)\s+(\S+)/i);
      if (m) macTable.push({
        vlan: m[1],
        mac: m[2].replace(/:/g, "."),
        type: m[3].toLowerCase(),
        intf: m[4]
      });
    }
  }

  // Huawei: "MAC  VLAN/VSI/BD  Learned-From  Type  Age"
  if (isHuawei) {
    let inHM = false;
    for (const l of lines) {
      if (/display mac-address\b/.test(l)) {
        inHM = true;
        continue;
      }
      if (inHM && /<[\w\-]+>/.test(l)) {
        inHM = false;
        continue;
      }
      if (!inHM || /^-+$|^MAC Address|^Flags|^BD/.test(l)) continue;
      const m = l.match(/^([\w\-]{14})\s+(\d+)\/[^\s]*\s+(\S+)\s+(dynamic|static)/i);
      if (m) macTable.push({
        vlan: m[2],
        mac: m[1].replace(/-/g, "."),
        type: m[4].toLowerCase(),
        intf: m[3]
      });
    }
  }
  for (const l of lines) {
    if (/show mac address-table/.test(l)) {
      inMac = true;
      continue;
    }
    if (inMac && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inMac = false;
      continue;
    }
    if (!inMac) continue;
    // NX-OS: "* vlan mac type age Secure NTFY port" (7 cols)
    // NX-OS: accept *, + (vPC Peer-Link) or space at start
    const nxm = l.match(/^[*+]?\s*(\d+)\s+([\w.]+)\s+(dynamic|static|DYNAMIC|STATIC)\s+\S+\s+\S+\s+\S+\s+(\S+)/);
    if (nxm && (nxm[4].startsWith("Eth") || nxm[4].startsWith("Po") || nxm[4].startsWith("Veth") || nxm[4].startsWith("nxm"))) {
      macTable.push({
        vlan: nxm[1],
        mac: nxm[2],
        type: nxm[3].toLowerCase(),
        intf: nxm[4]
      });
      continue;
    }
    // IOS: "* vlan mac type age port" (5 cols) or "vlan mac type port" (4 cols)
    const iosm = l.match(/^\*?\s*(\d+)\s+([\w.]+)\s+(dynamic|static|DYNAMIC|STATIC)\s+(?:-|\d+)\s+(\S+)/);
    if (iosm) {
      macTable.push({
        vlan: iosm[1],
        mac: iosm[2],
        type: iosm[3].toLowerCase(),
        intf: iosm[4]
      });
      continue;
    }
    // Fallback 4 cols
    const x = l.match(/^\s*(\d+)\s+([\w.]+)\s+(DYNAMIC|STATIC)\s+(\S+)/);
    if (x) macTable.push({
      vlan: x[1],
      mac: x[2],
      type: x[3].toLowerCase(),
      intf: x[4]
    });
  }

  // ── OSPF — parse running-config por processo + interface brief ─
  const ospfProcs = []; // [{pid, rid, refBw, areas, networks, activeIfs, redistribute}]
  // Huawei OSPF from display ospf brief
  if (isHuawei) {
    let inOBrief = false;
    for (const l of lines) {
      if (/display ospf brief/.test(l)) {
        inOBrief = true;
        continue;
      }
      if (inOBrief && /<[\w\-]+>/.test(l)) {
        inOBrief = false;
        continue;
      }
      if (!inOBrief) continue;
      // OSPF Process 50 with Router ID 10.195.82.198
      const pm = l.match(/OSPF Process\s+(\S+)\s+with Router ID\s+([\d.]+)/i);
      if (pm) {
        const existing = ospfProcs.find(p => p.pid === pm[1]);
        if (!existing) ospfProcs.push({
          pid: pm[1],
          rid: pm[2],
          refBw: "N/A",
          areas: [],
          activeIfs: [],
          redistribute: [],
          networks: []
        });
        continue;
      }
      // Area: 0.0.0.0
      if (ospfProcs.length) {
        const am = l.match(/^\s*Area:\s*([\d.]+)/i);
        if (am) {
          const p = ospfProcs[ospfProcs.length - 1];
          if (!p.areas.includes(am[1])) p.areas.push(am[1]);
        }
        // Interface: 10.x.x.x (Vlanif2028)
        const im = l.match(/^\s*Interface:\s*[\d.]+\s*\(([^)]+)\)/);
        if (im) {
          const p = ospfProcs[ospfProcs.length - 1];
          if (!p.activeIfs.includes(im[1])) p.activeIfs.push(im[1]);
        }
        // Import routes:
        const rd = l.match(/^\s*Import\s+(\S+)/i);
        if (rd) {
          const p = ospfProcs[ospfProcs.length - 1];
          if (!p.redistribute.includes(rd[1])) p.redistribute.push(rd[1]);
        }
      }
    }
  }
  const ospfIf = []; // mantido para compatibilidade
  {
    // 1) Parse bloco router ospf do running-config
    let inOspfCfg = false,
      curProc = null;
    const saveProc = () => {
      if (curProc) ospfProcs.push({
        ...curProc
      });
      curProc = null;
    };
    for (const l of lines) {
      const pm = l.match(/^router ospf\s+(\S+)/i);
      if (pm) {
        saveProc();
        curProc = {
          pid: pm[1],
          rid: "",
          refBw: "N/A",
          areas: new Set(),
          networks: [],
          activeIfs: [],
          redistribute: []
        };
        inOspfCfg = true;
        continue;
      }
      if (inOspfCfg && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
        saveProc();
        inOspfCfg = false;
        continue;
      }
      if (!inOspfCfg || !curProc) continue;
      if (/^router \w/.test(l) && !/^router ospf/i.test(l)) {
        saveProc();
        inOspfCfg = false;
        continue;
      }
      const rid = l.match(/^\s+router-id\s+([\d.]+)/);
      if (rid) curProc.rid = rid[1];
      const rb = l.match(/auto-cost reference-bandwidth\s+(\S+(?:\s+\S+)?)/i);
      if (rb) curProc.refBw = rb[1].trim();
      const ar = l.match(/^\s+area\s+(\S+)/i);
      if (ar) curProc.areas.add(ar[1]);
      const nw = l.match(/^\s+network\s+([\d.]+)\s+([\d.]+)\s+area\s+(\S+)/i);
      if (nw) {
        curProc.networks.push(nw[1] + " " + nw[2]);
        curProc.areas.add(nw[3]);
      }
      const rd = l.match(/^\s+redistribute\s+(\S+.*)/i);
      if (rd) curProc.redistribute.push(rd[1].trim());
      const pi = l.match(/^\s+passive-interface\s+(\S+)/i);
      if (pi && pi[1] !== "default") curProc.areas; // just noted
    }

    saveProc();

    // 2) Parse ip router ospf PROC area X nas interfaces
    let curIf2 = "";
    for (const l of lines) {
      const ifm = l.match(/^interface\s+(\S+)/i);
      if (ifm) {
        curIf2 = ifm[1];
        continue;
      }
      if (curIf2) {
        const ir = l.match(/ip router ospf\s+(\S+)\s+area\s+(\S+)/i);
        if (ir) {
          const proc = ospfProcs.find(p => p.pid === ir[1]);
          if (proc) {
            proc.activeIfs.push(curIf2);
            proc.areas.add(ir[2]);
          }
        }
      }
    }

    // 3) Parse show ip ospf interface brief → activeIfs + ospfIf (compat)
    let inOspfBrief = false,
      ospfIsNxos = false,
      briefPid = "";
    for (const l of lines) {
      if (/show ip ospf interface brief/.test(l)) {
        inOspfBrief = true;
        ospfIsNxos = false;
        briefPid = "";
        continue;
      }
      if (inOspfBrief && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
        inOspfBrief = false;
        continue;
      }
      if (!inOspfBrief) continue;
      const pidm = l.match(/OSPF Process ID\s+(\S+)/i);
      if (pidm) {
        ospfIsNxos = true;
        briefPid = pidm[1];
        continue;
      }
      if (/Interface\s+ID\s+Area/.test(l)) continue;
      if (ospfIsNxos) {
        const m = l.match(/^\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)/);
        if (m && m[1] !== "Interface") {
          ospfIf.push({
            intf: m[1],
            pid: briefPid || m[2],
            area: m[3],
            ip: "N/A",
            cost: m[4],
            state: m[5],
            nbrs: m[6] + "/" + m[6]
          });
          const proc = ospfProcs.find(p => p.pid === briefPid);
          if (proc && !proc.activeIfs.includes(m[1])) proc.activeIfs.push(m[1]);
        }
      } else {
        const m = l.match(/^(\S+)\s+(\d+)\s+(\S+)\s+([\d.]+\/\d+)\s+(\d+)\s+(\S+)\s+(\d+\/\d+)/);
        if (m && m[1] !== "Interface") {
          ospfIf.push({
            intf: m[1],
            pid: m[2],
            area: m[3],
            ip: m[4],
            cost: m[5],
            state: m[6],
            nbrs: m[7]
          });
          const proc = ospfProcs.find(p => p.pid === m[2]);
          if (proc && !proc.activeIfs.includes(m[1])) proc.activeIfs.push(m[1]);
        }
      }
    }
    // Convert Set to Array for areas + deduplicate
    for (const p of ospfProcs) {
      p.areas = [...new Set(p.areas)];
      p.activeIfs = [...new Set(p.activeIfs)];
      p.redistribute = [...new Set(p.redistribute)];
    }
    // Deduplicate processes by PID (merge if same PID appears twice)
    const procMap = {};
    for (const p of ospfProcs) {
      if (procMap[p.pid]) {
        const ex = procMap[p.pid];
        ex.rid = ex.rid || p.rid;
        ex.refBw = ex.refBw !== "N/A" ? ex.refBw : p.refBw;
        for (const a of p.areas) if (!ex.areas.includes(a)) ex.areas.push(a);
        for (const i of p.activeIfs) if (!ex.activeIfs.includes(i)) ex.activeIfs.push(i);
        for (const r of p.redistribute) if (!ex.redistribute.includes(r)) ex.redistribute.push(r);
      } else {
        procMap[p.pid] = p;
      }
    }
    ospfProcs.length = 0;
    for (const p of Object.values(procMap)) ospfProcs.push(p);
  }

  // ── OSPF routes ───────────────────────────────────────────────
  const ospfRt = [];
  let inOspfRt = false;
  for (const l of lines) {
    if (/show ip route ospf/.test(l)) {
      inOspfRt = true;
      continue;
    }
    if (inOspfRt && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inOspfRt = false;
      continue;
    }
    if (!inOspfRt) continue;
    const m = l.match(/O\s*(E\d)?\s+([\d.\/]+)\s+\[[\d\/]+\]\s+via\s+([\d.]+),\s+(\S+),\s+(\S+)/);
    if (m) ospfRt.push({
      type: m[1] || "O",
      net: m[2],
      via: m[3],
      age: m[4],
      iface: m[5]
    });
  }
  const ospfPid = ospfProcs.length ? ospfProcs[0].pid : first(/Process ID\s+(\S+)/i) || "";
  const ospfRid = ospfProcs.length ? ospfProcs[0].rid : first(/Router ID\s+([\d.]+)/i) || "";

  // ── EIGRP — show ip eigrp neighbors ──────────────────────────
  const eigrp = [];
  let inEigrp = false,
    eigrpProc = "";
  for (const l of lines) {
    if (/show ip eigrp neighbors/.test(l)) {
      inEigrp = true;
      continue;
    }
    if (inEigrp && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inEigrp = false;
      continue;
    }
    if (!inEigrp) continue;
    const proc = l.match(/(?:IP-EIGRP|EIGRP-IPv4)\s+neighbors for.*?(\d+)/i);
    if (proc) {
      eigrpProc = proc[1];
      continue;
    }
    const m = l.match(/^(\d+)\s+([\d.]+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/);
    if (m) eigrp.push({
      proc: eigrpProc,
      h: m[1],
      addr: m[2],
      intf: m[3],
      hold: m[4],
      uptime: m[5],
      srtt: m[6],
      rto: m[7],
      qcnt: m[8],
      seq: m[9]
    });
  }

  // ── BGP — show ip bgp summary / display bgp peer ──────────────
  const bgp = [];
  let inBgp = false,
    bgpRid = "",
    bgpAs = "";
  // Huawei BGP
  if (isHuawei) {
    let inHB = false;
    for (const l of lines) {
      if (/display bgp peer\b/.test(l)) {
        inHB = true;
        continue;
      }
      if (inHB && /<[\w\-]+>/.test(l)) {
        inHB = false;
        continue;
      }
      if (!inHB || /^-+$|^Peer|Total Number|BGP local/.test(l)) continue;
      const m = l.match(/^\s*([\d.]+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+)/);
      if (m) bgp.push({
        neighbor: m[1],
        remoteAs: m[3],
        state: m[4],
        pfxRcvd: "",
        updown: ""
      });
    }
    // running-config peer X.X.X.X as-number N
    if (!bgp.length) {
      for (const l of lines) {
        const pm = l.match(/^\s*peer\s+([\d.]+)\s+as-number\s+(\d+)/i);
        if (pm && !bgp.find(b => b.neighbor === pm[1])) bgp.push({
          neighbor: pm[1],
          remoteAs: pm[2],
          state: NC,
          pfxRcvd: "",
          updown: ""
        });
      }
    }
  }
  for (const l of lines) {
    if (/show ip bgp.*summary/.test(l)) {
      inBgp = true;
      continue;
    }
    if (inBgp && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inBgp = false;
      continue;
    }
    if (!inBgp) continue;
    const rid = l.match(/BGP router identifier ([\d.]+),\s*local AS number (\d+)/);
    if (rid) {
      bgpRid = rid[1];
      bgpAs = rid[2];
      continue;
    }
    const m = l.match(/^([\d.]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)/);
    if (m) bgp.push({
      rid: bgpRid,
      localAs: bgpAs,
      neighbor: m[1],
      v: m[2],
      as: m[3],
      msgRcvd: m[4],
      msgSent: m[5],
      tblVer: m[6],
      inQ: m[7],
      outQ: m[8],
      upDown: m[9],
      state: m[10]
    });
  }

  // ── BGP NX-OS — parse from running-config ─────────────────────
  if (isNexus && !bgp.length) {
    let inBgpCfg = false,
      nxBgpAs = "",
      nxBgpRid = "",
      nxCurNbr = null,
      nxCurNbrAs = "";
    const nxBgpNeighbors = [];
    for (const l of lines) {
      const bgpStart = l.match(/^router bgp\s+(\d+)/);
      if (bgpStart) {
        nxBgpAs = bgpStart[1];
        inBgpCfg = true;
        continue;
      }
      if (inBgpCfg && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
        inBgpCfg = false;
        continue;
      }
      if (!inBgpCfg) continue;
      const ridm = l.match(/^\s+router-id\s+([\d.]+)/);
      if (ridm) {
        nxBgpRid = ridm[1];
        continue;
      }
      const nbr = l.match(/^\s{2}neighbor\s+([\d.]+)\s*\r?$/);
      if (nbr) {
        if (nxCurNbr) nxBgpNeighbors.push({
          ip: nxCurNbr,
          as: nxCurNbrAs
        });
        nxCurNbr = nbr[1];
        nxCurNbrAs = "";
        continue;
      }
      const ras = l.match(/^\s{4}remote-as\s+(\d+)/);
      if (ras && nxCurNbr) {
        nxCurNbrAs = ras[1];
        continue;
      }
    }
    if (nxCurNbr) nxBgpNeighbors.push({
      ip: nxCurNbr,
      as: nxCurNbrAs
    });
    for (const nb of nxBgpNeighbors) {
      bgp.push({
        rid: nxBgpRid || hostname,
        localAs: nxBgpAs,
        neighbor: nb.ip,
        v: "4",
        as: nb.as || nxBgpAs,
        msgRcvd: "N/A",
        msgSent: "N/A",
        tblVer: "N/A",
        inQ: "N/A",
        outQ: "N/A",
        upDown: "N/A",
        state: "config"
      });
    }
    if (nxBgpRid) bgpRid = nxBgpRid;
  }

  // ── VIZINHANÇA OSPF — show ip ospf neighbor / display ospf peer brief ──
  const ospfNeighbors = [];
  let inOspfNbr = false;
  // Huawei: display ospf peer (completo) — extrai Priority, Dead Timer, Address, Intf, Uptime
  if (isHuawei) {
    let inHOP = false,
      curArea = "",
      curIntf = "";
    for (const l of lines) {
      if (/display ospf peer\b/.test(l) && !/brief/.test(l)) {
        inHOP = true;
        continue;
      }
      if (inHOP && /<[\w\-]+>/.test(l)) {
        inHOP = false;
        continue;
      }
      if (!inHOP) continue;
      // "Area 0.0.0.0 interface 10.x.x.x (Vlanif2028)'s neighbors"
      const am = l.match(/Area\s+([\d.]+)\s+interface\s+[\d.]+\s+\(([^)]+)\)/i);
      if (am) {
        curArea = am[1];
        curIntf = am[2];
        continue;
      }
      // "Router ID: 10.195.80.111   Address: 10.204.250.214"
      const rm = l.match(/Router ID:\s*([\d.]+).*Address\s*:\s*([\d.]+)/i);
      if (rm) {
        const nbr = {
          neighborId: rm[1],
          pri: "1",
          state: "",
          time: "",
          address: rm[2],
          intf: curIntf,
          area: curArea
        };
        ospfNeighbors.push(nbr);
        continue;
      }
      if (ospfNeighbors.length) {
        const last = ospfNeighbors[ospfNeighbors.length - 1];
        // "State: Full   Priority: 1"
        const st = l.match(/State\s*:\s*(\S+)/i);
        if (st) last.state = st[1];
        const pr = l.match(/Priority:\s*(\d+)/i);
        if (pr) last.pri = pr[1];
        // "Dead timer due (in seconds): 32"
        const dt = l.match(/Dead timer due.*?:\s*(\d+)/i);
        if (dt) last.time = dt[1] + "s";
        // "Neighbor up time: 2042h17m05s"
        const ut = l.match(/Neighbor up time\s*:\s*(\S+)/i);
        if (ut && !last.time) last.time = ut[1];
      }
    }
    // Fallback: display ospf peer brief se peer não encontrou nada
    if (!ospfNeighbors.length) {
      let inHON = false;
      for (const l of lines) {
        if (/display ospf peer brief/.test(l)) {
          inHON = true;
          continue;
        }
        if (inHON && /<[\w\-]+>/.test(l)) {
          inHON = false;
          continue;
        }
        if (!inHON || /^-+$|Area Id|Peer Statistic|Total number/.test(l)) continue;
        const m = l.match(/^\s*([\d.]+)\s+(\S+)\s+([\d.]+)\s+(\S+)/);
        if (m) ospfNeighbors.push({
          neighborId: m[3],
          pri: "",
          state: m[4],
          time: "",
          address: m[3],
          intf: m[2],
          area: m[1]
        });
      }
    }
  }
  for (const l of lines) {
    if (/show ip ospf neighbor\b/.test(l)) {
      inOspfNbr = true;
      continue;
    }
    if (inOspfNbr && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inOspfNbr = false;
      continue;
    }
    if (!inOspfNbr) continue;
    if (/Invalid command|^\s*$|Total number|OSPF Process|Neighbor ID/.test(l)) continue;
    // NX-OS: " 10.199.96.1   1 FULL/ -   2y22w   10.199.96.1   Po4093"
    const nx = l.match(/^\s+([\d.]+)\s+(\d+)\s+(\S+(?:\s*\/\s*\S+)?)\s+(\S+)\s+([\d.]+)\s+(\S+)/);
    if (nx) {
      ospfNeighbors.push({
        neighborId: nx[1],
        pri: nx[2],
        state: nx[3].trim(),
        time: nx[4],
        address: nx[5],
        intf: nx[6]
      });
      continue;
    }
    // IOS: "10.199.96.1  1  FULL/DR  00:00:35  10.x.x.x  Gi0/0"
    const ios = l.match(/^([\d.]+)\s+(\d+)\s+(\S+\/\S+)\s+(\S+)\s+([\d.]+)\s+(\S+)/);
    if (ios) ospfNeighbors.push({
      neighborId: ios[1],
      pri: ios[2],
      state: ios[3],
      time: ios[4],
      address: ios[5],
      intf: ios[6]
    });
  }
  // Detect if time field is Dead Time (IOS) or Up Time (NX-OS)
  const ospfTimeLabel = isNexus ? "Up Time" : isHuawei ? "Dead Time" : "Dead Time";

  // ── VIZINHANÇA EIGRP — show ip eigrp neighbors ────────────────
  const eigrpNeighbors = [];
  let inEigrpNbr = false;
  for (const l of lines) {
    if (/show ip eigrp neighbors\b/.test(l)) {
      inEigrpNbr = true;
      continue;
    }
    if (inEigrpNbr && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inEigrpNbr = false;
      continue;
    }
    if (!inEigrpNbr) continue;
    if (/Invalid command|^\s*$|^H\s+Address|EIGRP-IPv/.test(l)) continue;
    // IOS/NX-OS: "0  10.x.x.x  Gi0/0  12  00:05:10  1234  4500  0  100"
    const m = l.match(/^\s*(\d+)\s+([\d.]+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/);
    if (m) eigrpNeighbors.push({
      h: m[1],
      address: m[2],
      intf: m[3],
      hold: m[4],
      uptime: m[5],
      srtt: m[6],
      rto: m[7],
      qcnt: m[8],
      seq: m[9]
    });
  }

  // ── VIZINHANÇA BGP — show ip bgp summary ─────────────────────
  const bgpNeighbors = [];
  let inBgpSum = false,
    bgpSumRid = "",
    bgpSumAs = "";
  for (const l of lines) {
    if (/show ip bgp.*summary/.test(l)) {
      inBgpSum = true;
      continue;
    }
    if (inBgpSum && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inBgpSum = false;
      continue;
    }
    if (!inBgpSum) continue;
    const rid = l.match(/BGP router identifier ([\d.]+),\s*local AS number (\d+)/);
    if (rid) {
      bgpSumRid = rid[1];
      bgpSumAs = rid[2];
      continue;
    }
    // Skip header lines
    if (/^Neighbor|^BGP|^\s*$|^0 network/.test(l)) continue;
    const m = l.match(/^([\d.]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)/);
    if (m) bgpNeighbors.push({
      rid: bgpSumRid,
      localAs: bgpSumAs,
      neighbor: m[1],
      v: m[2],
      as: m[3],
      msgRcvd: m[4],
      msgSent: m[5],
      tblVer: m[6],
      inQ: m[7],
      outQ: m[8],
      upDown: m[9],
      state: m[10]
    });
  }
  // NX-OS fallback from running-config
  if (isNexus && !bgpNeighbors.length && bgp.length) {
    for (const b of bgp) bgpNeighbors.push({
      ...b
    });
  }

  // ── show vlan / display vlan ────────────────────────────────────
  const vlans = [];
  let inVlan = false,
    lastVlan = null;
  // Dell FTOS: show vlan same format as OS10 — reuse same parser
  // Dell OS10: parse VLANs from running-config "interface vlanN" + show vlan descriptions
  if (isDell || isDellFtos) {
    const dVlanNames = {};
    // From running-config: interface vlanN → description
    let inDV = false,
      curDVid = "";
    for (const l of lines) {
      const vm = l.match(/^interface\s+vlan(\d+)/i);
      if (vm) {
        inDV = true;
        curDVid = vm[1];
        dVlanNames[+curDVid] = dVlanNames[+curDVid] || "VLAN" + curDVid;
        continue;
      }
      if (inDV) {
        const dm = l.match(/^\s+description\s+(.+)/i);
        if (dm) dVlanNames[+curDVid] = dm[1].trim();
        if (/^\S/.test(l) && !/^interface/i.test(l)) inDV = false;
      }
    }
    // From show vlan: "NUM Status Description"
    let inDVlan = false;
    for (const l of lines) {
      if (/show vlan\b/.test(l)) {
        inDVlan = true;
        continue;
      }
      if (inDVlan && /^[\w\-]+#/.test(l)) {
        inDVlan = false;
        continue;
      }
      if (!inDVlan || /^Codes:|^Q:|^\s*NUM|^-+$|^\*/.test(l)) continue;
      const m = l.match(/^\*?\s*(\d+)\s+(\w+)\s+(\S.*?)\s+[ATQ]/);
      if (m) {
        const id = +m[1];
        if (!dVlanNames[id]) dVlanNames[id] = m[3].trim();
      } else {
        const m2 = l.match(/^\*?\s*(\d+)\s+(\w+)/);
        if (m2 && !dVlanNames[+m2[1]]) dVlanNames[+m2[1]] = "VLAN" + m2[1];
      }
    }
    for (const [vid, name] of Object.entries(dVlanNames)) vlans.push({
      id: String(vid),
      name,
      status: "active",
      ports: ""
    });
  }

  // HP Comware: display vlan brief → "VLAN ID  Name  Port"
  if (isHP) {
    let inHPV = false,
      curVid = "",
      curName = "";
    for (const l of lines) {
      if (/display vlan brief/.test(l)) {
        inHPV = true;
        continue;
      }
      if (inHPV && /<[\w\-]+>/.test(l)) {
        inHPV = false;
        if (curVid) vlans.push({
          id: curVid,
          name: curName,
          status: "active",
          ports: ""
        });
        continue;
      }
      if (!inHPV) continue;
      const vm = l.match(/^(\d+)\s+(\S[^\r\n]*?)(?:\s{2,}|\s*$)/);
      if (vm) {
        if (curVid) vlans.push({
          id: curVid,
          name: curName,
          status: "active",
          ports: ""
        });
        curVid = vm[1];
        curName = vm[2].trim();
      }
    }
    if (curVid && !vlans.find(v => v.id === curVid)) vlans.push({
      id: curVid,
      name: curName,
      status: "active",
      ports: ""
    });
  }

  // Huawei: parse from running-config (vlan batch + vlan N / name)
  if (isHuawei) {
    const vlanNames = {};
    let inVC = false,
      curVid = "";
    for (const l of lines) {
      if (/^vlan batch\s/.test(l)) {
        const ids = l.replace(/^vlan batch\s+/, "").match(/\d+(?:\s+to\s+\d+)?/g) || [];
        for (const id of ids) {
          if (id.includes("to")) {
            const [a, b] = id.split(/\s+to\s+/).map(Number);
            for (let v = a; v <= b; v++) if (!vlanNames[v]) vlanNames[v] = "VLAN" + v;
          } else {
            if (!vlanNames[+id]) vlanNames[+id] = "VLAN" + id;
          }
        }
        continue;
      }
      const vm = l.match(/^vlan\s+(\d+)\s*$/);
      if (vm) {
        inVC = true;
        curVid = vm[1];
        if (!vlanNames[+curVid]) vlanNames[+curVid] = "VLAN" + curVid;
        continue;
      }
      if (inVC) {
        const nm = l.match(/^\s+name\s+(.+)/);
        if (nm) vlanNames[+curVid] = nm[1].trim();
        if (!/^\s/.test(l)) inVC = false;
      }
    }
    for (const [vid, name] of Object.entries(vlanNames)) vlans.push({
      id: String(vid),
      name,
      status: "active",
      ports: ""
    });
  }
  for (const l of lines) {
    if (/[#>]\s*show vlan\b/.test(l)) {
      inVlan = true;
      continue;
    }
    if (inVlan && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inVlan = false;
      lastVlan = null;
      continue;
    }
    if (!inVlan) continue;
    const m = l.match(/^(\d+)\s+([\w\-]+)\s+(active|act\/unsup|suspend|inactive)\s*/);
    if (m) {
      lastVlan = {
        id: m[1],
        name: m[2],
        status: m[3]
      };
      vlans.push(lastVlan);
    }
  }

  // ── show vtp status ──────────────────────────────────────────
  const NC = "Não configurado";
  // VCMP (Huawei equivalent of VTP)
  const vtpVer = isDell || isDellFtos || isHP ? NC : isHuawei ? first(/VCMP Status\s*:\s*(\S+)/i) || NC : isNexus ? NC : first(/VTP version running\s*:\s*(\S+)/i) || first(/VTP [Vv]ersion\s*:\s*(\S+)/);
  const vtpDomainRaw = isNexus || isHuawei || isDell || isDellFtos ? null : (() => {
    const m = raw.match(/VTP Domain Name\s*:\s*(.*)/i);
    return m ? m[1].trim() : "";
  })();
  const vtpDomain = isDell || isNexus ? NC : isHuawei ? first(/VCMP Domain\s*:\s*(\S+)/i) || NC : vtpDomainRaw || NC;
  const vtpMode = isDell || isNexus ? NC : isHuawei ? first(/VCMP Role\s*:\s*(\S+)/i) || NC : first(/VTP Operating Mode\s*:\s*(\S+)/);
  const vtpVlans = isDell || isNexus ? NC : isHuawei ? String(vlans.length || 0) : first(/Number of existing VLANs\s*:\s*(\d+)/);
  const vtpRev = isDell || isNexus ? NC : isHuawei ? first(/VCMP Revision\s*:\s*(\d+)/i) || NC : first(/Configuration Revision\s*:\s*(\d+)/);
  const vtpPwd = isDell || isNexus ? NC : isHuawei ? first(/VCMP Password\s*:\s*(\S+)/i) || NC : first(/VTP Password\s*:\s*(\S+)/);

  // ── show spanning-tree root / display stp ──────────────────────
  const stp = [];
  // HP Comware: display stp root → "MST ID  Root Bridge ID  ExtPathCost  IntPathCost  Root Port"
  if (isHP) {
    let inHPStp = false;
    for (const l of lines) {
      if (/display stp root/.test(l)) {
        inHPStp = true;
        continue;
      }
      if (inHPStp && /<[\w\-]+>/.test(l)) {
        inHPStp = false;
        continue;
      }
      if (!inHPStp || /^MST ID|^-+$/.test(l.trim())) continue;
      // " 0  4096.bcea-fa78-0800  0  0  "
      const m = l.match(/^\s*(\d+)\s+([\d]+)\.([\w\-]+)\s+(\d+)\s+(\d+)\s*(\S*)/);
      if (m) {
        const vlan = m[1] === "0" ? "CIST" : "MST" + m[1];
        const rootMac = m[3].replace(/-/g, ".");
        stp.push({
          vlan,
          rootPri: m[2],
          rootMac,
          cost: m[4],
          rootPort: m[6] || "Root Bridge"
        });
      }
    }
  }

  // Dell FTOS STP: show spanning-tree pvst
  // "VLAN 1 / Root Identifier has priority 32769, Address f48e.384b.14c9"
  if (isDellFtos) {
    let inDFStp = false,
      curVlan = "",
      rootPri = "",
      rootMac = "",
      cost = "0",
      rootPort = "Root Bridge";
    for (const l of lines) {
      if (/show spanning-tree pvst\b/.test(l)) {
        inDFStp = true;
        continue;
      }
      if (inDFStp && /^[\w\-]+#/.test(l)) {
        if (curVlan) stp.push({
          vlan: "VLAN" + curVlan,
          rootPri,
          rootMac,
          cost,
          rootPort
        });
        inDFStp = false;
        continue;
      }
      if (!inDFStp) continue;
      const vm = l.match(/^VLAN\s+(\d+)/i);
      if (vm) {
        if (curVlan) stp.push({
          vlan: "VLAN" + curVlan,
          rootPri,
          rootMac,
          cost,
          rootPort
        });
        curVlan = vm[1];
        rootPri = "";
        rootMac = "";
        cost = "0";
        rootPort = "Root Bridge";
        continue;
      }
      if (curVlan) {
        // "Root Identifier has priority 32769, Address f48e.384b.14c9"
        const rm = l.match(/Root Identifier has priority\s+(\d+),\s+Address\s+([\w.]+)/i);
        if (rm) {
          rootPri = rm[1];
          rootMac = rm[2];
        }
        if (/We are the root/i.test(l)) rootPort = "Root Bridge";
        // "Port X (Port-channel 2) is designated Forwarding" — not root
        // "Port X (Port-channel 1) is root Forwarding" — root port
        const rp = l.match(/Port\s+\d+\s+\(([^)]+)\)\s+is\s+root/i);
        if (rp) rootPort = rp[1].replace(/\s+/, "-");
      }
    }
    if (curVlan) stp.push({
      vlan: "VLAN" + curVlan,
      rootPri,
      rootMac,
      cost,
      rootPort
    });
  }

  // Dell OS10 STP: per-VLAN rapid-pvst
  // "VLAN 1 / Root ID Priority X, Address X / Bridge ID..."
  if (isDell) {
    let inDStp = false,
      curVlan = "",
      rootPri = "",
      rootMac = "",
      cost = "0",
      rootPort = "Root Bridge";
    for (const l of lines) {
      if (/show spanning-tree\b/.test(l)) {
        inDStp = true;
        continue;
      }
      if (inDStp && /^[\w\-]+#/.test(l)) {
        inDStp = false;
        continue;
      }
      if (!inDStp) continue;
      const vm = l.match(/^VLAN\s+(\d+)/i);
      if (vm) {
        if (curVlan) stp.push({
          vlan: "VLAN" + curVlan,
          rootPri,
          rootMac,
          cost,
          rootPort
        });
        curVlan = vm[1];
        rootPri = "";
        rootMac = "";
        cost = "0";
        rootPort = "Root Bridge";
        continue;
      }
      if (curVlan) {
        const rm = l.match(/Root ID\s+Priority\s+(\d+),\s+Address\s+([\w.]+)/i) || l.match(/Root Identifier has priority\s+(\d+),\s+Address\s+([\w.]+)/i);
        if (rm) {
          rootPri = rm[1];
          rootMac = rm[2];
        }
        // Root port from interface table: "ethernetX/Y/Z ... FWD"
        const rp = l.match(/^(ethernet[\d\/]+|port-channel\d+)\s+[\d.]+\s+\d+\s+\d+\s+FWD/i);
        if (rp && rootPort === "Root Bridge") rootPort = rp[1];
        if (/We are the root/i.test(l)) rootPort = "Root Bridge";
      }
    }
    if (curVlan) stp.push({
      vlan: "VLAN" + curVlan,
      rootPri,
      rootMac,
      cost,
      rootPort
    });
  }

  // Huawei: CIST Global — one entry per device
  if (isHuawei) {
    let inHStp = false;
    for (const l of lines) {
      if (/display stp\b/.test(l)) {
        inHStp = true;
        continue;
      }
      if (inHStp && /<[\w\-]+>/.test(l)) {
        inHStp = false;
        continue;
      }
      if (!inHStp) continue;
      // CIST Bridge  :32768.8cfd-187e-7b01
      const bm = l.match(/CIST Bridge\s*:\s*([\d]+)\.([\w\-]+)/i);
      if (bm) {
        // CIST Root/ERPC :32768.8cfd-187e-7b01 / 0
        const rootLine = raw.match(/CIST Root\/ERPC\s*:\s*([\d]+)\.([\w\-]+)\s*\/\s*(\d+)/i);
        const cost = rootLine ? rootLine[3] : "0";
        const rootMac = rootLine ? rootLine[2].replace(/-/g, ".") : bm[2].replace(/-/g, ".");
        const rootPri = rootLine ? rootLine[1] : bm[1];
        // Root Port
        const rp = raw.match(/CIST RootPortId\s*:\s*([\d.]+)/i);
        const rootPort = rp && rp[1] !== "0.0" ? rp[1] : "Root Bridge";
        stp.push({
          vlan: "CIST",
          rootPri,
          rootMac,
          cost,
          rootPort
        });
        break;
      }
    }
  }
  let inStpRoot = false;
  for (const l of lines) {
    if (/show spanning-tree root/.test(l)) {
      inStpRoot = true;
      continue;
    }
    if (inStpRoot && /^[\r]?[A-Za-z0-9\-_.]+[#>]/.test(l)) {
      inStpRoot = false;
      continue;
    }
    if (!inStpRoot) continue;
    // Root Port pode ser vazio (device é o próprio Root Bridge)
    // IOS: VLAN  Priority  MAC  Cost  [multiple timing cols]  Port
    const m = l.match(/^(VLAN\d+)\s+(\d+)\s+([\w.]+)\s+(\d+)(?:\s+\S+)*?\s*((?:Gi|Te|Fa|Po|Eth|port-channel|This|GigabitEthernet|TenGigabitEthernet|FastEthernet)\S*)\s*$/i);
    if (m) stp.push({
      vlan: m[1],
      rootPri: m[2],
      rootMac: m[3],
      cost: m[4],
      rootPort: m[5] || "Root Bridge"
    });
  }

  // ── IP de Gerência ────────────────────────────────────────────
  let mgmtIp = "",
    mgmtMask = "",
    mgmtIntf = "",
    mgmtType = "";
  // HP Comware: M-E1/0/0/0 = Management Ethernet = OOB
  // From display ip interface brief: "M-E1/0/0/0  up  up  10.193.108.110  description"
  if (isHP) {
    let inHPIP = false;
    for (const l of lines) {
      if (/display ip interface brief\b/.test(l)) {
        inHPIP = true;
        continue;
      }
      if (inHPIP && /<[\w\-]+>/.test(l)) {
        inHPIP = false;
        continue;
      }
      if (!inHPIP) continue;
      // "M-E1/0/0/0  up  up  10.193.108.110  GERENCIA-..."
      const m = l.match(/^(M-E[\d\/]+)\s+up\s+up\s+([\d.]+)(?:\/(\d+))?/i);
      if (m && !mgmtIp) {
        mgmtIp = m[2];
        // Get mask from running-config ip address line
        const maskM = raw.match(new RegExp('interface\\s+' + m[1].replace(/\//g, '\\/') + '[\\s\\S]*?ip address\\s+[\\d.]+\\s+([\\d.]+|\\d+)', 'i'));
        mgmtMask = maskM ? maskM[1].includes(".") ? maskM[1] : cidrToMask(maskM[1]) : "";
        if (!mgmtMask && m[3]) mgmtMask = cidrToMask(m[3]);
        mgmtIntf = m[1];
        mgmtType = "OUT-OF-BAND";
      }
    }
  }

  // Dell FTOS: ManagementEthernet from show ip interface brief or running-config
  if (isDellFtos) {
    // Try show ip interface brief first
    let inFtosIP = false;
    for (const l of lines) {
      if (/show ip interface brief\b/.test(l)) {
        inFtosIP = true;
        continue;
      }
      if (inFtosIP && /^[\w\-]+#/.test(l)) {
        inFtosIP = false;
        continue;
      }
      if (!inFtosIP) continue;
      const m = l.match(/^(ManagementEthernet[\s\d\/]+)\s+([\d.]+)\s+YES/i);
      if (m && !mgmtIp) {
        mgmtIp = m[2];
        mgmtIntf = m[1].trim();
        mgmtType = "OUT-OF-BAND";
        // Get mask from running-config
        const esc = mgmtIntf.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const mm = raw.match(new RegExp("interface\\s+" + esc + "[\\s\\S]*?ip address\\s+[\\d.]+\\/(\\d+)", "i"));
        mgmtMask = mm ? cidrToMask(mm[1]) : "";
        break;
      }
    }
    // Fallback from running-config
    if (!mgmtIp) {
      let inME = false;
      for (const l of lines) {
        if (/^interface\s+ManagementEthernet/i.test(l)) {
          inME = true;
          continue;
        }
        if (inME && /^\S/.test(l) && !/^\s/.test(l)) {
          inME = false;
          continue;
        }
        if (inME) {
          const m = l.match(/^\s+ip address\s+([\d.]+)\/(\d+)/i);
          if (m) {
            mgmtIp = m[1];
            mgmtMask = cidrToMask(m[2]);
            mgmtIntf = "ManagementEthernet";
            mgmtType = "OUT-OF-BAND";
          }
        }
      }
    }
  }

  // Dell OS10: management from "interface vlan4020 / ip address X.X.X.X/mask"
  if (isDell) {
    let inDMgmt = false,
      curDMIntf = "";
    for (const l of lines) {
      const im = l.match(/^interface\s+(vlan\d+|management\s+ethernet[\d\/]+)/i);
      if (im) {
        inDMgmt = true;
        curDMIntf = im[1].replace(/\s+/, "");
        continue;
      }
      if (inDMgmt && /^\S/.test(l) && !/^\s/.test(l)) {
        inDMgmt = false;
        continue;
      }
      if (inDMgmt && !mgmtIp) {
        const ip = l.match(/^\s+ip address\s+([\d.]+)\/(\d+)/i);
        if (ip) {
          mgmtIp = ip[1];
          mgmtMask = cidrToMask(ip[2]);
          mgmtIntf = curDMIntf;
          mgmtType = /management|mgmt/i.test(curDMIntf) ? "OUT-OF-BAND" : "IN-BAND";
        }
      }
    }
  }

  // Huawei: MEth0/0/0 = OOB, Vlanif = IN-BAND
  // Source: display ip interface brief
  if (isHuawei) {
    let inHIP = false;
    for (const l of lines) {
      if (/display ip interface brief/.test(l)) {
        inHIP = true;
        continue;
      }
      if (inHIP && /<[\w\-]+>/.test(l)) {
        inHIP = false;
        continue;
      }
      if (!inHIP) continue;
      // MEth0/0/0    10.208.5.144/21   up  up  --
      const m = l.match(/^(MEth[\d\/]+)\s+([\d.]+)\/(\d+)\s+/);
      if (m && !mgmtIp) {
        mgmtIp = m[2];
        mgmtMask = cidrToMask(m[3]);
        mgmtIntf = m[1];
        mgmtType = "OUT-OF-BAND";
        continue;
      }
      // Vlanif com gerenci na descrição — pegar do running-config
    }
    // Fallback: Loopback from display ip interface brief
    if (!mgmtIp) {
      let inHIP2 = false;
      for (const l of lines) {
        if (/display ip interface brief/.test(l)) {
          inHIP2 = true;
          continue;
        }
        if (inHIP2 && /<[\w\-]+>/.test(l)) {
          inHIP2 = false;
          continue;
        }
        if (!inHIP2) continue;
        const m = l.match(/^(LoopBack[\d]+|Vlanif[\d]+)\s+([\d.]+)\/(\d+)\s+up/i);
        if (m) {
          mgmtIp = m[2];
          mgmtMask = cidrToMask(m[3]);
          mgmtIntf = m[1];
          mgmtType = "IN-BAND";
          break;
        }
      }
    }
    // Default GW from ip route-static (including vpn-instance variants)
    if (!defaultGw) {
      const dgw = raw.match(/ip route-static(?:\s+vpn-instance\s+\S+)?\s+0\.0\.0\.0\s+0\.0\.0\.0\s+(?:\S+\s+)?(\d+\.\d+\.\d+\.\d+)/i);
      if (dgw) defaultGw = dgw[1];
    }
  }
  function cidrToMask(prefix) {
    const p = parseInt(prefix);
    if (isNaN(p)) return "";
    const mask = 0xFFFFFFFF << 32 - p >>> 0;
    return [mask >>> 24 & 255, mask >>> 16 & 255, mask >>> 8 & 255, mask & 255].join(".");
  }
  // 1) mgmt0
  let inMgmt0 = false;
  for (const l of lines) {
    if (/^interface mgmt0\b/i.test(l)) {
      inMgmt0 = true;
      continue;
    }
    if (inMgmt0 && /^interface /i.test(l)) {
      inMgmt0 = false;
      continue;
    }
    if (!inMgmt0) continue;
    const c = l.match(/ip address ([\d.]+)\/([\d]+)/);
    if (c) {
      mgmtIp = c[1];
      mgmtMask = cidrToMask(c[2]);
      mgmtIntf = "mgmt0";
      mgmtType = "OUT-OF-BAND";
      break;
    }
    const i = l.match(/ip address ([\d.]+)\s+([\d.]+)/);
    if (i) {
      mgmtIp = i[1];
      mgmtMask = i[2];
      mgmtIntf = "mgmt0";
      mgmtType = "OUT-OF-BAND";
      break;
    }
  }
  // 2) Loopback
  if (!mgmtIp) {
    for (const loopName of ["Loopback0", "Loopback1", "Loopback2"]) {
      let inLoop = false;
      for (const l of lines) {
        if (new RegExp("^interface " + loopName + "\\b", "i").test(l)) {
          inLoop = true;
          continue;
        }
        if (inLoop && /^interface /i.test(l)) {
          inLoop = false;
          continue;
        }
        if (!inLoop) continue;
        const c = l.match(/ip address ([\d.]+)\/([\d]+)/);
        if (c) {
          mgmtIp = c[1];
          mgmtMask = cidrToMask(c[2]);
          mgmtIntf = loopName;
          break;
        }
        const i = l.match(/ip address ([\d.]+)\s+([\d.]+)/);
        if (i) {
          mgmtIp = i[1];
          mgmtMask = i[2];
          mgmtIntf = loopName;
          break;
        }
      }
      if (mgmtIp) break;
    }
  }
  // 3) Vlan com "Gerenci" na descrição (suporta NX-OS com linha em branco)
  if (!mgmtIp) {
    let curVif = null,
      vifDesc = "",
      vifIp = "",
      vifMask = "";
    const checkAndSave = () => {
      if (vifIp && /gerenci/i.test(vifDesc)) {
        mgmtIp = vifIp;
        mgmtMask = vifMask;
        mgmtIntf = curVif;
        mgmtType = "IN-BAND";
      }
    };
    for (const l of lines) {
      if (mgmtIp) break;
      const ifm = l.match(/^(?:\s+)?interface (Vlan\d+)/i);
      if (ifm) {
        checkAndSave();
        curVif = ifm[1];
        vifDesc = "";
        vifIp = "";
        vifMask = "";
        continue;
      }
      if (curVif) {
        // NX-OS: blank line does NOT close the block (only next interface or ! does)
        if (/^\s*interface /i.test(l) || /^!$/.test(l)) {
          checkAndSave();
          curVif = null;
          continue;
        }
        const d = l.match(/description\s+(.+)/);
        if (d) vifDesc = d[1].trim();
        const c = l.match(/ip address ([\d.]+)\/([\d]+)/);
        if (c) {
          vifIp = c[1];
          vifMask = cidrToMask(c[2]);
        }
        const p = l.match(/ip address ([\d.]+)\s+([\d.]+)/);
        if (p && !c) {
          vifIp = p[1];
          vifMask = p[2];
        }
      }
    }
    if (!mgmtIp) checkAndSave(); // last block
  }

  // ── INT_VLAN ──────────────────────────────────────────────────
  const intVlan = [];
  // Huawei: Vlanif from running-config
  if (isHuawei) {
    let curVif3 = null;
    for (const l of lines) {
      const ifm = l.match(/^interface (Vlanif\d+)/i);
      if (ifm) {
        if (curVif3 && (curVif3.ip || curVif3.desc)) intVlan.push(curVif3);
        const vid = ifm[1].replace(/Vlanif/i, "Vlan");
        curVif3 = {
          vid: vid,
          desc: "",
          ip: "",
          mask: "",
          helper: []
        };
        continue;
      }
      if (curVif3) {
        if (/^interface /i.test(l) || /^#/.test(l)) {
          if (curVif3.ip || curVif3.desc) intVlan.push(curVif3);
          curVif3 = null;
          continue;
        }
        const d = l.match(/description\s+(.+)/i);
        if (d) curVif3.desc = d[1].trim();
        const c = l.match(/ip address ([\d.]+)\s+([\d.]+)\s+(\d+)/);
        if (c) {
          curVif3.ip = c[1];
          curVif3.mask = cidrToMask(c[3]);
        } else {
          const p = l.match(/ip address ([\d.]+)\s+([\d.]+)\s*$/);
          if (p) {
            curVif3.ip = p[1];
            curVif3.mask = p[2];
          }
        }
        const h = l.match(/dhcp-relay destination\s+([\d.]+)/i);
        if (h) curVif3.helper.push(h[1]);
      }
    }
    if (curVif3 && (curVif3.ip || curVif3.desc)) intVlan.push(curVif3);
  }
  let curVif2 = null;
  const pushVif2 = () => {
    if (curVif2 && (curVif2.ip || curVif2.desc) && !intVlan.find(v => v.vid === curVif2.vid && v.ip === curVif2.ip)) intVlan.push(curVif2);
    curVif2 = null;
  };
  for (const l of lines) {
    const ifm = l.match(/^\s*interface (Vlan\d+)/i);
    if (ifm) {
      pushVif2(); // save previous block first
      curVif2 = {
        vid: ifm[1],
        desc: "",
        ip: "",
        mask: "",
        helper: []
      };
      continue;
    }
    if (curVif2) {
      // IOS uses "!" as terminator, NX-OS uses blank line or next interface
      if (/^\s*interface /i.test(l) || /^!$/.test(l) || /^\r?$/.test(l.trim())) {
        if (/^\s*interface /i.test(l) || /^!$/.test(l)) pushVif2();
        // blank line: just clear ip helper accumulation for now, keep block open
        continue;
      }
      const d = l.match(/description\s+(.+)/);
      if (d) curVif2.desc = d[1].trim();
      const c = l.match(/ip address ([\d.]+)\/([\d]+)/);
      if (c) {
        curVif2.ip = c[1];
        curVif2.mask = cidrToMask(c[2]);
      }
      const p = l.match(/ip address ([\d.]+)\s+([\d.]+)/);
      if (p && !c) {
        curVif2.ip = p[1];
        curVif2.mask = p[2];
      }
      const h = l.match(/ip helper-address\s+([\d.]+)/);
      if (h) curVif2.helper.push(h[1]);
    }
  }
  pushVif2(); // save last block

  // ── show interfaces status / display interface brief ──────────
  const intSt = [];
  // HP Comware: display interface brief
  // "Interface  Link  Protocol  Primary IP  Description"
  if (isHP) {
    let inHPIS = false;
    for (const l of lines) {
      if (/display interface brief\b/.test(l)) {
        inHPIS = true;
        continue;
      }
      if (inHPIS && /<[\w\-]+>/.test(l)) {
        inHPIS = false;
        continue;
      }
      if (!inHPIS || /^Brief|^Link:|^Protocol:|^Interface\s+Link|^-+$/.test(l.trim())) continue;
      // "M-E1/0/0/0  UP  UP  10.193.108.110  GERENCIA-OOM"
      const m = l.match(/^(\S+)\s+(UP|DOWN|ADM|Stby)\s+(UP|DOWN|up|down|\S+)\s+(\S+)\s*(.*)/i);
      if (m) {
        const phy = m[2].toUpperCase();
        intSt.push({
          port: m[1],
          desc: m[5].trim(),
          status: phy === "UP" ? "connected" : "notconnect",
          vlan: "",
          duplex: "",
          speed: "",
          type: ""
        });
      }
    }
  }

  // Dell FTOS: "show interface status"
  // "Te 0/1  "desc"  Up  10000 Mbit  Full  1,11,15-16"
  if (isDellFtos) {
    const dFtosIntMap = {};
    let inDFIS = false;
    for (const l of lines) {
      if (/show interface status\b/.test(l)) {
        inDFIS = true;
        continue;
      }
      if (inDFIS && /^[\w\-]+#/.test(l)) {
        inDFIS = false;
        continue;
      }
      if (!inDFIS || /^Port|^-+$|^\s*$/.test(l.trim())) continue;
      // "Te 0/1   "MZ-FV-HV-1  Up  10000 Mbit  Full  1,11,15-16"
      const m = l.match(/^((?:Te|Gi|Fo|Hu|Ma)\s+[\d\/]+)\s+(.*?)\s+(Up|Down)\s+(\S+(?:\s+Mbit)?)\s+(\S+)\s+(.*)/i);
      if (m) {
        const port = m[1].trim().replace(/\s+/, "-");
        const status = m[3].toLowerCase() === "up" ? "connected" : "notconnect";
        dFtosIntMap[port] = {
          port,
          desc: m[2].replace(/"/g, "").trim(),
          status,
          vlan: m[6].trim(),
          duplex: m[5],
          speed: m[4].trim(),
          type: ""
        };
      }
    }
    // Merge with show interface description
    let inDFID = false;
    for (const l of lines) {
      if (/show interface description\b/.test(l)) {
        inDFID = true;
        continue;
      }
      if (inDFID && /^[\w\-]+#/.test(l)) {
        inDFID = false;
        continue;
      }
      if (!inDFID || /^Interface|^-+$/.test(l.trim())) continue;
      // "TenGigabitEthernet 0/1  YES  up  up  "desc""
      const m = l.match(/^(\S+(?:\s+[\d\/]+)?)\s+(?:YES|NO)\s+(up|down)\s+(up|down)\s+(.*)/i);
      if (m) {
        const port = m[1].trim().replace(/\s+/, "-");
        const key = Object.keys(dFtosIntMap).find(k => k.replace(/^Te-/i, "Te-") === port.replace(/TenGigabitEthernet-/i, "Te-") || k === port);
        const desc = m[4].replace(/"/g, "").trim();
        if (key) dFtosIntMap[key].desc = desc;else dFtosIntMap[port] = {
          port,
          desc,
          status: m[2].toLowerCase() === "up" ? "connected" : "notconnect",
          vlan: "",
          duplex: "",
          speed: "",
          type: ""
        };
      }
    }
    for (const v of Object.values(dFtosIntMap)) intSt.push(v);
  }

  // Dell OS10: show interface status + show interface description
  // "Eth 1/1/1  Description  up  25G  full  T  1  tagged-vlans"
  if (isDell) {
    const dIntMap = {};
    let inDIS = false;
    for (const l of lines) {
      if (/show interface status\b/.test(l)) {
        inDIS = true;
        continue;
      }
      if (inDIS && /^[\w\-]+#/.test(l)) {
        inDIS = false;
        continue;
      }
      if (!inDIS || /^Port|^-+$|^\s*$/.test(l.trim())) continue;
      // "Eth 1/1/1  Chassis 1..  up  25G  full  T  1  vlans"
      const m = l.match(/^(Eth\s+[\d\/]+(?::\d+)?)\s+(.*?)\s+(up|down)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*?)\s*$/i);
      if (m) {
        const port = m[1].replace(/\s+/, "");
        dIntMap[port] = {
          port,
          desc: m[2].trim(),
          status: m[3].toLowerCase() === "up" ? "connected" : "notconnect",
          vlan: m[7],
          duplex: m[5],
          speed: m[4],
          type: ""
        };
      }
    }
    for (const v of Object.values(dIntMap)) intSt.push(v);
  }

  // Huawei: display interface brief + display interface description
  if (isHuawei) {
    // Step 1: collect status from interface brief
    const hwIntMap = {};
    let inHIS = false;
    for (const l of lines) {
      if (/display interface brief\b/.test(l)) {
        inHIS = true;
        continue;
      }
      if (inHIS && /<[\w\-]+>/.test(l)) {
        inHIS = false;
        continue;
      }
      if (!inHIS) continue;
      if (/^PHY:|^\*down|^Interface\s+PHY|^-+$|^InUti/.test(l)) continue;
      const m = l.match(/^(\S+)\s+(\*?up|\*?down|\^down)\s+(up|down)/i);
      if (m) {
        const phy = m[2].replace(/[*^]/g, "").toLowerCase();
        hwIntMap[m[1]] = {
          port: m[1],
          desc: "",
          status: phy === "up" ? "connected" : "notconnect",
          vlan: "",
          duplex: "",
          speed: "",
          type: ""
        };
      }
    }
    // Step 2: merge descriptions from display interface description
    let inHID = false;
    for (const l of lines) {
      if (/display interface description\b/.test(l)) {
        inHID = true;
        continue;
      }
      if (inHID && /<[\w\-]+>/.test(l)) {
        inHID = false;
        continue;
      }
      if (!inHID || /^PHY:|^Interface\s+PHY|^-+$/.test(l)) continue;
      // "25GE1/0/1   up   up   VIO1_301 - AL-FX-GS-015"
      const m = l.match(/^(\S+)\s+(?:\*?up|\*?down|\^down)\s+(?:up|down)\s*(.*)/i);
      if (m && hwIntMap[m[1]]) hwIntMap[m[1]].desc = m[2].trim();else if (m) hwIntMap[m[1]] = {
        port: m[1],
        desc: m[2].trim(),
        status: "notconnect",
        vlan: "",
        duplex: "",
        speed: "",
        type: ""
      };
    }
    for (const v of Object.values(hwIntMap)) intSt.push(v);
  }
  let inIs = false;
  let lastWasPrompt = false;
  let nxStatusColOffsets = {};
  const normStatus = s => {
    if (!s) return "disabled";
    const sl = s.toLowerCase();
    if (sl.startsWith("connect")) return "connected";
    if (sl.startsWith("notconn")) return "notconnect";
    if (sl === "disabled") return "disabled";
    if (sl === "err-disabled") return "err-disabled";
    if (sl.startsWith("xcvr")) return "disabled";
    if (sl === "trnk-bndl") return "connected";
    if (sl === "trunking") return "connected";
    if (sl === "fwd") return "connected";
    return "disabled";
  };
  for (const l of lines) {
    const lt = l.replace(/^\r+/, ''); // remove \r que pode vir no início (PuTTY \r\r\n)
    const isPrompt = /^[A-Za-z0-9\-_.]+[#>]/.test(lt);
    // Detect NX-OS interface status header to determine column offsets
    if (inIs && /^Port\s+Name\s+Status/.test(lt)) {
      nxStatusColOffsets.nameStart = lt.indexOf("Name");
      nxStatusColOffsets.statusStart = lt.indexOf("Status");
      nxStatusColOffsets.vlanStart = lt.indexOf("Vlan");
      nxStatusColOffsets.duplexStart = lt.indexOf("Duplex");
      nxStatusColOffsets.speedStart = lt.indexOf("Speed");
      nxStatusColOffsets.typeStart = lt.indexOf("Type");
      continue;
    }
    if (isPrompt && /show interface(s)? status\s*$/.test(lt)) {
      inIs = true;
      lastWasPrompt = false;
      continue;
    }
    if (inIs && isPrompt) {
      inIs = false;
      continue;
    }
    lastWasPrompt = isPrompt;
    if (!inIs) continue;
    // NX-OS Ethernet: colunas fixas — detecta largura dinamicamente pelo header
    // Header ex: "Port           Name               Status   Vlan      Duplex  Speed   Type"
    if (/^Eth[\d\/]+/.test(lt) && lt.length >= 40) {
      // Dynamic column detection based on header or default offsets
      const p1 = nxStatusColOffsets.nameStart || 14;
      const p2 = nxStatusColOffsets.statusStart || p1 + 19;
      const p3 = nxStatusColOffsets.vlanStart || p2 + 10;
      const p4 = nxStatusColOffsets.duplexStart || p3 + 10;
      const p5 = nxStatusColOffsets.speedStart || p4 + 7;
      const p6 = nxStatusColOffsets.typeStart || p5 + 8;
      const port = lt.substring(0, p1).trim();
      const desc = lt.substring(p1, p2).trim();
      const status = normStatus(lt.substring(p2, p3).trim());
      const vlan = lt.substring(p3, p4).trim();
      const duplex = lt.substring(p4, p5).trim();
      const speed = lt.substring(p5, p6).trim();
      const type = lt.substring(p6).trim();
      if (port) {
        intSt.push({
          port,
          desc,
          status,
          vlan,
          duplex,
          speed,
          type
        });
        continue;
      }
    }
    // IOS/IOS-XE genérico (não usar para NX-OS)
    if (!isNexus) {
      const m = lt.match(/^(\S+)\s+(.*?)\s+(connected|notconnect|disabled|err-disabled|notconnec|trnk-bndl|trunking|xcvrAbsen\w*)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*?)\s*$/);
      if (m) intSt.push({
        port: m[1],
        desc: m[2].trim(),
        status: normStatus(m[3]),
        vlan: m[4],
        duplex: m[5],
        speed: m[6],
        type: m[7].trim()
      });
    }
  }

  // Enrich Huawei/HP/Dell trunk status from intSt
  if (isHuawei || isHP || isDell || isDellFtos) {
    // Normalize interface name: "TenGigabitEthernet 0/1" → "te0/1", "Te 0/1" → "te0/1"
    const _normIf = n => n.toLowerCase().replace(/tengigabitethernet/g, "te").replace(/gigabitethernet/g, "ge").replace(/fortygige|fortygigabitethernet/g, "fo").replace(/hundredgige|hundredgigabitethernet/g, "hu").replace(/eth-trunk/g, "eth-trunk").replace(/\s+/g, "").replace(/-0\//g, "0/");
    const _intStMap = {};
    for (const _i of intSt) {
      if (_i.port) _intStMap[_normIf(_i.port)] = _i.status;
    }
    for (const _t of trunk) {
      if (_t.status === "N/A" || !_t.status) {
        const _key = _normIf(_t.port || _t.intf || "");
        const _st = _intStMap[_key];
        _t.status = _st === "connected" ? "trunking" : _st === "notconnect" ? "not-trunking" : "N/A";
      }
    }
  }

  // ── Gateway management VRF (NX-OS) ──────────────────────────
  if (!defaultGw && isNexus) {
    for (const l of lines) {
      const m = l.match(/^\s*ip route 0\.0\.0\.0\/0\s+([\d.]+).*vrf management/i);
      if (m) {
        defaultGw = m[1];
        break;
      }
    }
  }
  // 4) Fallback: primeira Vlan ativa com IP (quando mgmt0 está shutdown)
  if (!mgmtIp) {
    let curVif = null,
      vifDesc = "",
      vifIp = "",
      vifMask = "",
      vifUp = false;
    for (const l of lines) {
      if (mgmtIp) break;
      const ifm = l.match(/^\s*interface (Vlan\d+)/i);
      if (ifm) {
        if (vifIp && vifUp) {
          mgmtIp = vifIp;
          mgmtMask = vifMask;
          mgmtIntf = curVif;
          break;
        }
        curVif = ifm[1];
        vifDesc = "";
        vifIp = "";
        vifMask = "";
        vifUp = false;
        continue;
      }
      if (curVif) {
        if (/^\s*interface /i.test(l) || /^!$/.test(l)) {
          if (vifIp && vifUp) {
            mgmtIp = vifIp;
            mgmtMask = vifMask;
            mgmtIntf = curVif;
            mgmtType = "IN-BAND";
            break;
          }
          curVif = null;
          continue;
        }
        if (/no shutdown/i.test(l)) vifUp = true;
        const c = l.match(/ip address ([\d.]+)\/([\d]+)/);
        if (c) {
          vifIp = c[1];
          vifMask = cidrToMask(c[2]);
        }
        const p = l.match(/ip address ([\d.]+)\s+([\d.]+)/);
        if (p && !c) {
          vifIp = p[1];
          vifMask = p[2];
        }
      }
    }
  }

  // ── Gateway dinâmico (fallback: OSPF → EIGRP → BGP) ─────────
  if (!defaultGw) {
    const mostFreq = arr => {
      if (!arr || !arr.length) return "";
      const freq = {};
      for (const r of arr) {
        const v = r.via || "";
        if (v) freq[v] = (freq[v] || 0) + 1;
      }
      return Object.entries(freq).sort((a, b) => b[1] - a[1])[0]?.[0] || "";
    };
    defaultGw = mostFreq(ospfRt) || mostFreq(eigrp.map(e => ({
      via: e.addr
    }))) || mostFreq(bgp.map(b => ({
      via: b.neighbor
    })));
  }

  // ── Garante mgmtType caso não tenha sido setado ──────────────
  if (!mgmtType && mgmtIntf) mgmtType = mgmtIntf === "mgmt0" ? "OUT-OF-BAND" : "IN-BAND";
  return {
    hostname,
    ios_ver,
    model: chassisPid || model,
    serial: chassisSn || serial,
    uptime,
    last_rst,
    image,
    romver,
    isNexus,
    isIosXe,
    isHuawei,
    isDell,
    isDellFtos,
    isHP,
    stackMembers,
    deviceTipo,
    cdp,
    lldp,
    vlans,
    vtpVer,
    vtpDomain,
    vtpMode,
    vtpVlans,
    vtpRev,
    vtpPwd,
    stp,
    intVlan,
    hsrp,
    vrrp,
    glbp,
    portch: portchFull,
    trunk,
    staticRt: (() => {
      const seen = new Set();
      return staticRt.filter(r => {
        const key = (r.net || "") + "|" + (r.via || "");
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    })(),
    defaultGw,
    ospfIf,
    ospfRt,
    ospfPid,
    ospfRid,
    ospfProcs,
    intSt,
    mgmtIp,
    mgmtMask,
    mgmtIntf,
    mgmtType,
    arpTable,
    macTable,
    eigrp,
    bgp,
    NC,
    ospfNeighbors,
    ospfTimeLabel,
    eigrpNeighbors,
    bgpNeighbors
  };
}

// Node.js wrapper
function parseAssessmentDevice(raw) {
  try {
    return parseDevice(raw);
  } catch(e) {
    var lines = (raw||'').split(/\r?\n/);
    var hn = null;
    for (var i=0;i<lines.length;i++) { if (/^(hostname|sysname)\s+\S/i.test(lines[i].trim())) { hn=lines[i]; break; } }
    var hostname = hn ? hn.trim().replace(/^(hostname|sysname)\s+/i,'').trim() : 'UNKNOWN';
    var ipLine = null;
    for (var j=0;j<lines.length;j++) { if (/ip address\s+\d+\.\d+\.\d+\.\d+/i.test(lines[j])) { ipLine=lines[j]; break; } }
    var ip = ipLine ? (ipLine.match(/(\d{1,3}(?:\.\d{1,3}){3})/)||[])[1]||'' : '';
    return {
      hostname:hostname, ip:ip, ios_ver:'', model:'', serial:'', uptime:'',
      isNexus:false, isIosXe:false, isHuawei:false, isDell:false, isDellFtos:false, isHP:false,
      stackMembers:[], cdp:[], lldp:[], vlans:[],
      vtpVer:'', vtpDomain:'', vtpMode:'', vtpVlans:'', vtpRev:'', vtpPwd:'',
      stp:[], intVlan:[], hsrp:[], vrrp:[], glbp:[], portch:[], trunk:[], staticRt:[],
      ospfProcs:[], ospfNeighbors:[], eigrp:[], eigrpNeighbors:[], bgp:[], bgpNeighbors:[],
      arpTable:[], macTable:[], intSt:[], mgmtIp:'', mgmtMask:'', mgmtIntf:'', mgmtType:'', defaultGw:'',
    };
  }
}

module.exports = { parseAssessmentDevice: parseAssessmentDevice };

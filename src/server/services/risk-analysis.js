// ─────────────────────────────────────────────────────────────────────────────
// Magneto — Risk Assessment Module
// Integrates runAnalysis for: IOS, NX-OS, Dell OS10, HP Comware, Huawei VRP
// ─────────────────────────────────────────────────────────────────────────────

// ── Individual OS analysis engines ───────────────────────────────────────────

function runAnalysis_ios(log){

  // Abreviar nomes de interfaces
  function abbrevIf(s){
    return s.replace(/GigabitEthernet/gi,'Gi').replace(/FastEthernet/gi,'Fa')
            .replace(/TenGigabitEthernet/gi,'Te').replace(/TengigabitEthernet/gi,'Te')
            .replace(/Port-channel/gi,'Po').replace(/port-channel/gi,'Po')
            .replace(/Loopback/gi,'Lo').replace(/Vlan/gi,'Vlan');
  }
  function abbrevList(arr){return arr.map(function(x){return abbrevIf(x);});}

  var L=log.split('\n');
  var items=[];
  function has(kw){return L.some(function(l){return l.toLowerCase().includes(kw.toLowerCase());});}
  function find(kw){return L.filter(function(l){return l.toLowerCase().includes(kw.toLowerCase());});}
  function S(sec){items.push({status:'SECTION',item:sec});}
  function A(item,status,risco,obs){items.push({item:item,status:status,risco:risco,obs:obs});}

  // ===== DETECÇÃO DE PLATAFORMA E VERSÃO =====
  var hostVersion='';
  var isSwitch=false, isRouter=false, isCat6K=false, isCat3K=false, isCat2K=false, isBlade=false;

  var verLine=L.find(function(l){return /Cisco IOS Software.*Version\s+[\d\.]+/i.test(l);});
  if(verLine){var vm=verLine.match(/Version\s+([\d\.\(\)a-zA-Z]+)/i);if(vm)hostVersion=vm[1];}
  var majorVer=parseInt((hostVersion.match(/^(\d+)\./)||['','0'])[1])||0;

  // Detectar modelo pelo PID ou linha cisco WS-C
  var modelLine=L.find(function(l){return /cisco\s+(WS-C|CBS|C[23456789]\d{3})/i.test(l)&&/processor/i.test(l);});
  if(!modelLine)modelLine=L.find(function(l){return /NAME:.*WS-C|NAME:.*CBS|NAME:.*C[23456789]\d{3}/i.test(l);});
  var modelStr=modelLine?(modelLine.match(/(WS-C[\w-]+|CBS[\w-]+|C[23456789]\d{3}[\w-]*)/i)||['',''])[1]:'';

  if(/WS-C6[45]\d{2}|WS-C6[0-9]{3}/i.test(modelStr)){isCat6K=true;isSwitch=true;}
  else if(/WS-C3[5-9]\d{2}|C3[5-9]\d{2}/i.test(modelStr)){isCat3K=true;isSwitch=true;}
  else if(/WS-C2[0-9]\d{2}|C2[0-9]\d{2}/i.test(modelStr)){isCat2K=true;isSwitch=true;}
  else if(/CBS3\d{3}/i.test(modelStr)){isBlade=true;isSwitch=true;}
  else if(/WS-C/i.test(modelStr)){isSwitch=true;}
  // Fallback: se tem spanning-tree, vlan, switchport → switch
  if(!isSwitch&&!isRouter){
    if(has('spanning-tree')||has('switchport')||has('vtp mode'))isSwitch=true;
    else isRouter=true;
  }
  var platStr=modelStr||(isSwitch?'Catalyst':'IOS Router');
  if(hostVersion)platStr+=' '+hostVersion;

  // ===== VARIÁVEIS PRÉ-CALCULADAS =====
  var snmpComm=find('snmp-server community').filter(function(l){return l.trim().startsWith('snmp-server community');});
  var snmpUsers=find('snmp-server user').filter(function(l){return l.trim().startsWith('snmp-server user');});

  // SSH
  var sshV2=has('ip ssh version 2');
  var sshKeyPresent=L.some(function(l){return/^ssh-rsa AAAA|^ssh-dsa AAAA/i.test(l.trim());});
  var cryptoKeyExist=has('crypto key generate rsa')||L.some(function(l){return/^crypto key/i.test(l.trim())&&/rsa/i.test(l);});
  var sshEnabled=sshV2||sshKeyPresent||cryptoKeyExist||has('ip ssh');
  var transportSsh=find('transport input').some(function(l){return l.includes('ssh')&&!l.includes('telnet');});

  // exec-timeout por bloco
  var exToVty=[];var exToCon=[];var inVty=false;var inCon=false;
  L.forEach(function(l){
    var lt=l.trim();
    if(/^line vty/.test(lt)){inVty=true;inCon=false;}
    else if(/^line con/.test(lt)){inCon=true;inVty=false;}
    else if(/^line /.test(lt)){inVty=false;inCon=false;}
    if(lt.startsWith('exec-timeout')){if(inVty)exToVty.push(lt);if(inCon)exToCon.push(lt);}
  });

  // Port-channel / EtherChannel
  var cgLines=find('channel-group').filter(function(l){return/channel-group\s+\d+/.test(l.trim());});
  var poIfaces=L.filter(function(l){return/^interface [Pp]ort-[Cc]hannel\d+/i.test(l.trim());});
  var cgModes={on:0,active:0,passive:0,auto:0,desirable:0};
  cgLines.forEach(function(l){var m=l.match(/mode\s+(\S+)/i);if(m){var md=m[1].toLowerCase();if(cgModes[md]!==undefined)cgModes[md]++;else cgModes.on++;}});
  var cgNone=cgModes.on;
  var cgLacp=cgModes.active+cgModes.passive;
  var cgPagp=cgModes.auto+cgModes.desirable;

  // interface status — show interfaces / show etherchannel summary
  var ecIdx=L.findIndex(function(l){return/Group\s+Port[-\s]/i.test(l);});
  var ecLines=[];
  if(ecIdx>=0){for(var i=ecIdx+1;i<Math.min(ecIdx+100,L.length);i++){var pl=L[i].trim();if(!pl||/^-+$/.test(pl))continue;if(pl.startsWith('show ')||pl.includes('#'))break;if(/^\d+\s+Po\d+|^Po\d+/.test(pl))ecLines.push(pl);}}
  var ecDown=ecLines.filter(function(l){return/\(SD\)|\(RD\)/.test(l);});
  var ecSU=ecLines.filter(function(l){return/\(SU\)/.test(l);});
  var ecMemD=ecLines.filter(function(l){return/Eth\S+\([Dd]\)|Gi\S+\([Dd]\)|Fa\S+\([Dd]\)/.test(l);});
  var ecMemS=ecLines.filter(function(l){return/Eth\S+\([sS]\)|Gi\S+\([sS]\)|Fa\S+\([sS]\)/.test(l);});
  var ecNone=ecLines.filter(function(l){return/\bNONE\b/.test(l);});

  // OSPF/BGP/EIGRP
  var hasOspf=L.some(function(l){return/^router ospf/.test(l.trim());});
  var hasBgp=L.some(function(l){return/^router bgp/.test(l.trim());});
  var hasEigrp=L.some(function(l){return/^router eigrp/.test(l.trim());});

  // HSRP/VRRP/GLBP
  var hsrpIfaces=find('standby').filter(function(l){return/standby\s+\d*\s*ip/.test(l);});
  var vrrpIfaces=find('vrrp').filter(function(l){return/vrrp\s+\d+\s+ip/.test(l);});
  var glbpIfaces=find('glbp').filter(function(l){return/glbp\s+\d+\s+ip/.test(l);});

  // NTP
  var ntpSvrs=find('ntp server').filter(function(l){return l.trim().startsWith('ntp server');});
  var ntpIPs=[...new Set(ntpSvrs.map(function(l){return l.trim().replace(/^ntp server\s+/i,'').split(' ')[0];}).filter(Boolean))];

  // TACACS
  var tacOld=find('tacacs-server host').filter(function(l){return l.trim().startsWith('tacacs-server host');});
  var tacGrp=find('aaa group server tacacs+').filter(function(l){return l.trim().startsWith('aaa group server tacacs+');});
  var tacNewBlk=find('tacacs server ').filter(function(l){return/^tacacs server\s+\S+/i.test(l.trim());});
  var tacHostNew=find('address ipv4').filter(function(l){return l.trim().startsWith('address ipv4');});

  // ================================================================
  S('AUTENTICAÇÃO E ACESSO');
  // ================================================================

  // 01. SSH
  if(sshEnabled&&sshV2&&transportSsh){A('SSH','SIM','N/A','SSH versão 2 habilitado. Acesso VTY restrito a SSH.');}
  else if(sshEnabled&&sshV2){A('SSH','PARCIAL','⚠','SSH versão 2 habilitado mas VTY aceita outros protocolos. Configurar "transport input ssh".');}
  else if(sshEnabled){A('SSH','PARCIAL','⚠','SSH habilitado mas versão 2 não configurada. Usar "ip ssh version 2".');}
  else{A('SSH','NÃO','✘','SSH não habilitado. Gerar chave RSA e configurar "ip ssh version 2".');}

  // 02. TELNET
  var telnetVty=find('transport input').some(function(l){return l.toLowerCase().includes('telnet')&&!l.trim().startsWith('no ');});
  if(telnetVty){A('TELNET','SIM','✘','Telnet habilitado. Protocolo inseguro — configurar "transport input ssh".');}
  else{A('TELNET','NÃO','N/A','Telnet não habilitado.');}

  // 03. ACL PARA GERÊNCIA (VTY)
  var aclVty=find('access-class').filter(function(l){return l.trim().startsWith('access-class')&&l.includes('in');});
  if(aclVty.length>0){var aname=(aclVty[0].trim().match(/access-class\s+(\S+)/)||['',''])[1];A('ACL PARA GERÊNCIA (VTY)','SIM','N/A','ACL de gerência aplicada ao VTY: '+aname+'.');}
  else{A('ACL PARA GERÊNCIA (VTY)','NÃO','⚠','Nenhuma ACL (access-class) aplicada ao line vty.');}

  // 04. TACACS/RADIUS (AAA)
  if(tacOld.length>0){var ips=[...new Set(tacOld.map(function(l){return(l.match(/tacacs-server host\s+([\d\.]+)/)||['',''])[1];}).filter(Boolean))];A('TACACS/RADIUS (AAA)','SIM','N/A','TACACS+ configurado. '+ips.length+' servidor(es): '+ips.join(', ')+'.');}
  else if(tacGrp.length>0){var svrs=find('tacacs-server host').concat(find('address ipv4')).filter(function(l){return l.trim().startsWith('tacacs-server host')||l.trim().startsWith('address ipv4');});var ips2=[...new Set(svrs.map(function(l){return(l.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)||['',''])[1];}).filter(Boolean))];A('TACACS/RADIUS (AAA)','SIM','N/A','TACACS+ configurado via aaa group. '+(ips2.length>0?ips2.length+' servidor(es): '+ips2.join(', ')+'.':'Incluir "show tacacs" no log.'));}
  else if(tacNewBlk.length>0){var ips3=[...new Set(tacHostNew.map(function(l){return(l.match(/address ipv4\s+([\d\.]+)/)||['',''])[1];}).filter(Boolean))];A('TACACS/RADIUS (AAA)','SIM','N/A','TACACS+ configurado. '+tacNewBlk.length+' bloco(s): '+(ips3.length>0?ips3.join(', '):'ver config')+'.');}
  else if(has('radius-server host')){var rips=[...new Set(find('radius-server host').map(function(l){return(l.match(/radius-server host\s+([\d\.]+)/)||['',''])[1];}).filter(Boolean))];A('TACACS/RADIUS (AAA)','SIM','N/A','RADIUS configurado. '+rips.length+' servidor(es): '+rips.join(', ')+'.');}
  else{A('TACACS/RADIUS (AAA)','NÃO','✘','Nenhum servidor TACACS+/RADIUS configurado. Autenticação apenas local.');}

  // 05. AAA NEW-MODEL
  var aaaLines=find('aaa authentication login').filter(function(l){return l.trim().startsWith('aaa authentication login');});
  var aaaAcct=find('aaa accounting').filter(function(l){return l.trim().startsWith('aaa accounting');});
  if(has('aaa new-model')&&aaaLines.length>0){A('AAA NEW-MODEL','SIM','N/A','AAA new-model habilitado: '+aaaLines[0].trim()+(aaaAcct.length>0?'. Accounting configurado.':'.')+'.');}
  else if(has('aaa new-model')){A('AAA NEW-MODEL','PARCIAL','⚠','aaa new-model habilitado mas sem políticas de autenticação configuradas.');}
  else{A('AAA NEW-MODEL','NÃO','⚠','aaa new-model não configurado. Autenticação sem política centralizada.');}

  // 06. USERNAME LOCAL (FALLBACK)
  var users=find('username ').filter(function(l){return l.trim().startsWith('username ');});
  var uniqueUsers=[...new Set(users.map(function(l){return l.trim().split(' ')[1];}).filter(Boolean))];
  if(uniqueUsers.length>0){A('USERNAME LOCAL (FALLBACK)','SIM','N/A',uniqueUsers.length+' usuário(s) local(is): '+uniqueUsers.slice(0,4).join(', ')+'.');}
  else{A('USERNAME LOCAL (FALLBACK)','NÃO','⚠','Nenhum usuário local. Sem fallback de autenticação se AAA cair.');}

  // 07. LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)
  if(has('login block-for')){A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','SIM','N/A',(find('login block-for')[0]||'').trim()+'.');}
  else{A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','NÃO','⚠','Login block-for não configurado. Sem proteção contra brute-force SSH.');}

  // 08. EXEC-TIMEOUT
  if(exToVty.length>0){A('EXEC-TIMEOUT','SIM','N/A','exec-timeout VTY: '+exToVty[0].replace('exec-timeout','').trim()+' min.');}
  else if(has('exec-timeout')){A('EXEC-TIMEOUT','SIM','N/A','exec-timeout configurado.');}
  else{A('EXEC-TIMEOUT','NÃO','⚠','exec-timeout não configurado. Sessões ociosas sem limite de tempo.');}

  // ================================================================
  S('CRIPTOGRAFIA');
  // ================================================================

  // 09. SSH 2048 BITS
  // Detectar tamanho RSA pelo hex ASN.1 do show crypto key mypubkey rsa
  // 028181 = 1024 bits, 02820101 = 2048 bits, 02820201 = 4096 bits
  var rsaBits=0;
  var cryptoKeyHex=L.filter(function(l){return/^\s*[0-9A-F]{8}(\s+[0-9A-F]{8})+/i.test(l.trim());}).join(' ').replace(/\s+/g,'').toUpperCase();
  if(cryptoKeyHex.indexOf('02820201')>=0)rsaBits=4096;
  else if(cryptoKeyHex.indexOf('02820101')>=0)rsaBits=2048;
  else if(cryptoKeyHex.indexOf('028181')>=0)rsaBits=1024;
  else if(cryptoKeyHex.indexOf('02818100')>=0)rsaBits=1024;
  var bitcountLine=L.find(function(l){return/bitcount\s*[:=]?\s*\d+/i.test(l.trim())&&!/^could not|bitcount: 0/i.test(l.trim());});
  var bitcountVal=rsaBits>0?rsaBits:(bitcountLine?(parseInt((bitcountLine.match(/bitcount\s*[:=]?\s*(\d+)/i)||['','0'])[1])||0):0);
  var cryptoKeyLine=L.find(function(l){return/^ssh-rsa AAAA/i.test(l.trim());});
  var cryptoSzLine=L.find(function(l){return/modulus\s+(\d+)|(\d{4})\s+bit/i.test(l)&&/rsa|ssh|key/i.test(l);});
  if(bitcountVal>0){A('SSH 2048 BITS',bitcountVal>=2048?'SIM':'NÃO',bitcountVal>=2048?'N/A':'✘','Chave RSA: '+bitcountVal+' bits '+(bitcountVal>=2048?'(adequado).':'(insuficiente). Gerar nova: "crypto key generate rsa modulus 2048".'));}
  else if(cryptoSzLine){var bits=(cryptoSzLine.match(/(\d{3,4})/)||['',''])[1];A('SSH 2048 BITS',parseInt(bits)>=2048?'SIM':'NÃO',parseInt(bits)>=2048?'N/A':'✘','Chave RSA: '+bits+' bits '+(parseInt(bits)>=2048?'(adequado).':'(insuficiente — gerar nova chave >=2048 bits).'));}
  else if(cryptoKeyLine){var est=cryptoKeyLine.length>300?'≥2048 bits (estimado).':'<2048 bits (estimado — verificar).';A('SSH 2048 BITS',cryptoKeyLine.length>300?'SIM':'PARCIAL',cryptoKeyLine.length>300?'N/A':'⚠','Chave RSA detectada. '+est+' Incluir "show crypto key mypubkey rsa" no log.');}
  else if(sshEnabled){A('SSH 2048 BITS','PARCIAL','⚠','SSH habilitado mas tamanho da chave RSA não detectado. Incluir "show crypto key mypubkey rsa".');}
  else{A('SSH 2048 BITS','N/A','N/A','SSH não habilitado.');}

  // 10. SERVICE PASSWORD-ENCRYPTION
  if(has('service password-encryption')){A('SERVICE PASSWORD-ENCRYPTION','SIM','N/A','service password-encryption habilitado. Senhas ofuscadas com MD5.');}
  else{A('SERVICE PASSWORD-ENCRYPTION','NÃO','⚠','service password-encryption não configurado. Senhas em texto claro.');}

  // 11. ENABLE SECRET / RBAC
  if(has('enable secret')){A('ENABLE SECRET / RBAC','SIM','N/A','Enable secret configurado.');}
  else if(has('enable password')){A('ENABLE SECRET / RBAC','PARCIAL','⚠','Enable password configurado (criptografia fraca). Recomendado substituir por enable secret.');}
  else{A('ENABLE SECRET / RBAC','NÃO','✘','Enable secret e enable password não configurados. Acesso privilegiado sem proteção.');}

  // ================================================================
  S('ACESSO E VISUALIZAÇÃO');
  // ================================================================

  // 12. HTTPS HABILITADO / HTTP DESABILITADO
  var httpSvr=has('ip http server')&&!has('no ip http server');
  var httpsSvr=has('ip http secure-server')&&!has('no ip http secure-server');
  if(!httpSvr&&!httpsSvr){A('HTTPS HABILITADO / HTTP DESABILITADO','SIM','N/A','HTTP server não habilitado.');}
  else if(httpsSvr&&!httpSvr){A('HTTPS HABILITADO / HTTP DESABILITADO','SIM','N/A','Apenas HTTPS habilitado. HTTP desabilitado.');}
  else if(httpSvr){A('HTTPS HABILITADO / HTTP DESABILITADO','NÃO','⚠','HTTP server habilitado. Desabilitar: "no ip http server".');}
  else{A('HTTPS HABILITADO / HTTP DESABILITADO','PARCIAL','⚠','Verificar configuração HTTP/HTTPS.');}

  // 13. BANNER MOTD
  var hasBannerMotd=has('banner motd');
  var hasBannerExec=has('banner exec');
  var bannerParts=[];
  bannerParts.push(hasBannerMotd?'Banner MOTD configurado.':'Banner MOTD não configurado.');
  bannerParts.push(hasBannerExec?'Banner EXEC configurado.':'Banner EXEC não configurado.');
  var bannerObs=bannerParts.join(' ');
  if(hasBannerMotd){A('BANNER MOTD','SIM','N/A',bannerObs);}
  else{A('BANNER MOTD','NÃO','✔',bannerObs);}

  // 14. CDP/LLDP NAS PORTAS DE ACESSO
  var cdpGlobal=!has('no cdp run');
  var lldpGlobal=has('lldp run')&&!has('no lldp run');
  var accessPortsCdp=[];var curIfCdp=null;var isAccessCdp=false;var hasCdpDis=false;
  L.forEach(function(l){
    var lt=l.trim();
    var ifm=lt.match(/^interface\s+(\S+)/);
    if(ifm){if(curIfCdp&&isAccessCdp&&!hasCdpDis&&cdpGlobal&&!accessPortsCdp.includes(curIfCdp))accessPortsCdp.push(curIfCdp);curIfCdp=ifm[1];isAccessCdp=false;hasCdpDis=false;}
    if(curIfCdp&&/switchport mode access/i.test(lt))isAccessCdp=true;
    if(curIfCdp&&/^no cdp enable/i.test(lt))hasCdpDis=true;
  });
  if(curIfCdp&&isAccessCdp&&!hasCdpDis&&cdpGlobal&&!accessPortsCdp.includes(curIfCdp))accessPortsCdp.push(curIfCdp);
  var accessPortsLldp=[];var curIfLldp=null;var isAccessLldp=false;var hasLldpDis=false;
  L.forEach(function(l){
    var lt=l.trim();
    var ifm=lt.match(/^interface\s+(\S+)/);
    if(ifm){if(curIfLldp&&isAccessLldp&&!hasLldpDis&&lldpGlobal&&!accessPortsLldp.includes(curIfLldp))accessPortsLldp.push(curIfLldp);curIfLldp=ifm[1];isAccessLldp=false;hasLldpDis=false;}
    if(curIfLldp&&/switchport mode access/i.test(lt))isAccessLldp=true;
    if(curIfLldp&&/^no lldp (transmit|receive)/i.test(lt))hasLldpDis=true;
  });
  if(curIfLldp&&isAccessLldp&&!hasLldpDis&&lldpGlobal&&!accessPortsLldp.includes(curIfLldp))accessPortsLldp.push(curIfLldp);
  var cdpStr=(cdpGlobal?'CDP habilitado globalmente.':'CDP desabilitado globalmente.')+' '+(lldpGlobal?'LLDP habilitado globalmente.':'LLDP não habilitado.');
  if(accessPortsCdp.length>0)cdpStr+=' CDP ativo em '+accessPortsCdp.length+' porta(s) de acesso.';
  if(accessPortsLldp.length>0)cdpStr+=' LLDP ativo em '+accessPortsLldp.length+' porta(s) de acesso.';
  var cdpProb=cdpGlobal&&(accessPortsCdp.length>0||accessPortsLldp.length>0);
  if(!cdpGlobal&&!lldpGlobal){A('CDP/LLDP NAS PORTAS DE ACESSO','SIM','N/A',cdpStr);}
  else if(cdpProb){A('CDP/LLDP NAS PORTAS DE ACESSO','PARCIAL','⚠',cdpStr);}
  else{A('CDP/LLDP NAS PORTAS DE ACESSO','NÃO','⚠',cdpStr);}

  // ================================================================
  S('GERÊNCIA');
  // ================================================================

  // 15. GERÊNCIA OUT OF BAND (OOB)
  var hasMgmt=L.some(function(l){return/^interface (Mgmt0?|FastEthernet0|GigabitEthernet0(\/0)?|GigabitEthernet0\/0\/0)$/i.test(l.trim());});
  var hasLoopback=L.some(function(l){return/^interface Loopback\d*$/i.test(l.trim());});
  var hasVlanMgmt=(function(){var cur=null;for(var mi=0;mi<L.length;mi++){if(/^interface Vlan\d+/i.test(L[mi].trim()))cur=mi;if(cur!==null&&/description.*(gerenci|management|mgmt)/i.test(L[mi])&&mi<cur+8)return true;}return false;})();
  if(hasMgmt){A('GERÊNCIA OUT OF BAND (OOB)','SIM','N/A','Interface de gerência dedicada detectada.');}
  else if(hasLoopback){A('GERÊNCIA OUT OF BAND (OOB)','SIM','N/A','Loopback0 usado como interface de gerência.');}
  else if(hasVlanMgmt){A('GERÊNCIA OUT OF BAND (OOB)','SIM','N/A','VLAN de gerência detectada.');}
  else{A('GERÊNCIA OUT OF BAND (OOB)','NÃO','⚠','Interface de gerência não detectada. Gerência possivelmente in-band.');}

  // 16. CONTROL PLANE POLICING (CoPP)
  var copp=has('policy-map type control-plane')||has('control-plane');
  if(copp&&has('service-policy input')){A('CONTROL PLANE POLICING (CoPP)','SIM','N/A','CoPP configurado via policy-map type control-plane.');}
  else if(copp){A('CONTROL PLANE POLICING (CoPP)','PARCIAL','⚠','Control-plane configurado mas sem service-policy aplicado.');}
  else{A('CONTROL PLANE POLICING (CoPP)','NÃO','⚠','CoPP não configurado. Control Plane sem proteção contra flood de pacotes.');}

  // 17. SERVIDOR DE LOGGING
  var logSvrs=find('logging host').filter(function(l){return l.trim().startsWith('logging host');});
  if(logSvrs.length===0)logSvrs=find('logging ').filter(function(l){return/^logging\s+[\d\.]+/.test(l.trim());});
  if(logSvrs.length>0){var logIPs=[...new Set(logSvrs.map(function(l){return(l.match(/(?:logging host|logging)\s+([\d\.]+)/)||['',''])[1];}).filter(Boolean))];A('SERVIDOR DE LOGGING','SIM','N/A',logIPs.length+' servidor(es) syslog: '+logIPs.join(', ')+'.');}
  else{A('SERVIDOR DE LOGGING','NÃO','⚠','Nenhum servidor syslog remoto configurado. Logs apenas locais.');}

  // 18. LOGGING BUFFERED
  var logBuf=find('logging buffered').filter(function(l){return l.trim().startsWith('logging buffered');});
  if(logBuf.length>0){A('LOGGING BUFFERED','SIM','N/A','Logging buffered configurado.');}
  else{A('LOGGING BUFFERED','NÃO','⚠','logging buffered não configurado. Logs locais sem buffer.');}

  // 19. SNMP PUBLIC/PRIVATE
  var snmpPub=snmpComm.filter(function(l){return/ public(\s|$)/i.test(l);});
  var snmpPrv=snmpComm.filter(function(l){return/ private(\s|$)/i.test(l);});
  if(snmpPub.length===0&&snmpPrv.length===0){
    if(snmpComm.length>0){A('SNMP PUBLIC/PRIVATE','SIM','N/A','Communities public/private ausentes. '+snmpComm.length+' community(ies) customizada(s).');}
    else{A('SNMP PUBLIC/PRIVATE','SIM','N/A','SNMP sem communities public/private configuradas.');}
  } else {
    var badComm=[...snmpPub,...snmpPrv].map(function(l){return l.trim().split(' ')[2];}).join(', ');
    A('SNMP PUBLIC/PRIVATE','NÃO','✘','Community insegura detectada: '+badComm+'. Remover imediatamente.');
  }

  // 20. SNMP PROTEGIDO POR ACL
  var snmpAcl=snmpComm.filter(function(l){return/\s+\d+$|\s+[A-Za-z][\w-]+$/.test(l.trim())&&l.split(' ').length>=4;});
  var snmpGrpAcl=find('snmp-server group').filter(function(l){return/access|acl/i.test(l);});
  if(snmpAcl.length>0){A('SNMP PROTEGIDO POR ACL','SIM','N/A','SNMP community com ACL configurada em '+snmpAcl.length+' community(ies).');}
  else if(snmpGrpAcl.length>0){A('SNMP PROTEGIDO POR ACL','SIM','N/A','SNMP protegido por ACL via snmp-server group.');}
  else if(snmpComm.length>0||snmpUsers.length>0){A('SNMP PROTEGIDO POR ACL','NÃO','⚠','SNMP configurado sem ACL de restrição. Qualquer host pode consultar.');}
  else{A('SNMP PROTEGIDO POR ACL','N/A','N/A','SNMP não configurado.');}

  // 21. SNMPv3 (SEGURO)
  var uniqSnmpUsers=[...new Set(snmpUsers.map(function(l){return l.trim().split(' ')[3];}).filter(Boolean))];
  if(uniqSnmpUsers.length>0&&snmpComm.length>0){A('SNMPv3 (SEGURO)','PARCIAL','⚠','SNMPv3 ('+uniqSnmpUsers.slice(0,2).join(', ')+') e SNMPv2c ambos ativos. Migrar para v3 exclusivo.');}
  else if(uniqSnmpUsers.length>0){A('SNMPv3 (SEGURO)','SIM','N/A','SNMPv3 configurado com '+uniqSnmpUsers.length+' usuário(s).');}
  else{A('SNMPv3 (SEGURO)','NÃO','⚠','SNMPv3 não configurado. Apenas SNMPv2c ativo.');}

  // ================================================================
  S('INFRAESTRUTURA: Funcionalidade e Serviços de Rede');
  S('ROTEAMENTO');
  // ================================================================

  // 22-25. OSPF
  if(hasOspf){
    A('PROTOCOLO DE ROTEAMENTO (OSPF)','SIM','N/A','OSPF configurado.');
    var ospfPassive=has('passive-interface default');
    var ospfPaIf=find('passive-interface').filter(function(l){return/^\s*passive-interface\s+\S+/.test(l)&&!l.includes('no passive');});
    if(ospfPassive){A('OSPF PASSIVE-INTERFACE DEFAULT','SIM','N/A','passive-interface default configurado no OSPF.');}
    else if(ospfPaIf.length>0){A('OSPF PASSIVE-INTERFACE DEFAULT','PARCIAL','⚠',ospfPaIf.length+' interface(s) passive mas não como default.');}
    else{A('OSPF PASSIVE-INTERFACE DEFAULT','NÃO','⚠','passive-interface default não configurado.');}
    var ospfAuthLines=find('ip ospf authentication').concat(find('area authentication'));
    var ospfMd5=ospfAuthLines.some(function(l){return l.includes('message-digest');});
    var ospfIfNoAuth=[];var curIfOs=null;
    L.forEach(function(l){var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/);if(ifm)curIfOs=ifm[1];if(curIfOs&&/ip ospf \d+ area/i.test(lt)&&!ospfIfNoAuth.includes(curIfOs))ospfIfNoAuth.push(curIfOs);if(curIfOs&&/ip ospf authentication/i.test(lt)){var idx=ospfIfNoAuth.indexOf(curIfOs);if(idx>=0)ospfIfNoAuth.splice(idx,1);}});
    var ospfNoAuthStr=ospfIfNoAuth.length>0?' Interfaces sem autenticação: '+abbrevList(ospfIfNoAuth).join(', ')+'.':'';
    if(ospfMd5){A('OSPF AUTENTICAÇÃO','SIM','N/A','OSPF autenticação MD5 configurada.'+ospfNoAuthStr);A('OSPF MD5/SHA AUTHENTICATION','SIM','N/A','OSPF com autenticação MD5.'+ospfNoAuthStr);}
    else if(ospfAuthLines.length>0){A('OSPF AUTENTICAÇÃO','PARCIAL','⚠','OSPF autenticação sem MD5/SHA.'+ospfNoAuthStr);A('OSPF MD5/SHA AUTHENTICATION','NÃO','⚠','OSPF sem MD5/SHA.'+ospfNoAuthStr);}
    else{A('OSPF AUTENTICAÇÃO','NÃO','⚠','OSPF sem autenticação. Risco de injeção de rotas.'+ospfNoAuthStr);A('OSPF MD5/SHA AUTHENTICATION','NÃO','⚠','OSPF sem autenticação MD5/SHA.');}
  } else {
    A('PROTOCOLO DE ROTEAMENTO (OSPF)','N/A','N/A','OSPF não configurado.');
    A('OSPF PASSIVE-INTERFACE DEFAULT','N/A','N/A','OSPF não configurado.');
    A('OSPF AUTENTICAÇÃO','N/A','N/A','OSPF não configurado.');
    A('OSPF MD5/SHA AUTHENTICATION','N/A','N/A','OSPF não configurado.');
  }

  // 26-27. BGP
  if(hasBgp){
    A('BGP','SIM','N/A','BGP configurado.');
    var bgpNeighbors=[...new Set(find('neighbor').filter(function(l){return/neighbor\s+[\d\.]+\s+remote-as/i.test(l);}).map(function(l){return(l.match(/neighbor\s+([\d\.]+)/i)||['',''])[1];}).filter(Boolean))];
    var bgpAuthN=[...new Set(find('neighbor').filter(function(l){return l.includes('password');}).map(function(l){return(l.match(/neighbor\s+([\d\.]+)/i)||['',''])[1];}).filter(Boolean))];
    var bgpNoAuth=bgpNeighbors.filter(function(n){return!bgpAuthN.includes(n);});
    var bgpAuthObs=(bgpAuthN.length>0?'Autenticação MD5 em: '+abbrevList(bgpAuthN).join(', ')+'. ':'')+(bgpNoAuth.length>0?'Sem autenticação: '+abbrevList(bgpNoAuth).join(', ')+'.':'BGP sem autenticação MD5 nos vizinhos.');
    A('BGP AUTENTICAÇÃO',bgpNoAuth.length===0&&bgpAuthN.length>0?'SIM':bgpAuthN.length>0?'PARCIAL':'NÃO',bgpNoAuth.length===0&&bgpAuthN.length>0?'N/A':'⚠',bgpAuthObs);
  } else {A('BGP','N/A','N/A','BGP não configurado.');A('BGP AUTENTICAÇÃO','N/A','N/A','BGP não configurado.');}

  // 28-29. EIGRP
  if(hasEigrp){
    A('EIGRP','SIM','N/A','EIGRP configurado.');
    // Auth no bloco router eigrp (global)
    var eigrpGlobalAuth=false;var inEigrpBlk=false;
    L.forEach(function(l){var lt=l.trim();if(/^router eigrp/i.test(lt))inEigrpBlk=true;if(inEigrpBlk&&/^!/i.test(lt))inEigrpBlk=false;if(inEigrpBlk&&/authentication mode md5|authentication key-chain/i.test(lt))eigrpGlobalAuth=true;});
    // Auth por interface — ignorar interfaces dentro do bloco router eigrp
    var eigrpIfAll=[];var eigrpIfAuthOk=[];var curIfEi=null;var inEigrpRouter=false;
    L.forEach(function(l){var lt=l.trim();
      if(/^router eigrp/i.test(lt)){inEigrpRouter=true;curIfEi=null;return;}
      if(inEigrpRouter&&/^!/i.test(lt)){inEigrpRouter=false;return;}
      if(inEigrpRouter)return;
      var ifm=lt.match(/^interface\s+(\S+)/);if(ifm)curIfEi=ifm[1];
      if(curIfEi&&/ip eigrp \d+/i.test(lt)&&!eigrpIfAll.includes(curIfEi))eigrpIfAll.push(curIfEi);
      if(curIfEi&&/ip authentication mode eigrp/i.test(lt)&&!eigrpIfAuthOk.includes(curIfEi))eigrpIfAuthOk.push(curIfEi);
    });
    var eigrpNoAuth=eigrpIfAll.filter(function(i){return!eigrpIfAuthOk.includes(i);});
    if(eigrpGlobalAuth){
      A('EIGRP AUTENTICAÇÃO','SIM','N/A','EIGRP autenticação MD5 configurada globalmente no bloco router eigrp.');
    } else {
      var eigrpAuthObs=(eigrpIfAuthOk.length>0?'Autenticação em: '+abbrevList(eigrpIfAuthOk).join(', ')+'. ':'')+(eigrpNoAuth.length>0?'Sem autenticação: '+abbrevList(eigrpNoAuth).join(', ')+'.':'');
      A('EIGRP AUTENTICAÇÃO',eigrpNoAuth.length===0&&eigrpIfAuthOk.length>0?'SIM':eigrpIfAuthOk.length>0?'PARCIAL':'NÃO',eigrpNoAuth.length===0&&eigrpIfAuthOk.length>0?'N/A':'⚠',eigrpAuthObs||'EIGRP sem autenticação. Risco de injeção de rotas.');
    }
  } else {A('EIGRP','N/A','N/A','EIGRP não configurado.');A('EIGRP AUTENTICAÇÃO','N/A','N/A','EIGRP não configurado.');}

  // 30. NO IP SOURCE-ROUTE
  var srcOn=find('ip source-route').filter(function(l){return l.trim()==='ip source-route';});
  if(srcOn.length>0){A('NO IP SOURCE-ROUTE','NÃO','⚠','ip source-route habilitado. Desabilitar: "no ip source-route".');}
  else if(has('no ip source-route')){A('NO IP SOURCE-ROUTE','SIM','N/A','no ip source-route configurado explicitamente.');}
  else{A('NO IP SOURCE-ROUTE','SIM','N/A','ip source-route desabilitado por padrão no IOS.');}

  // 31. NO IP REDIRECTS
  var redirWithNo=[];var redirWithout=[];var curIfR=null;
  L.forEach(function(l){
    var lt=l.trim();var m=lt.match(/^interface\s+(\S+)/);if(m)curIfR=m[1];
    if(curIfR&&/^no ip redirects/i.test(lt)&&!redirWithNo.includes(curIfR))redirWithNo.push(curIfR);
  });
  // Interfaces L3 (Vlan e fisicas) que nao tem no ip redirects — ignorar Loopback
  var l3Ifaces=[];var curIfL3=null;var hasIpAddr=false;
  L.forEach(function(l){
    var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/i);
    if(ifm){
      if(curIfL3&&hasIpAddr&&!l3Ifaces.includes(curIfL3))l3Ifaces.push(curIfL3);
      curIfL3=ifm[1];hasIpAddr=false;
    }
    if(curIfL3&&/^ip address/i.test(lt))hasIpAddr=true;
    if(/^!$/.test(lt)&&curIfL3){if(hasIpAddr&&!l3Ifaces.includes(curIfL3))l3Ifaces.push(curIfL3);curIfL3=null;hasIpAddr=false;}
  });
  // Filtrar apenas SVIs (Vlan) e interfaces fisicas (Gi/Fa/Te) — ignorar Loopback
  l3Ifaces=l3Ifaces.filter(function(i){return!/^Loopback/i.test(i);});
  redirWithNo=redirWithNo.filter(function(i){return!/^Loopback/i.test(i);});
  redirWithout=l3Ifaces.filter(function(i){return!redirWithNo.includes(i);});
  var redirObs=redirWithNo.length+' interface(s) com no ip redirects.';
  if(redirWithout.length>0)redirObs+=' Sem configuração: '+abbrevList(redirWithout).join(', ')+'.';
  if(redirWithNo.length===0&&redirWithout.length===0){A('NO IP REDIRECTS','SIM','N/A','ip redirects desabilitado por padrão no IOS.');}
  else if(redirWithout.length===0){A('NO IP REDIRECTS','SIM','N/A',redirObs);}
  else if(redirWithNo.length>0){A('NO IP REDIRECTS','PARCIAL','⚠',redirObs);}
  else{A('NO IP REDIRECTS','NÃO','⚠',redirObs);}

  // 32. UNICAST RPF
  var urpf=find('ip verify unicast').filter(function(l){return l.trim().startsWith('ip verify unicast');});
  if(urpf.length>0){A('UNICAST RPF (ANTI-SPOOFING)','SIM','N/A','uRPF configurado em '+urpf.length+' interface(s).');}
  else{A('UNICAST RPF (ANTI-SPOOFING)','NÃO','✘','uRPF não configurado. Anti-spoofing ausente.');}

  // ================================================================
  S('REDUNDÂNCIA DE GATEWAY');
  // ================================================================

  // 33-35. HSRP
  if(hsrpIfaces.length>0){
    var hsrpIfMap={};var curIfHs=null;
    L.forEach(function(l){var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/);if(ifm)curIfHs=ifm[1];if(curIfHs&&/standby\s+\d*\s*ip/i.test(lt)){if(!hsrpIfMap[curIfHs])hsrpIfMap[curIfHs]={auth:false,prio:false};}if(curIfHs&&hsrpIfMap[curIfHs]){if(/standby.*authentication/i.test(lt))hsrpIfMap[curIfHs].auth=true;if(/standby.*priority/i.test(lt))hsrpIfMap[curIfHs].prio=true;}});
    var hsrpAll=Object.keys(hsrpIfMap);
    var hsrpNoAuth=hsrpAll.filter(function(i){return!hsrpIfMap[i].auth;});
    var hsrpNoPrio=hsrpAll.filter(function(i){return!hsrpIfMap[i].prio;});
    A('HSRP','SIM','N/A','HSRP em '+hsrpAll.length+' interface(s): '+abbrevList(hsrpAll).join(', ')+'.');
    A('HSRP AUTENTICAÇÃO',hsrpNoAuth.length===0?'SIM':'NÃO',hsrpNoAuth.length===0?'N/A':'⚠',hsrpNoAuth.length===0?'HSRP autenticação configurada em todas as interfaces.':'HSRP sem autenticação em: '+abbrevList(hsrpNoAuth).join(', ')+'.');
    A('HSRP PRIORIDADE',hsrpNoPrio.length===0?'SIM':'NÃO',hsrpNoPrio.length===0?'N/A':'⚠',hsrpNoPrio.length===0?'HSRP prioridade configurada em todas as interfaces.':'HSRP sem prioridade em: '+abbrevList(hsrpNoPrio).join(', ')+'.');
  } else {A('HSRP','N/A','N/A','HSRP não configurado.');A('HSRP AUTENTICAÇÃO','N/A','N/A','HSRP não configurado.');A('HSRP PRIORIDADE','N/A','N/A','HSRP não configurado.');}

  // 36-38. VRRP
  if(vrrpIfaces.length>0){
    var vrrpIfMap={};var curIfVr=null;
    L.forEach(function(l){var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/);if(ifm)curIfVr=ifm[1];if(curIfVr&&/vrrp\s+\d+\s+ip/i.test(lt)){if(!vrrpIfMap[curIfVr])vrrpIfMap[curIfVr]={auth:false,prio:false};}if(curIfVr&&vrrpIfMap[curIfVr]){if(/vrrp.*authentication/i.test(lt))vrrpIfMap[curIfVr].auth=true;if(/vrrp.*priority/i.test(lt))vrrpIfMap[curIfVr].prio=true;}});
    var vrrpAll=Object.keys(vrrpIfMap);
    var vrrpNoAuth=vrrpAll.filter(function(i){return!vrrpIfMap[i].auth;});
    var vrrpNoPrio=vrrpAll.filter(function(i){return!vrrpIfMap[i].prio;});
    A('VRRP','SIM','N/A','VRRP em '+vrrpAll.length+' interface(s): '+abbrevList(vrrpAll).join(', ')+'.');
    A('VRRP AUTENTICAÇÃO',vrrpNoAuth.length===0?'SIM':'NÃO',vrrpNoAuth.length===0?'N/A':'⚠',vrrpNoAuth.length===0?'VRRP autenticação configurada.':'VRRP sem autenticação em: '+abbrevList(vrrpNoAuth).join(', ')+'.');
    A('VRRP PRIORIDADE',vrrpNoPrio.length===0?'SIM':'NÃO',vrrpNoPrio.length===0?'N/A':'⚠',vrrpNoPrio.length===0?'VRRP prioridade configurada.':'VRRP sem prioridade em: '+abbrevList(vrrpNoPrio).join(', ')+'.');
  } else {A('VRRP','N/A','N/A','VRRP não configurado.');A('VRRP AUTENTICAÇÃO','N/A','N/A','VRRP não configurado.');A('VRRP PRIORIDADE','N/A','N/A','VRRP não configurado.');}

  // 39-41. GLBP
  if(glbpIfaces.length>0){
    var glbpIfMap={};var curIfGl=null;
    L.forEach(function(l){var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/);if(ifm)curIfGl=ifm[1];if(curIfGl&&/glbp\s+\d+\s+ip/i.test(lt)){if(!glbpIfMap[curIfGl])glbpIfMap[curIfGl]={auth:false,prio:false};}if(curIfGl&&glbpIfMap[curIfGl]){if(/glbp.*authentication/i.test(lt))glbpIfMap[curIfGl].auth=true;if(/glbp.*priority/i.test(lt))glbpIfMap[curIfGl].prio=true;}});
    var glbpAll=Object.keys(glbpIfMap);
    var glbpNoAuth=glbpAll.filter(function(i){return!glbpIfMap[i].auth;});
    var glbpNoPrio=glbpAll.filter(function(i){return!glbpIfMap[i].prio;});
    A('GLBP','SIM','N/A','GLBP em '+glbpAll.length+' interface(s): '+abbrevList(glbpAll).join(', ')+'.');
    A('GLBP AUTENTICAÇÃO',glbpNoAuth.length===0?'SIM':'NÃO',glbpNoAuth.length===0?'N/A':'⚠',glbpNoAuth.length===0?'GLBP autenticação configurada.':'GLBP sem autenticação em: '+abbrevList(glbpNoAuth).join(', ')+'.');
    A('GLBP PRIORIDADE',glbpNoPrio.length===0?'SIM':'NÃO',glbpNoPrio.length===0?'N/A':'⚠',glbpNoPrio.length===0?'GLBP prioridade configurada.':'GLBP sem prioridade em: '+abbrevList(glbpNoPrio).join(', ')+'.');
  } else {A('GLBP','N/A','N/A','GLBP não configurado.');A('GLBP AUTENTICAÇÃO','N/A','N/A','GLBP não configurado.');A('GLBP PRIORIDADE','N/A','N/A','GLBP não configurado.');}

  // ================================================================
  S('SERVIÇOS DE REDE');
  // ================================================================

  // 42. NTP CONFIGURADO
  if(ntpIPs.length>0){A('NTP CONFIGURADO','SIM','N/A',ntpIPs.length+' servidor(es) NTP: '+ntpIPs.join(', ')+'.');}
  else{A('NTP CONFIGURADO','NÃO','⚠','Nenhum servidor NTP configurado.');}

  // 43. NTP SINCRONIZADO
  var ntpSync=L.some(function(l){return/synchronized|synced|stratum\s+[1-9](?!\d)/i.test(l)&&/ntp|clock/i.test(l);});
  var ntpUnsync=L.some(function(l){return/unsynchronized|not.*sync|stratum\s+16/i.test(l);});
  if(ntpSync){A('NTP SINCRONIZADO','SIM','N/A','NTP sincronizado confirmado no log.');}
  else if(ntpUnsync){A('NTP SINCRONIZADO','PARCIAL','⚠','NTP com problema de sincronização detectado.');}
  else if(ntpIPs.length>0){A('NTP SINCRONIZADO','SIM','N/A','NTP configurado sem erros detectados. Validar com "show ntp status".');}
  else{A('NTP SINCRONIZADO','NÃO','⚠','NTP não configurado.');}

  // 44. NTP PROTEGIDO POR ACL
  var ntpAcl=find('ntp access-group').filter(function(l){return l.trim().startsWith('ntp access-group');});
  if(ntpAcl.length>0){A('NTP PROTEGIDO POR ACL','SIM','N/A','ntp access-group configurado: '+ntpAcl[0].trim()+'.');}
  else{A('NTP PROTEGIDO POR ACL','NÃO','⚠','Nenhuma ACL de proteção NTP configurada.');}

  // 45. NTP AUTENTICAÇÃO
  var ntpAuthCmd=has('ntp authenticate');
  var ntpAuthKey=has('ntp authentication-key');
  var ntpTrusted=has('ntp trusted-key');
  if(ntpAuthCmd&&ntpAuthKey&&ntpTrusted){A('NTP AUTENTICAÇÃO','SIM','N/A','Autenticação NTP completa.');}
  else if(ntpAuthCmd||ntpAuthKey){var miss=[];if(!ntpAuthCmd)miss.push('ntp authenticate');if(!ntpAuthKey)miss.push('ntp authentication-key');if(!ntpTrusted)miss.push('ntp trusted-key');A('NTP AUTENTICAÇÃO','PARCIAL','⚠','Autenticação NTP incompleta. Faltando: '+miss.join(', ')+'.');}
  else{A('NTP AUTENTICAÇÃO','NÃO','⚠','Autenticação NTP não configurada. Risco de NTP spoofing.');}

  // 46. NO IP PROXY-ARP (SVIs)
  var sviProxy=[];var curIfP=null;
  L.forEach(function(l){var m=l.trim().match(/^interface\s+(\S+)/);if(m)curIfP=m[1];if(/^\s*ip proxy-arp/.test(l)&&!l.includes('no ip proxy-arp')&&curIfP&&/[Vv]lan/i.test(curIfP)&&!sviProxy.includes(curIfP))sviProxy.push(curIfP);});
  if(sviProxy.length===0){A('NO IP PROXY-ARP (SVIs)','SIM','N/A','Proxy-ARP não habilitado nas SVIs.');}
  else{A('NO IP PROXY-ARP (SVIs)','NÃO','⚠','ip proxy-arp ativo em '+sviProxy.length+' SVI(s).');}

  // 47. IP SOURCE GUARD
  if(!isSwitch){A('IP SOURCE GUARD','N/A','N/A','IP Source Guard aplicável apenas em switches.');}
  else{var ipsg=find('ip verify source').filter(function(l){return l.trim().startsWith('ip verify source');});if(ipsg.length>0){A('IP SOURCE GUARD','SIM','N/A','IP Source Guard em '+ipsg.length+' interface(s).');}else{A('IP SOURCE GUARD','NÃO','⚠','IP Source Guard não configurado. Risco de IP spoofing em portas de acesso.');}}

  // 48. DHCP SNOOPING
  if(!isSwitch){A('DHCP SNOOPING','N/A','N/A','DHCP Snooping aplicável apenas em switches.');}
  else{var dhcpG=has('ip dhcp snooping')&&!has('no ip dhcp snooping');var dhcpV=find('ip dhcp snooping vlan').filter(function(l){return l.trim().startsWith('ip dhcp snooping vlan');});if(dhcpG&&dhcpV.length>0){A('DHCP SNOOPING','SIM','N/A','DHCP Snooping habilitado em '+dhcpV.length+' VLAN(s).');}else if(dhcpG){A('DHCP SNOOPING','PARCIAL','⚠','DHCP Snooping global sem "ip dhcp snooping vlan X".');}else{A('DHCP SNOOPING','NÃO','⚠','DHCP Snooping não configurado. Risco de DHCP spoofing/starvation.');}}

  // 49. DYNAMIC ARP INSPECTION (DAI)
  if(!isSwitch){A('DYNAMIC ARP INSPECTION (DAI)','N/A','N/A','DAI aplicável apenas em switches.');}
  else{var daiG=has('ip arp inspection')&&!has('no ip arp inspection');var daiV=find('ip arp inspection vlan').filter(function(l){return l.trim().startsWith('ip arp inspection vlan');});if(daiG&&daiV.length>0){A('DYNAMIC ARP INSPECTION (DAI)','SIM','N/A','DAI habilitado em '+daiV.length+' VLAN(s).');}else if(daiG){A('DYNAMIC ARP INSPECTION (DAI)','PARCIAL','⚠','DAI global sem "ip arp inspection vlan X".');}else{A('DYNAMIC ARP INSPECTION (DAI)','NÃO','⚠','DAI não configurado. Risco de ARP spoofing/poisoning.');}}

  // ================================================================
  S('SWITCHING / L2');
  // ================================================================

  // 50. VLAN SEM MAC_ADRRESS VINCULADO
  if(!isSwitch){A('VLAN SEM MAC_ADRRESS VINCULADO','N/A','N/A','Aplicável apenas em switches.');}
  else{
    var macDynLines=L.filter(function(l){return/DYNAMIC|dynamic/i.test(l)&&/[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}/.test(l);});
    var vlanIdsAll=[...new Set(L.filter(function(l){return/^vlan\s+\d+$/.test(l.trim());}).map(function(l){return l.trim().replace(/^vlan\s+/,'');}))];
    if(macDynLines.length===0&&vlanIdsAll.length===0){A('VLAN SEM MAC_ADRRESS VINCULADO','N/A','N/A','Incluir "show mac address-table" no log para análise.');}
    else if(macDynLines.length===0){A('VLAN SEM MAC_ADRRESS VINCULADO','PARCIAL','⚠',vlanIdsAll.length+' VLAN(s) detectadas. Incluir "show mac address-table" no log para verificar MACs dinâmicos.');}
    else{
      var vlansComMac=[...new Set(macDynLines.map(function(l){var m=l.trim().match(/^\s*(\d+)\s+/);return m?m[1]:'';}).filter(Boolean))];
      var vlansSemMac=vlanIdsAll.filter(function(v){return!vlansComMac.includes(v);});
      if(vlansSemMac.length===0){A('VLAN SEM MAC_ADRRESS VINCULADO','SIM','N/A','Todas as '+vlanIdsAll.length+' VLAN(s) com MAC dinâmico detectado.');}
      else{A('VLAN SEM MAC_ADRRESS VINCULADO','PARCIAL','⚠',vlansSemMac.length+' VLAN(s) sem MAC dinâmico: '+vlansSemMac.join(', ')+'.');}
    }
  }

  // 51. VLAN SEM NAME
  if(!isSwitch){A('VLAN SEM NAME','N/A','N/A','Aplicável apenas em switches.');}
  else{var vBlk={};var cVl=null;L.forEach(function(l){var m=l.trim().match(/^vlan\s+(\d+)$/);if(m){cVl=m[1];vBlk[cVl]=vBlk[cVl]||{hasName:false};}if(cVl&&l.trim().startsWith('name ')&&!l.trim().startsWith('name VLAN'))vBlk[cVl].hasName=true;});var tot=Object.keys(vBlk).length;var noN=Object.entries(vBlk).filter(function(e){return!e[1].hasName;}).map(function(e){return e[0];});if(tot===0){A('VLAN SEM NAME','N/A','N/A','VLANs não detectadas.');}else if(noN.length===0){A('VLAN SEM NAME','SIM','N/A','Todas as VLANs com nome configurado.');}else{A('VLAN SEM NAME','PARCIAL','⚠',noN.length+' VLAN(s) sem nome: '+noN.join(', ')+'.');}}

  // 52. STP: MODO RAPID-PVST/MST
  if(!isSwitch){A('STP: MODO RAPID-PVST/MST','N/A','N/A','Aplicável apenas em switches.');}
  else{var stpM=find('spanning-tree mode').filter(function(l){return l.trim().startsWith('spanning-tree mode');});if(stpM.length>0){var m=(stpM[0].trim().match(/spanning-tree mode\s+(\S+)/i)||['',''])[1].toUpperCase();A('STP: MODO RAPID-PVST/MST','SIM','N/A','Modo STP: '+m+'.');}else{A('STP: MODO RAPID-PVST/MST','PARCIAL','⚠','Modo STP não configurado explicitamente. Padrão é PVST+. Recomenda-se rapid-pvst.');}}

  // 53. STP: PRIORIDADE CONFIGURADA
  if(!isSwitch){A('STP: PRIORIDADE CONFIGURADA','N/A','N/A','Aplicável apenas em switches.');}
  else{var stpP=find('spanning-tree vlan').filter(function(l){return/spanning-tree vlan[\s\d,\-]+priority/i.test(l.trim());});var stpPRoot=find('spanning-tree vlan').filter(function(l){return/spanning-tree vlan[\s\d,\-]+root/i.test(l.trim());});if(stpP.length>0){
  var stpPDetail=stpP.map(function(l){
    var m=l.trim().match(/spanning-tree vlan\s+([\d,\-]+)\s+priority\s+(\d+)/i);
    return m?'Vlan'+m[1]+'→'+m[2]:l.trim();
  }).join(', ');
  A('STP: PRIORIDADE CONFIGURADA','SIM','N/A','STP prioridade configurada: '+stpPDetail+'.');
}else if(stpPRoot.length>0){
  var stpRootDetail=stpPRoot.map(function(l){
    var m=l.trim().match(/spanning-tree vlan\s+([\d,\-]+)\s+root\s+(\S+)/i);
    return m?'Vlan'+m[1]+'→root '+m[2]:l.trim();
  }).join(', ');
  A('STP: PRIORIDADE CONFIGURADA','SIM','N/A','STP root configurado: '+stpRootDetail+'.');
}else{A('STP: PRIORIDADE CONFIGURADA','NÃO','⚠','STP prioridade não configurada. Usando default (32768).');}}

  // 54. STP: BPDU GUARD
  if(!isSwitch){A('STP: BPDU GUARD','N/A','N/A','Aplicável apenas em switches.');}
  else{var bpduG=has('spanning-tree portfast bpduguard default');var bpduIF=find('spanning-tree bpduguard enable').filter(function(l){return l.trim().startsWith('spanning-tree bpduguard enable');});if(bpduG){A('STP: BPDU GUARD','SIM','N/A','BPDU Guard habilitado globalmente (spanning-tree portfast bpduguard default).');}else if(bpduIF.length>0){A('STP: BPDU GUARD','PARCIAL','⚠','BPDU Guard em '+bpduIF.length+' interface(s) mas não globalmente.');}else{A('STP: BPDU GUARD','NÃO','⚠','BPDU Guard não configurado.');}}

  // 55. STP: BPDU FILTER
  if(!isSwitch){A('STP: BPDU FILTER','N/A','N/A','Aplicável apenas em switches.');}
  else{var bpduFlt=has('spanning-tree portfast bpdufilter default');var bpduFIF=find('spanning-tree bpdufilter enable').filter(function(l){return l.trim().startsWith('spanning-tree bpdufilter enable');});if(bpduFlt){A('STP: BPDU FILTER','SIM','N/A','BPDU Filter habilitado globalmente.');}else if(bpduFIF.length>0){A('STP: BPDU FILTER','PARCIAL','⚠','BPDU Filter em '+bpduFIF.length+' interface(s).');}else{A('STP: BPDU FILTER','NÃO','⚠','BPDU Filter não configurado.');}}

  // 56. STP: BRIDGE ASSURANCE
  if(!isSwitch){A('STP: BRIDGE ASSURANCE','N/A','N/A','Aplicável apenas em switches.');}
  else{
    var baEnabled=L.some(function(l){return/Bridge Assurance\s+is enabled/i.test(l);});
    var baDisabled=L.some(function(l){return/Bridge Assurance\s+is disabled/i.test(l);});
    var baConfig=has('spanning-tree bridge assurance');
    if(baEnabled||baConfig){A('STP: BRIDGE ASSURANCE','SIM','N/A','Bridge Assurance habilitado (show spanning-tree summary).');}
    else if(baDisabled){A('STP: BRIDGE ASSURANCE','NÃO','⚠','Bridge Assurance desabilitado. Configurar em switches que suportam (Cat6500, Cat4500).');}
    else{A('STP: BRIDGE ASSURANCE','N/A','N/A','Bridge Assurance não detectado. Incluir "show spanning-tree summary" no log.');}
  }

  // 57. STP: LOOP GUARD
  if(!isSwitch){A('STP: LOOP GUARD','N/A','N/A','Aplicável apenas em switches.');}
  else{var lgG=has('spanning-tree loopguard default');var lgIF=find('spanning-tree guard loop').filter(function(l){return l.trim().startsWith('spanning-tree guard loop');});if(lgG){A('STP: LOOP GUARD','SIM','N/A','Loop Guard habilitado globalmente.');}else if(lgIF.length>0){A('STP: LOOP GUARD','PARCIAL','⚠','Loop Guard em '+lgIF.length+' interface(s) mas não globalmente.');}else{A('STP: LOOP GUARD','NÃO','⚠','Loop Guard não configurado. Risco de loop unidirecional.');}}

  // 58. STP: ROOT GUARD
  if(!isSwitch){A('STP: ROOT GUARD CONFIGURADO','N/A','N/A','Aplicável apenas em switches.');}
  else{var rg=find('spanning-tree guard root');if(rg.length>0){A('STP: ROOT GUARD CONFIGURADO','SIM','N/A','Root Guard em '+rg.length+' interface(s).');}else{A('STP: ROOT GUARD CONFIGURADO','NÃO','✘','Root Guard não configurado. Risco de Root Bridge hijack.');}}

  // 59. STORM CONTROL
  if(!isSwitch){A('STORM CONTROL','N/A','N/A','Aplicável apenas em switches.');}
  else{var stIf=[];var cIfs=null;L.forEach(function(l){var m=l.trim().match(/^interface\s+(\S+)/);if(m)cIfs=m[1];if(l.trim().startsWith('storm-control')&&cIfs&&!stIf.includes(cIfs))stIf.push(cIfs);});if(stIf.length>10){A('STORM CONTROL','SIM','N/A','Storm-control em '+stIf.length+' interface(s).');}else if(stIf.length>0){A('STORM CONTROL','PARCIAL','⚠','Storm-control em apenas '+stIf.length+' interface(s).');}else{A('STORM CONTROL','NÃO','⚠','Storm-control não configurado. Risco de broadcast storm.');}}

  // 60. UDLD HABILITADO
  if(!isSwitch){A('UDLD HABILITADO','N/A','N/A','Aplicável apenas em switches.');}
  else{var udldG=has('udld enable')||has('udld aggressive');var udldDis=find('no udld enable').filter(function(l){return l.trim().startsWith('no udld enable');});if(udldG&&udldDis.length===0){A('UDLD HABILITADO','SIM','N/A','UDLD habilitado globalmente.');}else if(udldG){A('UDLD HABILITADO','PARCIAL','⚠','UDLD habilitado mas desabilitado em '+udldDis.length+' interface(s).');}else{A('UDLD HABILITADO','NÃO','⚠','UDLD não habilitado. Usar "udld enable".');}}

  // 61. VLAN 1 SEM USO EM PORTAS
  if(!isSwitch){A('VLAN 1 SEM USO EM PORTAS','N/A','N/A','Aplicável apenas em switches.');}
  else{
    // Detectar Vlan 1 apenas quando explicitamente configurada
    var v1AccessExpl=[];   // switchport access vlan 1
    var v1NativeExpl=[];   // switchport trunk native vlan 1
    var v1AllowedExpl=[];  // switchport trunk allowed vlan 1 (exato ou contendo ,1, 1- etc)
    var curIfV1=null;
    L.forEach(function(l){
      var lt=l.trim();
      var ifm=lt.match(/^interface\s+(\S+)/i);if(ifm)curIfV1=ifm[1];
      if(curIfV1&&/^switchport access vlan\s+1$/i.test(lt)&&!v1AccessExpl.includes(curIfV1))v1AccessExpl.push(curIfV1);
      if(curIfV1&&/^switchport trunk native vlan\s+1$/i.test(lt)&&!v1NativeExpl.includes(curIfV1))v1NativeExpl.push(curIfV1);
      if(curIfV1&&/^switchport trunk allowed vlan/i.test(lt)){
        // detectar vlan 1 explicita: 'allowed vlan 1', 'allowed vlan 1,X', 'allowed vlan all'
        var av=lt.replace(/switchport trunk allowed vlan/i,'').trim();
        if(/^1$|^1,|,1,|,1$|\ball\b/i.test(av)&&!v1AllowedExpl.includes(curIfV1))v1AllowedExpl.push(curIfV1);
      }
    });
    var allV1Parts=[];
    if(v1AccessExpl.length>0)allV1Parts.push(v1AccessExpl.length+' porta(s) com access vlan 1: '+abbrevList(v1AccessExpl).join(', '));
    if(v1NativeExpl.length>0)allV1Parts.push(v1NativeExpl.length+' trunk(s) com native vlan 1: '+abbrevList(v1NativeExpl).join(', '));
    if(v1AllowedExpl.length>0)allV1Parts.push(v1AllowedExpl.length+' trunk(s) com allowed vlan 1: '+abbrevList(v1AllowedExpl).join(', '));
    var totalV1=v1AccessExpl.length+v1NativeExpl.length+v1AllowedExpl.length;
    if(totalV1>0){A('VLAN 1 SEM USO EM PORTAS','NÃO','⚠','Vlan 1 em uso: '+allV1Parts.join('. ')+'.');}
    else{A('VLAN 1 SEM USO EM PORTAS','SIM','N/A','Vlan 1 não está em uso em nenhuma porta.');}
  }

  // 62. TRUNK COM FILTRO DE VLANS
  if(!isSwitch){A('TRUNK COM FILTRO DE VLANS','N/A','N/A','Aplicável apenas em switches.');}
  else{var tIf={};var cTf=null;L.forEach(function(l){var lt=l.trim();if(lt.startsWith('interface ')){cTf=lt;if(!tIf[cTf])tIf[cTf]={trunk:false,allowed:false,allowAll:false};}if(cTf&&lt.includes('switchport mode trunk'))tIf[cTf].trunk=true;if(cTf&&lt.includes('switchport trunk allowed vlan')){tIf[cTf].allowed=true;if(/allowed vlan all\b/i.test(lt))tIf[cTf].allowAll=true;}});var trnks=Object.entries(tIf).filter(function(e){return e[1].trunk;});var tOk=trnks.filter(function(e){return e[1].allowed&&!e[1].allowAll;});var tBad=trnks.filter(function(e){return!e[1].allowed||e[1].allowAll;});var tAllVlan=trnks.filter(function(e){return e[1].allowAll;});
    var tNoFilter=trnks.filter(function(e){return!e[1].allowed;});
    var tProblema=tAllVlan.concat(tNoFilter.filter(function(e){return tAllVlan.indexOf(e)<0;}));
    if(trnks.length===0){A('TRUNK COM FILTRO DE VLANS','N/A','N/A','Nenhuma interface trunk identificada.');}
    else if(tProblema.length===0){A('TRUNK COM FILTRO DE VLANS','SIM','N/A','Nenhuma interface trunk sem filtro de VLANs detectada.');}
    else{
      var tProblemaList=tProblema.map(function(e){return abbrevIf(e[0].replace('interface ',''));}).join(', ');
      var temAll=tAllVlan.length>0;
      A('TRUNK COM FILTRO DE VLANS',temAll?'NÃO':'PARCIAL',temAll?'✘':'⚠',
        tProblema.length+' trunk(s) com "allowed vlan all" ou sem filtro (falha de segurança): '+tProblemaList+'.');
    }}

  // 63. VTP MODE TRANSPARENTE
  if(!isSwitch){A('VTP MODE TRANSPARENTE','N/A','N/A','VTP aplicável apenas em switches.');}
  else{var vtpM=find('vtp mode').filter(function(l){return l.trim().startsWith('vtp mode');});if(vtpM.length>0&&vtpM[0].includes('transparent')){A('VTP MODE TRANSPARENTE','SIM','N/A','VTP mode transparent configurado. Sem propagação de VLANs.');}else if(vtpM.length>0&&vtpM[0].includes('off')){A('VTP MODE TRANSPARENTE','SIM','N/A','VTP desabilitado (mode off).');}else if(vtpM.length>0){A('VTP MODE TRANSPARENTE','NÃO','⚠','VTP mode: '+vtpM[0].trim()+'. Risco de propagação indevida de VLANs.');}else{A('VTP MODE TRANSPARENTE','PARCIAL','⚠','VTP mode não configurado explicitamente. Verificar padrão.');}}

  // 64. ERRDISABLE RECOVERY
  var errPorts=L.filter(function(l){return/err-disabled|errdisable/i.test(l)&&/(Gi|Fa|Te|Eth|Po)[\/\d]/i.test(l);});
  var errCfg=has('errdisable recovery');
  if(errPorts.length>0&&!errCfg){A('ERRDISABLE RECOVERY','NÃO','⚠',errPorts.length+' porta(s) em err-disabled sem errdisable recovery configurado.');}
  else if(errPorts.length>0&&errCfg){A('ERRDISABLE RECOVERY','SIM','N/A',errPorts.length+' porta(s) em err-disabled. errdisable recovery configurado.');}
  else if(errCfg){A('ERRDISABLE RECOVERY','SIM','N/A','errdisable recovery configurado.');}
  else{A('ERRDISABLE RECOVERY','N/A','N/A','Nenhuma porta em err-disabled detectada.');}

  // 65. PORT SECURITY
  if(!isSwitch){A('PORT SECURITY','N/A','N/A','Aplicável apenas em switches.');}
  else{var psec=[];var cIpo=null;L.forEach(function(l){var m=l.trim().match(/^interface\s+(\S+)/);if(m)cIpo=m[1];if(l.trim()==='switchport port-security'&&cIpo&&!psec.includes(cIpo))psec.push(cIpo);});if(psec.length>0){A('PORT SECURITY','SIM','N/A','Port Security em '+psec.length+' interface(s).');}else{A('PORT SECURITY','NÃO','✔','Port Security não configurado. Recomendado para portas de acesso de usuários (notebooks/estações). Avaliar implementação de Port Security ou 802.1X.');}}

  // ================================================================
  S('PORT-CHANNEL');
  // ================================================================

  // 66-70. PORT-CHANNEL
  if(ecLines.length>0||poIfaces.length>0||cgLines.length>0){
    var totalPo=poIfaces.length||ecLines.length;
    // Mapear grupos sem protocolo (mode on)
    var cgNoProto=[];
    cgLines.forEach(function(l){var m=l.match(/channel-group\s+(\d+)\s+mode\s+(\S+)/i);if(m&&m[2].toLowerCase()==='on')if(!cgNoProto.includes('Po'+m[1]))cgNoProto.push('Po'+m[1]);});
    var ecNoProtoList=ecNone.map(function(l){return(l.match(/Po\d+/)||[''])[0];}).filter(Boolean);
    var allNoProto=[...new Set(cgNoProto.concat(ecNoProtoList))];
    if(allNoProto.length>0){A('PORT-CHANNEL COM LACP/PAGP','PARCIAL','⚠',totalPo+' port-channel(s). LACP: '+cgLacp+' / PAgP: '+cgPagp+'. Port-channel(s) em mode ON (sem protocolo): '+allNoProto.join(', ')+'.');}
    else{A('PORT-CHANNEL COM LACP/PAGP','SIM','N/A',totalPo+' port-channel(s). LACP: '+cgLacp+' / PAgP: '+cgPagp+'. Nenhum port-channel em mode ON.');}
  } else {A('PORT-CHANNEL COM LACP/PAGP','N/A','N/A','Nenhum port-channel detectado.');}

  if(ecMemD.length>0){var dl=ecLines.filter(function(l){return/Gi\S+\([Dd]\)|Fa\S+\([Dd]\)|Eth\S+\([Dd]\)/.test(l);}).map(function(l){var po=(l.match(/Po\d+/)||[''])[0];var ms=(l.match(/(Gi|Fa|Eth)\S+\([Dd]\)/g)||[]);return po+': '+ms.join(',');}).filter(function(s){return s.length>4;}).join(' | ');A('PORT-CHANNELS COM MEMBROS DOWN','NÃO','✘','Membros DOWN: '+dl+'.');}
  else if(ecLines.length>0||cgLines.length>0){A('PORT-CHANNELS COM MEMBROS DOWN','SIM','N/A','Nenhum membro com status DOWN.');}
  else{A('PORT-CHANNELS COM MEMBROS DOWN','N/A','N/A','Nenhum port-channel detectado.');}

  if(ecDown.length>0){var dpl=ecDown.map(function(l){return(l.match(/Po\d+/)||[''])[0];}).filter(Boolean).join(', ');A('PORT-CHANNEL DOWN','NÃO','✘','Port-channel(s) DOWN: '+dpl+'.');}
  else if(ecLines.length>0){A('PORT-CHANNEL DOWN','SIM','N/A','Todos os port-channels ativos.');}
  else{A('PORT-CHANNEL DOWN','N/A','N/A','Nenhum port-channel detectado.');}

  if(ecMemS.length>0){A('PORT-CHANNEL MEMBROS INCONSISTENTES','NÃO','⚠','Membros suspensos (s) por inconsistência LACP em '+ecMemS.length+' ocorrência(s).');}
  else if(ecLines.length>0||cgLines.length>0){A('PORT-CHANNEL MEMBROS INCONSISTENTES','SIM','N/A','Nenhum membro suspenso detectado.');}
  else{A('PORT-CHANNEL MEMBROS INCONSISTENTES','N/A','N/A','Nenhum port-channel detectado.');}

  if(ecNone.length>0){var npl2=ecNone.map(function(l){return(l.match(/Po\d+/)||[''])[0];}).filter(Boolean).join(', ');A('PORT-CHANNEL SEM MEMBROS','NÃO','✘','Port-channel(s) sem membros ativos: '+npl2+'.');}
  else if(ecLines.length>0||cgLines.length>0){A('PORT-CHANNEL SEM MEMBROS','SIM','N/A','Todos os port-channels com membros.');}
  else{A('PORT-CHANNEL SEM MEMBROS','N/A','N/A','Nenhum port-channel detectado.');}

  // ================================================================
  S('INFRAESTRUTURA FÍSICA');
  // ================================================================

  // 71. FONTE REDUNDANTE
  // Detectar PSU via NAME: "PS X ..." ou "Switch X - Power Supply Y" + PID na linha seguinte
  var psuNames=[];var curIsPsu=false;var curPsuLabel='';
  L.forEach(function(l){
    var nm=l.match(/NAME:\s*"([^"]*)"/i);
    if(nm){curIsPsu=/power.?supply|\bPS\s+\d/i.test(nm[1]);curPsuLabel=nm[1];}
    var pid=l.match(/PID:\s*([\w\-]+)/i);
    if(pid&&curIsPsu){
      var p=pid[1].trim();
      if(p&&p!=='N/A'&&p.length>2)psuNames.push(curPsuLabel||p);
      curIsPsu=false;curPsuLabel='';
    }
  });
  // Fallback: show environment power
  if(psuNames.length===0){
    L.filter(function(l){return/PWR-|AC-PS|DC-PS|\bWAC\b|\bWDC\b/i.test(l)&&/ok|present|on-line|good|normal/i.test(l);})
    .forEach(function(l){var m=l.match(/([\w\-]*(PWR|WAC|WDC)[\w\-]*)/i);if(m&&!psuNames.includes(m[1]))psuNames.push(m[1]);});
  }
  if(psuNames.length>=2){A('FONTE REDUNDANTE','SIM','N/A',psuNames.length+' fonte(s): '+psuNames.join(', ')+'.');}
  else if(psuNames.length===1){A('FONTE REDUNDANTE','PARCIAL','⚠','Apenas 1 fonte detectada: '+psuNames[0]+'. Sem redundância.');}
  else{A('FONTE REDUNDANTE','NÃO','⚠','PSU não detectada. Incluir "show inventory" ou "show environment power" no log.');}

  // 72. PORTAS NO STATUS NOTCONNECT
  var notconnPorts=[];
  L.forEach(function(l){
    var lt=l.trim();
    var m=lt.match(/^(Gi|Fa|Te|TenGig|GigabitEthernet|FastEthernet)([\d\/]+)/i);
    if(m&&/notconnect|not\s+connect/i.test(lt)){var port=m[1]+m[2];if(!notconnPorts.includes(port))notconnPorts.push(port);}
  });
  if(notconnPorts.length===0){A('PORTAS NO STATUS NOTCONNECT','N/A','N/A','Nenhuma porta notconnect detectada. Incluir "show interfaces status" no log.');}
  else{A('PORTAS NO STATUS NOTCONNECT','PARCIAL','⚠',notconnPorts.length+' porta(s) com status notconnect: '+abbrevList(notconnPorts).join(', ')+'.');}

  // 73. VIRTUALIZAÇÃO (VSS/STACK)
  var stack=L.some(function(l){return/^switch\s+\d+\s+provision|^stack-mac/i.test(l.trim());});
  var stackShow=L.some(function(l){return/Switch\s+\d+\s+\*?\s*(Master|Active|Member)/i.test(l);});
  // Deduplica membros pelo MAC address para evitar contagem de linhas repetidas no log
  var stackMacSeen={};
  L.forEach(function(l){
    var m=l.match(/^\s*\*?\s*(\d+)\s+(Master|Member|Active|Standby)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})/i);
    if(m)stackMacSeen[m[3].toLowerCase()]=m[2];
  });
  var stackCount=Object.keys(stackMacSeen).length;
  var stackDetail=stackCount>0?'StackWise com '+stackCount+' membro(s) único(s) detectado(s).':'';
  if(stack||stackShow){
    A('VIRTUALIZACAO (VPC/VSS/STACK)','SIM','N/A','StackWise configurado. '+stackDetail);
  }
  else{A('VIRTUALIZACAO (VPC/VSS/STACK)','NÃO','⚠','VSS, VPC, StackWise não detectado. Avaliar necessidade de redundância.');}

  // 74. DUPLA ABORDAGEM COM CORE
  if(ecSU.length>=2){A('DUPLA ABORDAGEM COM CORE','SIM','N/A',ecSU.length+' port-channel(s) ativos (SU).');}
  else if(ecSU.length===1){A('DUPLA ABORDAGEM COM CORE','PARCIAL','⚠','Apenas 1 port-channel ativo.');}
  else if(poIfaces.length>=2){A('DUPLA ABORDAGEM COM CORE','SIM','N/A',poIfaces.length+' port-channel(s) configurados. Incluir "show etherchannel summary" para confirmar status.');}
  else if(poIfaces.length===1){A('DUPLA ABORDAGEM COM CORE','PARCIAL','⚠','Apenas 1 port-channel configurado. Redundância de uplink não confirmada.');}
  else{A('DUPLA ABORDAGEM COM CORE','NÃO','⚠','Nenhum port-channel detectado. Uplink redundante ausente.');}

  // 75. SPEED/DUPLEX UPLINKS
  var halfDup=L.filter(function(l){return/Half-duplex|half duplex/i.test(l)&&/Gi|Fa|Te/i.test(l);});
  var mism=L.filter(function(l){return/duplex mismatch|speed mismatch/i.test(l);});
  // Detectar auto na config
  var autoIfaces=[];var curIfAu=null;var hasSpAuto=false;var hasDpAuto=false;
  L.forEach(function(l){
    var lt=l.trim();
    var ifm=lt.match(/^interface\s+((Gi|Fa|Te|GigabitEthernet|FastEthernet|TenGigabitEthernet)[\d\/]+)(?!.*[Cc]hannel)/i);
    if(ifm){if(curIfAu&&(hasSpAuto||hasDpAuto)&&!autoIfaces.includes(curIfAu))autoIfaces.push(curIfAu);curIfAu=ifm[1];hasSpAuto=false;hasDpAuto=false;}
    if(curIfAu&&/^speed auto$/i.test(lt))hasSpAuto=true;
    if(curIfAu&&/^duplex auto$/i.test(lt))hasDpAuto=true;
    if(/^!$/.test(lt)&&curIfAu){if(hasSpAuto||hasDpAuto)if(!autoIfaces.includes(curIfAu))autoIfaces.push(curIfAu);curIfAu=null;hasSpAuto=false;hasDpAuto=false;}
  });
  // Detectar auto no show interfaces status (colunas Duplex/Speed)
  var autoIfStatus=[];
  L.forEach(function(l){
    var lt=l.trim();
    // Formato: Gi1/0/3  desc  notconnect  1  auto  auto  10/100/1000BaseTX
    var m=lt.match(/^((?:Gi|Fa|Te|Gig|Fas|Ten)[\d\/\.]+)\s+.{0,20}\s+auto\s+auto(?:\s|$)/i);
    if(m){var p=abbrevIf(m[1]);if(!autoIfStatus.includes(p))autoIfStatus.push(p);}
  });
  // Unir os dois
  var allAuto=[...new Set(abbrevList(autoIfaces).concat(autoIfStatus))];
  if(mism.length>0){A('SPEED/DUPLEX UPLINKS','NÃO','⚠',mism.length+' interface(s) com mismatch.');}
  else if(halfDup.length>0){A('SPEED/DUPLEX UPLINKS','NÃO','⚠',halfDup.length+' interface(s) em Half-duplex.');}
  else if(allAuto.length>0){A('SPEED/DUPLEX UPLINKS','PARCIAL','⚠',allAuto.length+' interface(s) com speed/duplex auto: '+allAuto.join(', ')+'.');}
  else{A('SPEED/DUPLEX UPLINKS','SIM','N/A','Nenhuma interface com speed/duplex auto ou mismatch detectado.');}

  // 76. EQUIPAMENTO EM SUPORTE (NÃO EOL)
  A('EQUIPAMENTO EM SUPORTE (NÃO EOL)','VERIFICAR NO PORTAL CISCO','VERIFICAR NO PORTAL CISCO','Verificar no portal Cisco.');

  // 77-78. BASELINE
  A('BASELINE CPU E MEMÓRIA','ANALISAR NO DX NETOPS','ANALISAR NO DX NETOPS','Inserir resultado após análise.');
  A('BASELINE UPLINKS','ANALISAR NO DX NETOPS','ANALISAR NO DX NETOPS','Inserir resultado após análise.');

  return items;
}



function runAnalysis_nxos(log){
  var L=log.split('\n');
  var items=[];
  function has(kw){return L.some(function(l){return l.toLowerCase().includes(kw.toLowerCase());});}
  function find(kw){return L.filter(function(l){return l.toLowerCase().includes(kw.toLowerCase());});}
  function S(sec){items.push({status:'SECTION',item:sec});}
  function A(item,status,risco,obs){items.push({item:item,status:status,risco:risco,obs:obs});}

  // ===== DETECÇÃO DE PLATAFORMA E VERSÃO =====
  var hostVersion='';
  var isN9K=false,isN5K=false,isN7K=false,isN3K=false;
  var verPatterns=[
    /NXOS:\s+version\s+([\d\.\(\)a-zA-Z]+)/i,
    /system:\s+version\s+([\d\.\(\)a-zA-Z]+)/i,
    /kickstart:\s+version\s+([\d\.\(\)a-zA-Z]+)/i,
    /cisco\s+Nexus.*Version\s+([\d\.\(\)a-zA-Z]+)/i,
    /NX-OS.*version\s+([\d\.\(\)a-zA-Z]+)/i,
    /Software.*Version\s+([\d\.\(\)a-zA-Z]+)/i
  ];
  for(var vi=0;vi<verPatterns.length;vi++){
    var vl=L.find(function(l){return verPatterns[vi].test(l)&&!/GPL|License|http|Copyright/i.test(l);});
    if(vl){var vm=vl.match(verPatterns[vi]);if(vm&&vm[1]){hostVersion=vm[1];break;}}
  }
  var pidLine=L.find(function(l){return /PID:\s*(N[3579][K]?-[C]?\d+)/i.test(l);});
  if(!pidLine)pidLine=L.find(function(l){return /cisco\s+(N[3579][K]?-C\d+)/i.test(l);});
  if(pidLine){var pm=pidLine.match(/N(\d)[K]?[-C]/i);if(pm){var pg=pm[1];if(pg==='9')isN9K=true;else if(pg==='5')isN5K=true;else if(pg==='7')isN7K=true;else if(pg==='3')isN3K=true;}}
  if(!isN9K&&!isN5K&&!isN7K&&!isN3K){if(/^10\./.test(hostVersion)||/^9\./.test(hostVersion))isN9K=true;else if(/^[67]\./.test(hostVersion))isN7K=true;else if(/^[45]\./.test(hostVersion))isN5K=true;else isN9K=true;}
  var majorVer=parseInt((hostVersion.match(/^(\d+)\./)||['','0'])[1])||0;
  var platStr=(isN9K?'N9K':isN5K?'N5K':isN7K?'N7K':isN3K?'N3K':'NX-OS')+(hostVersion?' '+hostVersion:'');

  // ===== VARIÁVEIS PRÉ-CALCULADAS =====
  var snmpComm=find('snmp-server community').filter(function(l){return l.trim().startsWith('snmp-server community');});
  var snmpUsers=find('snmp-server user').filter(function(l){return l.trim().startsWith('snmp-server user');});

  // SSH
  var sshEnabled=(has('feature ssh')&&!has('no feature ssh'))||(has('ip ssh')&&!has('no ip ssh'));
  var sshKeyPresent=L.some(function(l){return/^ssh-rsa AAAA|^ssh-dsa AAAA/i.test(l.trim());});
  var sshEnabledFinal=sshEnabled||sshKeyPresent;

  // exec-timeout por bloco
  var exToVty=[];var exToCon=[];var inVty=false;var inCon=false;
  L.forEach(function(l){
    var lt=l.trim();
    if(/^line vty/.test(lt)){inVty=true;inCon=false;}
    else if(/^line con/.test(lt)){inCon=true;inVty=false;}
    else if(/^line /.test(lt)){inVty=false;inCon=false;}
    if(lt.startsWith('exec-timeout')){if(inVty)exToVty.push(lt);if(inCon)exToCon.push(lt);}
  });

  // Port-channel summary
  var pcIdx=L.findIndex(function(l){return/Group\s+Port[-\s]/i.test(l);});
  var pcLines=[];
  if(pcIdx>=0){for(var i=pcIdx+1;i<Math.min(pcIdx+100,L.length);i++){var pl=L[i].trim();if(!pl||/^-+$/.test(pl))continue;if(pl.startsWith('show ')||pl.includes('#'))break;if(/^\d+\s+Po\d+|^Po\d+/.test(pl))pcLines.push(pl);}}
  var pcDown=pcLines.filter(function(l){return/\(SD\)|\(RD\)/.test(l);});
  var pcSU=pcLines.filter(function(l){return/\(SU\)/.test(l);});
  var pcNone=pcLines.filter(function(l){return/\bNONE\b/.test(l);});
  var pcMemD=pcLines.filter(function(l){return/Eth\S+\([Dd]\)/.test(l);});
  var pcMemS=pcLines.filter(function(l){return/Eth\S+\([sS]\)/.test(l);});
  var poIfaces=L.filter(function(l){return/^interface [Pp]ort-[Cc]hannel\d+|^interface Po\d+/.test(l.trim());});

  // OSPF
  var hasOspf=L.some(function(l){return l.trim().startsWith('router ospf');});
  var hasBgp=L.some(function(l){return l.trim().startsWith('router bgp');});
  var hasEigrp=L.some(function(l){return l.trim().startsWith('router eigrp');});

  // HSRP
  var hsrpEnabled=has('feature hsrp')&&!has('no feature hsrp');
  var hsrpIfaces=find('standby').filter(function(l){return/standby\s+\d*\s*ip/.test(l);});

  // VRRP
  var vrrpEnabled=!isN5K&&has('feature vrrp')&&!has('no feature vrrp');
  var vrrpIfaces=find('vrrp').filter(function(l){return/vrrp\s+\d/.test(l);});

  // GLBP
  var glbpEnabled=has('feature glbp')&&!has('no feature glbp');
  var glbpIfaces=find('glbp').filter(function(l){return/glbp\s+\d/.test(l);});

  // NTP
  var ntpSvrs=find('ntp server').filter(function(l){return l.trim().startsWith('ntp server');});
  var ntpIPs=[...new Set(ntpSvrs.map(function(l){return l.trim().replace(/^ntp server\s+/i,'').split(' ')[0];}).filter(Boolean))];

  // ================================================================
  S('AUTENTICAÇÃO E ACESSO');
  // ================================================================

  // 01. SSH
  var ssh2=has('ip ssh version 2')||L.some(function(l){return/ssh version 2 is enabled/i.test(l);});
  if(sshEnabledFinal&&ssh2){A('SSH','SIM','N/A','SSH versão 2 habilitado.');}
  else if(sshEnabledFinal){A('SSH','PARCIAL','⚠','SSH habilitado mas versão 2 não confirmada. Configurar: "ip ssh version 2".');}
  else if(has('no feature ssh')){A('SSH','NÃO','✘','Feature SSH explicitamente desabilitada.');}
  else{A('SSH','NÃO','✘','SSH não habilitado. Usar "feature ssh" + "ip ssh version 2".');}

  // 02. TELNET HABILITADO
  if(isN5K&&majorVer<5){
    var vtyTelnet=find('transport input').some(function(l){return l.includes('telnet');});
    if(vtyTelnet){A('TELNET HABILITADO','SIM','✘','Telnet habilitado no VTY. Protocolo inseguro — desabilitar imediatamente.');}
    else{A('TELNET HABILITADO','NÃO','N/A','Telnet não detectado no VTY. Acesso apenas via SSH.');}
  } else {
    if(has('feature telnet')&&!has('no feature telnet')){A('TELNET HABILITADO','SIM','✘','Feature Telnet habilitada. Protocolo inseguro — remover com "no feature telnet".');}
    else if(has('no feature telnet')){A('TELNET HABILITADO','NÃO','N/A','Feature Telnet explicitamente desabilitada (no feature telnet). Acesso apenas via SSH.');}
    else{A('TELNET HABILITADO','NÃO','N/A','Feature Telnet não configurada. Acesso apenas via SSH.');}
  }

  // 03. ACL PARA GERÊNCIA (VTY)
  var aclVty=find('access-class').filter(function(l){return l.includes('in');});
  if(aclVty.length>0){var aname=(aclVty[0].trim().match(/access-class\s+(\S+)/)||['',''])[1];A('ACL PARA GERÊNCIA (VTY)','SIM','N/A','ACL de gerência aplicada ao VTY: '+aname+'.');}
  else{A('ACL PARA GERÊNCIA (VTY)','NÃO','⚠','Nenhuma ACL (access-class) aplicada ao line vty.');}

  // 04. TACACS/RADIUS (AAA)
  var tacOld=find('tacacs-server host').filter(function(l){return l.trim().startsWith('tacacs-server host');});
  var tacNewBlocks=find('tacacs server').filter(function(l){return l.trim().startsWith('tacacs server ')&&!/host/.test((l.trim().split(' ')[2]||''));});
  var tacNewIPs=find('address ipv4').filter(function(l){return l.trim().startsWith('address ipv4');});
  var radOld=find('radius-server host').filter(function(l){return l.trim().startsWith('radius-server host');});
  if(tacOld.length>0){var tacIPs=[...new Set(tacOld.map(function(l){return(l.match(/tacacs-server host\s+([\d\.]+)/)||['',''])[1];}).filter(Boolean))];A('TACACS/RADIUS (AAA)','SIM','N/A','TACACS+ configurado. '+tacIPs.length+' servidor(es): '+tacIPs.join(', ')+'.');}
  else if(tacNewBlocks.length>0){var tacIPs2=[...new Set(tacNewIPs.map(function(l){return(l.match(/address ipv4\s+([\d\.]+)/)||['',''])[1];}).filter(Boolean))];A('TACACS/RADIUS (AAA)','SIM','N/A','TACACS+ configurado. '+tacNewBlocks.length+' servidor(es): '+(tacIPs2.length>0?tacIPs2.join(', '):'incluir "show tacacs-server" no log')+'.');}
  else if(radOld.length>0){var radIPs=[...new Set(radOld.map(function(l){return(l.match(/radius-server host\s+([\d\.]+)/)||['',''])[1];}).filter(Boolean))];A('TACACS/RADIUS (AAA)','SIM','N/A','RADIUS configurado. '+radIPs.length+' servidor(es): '+radIPs.join(', ')+'.');}
  else{A('TACACS/RADIUS (AAA)','NÃO','✘','Nenhum servidor TACACS+/RADIUS configurado. Autenticação apenas local.');}

  // 05. AAA NEW-MODEL
  var aaaL=find('aaa authentication login').filter(function(l){return l.trim().startsWith('aaa authentication login');});
  var aaaAcct=find('aaa accounting').filter(function(l){return l.trim().startsWith('aaa accounting');});
  if(aaaL.length>0){A('AAA NEW-MODEL','SIM','N/A','AAA configurado: '+aaaL[0].trim()+(aaaAcct.length>0?'. Accounting habilitado.':'.')+'.');}
  else{A('AAA NEW-MODEL','NÃO','⚠','AAA não configurado. Autenticação sem política centralizada.');}

  // 06. USERNAME LOCAL (FALLBACK)
  var users=find('username ').filter(function(l){return l.trim().startsWith('username ');});
  var uniqueUsers=[...new Set(users.map(function(l){return l.trim().split(' ')[1];}).filter(Boolean))];
  if(uniqueUsers.length>0){A('USERNAME LOCAL (FALLBACK)','SIM','N/A',uniqueUsers.length+' usuário(s) local(is): '+uniqueUsers.slice(0,4).join(', ')+'.');}
  else{A('USERNAME LOCAL (FALLBACK)','NÃO','⚠','Nenhum usuário local. Sem fallback de autenticação se AAA cair.');}

  // 07. LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)
  if(has('login block-for')){A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','SIM','N/A',(find('login block-for')[0]||'').trim()+'.');}
  else{A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','NÃO','✘','Login block-for não configurado. Sem proteção contra brute-force SSH.');}

  // 08. EXEC-TIMEOUT
  if(exToVty.length>0){A('EXEC-TIMEOUT','SIM','N/A','exec-timeout VTY: '+exToVty[0].replace('exec-timeout','').trim()+' min.');}
  else if(has('exec-timeout')){A('EXEC-TIMEOUT','SIM','N/A','exec-timeout configurado.');}
  else{A('EXEC-TIMEOUT','NÃO','⚠','exec-timeout não configurado. Sessões ociosas sem limite de tempo.');}

  // ================================================================
  S('CRIPTOGRAFIA');
  // ================================================================

  // 09. SSH 2048 BITS
  var bitcountLine=L.find(function(l){return/bitcount\s*[:=]?\s*\d+/i.test(l.trim())&&!/^could not|bitcount: 0/i.test(l.trim());});
  var bitcountVal=bitcountLine?(parseInt((bitcountLine.match(/bitcount\s*[:=]?\s*(\d+)/i)||['','0'])[1])||0):0;
  var cryptoKeyLine=L.find(function(l){return/^ssh-rsa AAAA|rsa AAAA/i.test(l.trim());});
  var cryptoKeySize=L.find(function(l){return/key\s+size\s*[:=]?\s*(\d+)|modulus\s+(\d+)|(\d{4})\s+bit/i.test(l)&&/rsa|ssh/i.test(l);});
  if(bitcountVal>0){A('SSH 2048 BITS',bitcountVal>=2048?'SIM':'NÃO',bitcountVal>=2048?'N/A':'✘','Chave RSA: '+bitcountVal+' bits '+(bitcountVal>=2048?'(adequado).':'(insuficiente — mínimo 2048 bits). Gerar nova chave: "crypto key generate rsa modulus 2048".'));}
  else if(cryptoKeySize){var bits=(cryptoKeySize.match(/(\d{3,4})/)||['',''])[1];A('SSH 2048 BITS',parseInt(bits)>=2048?'SIM':'NÃO',parseInt(bits)>=2048?'N/A':'✘','Chave RSA: '+bits+' bits '+(parseInt(bits)>=2048?'(adequado).':'(insuficiente — gerar nova chave >=2048 bits).'));}
  else if(cryptoKeyLine){var est=cryptoKeyLine.length>300?'≥2048 bits (estimado).':'<2048 bits (estimado — verificar).';A('SSH 2048 BITS',cryptoKeyLine.length>300?'SIM':'PARCIAL',cryptoKeyLine.length>300?'N/A':'⚠','Chave RSA detectada. '+est+' Incluir "show ssh key" no log para análise precisa.');}
  else if(sshEnabledFinal){A('SSH 2048 BITS','PARCIAL','⚠','SSH habilitado mas chave RSA não encontrada no log. Incluir "show ssh key" para verificar.');}
  else{A('SSH 2048 BITS','N/A','N/A','SSH não habilitado.');}

  // 10. SERVICE PASSWORD-ENCRYPTION
  if(has('no password strength-check')){A('SERVICE PASSWORD-ENCRYPTION','NÃO','⚠','Complexidade de senha desabilitada (no password strength-check).');}
  else if(has('password strength-check')){A('SERVICE PASSWORD-ENCRYPTION','SIM','N/A','password strength-check ativo. Complexidade de senha enforçada.');}
  else{A('SERVICE PASSWORD-ENCRYPTION','SIM','N/A','password strength-check ativo por padrão no NX-OS.');}

  // 11. ENABLE SECRET / RBAC
  A('ENABLE SECRET / RBAC','N/A','N/A','NX-OS não possui enable secret. Controle de acesso via RBAC roles. N/A para todas as versões NX-OS.');

  // ================================================================
  S('ACESSO E VISUALIZAÇÃO');
  // ================================================================

  // 12. HTTPS HABILITADO / HTTP DESABILITADO
  if(!has('feature http-server')&&!has('ip http server')){A('HTTPS HABILITADO / HTTP DESABILITADO','SIM','N/A','HTTP server não habilitado.');}
  else{A('HTTPS HABILITADO / HTTP DESABILITADO','NÃO','⚠','HTTP/HTTPS server habilitado. Verificar necessidade e garantir uso de HTTPS.');}

  // 13. BANNER MOTD
  if(has('banner motd')){A('BANNER MOTD','SIM','N/A','Banner MOTD configurado.');}
  else{A('BANNER MOTD','NÃO','✔','Banner MOTD não configurado. Recomenda-se configurar aviso legal.');}

  // 14. CDP/LLDP NAS PORTAS DE ACESSO
  var cdpF=has('feature cdp')&&!has('no feature cdp');
  var noFeatCdp=has('no feature cdp');
  var noCdpIf=find('no cdp enable').filter(function(l){return l.trim().startsWith('no cdp enable');});
  var cdpDefaultOn=isN5K||isN7K;
  if(cdpDefaultOn){
    if(noFeatCdp){A('CDP/LLDP NAS PORTAS DE ACESSO','SIM','N/A','Feature CDP desabilitada globalmente ('+platStr+').');}
    else if(cdpF&&noCdpIf.length>0){A('CDP/LLDP NAS PORTAS DE ACESSO','PARCIAL','⚠','CDP ativo por padrão no '+platStr+'. Restrito em '+noCdpIf.length+' interface(s). Avaliar desabilitar globalmente.');}
    else{A('CDP/LLDP NAS PORTAS DE ACESSO','NÃO','⚠','CDP habilitado globalmente por padrão no '+platStr+'. Sem restrição detectada.');}
  } else {
    if(!cdpF||noFeatCdp){A('CDP/LLDP NAS PORTAS DE ACESSO','SIM','N/A','Feature CDP não habilitada.');}
    else if(noCdpIf.length>0){A('CDP/LLDP NAS PORTAS DE ACESSO','PARCIAL','⚠','CDP habilitado com restrição em '+noCdpIf.length+' interface(s). Avaliar desabilitar globalmente.');}
    else{A('CDP/LLDP NAS PORTAS DE ACESSO','NÃO','⚠','CDP habilitado globalmente sem restrição.');}
  }

  // ================================================================
  S('GERÊNCIA');
  // ================================================================

  // 15. GERÊNCIA OUT OF BAND (OOB)
  if(has('interface mgmt0')||has('vrf management')){A('GERÊNCIA OUT OF BAND (OOB)','SIM','N/A','Gerência via mgmt0 dedicada.'+(has('vrf management')?' VRF management configurado.':''));}
  else{A('GERÊNCIA OUT OF BAND (OOB)','NÃO','⚠','Interface mgmt0 não detectada. Gerência possivelmente in-band.');}

  // 16. CONTROL PLANE POLICING (CoPP)
  if(isN5K&&majorVer<5){
    A('CONTROL PLANE POLICING (CoPP)','N/A','N/A','CoPP não disponível no NX-OS '+hostVersion+' (N5K 4.x).');
  } else if(isN7K){
    var coppN7K=has('policy-map type control-plane')||has('copp profile')||has('control-plane');
    A('CONTROL PLANE POLICING (CoPP)',coppN7K?'SIM':'NÃO',coppN7K?'N/A':'⚠',coppN7K?'CoPP configurado no N7K.':'CoPP não detectado no N7K. Verificar policy-map type control-plane.');
  } else {
    var coppStrict=has('copp profile strict')||has('copp profile moderate')||has('copp profile lenient');
    var coppCustom=has('policy-map type control-plane');
    if(coppStrict){A('CONTROL PLANE POLICING (CoPP)','SIM','N/A','CoPP ativo: '+(find('copp profile')[0]||'copp profile configurado').trim()+'.');}
    else if(coppCustom){A('CONTROL PLANE POLICING (CoPP)','SIM','N/A','CoPP ativo via policy-map type control-plane.');}
    else{A('CONTROL PLANE POLICING (CoPP)','NÃO','✘','CoPP não configurado. Control Plane sem proteção contra flood de pacotes.');}
  }

  // 17. SERVIDOR DE LOGGING
  var logSvrs=find('logging server').filter(function(l){return l.trim().startsWith('logging server');});
  if(logSvrs.length===0)logSvrs=find('logging host').filter(function(l){return l.trim().startsWith('logging host');});
  if(logSvrs.length>0){var logIPs=[...new Set(logSvrs.map(function(l){return(l.match(/(?:logging server|logging host)\s+([\d\.a-zA-Z\-]+)/)||['',''])[1];}).filter(Boolean))];A('SERVIDOR DE LOGGING','SIM','N/A',logIPs.length+' servidor(es) syslog: '+logIPs.slice(0,3).join(', ')+'.');}
  else{A('SERVIDOR DE LOGGING','NÃO','⚠','Nenhum servidor syslog remoto configurado. Logs apenas locais.');}

  // 18. LOGGING BUFFERED
  var logBuf=find('logging logfile').filter(function(l){return l.trim().startsWith('logging logfile');});
  if(logBuf.length===0)logBuf=find('logging buffered').filter(function(l){return l.trim().startsWith('logging buffered');});
  if(logBuf.length>0){A('LOGGING BUFFERED','SIM','N/A','Logging local configurado: '+logBuf[0].trim()+'.');}
  else{A('LOGGING BUFFERED','NÃO','⚠','Logging local (logfile/buffered) não configurado.');}

  // 19. SNMP PUBLIC/PRIVATE
  var snmpPub=snmpComm.filter(function(l){return/ public( |$)/i.test(l);});
  var snmpPrv=snmpComm.filter(function(l){return/ private( |$)/i.test(l);});
  if(snmpPub.length===0&&snmpPrv.length===0){
    if(snmpComm.length>0){A('SNMP PUBLIC/PRIVATE','SIM','N/A','Communities public/private ausentes. '+snmpComm.length+' community(ies) customizada(s).');}
    else{A('SNMP PUBLIC/PRIVATE','SIM','N/A','SNMP sem communities public/private configuradas.');}
  } else {
    var badComm=[...snmpPub,...snmpPrv].map(function(l){return l.trim().split(' ')[2];}).join(', ');
    A('SNMP PUBLIC/PRIVATE','NÃO','✘','Community insegura detectada: '+badComm+'. Remover imediatamente.');
  }

  // 20. SNMP PROTEGIDO POR ACL
  var snmpUseAcl=find('use-acl').filter(function(l){return/use-acl/i.test(l.trim());});
  var snmpGrpAcl=find('snmp-server group').filter(function(l){return/access|acl/i.test(l);});
  // Detectar ip access-list com nome SNMP
  var snmpIpAcl=L.some(function(l){return/^ip access-list\s+\S*snmp\S*/i.test(l.trim());});
  // Detectar snmp-server community com ACL referenciada no final da linha
  var snmpCommAcl=find('snmp-server community').filter(function(l){return/use-acl\s+\S+/i.test(l);});
  if(snmpUseAcl.length>0||snmpCommAcl.length>0){
    var acln=[...new Set(snmpUseAcl.concat(snmpCommAcl).map(function(l){return(l.match(/use-acl\s+(\S+)/i)||['',''])[1];}).filter(Boolean))].join(', ');
    A('SNMP PROTEGIDO POR ACL','SIM','N/A','SNMP protegido por ACL: '+acln+'.');
  } else if(snmpGrpAcl.length>0){A('SNMP PROTEGIDO POR ACL','SIM','N/A','SNMP protegido por ACL via snmp-server group.');}
  else if(snmpIpAcl){A('SNMP PROTEGIDO POR ACL','SIM','N/A','ip access-list SNMP detectada. Verificar vinculação com community.');}
  else if(snmpComm.length>0||snmpUsers.length>0){A('SNMP PROTEGIDO POR ACL','NÃO','⚠','SNMP configurado sem ACL de restrição. Qualquer host pode consultar.');}
  else{A('SNMP PROTEGIDO POR ACL','N/A','N/A','SNMP não configurado.');}

  // 21. SNMPv3 (SEGURO)
  var uniqueSnmpUsers=[...new Set(snmpUsers.map(function(l){return l.trim().split(' ')[3];}).filter(Boolean))];
  if(uniqueSnmpUsers.length>0&&snmpComm.length>0){A('SNMPv3 (SEGURO)','PARCIAL','✘','SNMPv3 ('+uniqueSnmpUsers.slice(0,2).join(', ')+') e SNMPv2c ambos ativos. Migrar para v3 exclusivo.');}
  else if(uniqueSnmpUsers.length>0){A('SNMPv3 (SEGURO)','SIM','N/A','SNMPv3 configurado com '+uniqueSnmpUsers.length+' usuário(s).');}
  else{A('SNMPv3 (SEGURO)','NÃO','✘','SNMPv3 não configurado. Apenas SNMPv2c ativo.');}

  // ================================================================
  S('INFRAESTRUTURA: Funcionalidade e Serviços de Rede');
  S('ROTEAMENTO');
  // ================================================================

  // 22. PROTOCOLO DE ROTEAMENTO (OSPF)
  if(hasOspf){A('PROTOCOLO DE ROTEAMENTO (OSPF)','SIM','N/A','OSPF configurado.');}
  else{A('PROTOCOLO DE ROTEAMENTO (OSPF)','N/A','N/A','OSPF não configurado.');}

  // 23. OSPF PASSIVE-INTERFACE DEFAULT
  if(hasOspf){
    var ospfPassive=has('passive-interface default');
    if(ospfPassive){A('OSPF PASSIVE-INTERFACE DEFAULT','SIM','N/A','passive-interface default configurado no OSPF.');}
    else{A('OSPF PASSIVE-INTERFACE DEFAULT','NÃO','⚠','passive-interface default não configurado. Interfaces ativas desnecessariamente.');}
  } else {A('OSPF PASSIVE-INTERFACE DEFAULT','N/A','N/A','OSPF não configurado.');}

  // 24. OSPF AUTENTICAÇÃO
  if(hasOspf){
    var ospfAuth=has('area')&&(has('authentication'))||has('ip ospf authentication');
    if(ospfAuth){A('OSPF AUTENTICAÇÃO','SIM','N/A','Autenticação OSPF configurada.');}
    else{A('OSPF AUTENTICAÇÃO','NÃO','⚠','Autenticação OSPF não configurada. Risco de injeção de rotas.');}
  } else {A('OSPF AUTENTICAÇÃO','N/A','N/A','OSPF não configurado.');}

  // 25. OSPF MD5/SHA AUTHENTICATION
  if(hasOspf){
    var ospfMd5=has('authentication message-digest')||has('ip ospf authentication message-digest');
    if(ospfMd5){A('OSPF MD5/SHA AUTHENTICATION','SIM','N/A','OSPF com autenticação MD5/SHA configurada.');}
    else{A('OSPF MD5/SHA AUTHENTICATION','NÃO','⚠','OSPF sem autenticação MD5/SHA. Risco de vizinhos não autenticados.');}
  } else {A('OSPF MD5/SHA AUTHENTICATION','N/A','N/A','OSPF não configurado.');}

  // 26. BGP
  if(hasBgp){A('BGP','SIM','N/A','BGP configurado.');}
  else{A('BGP','N/A','N/A','BGP não configurado.');}

  // 27. BGP AUTENTICAÇÃO
  if(hasBgp){
    var bgpAuth=find('neighbor').filter(function(l){return l.includes('password');});
    if(bgpAuth.length>0){A('BGP AUTENTICAÇÃO','SIM','N/A','BGP com autenticação MD5 em '+bgpAuth.length+' vizinho(s).');}
    else{A('BGP AUTENTICAÇÃO','NÃO','⚠','BGP sem autenticação MD5 nos vizinhos. Risco de BGP hijack.');}
  } else {A('BGP AUTENTICAÇÃO','N/A','N/A','BGP não configurado.');}

  // 28. EIGRP
  if(hasEigrp){A('EIGRP','SIM','N/A','EIGRP configurado.');}
  else{A('EIGRP','N/A','N/A','EIGRP não configurado.');}

  // 29. EIGRP AUTENTICAÇÃO
  if(hasEigrp){
    var eigrpAuth=has('authentication mode md5')||has('ip authentication mode eigrp');
    if(eigrpAuth){A('EIGRP AUTENTICAÇÃO','SIM','N/A','EIGRP com autenticação MD5 configurada.');}
    else{A('EIGRP AUTENTICAÇÃO','NÃO','⚠','EIGRP sem autenticação. Risco de injeção de rotas.');}
  } else {A('EIGRP AUTENTICAÇÃO','N/A','N/A','EIGRP não configurado.');}

  // 30. NO IP SOURCE-ROUTE
  var srcRouteOn=find('ip source-route').filter(function(l){return!l.includes('no ip source-route')&&l.trim().startsWith('ip source-route');});
  if(srcRouteOn.length>0){A('NO IP SOURCE-ROUTE','NÃO','⚠','ip source-route habilitado. Desabilitar: "no ip source-route".');}
  else if(has('no ip source-route')){A('NO IP SOURCE-ROUTE','SIM','N/A','no ip source-route configurado explicitamente.');}
  else{A('NO IP SOURCE-ROUTE','SIM','N/A','ip source-route desabilitado por padrão no NX-OS.');}

  // 31. NO IP REDIRECTS
  var redirIfaces=[];var curIfRedir=null;
  L.forEach(function(l){var ifm=l.trim().match(/^interface\s+(\S+)/);if(ifm)curIfRedir=ifm[1];if(/^\s*ip redirects/.test(l)&&!l.includes('no ip redirects')&&curIfRedir&&!redirIfaces.includes(curIfRedir))redirIfaces.push(curIfRedir);});
  if(redirIfaces.length>0){A('NO IP REDIRECTS','NÃO','✘','ip redirects em '+redirIfaces.length+' interface(s). Desabilitar: "no ip redirects".');}
  else if(has('no ip redirects')){A('NO IP REDIRECTS','SIM','N/A','no ip redirects configurado explicitamente.');}
  else{A('NO IP REDIRECTS','SIM','N/A','ip redirects desabilitado por padrão no NX-OS.');}

  // 32. UNICAST RPF (ANTI-SPOOFING)
  var urpf=find('ip verify unicast').filter(function(l){return l.trim().startsWith('ip verify unicast');});
  if(urpf.length>0){A('UNICAST RPF (ANTI-SPOOFING)','SIM','N/A','uRPF configurado em '+urpf.length+' interface(s).');}
  else{A('UNICAST RPF (ANTI-SPOOFING)','NÃO','✘','uRPF não configurado. Anti-spoofing ausente nas interfaces L3.');}

  // ================================================================
  S('REDUNDÂNCIA DE GATEWAY');
  // ================================================================

  // 33. HSRP
  if(hsrpEnabled&&hsrpIfaces.length>0){A('HSRP','SIM','N/A','HSRP em '+hsrpIfaces.length+' interface(s).');}
  else if(hsrpEnabled){A('HSRP','PARCIAL','⚠','Feature HSRP habilitada mas sem interfaces configuradas.');}
  else{A('HSRP','N/A','N/A','Feature HSRP não habilitada.');}

  // 34. HSRP AUTENTICAÇÃO
  if(hsrpEnabled&&hsrpIfaces.length>0){
    var hauth=find('standby').filter(function(l){return l.includes('authentication');});
    var hatype=hauth.length>0?(hauth[0].includes('md5')?'MD5':'texto simples'):'ausente';
    A('HSRP AUTENTICAÇÃO',hauth.length>0?'SIM':'NÃO',hauth.length>0?'N/A':'⚠','HSRP autenticação: '+hatype+'.');
  } else {A('HSRP AUTENTICAÇÃO','N/A','N/A','HSRP não configurado.');}

  // 35. HSRP PRIORIDADE
  if(hsrpEnabled&&hsrpIfaces.length>0){
    var hprio=find('standby').filter(function(l){return/standby\s+\d*\s*priority/.test(l);});
    if(hprio.length>0){A('HSRP PRIORIDADE','SIM','N/A','HSRP prioridade configurada em '+hprio.length+' interface(s).');}
    else{A('HSRP PRIORIDADE','NÃO','⚠','HSRP prioridade não configurada. Usando default (100).');}
  } else {A('HSRP PRIORIDADE','N/A','N/A','HSRP não configurado.');}

  // 36. VRRP
  if(isN5K){A('VRRP','N/A','N/A','VRRP não suportado no N5K. Usar HSRP.');}
  else if(vrrpEnabled&&vrrpIfaces.length>0){A('VRRP','SIM','N/A','VRRP em '+vrrpIfaces.length+' interface(s).');}
  else if(vrrpEnabled){A('VRRP','PARCIAL','⚠','Feature VRRP habilitada mas sem interfaces configuradas.');}
  else{A('VRRP','N/A','N/A','VRRP não configurado.');}

  // 37. VRRP AUTENTICAÇÃO
  if(isN5K){A('VRRP AUTENTICAÇÃO','N/A','N/A','VRRP não suportado no N5K. Usar HSRP.');}
  else if(vrrpEnabled&&vrrpIfaces.length>0){
    var vauth=find('vrrp').filter(function(l){return l.includes('authentication');});
    A('VRRP AUTENTICAÇÃO',vauth.length>0?'SIM':'NÃO',vauth.length>0?'N/A':'⚠',vauth.length>0?'VRRP com autenticação.':'VRRP sem autenticação. Risco de hijack.');
  } else {A('VRRP AUTENTICAÇÃO','N/A','N/A','VRRP não configurado.');}

  // 38. VRRP PRIORIDADE
  if(isN5K){A('VRRP PRIORIDADE','N/A','N/A','VRRP não suportado no N5K.');}
  else if(vrrpEnabled&&vrrpIfaces.length>0){
    var vprio=find('vrrp').filter(function(l){return/vrrp\s+\d+\s+priority/.test(l);});
    A('VRRP PRIORIDADE',vprio.length>0?'SIM':'NÃO',vprio.length>0?'N/A':'⚠',vprio.length>0?'VRRP prioridade em '+vprio.length+' interface(s).':'VRRP prioridade não configurada. Usando default (100).');
  } else {A('VRRP PRIORIDADE','N/A','N/A','VRRP não configurado.');}

  // 39. GLBP
  if(glbpEnabled&&glbpIfaces.length>0){A('GLBP','SIM','N/A','GLBP em '+glbpIfaces.length+' interface(s).');}
  else if(glbpEnabled){A('GLBP','PARCIAL','⚠','Feature GLBP habilitada mas sem interfaces configuradas.');}
  else{A('GLBP','N/A','N/A','GLBP não configurado.');}

  // 40. GLBP AUTENTICAÇÃO
  if(glbpEnabled&&glbpIfaces.length>0){
    var gauth=find('glbp').filter(function(l){return l.includes('authentication');});
    A('GLBP AUTENTICAÇÃO',gauth.length>0?'SIM':'NÃO',gauth.length>0?'N/A':'⚠',gauth.length>0?'GLBP com autenticação.':'GLBP sem autenticação. Risco de hijack.');
  } else {A('GLBP AUTENTICAÇÃO','N/A','N/A','GLBP não configurado.');}

  // 41. GLBP PRIORIDADE
  if(glbpEnabled&&glbpIfaces.length>0){
    var gprio=find('glbp').filter(function(l){return/glbp\s+\d+\s+priority/.test(l);});
    A('GLBP PRIORIDADE',gprio.length>0?'SIM':'NÃO',gprio.length>0?'N/A':'⚠',gprio.length>0?'GLBP prioridade configurada.':'GLBP prioridade não configurada. Usando default (100).');
  } else {A('GLBP PRIORIDADE','N/A','N/A','GLBP não configurado.');}

  // ================================================================
  S('SERVIÇOS DE REDE');
  // ================================================================

  // 42. NTP CONFIGURADO
  if(ntpIPs.length>0){A('NTP CONFIGURADO','SIM','N/A',ntpIPs.length+' servidor(es) NTP: '+ntpIPs.join(', ')+'.');}
  else{A('NTP CONFIGURADO','NÃO','⚠','Nenhum servidor NTP configurado. Risco de dessincronização de logs.');}

  // 43. NTP SINCRONIZADO
  var ntpUnreach=L.filter(function(l){return/unreach|unsynchronized|not.*sync|stratum\s+16/i.test(l)&&/ntp|clock/i.test(l);});
  var ntpSyncOk=L.some(function(l){return/synchronized|synced|stratum\s+[1-9](?!\d)/i.test(l)&&/ntp|clock/i.test(l);});
  if(ntpUnreach.length>0){A('NTP SINCRONIZADO','PARCIAL','⚠','NTP com problemas: '+ntpUnreach[0].trim().substring(0,80)+'.');}
  else if(ntpSyncOk){A('NTP SINCRONIZADO','SIM','N/A','NTP sincronizado confirmado no log.');}
  else if(ntpIPs.length>0){A('NTP SINCRONIZADO','SIM','N/A','NTP configurado sem erros detectados. Validar com "show ntp peer-status".');}
  else{A('NTP SINCRONIZADO','NÃO','⚠','NTP não configurado.');}

  // 44. NTP PROTEGIDO POR ACL
  var ntpAcl=find('ntp access-group').filter(function(l){return l.trim().startsWith('ntp access-group');});
  if(ntpAcl.length>0){A('NTP PROTEGIDO POR ACL','SIM','N/A','ntp access-group configurado: '+ntpAcl[0].trim()+'.');}
  else{A('NTP PROTEGIDO POR ACL','NÃO','⚠','Nenhuma ACL de proteção NTP configurada.');}

  // 45. NTP AUTENTICAÇÃO
  var ntpAuthCmd=has('ntp authenticate');
  var ntpAuthKey=has('ntp authentication-key');
  var ntpTrusted=has('ntp trusted-key');
  if(ntpAuthCmd&&ntpAuthKey&&ntpTrusted){A('NTP AUTENTICAÇÃO','SIM','N/A','Autenticação NTP completa.');}
  else if(ntpAuthCmd||ntpAuthKey){var miss=[];if(!ntpAuthCmd)miss.push('ntp authenticate');if(!ntpAuthKey)miss.push('ntp authentication-key');if(!ntpTrusted)miss.push('ntp trusted-key');A('NTP AUTENTICAÇÃO','PARCIAL','⚠','Autenticação NTP incompleta. Faltando: '+miss.join(', ')+'.');}
  else{A('NTP AUTENTICAÇÃO','NÃO','⚠','Autenticação NTP não configurada. Risco de NTP spoofing.');}

  // 46. NO IP PROXY-ARP (SVIs)
  var sviProxyIfaces=[];var curIfSvi=null;
  L.forEach(function(l){var ifm=l.trim().match(/^interface\s+(\S+)/);if(ifm)curIfSvi=ifm[1];if(/^\s*ip proxy-arp/.test(l)&&!l.includes('no ip proxy-arp')&&curIfSvi&&/[Vv]lan/i.test(curIfSvi)&&!sviProxyIfaces.includes(curIfSvi))sviProxyIfaces.push(curIfSvi);});
  if(sviProxyIfaces.length===0){A('NO IP PROXY-ARP (SVIs)','SIM','N/A','Proxy-ARP não habilitado nas SVIs.');}
  else{A('NO IP PROXY-ARP (SVIs)','NÃO','⚠','ip proxy-arp ativo em '+sviProxyIfaces.length+' SVI(s). Desabilitar: "no ip proxy-arp".');}

  // 47. IP SOURCE GUARD
  var ipsg=find('ip verify source').filter(function(l){return l.trim().startsWith('ip verify source');});
  if(ipsg.length>0){A('IP SOURCE GUARD','SIM','N/A','IP Source Guard em '+ipsg.length+' interface(s).');}
  else{A('IP SOURCE GUARD','NÃO','⚠','IP Source Guard não configurado. Risco de IP spoofing em portas de acesso.');}

  // 48. DHCP SNOOPING
  var dhcpGlobal=has('ip dhcp snooping')&&!has('no ip dhcp snooping');
  var dhcpVlan=find('ip dhcp snooping vlan').filter(function(l){return l.trim().startsWith('ip dhcp snooping vlan');});
  if(dhcpGlobal&&dhcpVlan.length>0){A('DHCP SNOOPING','SIM','N/A','DHCP Snooping habilitado. '+dhcpVlan.length+' VLAN(s) configurada(s).');}
  else if(dhcpGlobal){A('DHCP SNOOPING','PARCIAL','⚠','DHCP Snooping global sem "ip dhcp snooping vlan X". Verificar VLANs.');}
  else{A('DHCP SNOOPING','NÃO','⚠','DHCP Snooping não configurado. Risco de DHCP spoofing/starvation.');}

  // 49. DYNAMIC ARP INSPECTION (DAI)
  var daiGlobal=has('ip arp inspection')&&!has('no ip arp inspection');
  var daiVlan=find('ip arp inspection vlan').filter(function(l){return l.trim().startsWith('ip arp inspection vlan');});
  if(daiGlobal&&daiVlan.length>0){A('DYNAMIC ARP INSPECTION (DAI)','SIM','N/A','DAI habilitado em '+daiVlan.length+' VLAN(s).');}
  else if(daiGlobal){A('DYNAMIC ARP INSPECTION (DAI)','PARCIAL','⚠','DAI global sem "ip arp inspection vlan X". Verificar VLANs.');}
  else{A('DYNAMIC ARP INSPECTION (DAI)','NÃO','⚠','DAI não configurado. Risco de ARP spoofing/poisoning.');}

  // ================================================================
  S('SWITCHING / L2');
  // ================================================================

  // PRÉ-CÁLCULO: vlanBlocks (usado nos itens 50 e 51)
  var vlanBlocks={};var curVlan=null;
  L.forEach(function(l){
    var vm=l.trim().match(/^vlan\s+(\d+)$/);if(vm){curVlan=vm[1];vlanBlocks[curVlan]=vlanBlocks[curVlan]||{hasName:false};}
    if(curVlan&&l.trim().startsWith('name ')&&!l.trim().startsWith('name VLAN'))vlanBlocks[curVlan].hasName=true;
  });

  // 50. VLAN SEM MAC ADDRESS VINCULADO (apenas dinâmico)
  var vlanCfg=Object.keys(vlanBlocks).filter(function(v){return v&&v!=='1';});
  var macTableLines=L.filter(function(l){return/dynamic/i.test(l)&&/[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}/i.test(l);});
  var hasMacTableOutput=macTableLines.length>0||L.some(function(l){return/show mac address-table/i.test(l);});
  if(!hasMacTableOutput){
    A('VLAN SEM MAC ADDRESS VINCULADO','N/A','N/A','Output de "show mac address-table" não encontrado no log. Incluir para análise.');
  } else if(macTableLines.length===0){
    if(vlanCfg.length>0){A('VLAN SEM MAC ADDRESS VINCULADO','NÃO','⚠',vlanCfg.length+' VLAN(s) configurada(s) sem nenhum MAC dinâmico aprendido.');}
    else{A('VLAN SEM MAC ADDRESS VINCULADO','N/A','N/A','Nenhuma VLAN configurada detectada.');}
  } else {
    var vlansComMac=[...new Set(macTableLines.map(function(l){var m=l.match(/\b(\d+)\b/);return m?m[1]:'';}).filter(Boolean))];
    var vlansSemMac=vlanCfg.filter(function(v){return!vlansComMac.includes(v);});
    if(vlansSemMac.length===0){A('VLAN SEM MAC ADDRESS VINCULADO','SIM','N/A','Todas as '+vlanCfg.length+' VLAN(s) configurada(s) com MAC dinâmico aprendido.');}
    else if(vlansSemMac.length===vlanCfg.length){A('VLAN SEM MAC ADDRESS VINCULADO','NÃO','⚠','Nenhuma das '+vlanCfg.length+' VLAN(s) configurada(s) possui MAC dinâmico aprendido.');}
    else{A('VLAN SEM MAC ADDRESS VINCULADO','PARCIAL','⚠',vlansSemMac.length+' de '+vlanCfg.length+' VLAN(s) sem MAC dinâmico: '+vlansSemMac.slice(0,5).join(', ')+(vlansSemMac.length>5?' e mais '+(vlansSemMac.length-5):'')+'.');}
  }

  // 51. VLAN SEM NAME
  var vlansTotal=Object.keys(vlanBlocks).length;
  var vlansNoName=Object.entries(vlanBlocks).filter(function(e){return!e[1].hasName;}).map(function(e){return e[0];});
  if(vlansTotal===0){A('VLAN SEM NAME','N/A','N/A','VLANs não detectadas no log.');}
  else if(vlansNoName.length===0){A('VLAN SEM NAME','SIM','N/A','Todas as '+vlansTotal+' VLAN(s) com nome configurado.');}
  else{A('VLAN SEM NAME','PARCIAL','⚠',vlansNoName.length+' VLAN(s) sem nome configurado.');}

  // 52. STP: MODO RAPID-PVST/MST
  var stpmCfg=find('spanning-tree mode').filter(function(l){return l.trim().startsWith('spanning-tree mode');});
  if(stpmCfg.length>0){var stpMode=(stpmCfg[0].trim().match(/spanning-tree mode\s+(\S+)/i)||['',''])[1].toUpperCase();A('STP: MODO RAPID-PVST/MST','SIM','N/A','Modo STP: '+stpMode+'.');}
  else{A('STP: MODO RAPID-PVST/MST','SIM','N/A','Modo STP não configurado explicitamente. Rapid-PVST+ é padrão em todas as plataformas NX-OS.');}

  // 53. STP: PRIORIDADE CONFIGURADA
  var stpPrio=find('spanning-tree vlan').filter(function(l){return/spanning-tree vlan\s+[\d,\-]+\s+priority/.test(l.trim());});
  if(stpPrio.length>0){A('STP: PRIORIDADE CONFIGURADA','SIM','N/A','STP prioridade configurada: '+stpPrio[0].trim()+'.');}
  else{A('STP: PRIORIDADE CONFIGURADA','NÃO','✘','STP prioridade não configurada. Usando default (32768).');}

  // 54. STP: BPDU GUARD
  var bpduGlobalN9K=has('spanning-tree port type edge bpduguard default');
  var bpduGlobalN5K=has('spanning-tree bpduguard default');
  var bpduIfEnable=find('spanning-tree bpduguard enable').filter(function(l){return l.trim().startsWith('spanning-tree bpduguard enable');});
  if(bpduGlobalN9K||bpduGlobalN5K){A('STP: BPDU GUARD','SIM','N/A','BPDU Guard habilitado globalmente.');}
  else if(bpduIfEnable.length>0){A('STP: BPDU GUARD','PARCIAL','✘','BPDU Guard em '+bpduIfEnable.length+' interface(s) mas não globalmente.');}
  else{A('STP: BPDU GUARD','NÃO','✘','BPDU Guard não configurado. Risco em portas de acesso.');}

  // 55. STP: BPDU FILTER
  var bpduFilter=has('spanning-tree portfast bpdufilter default')||has('spanning-tree bpdufilter default');
  var bpduFilterIf=find('spanning-tree bpdufilter enable').filter(function(l){return l.trim().startsWith('spanning-tree bpdufilter enable');});
  if(bpduFilter){A('STP: BPDU FILTER','SIM','N/A','BPDU Filter habilitado globalmente.');}
  else if(bpduFilterIf.length>0){A('STP: BPDU FILTER','PARCIAL','⚠','BPDU Filter em '+bpduFilterIf.length+' interface(s) mas não globalmente.');}
  else{A('STP: BPDU FILTER','NÃO','⚠','BPDU Filter não configurado.');}

  // 56. STP: BRIDGE ASSURANCE
  var baGlobal=has('spanning-tree bridge assurance');
  var baShowEnabled=L.some(function(l){return/Bridge Assurance\s+is\s+enabled/i.test(l);});
  var baShowDisabled=L.some(function(l){return/Bridge Assurance\s+is\s+disabled/i.test(l);});
  if(baGlobal||baShowEnabled){A('STP: BRIDGE ASSURANCE','SIM','N/A','Bridge Assurance habilitado.');}
  else if(baShowDisabled){A('STP: BRIDGE ASSURANCE','NÃO','✘','Bridge Assurance desabilitado (show spanning-tree summary). Recomendado para prevenir loops.');}
  else if(isN5K||isN9K){A('STP: BRIDGE ASSURANCE','NÃO','✘','Bridge Assurance não configurado. Recomendado para prevenir loops.');}
  else{A('STP: BRIDGE ASSURANCE','N/A','N/A','Bridge Assurance não aplicável a esta plataforma.');}

  // 57. STP: LOOP GUARD
  var lgGlobal=has('spanning-tree loopguard default');
  var lgIf=find('spanning-tree guard loop').filter(function(l){return l.trim().startsWith('spanning-tree guard loop');});
  if(lgGlobal){A('STP: LOOP GUARD','SIM','N/A','Loop Guard habilitado globalmente.');}
  else if(lgIf.length>0){A('STP: LOOP GUARD','PARCIAL','✘','Loop Guard em '+lgIf.length+' interface(s) mas não globalmente.');}
  else{A('STP: LOOP GUARD','NÃO','✘','Loop Guard não configurado. Risco de loop unidirecional.');}

  // 58. STP: ROOT GUARD CONFIGURADO
  var rg=find('spanning-tree guard root');
  if(rg.length>0){A('STP: ROOT GUARD CONFIGURADO','SIM','N/A','Root Guard em '+rg.length+' interface(s).');}
  else{A('STP: ROOT GUARD CONFIGURADO','NÃO','✘','Root Guard não configurado. Risco de Root Bridge hijack.');}

  // 59. STORM CONTROL
  var stormIfaces=[];var curIfSt=null;
  L.forEach(function(l){var ifm=l.trim().match(/^interface\s+(\S+)/);if(ifm)curIfSt=ifm[1];if(l.trim().startsWith('storm-control')&&curIfSt&&!stormIfaces.includes(curIfSt))stormIfaces.push(curIfSt);});
  if(stormIfaces.length>10){A('STORM CONTROL','SIM','N/A','Storm-control em '+stormIfaces.length+' interface(s).');}
  else if(stormIfaces.length>0){A('STORM CONTROL','PARCIAL','✘','Storm-control em apenas '+stormIfaces.length+' interface(s). Verificar cobertura.');}
  else{A('STORM CONTROL','NÃO','✘','Storm-control não configurado. Risco de broadcast/multicast storm.');}

  // 60. UDLD HABILITADO
  var udldF=L.some(function(l){var lt=l.trim();return lt==='feature udld'||lt==='udld enable';})||has('udld enable');
  var udldDisIfaces=[];var curIfUdld=null;
  L.forEach(function(l){var ifm=l.trim().match(/^interface\s+(\S+)/);if(ifm)curIfUdld=ifm[1];if(l.trim().startsWith('udld disable')&&curIfUdld&&!udldDisIfaces.includes(curIfUdld))udldDisIfaces.push(curIfUdld);});
  if(udldF&&udldDisIfaces.length===0){A('UDLD HABILITADO','SIM','N/A','UDLD habilitado globalmente.');}
  else if(udldF&&udldDisIfaces.length>0){A('UDLD HABILITADO','PARCIAL','⚠','UDLD habilitado mas desabilitado em '+udldDisIfaces.length+' interface(s).');}
  else{A('UDLD HABILITADO','NÃO','⚠','UDLD não habilitado. Usar "feature udld".');}

  // 61. VLAN 1 SEM USO EM PORTAS
  var v1Access=[];var v1Allowed=[];var v1Native=[];var curIfV1=null;
  L.forEach(function(l){var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/);if(ifm){curIfV1=ifm[1];return;}if(!curIfV1)return;if(/^switchport access vlan 1\b/.test(lt))v1Access.push(curIfV1);if(/^switchport trunk allowed vlan\s+.*\b1\b/.test(lt))v1Allowed.push(curIfV1);if(/^switchport trunk native vlan 1\b/.test(lt))v1Native.push(curIfV1);});
  var v1All=[...new Set(v1Native.concat(v1Access).concat(v1Allowed))];
  if(v1All.length>0){
    var parts=[];
    if(v1Native.length>0)parts.push('native: '+v1Native.slice(0,3).join(', ')+(v1Native.length>3?' +'+(v1Native.length-3):''));
    if(v1Access.length>0)parts.push('access: '+v1Access.slice(0,3).join(', ')+(v1Access.length>3?' +'+(v1Access.length-3):''));
    if(v1Allowed.length>0)parts.push('trunk allowed: '+v1Allowed.slice(0,3).join(', ')+(v1Allowed.length>3?' +'+(v1Allowed.length-3):''));
    A('VLAN 1 SEM USO EM PORTAS','NÃO','⚠','VLAN 1 em uso em '+v1All.length+' interface(s). '+parts.join('; ')+'.');
  } else{A('VLAN 1 SEM USO EM PORTAS','SIM','N/A','VLAN 1 não configurada em nenhuma interface (access, trunk allowed ou native).');}

  // 62. TRUNK COM FILTRO DE VLANS
  var tIfaces={};var cIf=null;
  L.forEach(function(l){var lt=l.trim();if(lt.startsWith('interface ')){cIf=lt;if(!tIfaces[cIf])tIfaces[cIf]={trunk:false,allowed:false,allowAll:false};}if(cIf&&lt.includes('switchport mode trunk'))tIfaces[cIf].trunk=true;if(cIf&&lt.includes('switchport trunk allowed vlan')){tIfaces[cIf].allowed=true;if(/allowed vlan all\b/i.test(lt))tIfaces[cIf].allowAll=true;}});
  var trunks=Object.entries(tIfaces).filter(function(e){return e[1].trunk;});
  var tAllVlan=trunks.filter(function(e){return e[1].allowAll||!e[1].allowed;});
  if(trunks.length===0){A('TRUNK COM FILTRO DE VLANS','N/A','N/A','Nenhuma interface trunk identificada no log.');}
  else if(tAllVlan.length===0){A('TRUNK COM FILTRO DE VLANS','SIM','N/A','Nenhum trunk com "allowed vlan all". Todos os trunks possuem filtro explícito de VLANs.');}
  else{
    var tallNames=tAllVlan.map(function(e){return e[0].replace('interface ','');});
    A('TRUNK COM FILTRO DE VLANS','NÃO','✘',tAllVlan.length+' trunk(s) com "allowed vlan all" (sem filtro de segurança): '+tallNames.join(', ')+'.');
  }

  // 63. VTP MODE TRANSPARENTE
  A('VTP MODE TRANSPARENTE','N/A','N/A','NX-OS não utiliza VTP. Gerenciamento de VLANs via configuração local. N/A para todas as versões NX-OS.');

  // 64. ERRDISABLE RECOVERY
  var errDisPorts=find('err-disabled').filter(function(l){return/Eth|Po|Gi|Te/.test(l);});
  var errDisNames=errDisPorts.map(function(l){var m=l.match(/(Eth\S+|Po\d+|Gi\S+|Te\S+)/);return m?m[1]:'';}).filter(Boolean);
  var errDisStr=errDisNames.slice(0,5).join(', ')+(errDisNames.length>5?' e mais '+(errDisNames.length-5):'');
  var errDisCfg=has('errdisable recovery');
  if(errDisPorts.length>0&&!errDisCfg){A('ERRDISABLE RECOVERY','NÃO','✔',errDisPorts.length+' porta(s) em err-disabled sem errdisable recovery configurado'+(errDisStr?': '+errDisStr:'')+'.');}
  else if(errDisPorts.length>0&&errDisCfg){A('ERRDISABLE RECOVERY','SIM','N/A',errDisPorts.length+' porta(s) em err-disabled. errdisable recovery configurado'+(errDisStr?': '+errDisStr:'')+'.');}
  else if(errDisCfg){A('ERRDISABLE RECOVERY','SIM','N/A','errdisable recovery configurado.');}
  else{A('ERRDISABLE RECOVERY','N/A','N/A','Nenhuma porta em err-disabled detectada.');}

  // 65. PORT SECURITY
  var psecIfaces=[];var curIfPs=null;
  L.forEach(function(l){var ifm=l.trim().match(/^interface\s+(\S+)/);if(ifm)curIfPs=ifm[1];if(l.trim()==='switchport port-security'&&curIfPs&&!psecIfaces.includes(curIfPs))psecIfaces.push(curIfPs);});
  if(psecIfaces.length>0){A('PORT SECURITY','SIM','N/A','Port Security em '+psecIfaces.length+' interface(s).');}
  else{A('PORT SECURITY','NÃO','✔','Port Security não configurado. Recomendado para portas de acesso de usuários (notebooks/estações). Avaliar implementação.');}

  // ================================================================
  S('PORT-CHANNEL');
  // ================================================================

  // 66-70. PORT-CHANNEL
  if(pcLines.length>0){
    if(pcNone.length>0){
      var npIds=[...new Set(pcNone.map(function(l){return(l.trim().match(/Po\d+/)||[''])[0];}).filter(Boolean))];
      A('PORT-CHANNEL COM LACP/PAGP','PARCIAL','⚠',npIds.length+' port-channel(s) em modo ON (sem protocolo): '+npIds.join(', ')+'.');
    } else{A('PORT-CHANNEL COM LACP/PAGP','SIM','N/A',pcLines.length+' port-channel(s) configurados. Todos com LACP/PAgP.');}
  } else if(poIfaces.length>0){
    A('PORT-CHANNEL COM LACP/PAGP','SIM','N/A',poIfaces.length+' interface(s) port-channel na configuração.');
  } else {A('PORT-CHANNEL COM LACP/PAGP','NÃO','⚠','Nenhum port-channel detectado no log.');}

  if(pcMemD.length>0){var dlist=pcLines.filter(function(l){return/Eth\S+\([Dd]\)/.test(l);}).map(function(l){var po=(l.match(/Po\d+/)||[''])[0];var mems=(l.match(/Eth\S+\([Dd]\)/g)||[]);return po+': '+mems.join(',');}).filter(function(s){return s.length>5;}).join(' | ');A('PORT-CHANNELS COM MEMBROS DOWN','NÃO','✘','Membros DOWN: '+dlist+'.');}
  else if(pcLines.length>0){A('PORT-CHANNELS COM MEMBROS DOWN','SIM','N/A','Nenhum membro com status DOWN.');}
  else{A('PORT-CHANNELS COM MEMBROS DOWN','SIM','N/A','Nenhum membro DOWN detectado.');}

  if(pcDown.length>0){var dplist=pcDown.map(function(l){return(l.trim().match(/Po\d+/)||[''])[0];}).filter(Boolean).join(', ');A('PORT-CHANNEL DOWN','NÃO','✘','Port-channel(s) DOWN (SD/RD): '+dplist+'.');}
  else if(pcLines.length>0){A('PORT-CHANNEL DOWN','SIM','N/A','Todos os port-channels ativos (SU).');}
  else{A('PORT-CHANNEL DOWN','SIM','N/A','Nenhum port-channel DOWN detectado.');}

  if(pcMemS.length>0){A('PORT-CHANNEL MEMBROS INCONSISTENTES','NÃO','⚠','Membros suspensos (s) por inconsistência LACP em '+pcMemS.length+' ocorrência(s).');}
  else if(pcLines.length>0){A('PORT-CHANNEL MEMBROS INCONSISTENTES','SIM','N/A','Nenhum membro suspenso por inconsistência LACP.');}
  else{A('PORT-CHANNEL MEMBROS INCONSISTENTES','SIM','N/A','Nenhuma inconsistência LACP detectada.');}

  if(pcNone.length>0){var npd=pcNone.map(function(l){return(l.trim().match(/Po\d+/)||[''])[0];}).filter(Boolean).join(', ');A('PORT-CHANNEL SEM MEMBROS','NÃO','✘','Port-channel(s) sem membros/protocolo (NONE): '+npd+'.');}
  else if(pcLines.length>0){A('PORT-CHANNEL SEM MEMBROS','SIM','N/A','Todos os port-channels com membros ativos.');}
  else{A('PORT-CHANNEL SEM MEMBROS','SIM','N/A','Nenhum port-channel sem membros detectado.');}

  // ================================================================
  S('INFRAESTRUTURA FÍSICA');
  // ================================================================

  // 71. FONTE REDUNDANTE
  var psuPatterns=/-PAC-|-PDC-|NXA-PAC|N9K-PAC|N5K-PAC|N55-PAC|N56-PAC|N57-PAC|N7K-PAC|-AC-PSU|-DC-PSU/i;
  var psu=find('PID:').filter(function(l){return psuPatterns.test(l)&&(l.includes('SN:')||l.includes('VID:'));});
  if(psu.length===0)psu=L.filter(function(l){return psuPatterns.test(l)&&/ok|present|powered|on-line/i.test(l);});
  if(psu.length===0)psu=L.filter(function(l){return/Power Supply|power-supply/i.test(l)&&/ok|present|on|good/i.test(l);});
  if(psu.length>=2){var plist=psu.slice(0,2).map(function(l){var m=l.match(/([A-Z0-9]+-(?:PAC|PDC)-\S+)/i);return m?m[1]:'PSU';}).join(', ');A('FONTE REDUNDANTE','SIM','N/A',psu.length+' fonte(s) detectada(s): '+plist+'.');}
  else if(psu.length===1){A('FONTE REDUNDANTE','PARCIAL','✘','Apenas 1 fonte detectada. Sem redundância de alimentação.');}
  else{var psuEnv=L.some(function(l){return/redundan/i.test(l)&&/ok|operational/i.test(l);});if(psuEnv){A('FONTE REDUNDANTE','SIM','N/A','Redundância de fonte confirmada.');}else{A('FONTE REDUNDANTE','NÃO','✘','PSU não detectada. Incluir "show inventory" ou "show environment power".');}}

  // 72. PORTAS NÃO UTILIZADAS EM SHUTDOWN
  // Coletar interfaces físicas com shutdown na config
  var shutIfSet=new Set();var cifSh=null;
  L.forEach(function(l){
    var lt=l.trim();
    if(/^interface\s+(Eth|Gi|Te|Fa|Hu)/i.test(lt)){cifSh=lt.replace(/^interface\s+/i,'');return;}
    if(cifSh&&lt==='shutdown')shutIfSet.add(cifSh);
  });
  // Coletar portas notconnect ou sfpAbsent do show interface status
  var notconnPorts=[];
  L.forEach(function(l){
    var lt=l.trim();
    if(/notconnect|sfpAbsent|xcvrAbsent|noSFP/i.test(lt)){
      var pm=lt.match(/^(Eth\S+|Gi\S+|Te\S+|Fa\S+|Hu\S+)/i);
      if(pm&&!notconnPorts.includes(pm[1]))notconnPorts.push(pm[1]);
    }
  });
  var hasStatusOutput=L.some(function(l){return/show interface status/i.test(l)||(/notconnect|connected/i.test(l)&&/^(Eth|Gi|Te|Fa)/i.test(l.trim()));});
  if(!hasStatusOutput&&notconnPorts.length===0){
    A('PORTAS NÃO UTILIZADAS EM SHUTDOWN','N/A','N/A','Output de "show interface status" não encontrado. Incluir para análise de portas notconnect/sem SFP.');
  } else if(notconnPorts.length===0){
    A('PORTAS NÃO UTILIZADAS EM SHUTDOWN','SIM','N/A','Nenhuma porta notconnect ou sem SFP detectada.');
  } else {
    var semShut=notconnPorts.filter(function(p){return!shutIfSet.has(p);});
    var comShut=notconnPorts.filter(function(p){return shutIfSet.has(p);});
    if(semShut.length===0){
      A('PORTAS NÃO UTILIZADAS EM SHUTDOWN','SIM','N/A',notconnPorts.length+' porta(s) notconnect/sem SFP — todas com shutdown configurado.');
    } else if(comShut.length>0){
      A('PORTAS NÃO UTILIZADAS EM SHUTDOWN','PARCIAL','⚠',semShut.length+' porta(s) notconnect/sem SFP sem shutdown (risco de segurança). '+comShut.length+' porta(s) já com shutdown.');
    } else {
      A('PORTAS NÃO UTILIZADAS EM SHUTDOWN','NÃO','✘',semShut.length+' porta(s) notconnect/sem SFP sem shutdown configurado (risco de segurança).');
    }
  }

  // 73. VIRTUALIZACAO (VPC/VSS/STACK)
  var vpcD=find('vpc domain').filter(function(l){return l.trim().startsWith('vpc domain');});
  if(vpcD.length>0){var vid2=vpcD[0].trim().replace('vpc domain','').trim();A('VIRTUALIZACAO (VPC/VSS/STACK)','SIM','N/A','VPC domain '+vid2+' configurado.');}
  else if(isN5K&&majorVer<5){A('VIRTUALIZACAO (VPC/VSS/STACK)','N/A','N/A','VPC não disponível no NX-OS '+hostVersion+' (N5K 4.x).');}
  else{A('VIRTUALIZACAO (VPC/VSS/STACK)','NÃO','⚠','VPC não configurado. Avaliar necessidade de redundância L2.');}

  // 74. DUPLA ABORDAGEM COM CORE
  if(pcSU.length>=2){A('DUPLA ABORDAGEM COM CORE','SIM','N/A',pcSU.length+' port-channel(s) ativos (SU) detectados.');}
  else if(pcSU.length===1){A('DUPLA ABORDAGEM COM CORE','PARCIAL','⚠','Apenas 1 port-channel ativo (SU).');}
  else if(poIfaces.length>=2){A('DUPLA ABORDAGEM COM CORE','PARCIAL','⚠',poIfaces.length+' port-channel(s) na configuração. Incluir "show port-channel summary" para confirmar status.');}
  else if(poIfaces.length===1){A('DUPLA ABORDAGEM COM CORE','PARCIAL','⚠','1 port-channel detectado. Sem redundância de uplink.');}
  else{A('DUPLA ABORDAGEM COM CORE','NÃO','⚠','Nenhum uplink redundante detectado.');}

  // 75. SPEED/DUPLEX
  var sdAutoIfaces=[];var sdHalfIfaces=[];var sdMismatch=[];var curIfSd=null;
  L.forEach(function(l){var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/);if(ifm){curIfSd=ifm[1];return;}if(!curIfSd)return;if(/^speed auto\b|^duplex auto\b/i.test(lt)&&!sdAutoIfaces.includes(curIfSd))sdAutoIfaces.push(curIfSd);if(/^duplex half\b/i.test(lt)&&!sdHalfIfaces.includes(curIfSd))sdHalfIfaces.push(curIfSd);if(/duplex mismatch|speed mismatch/i.test(lt))sdMismatch.push(lt);});
  var sdAutoStr=sdAutoIfaces.slice(0,5).join(', ')+(sdAutoIfaces.length>5?' e mais '+(sdAutoIfaces.length-5):'');
  var sdHalfStr=sdHalfIfaces.slice(0,5).join(', ')+(sdHalfIfaces.length>5?' e mais '+(sdHalfIfaces.length-5):'');
  if(sdMismatch.length>0){A('SPEED/DUPLEX','NÃO','⚠',sdMismatch.length+' interface(s) com mismatch detectado.');}
  else if(sdHalfIfaces.length>0){A('SPEED/DUPLEX','NÃO','⚠',sdHalfIfaces.length+' interface(s) em half-duplex: '+sdHalfStr+'.');}
  else if(sdAutoIfaces.length>0){A('SPEED/DUPLEX','NÃO','⚠',sdAutoIfaces.length+' interface(s) com speed/duplex auto (inadequado para NX-OS): '+sdAutoStr+'.');}
  else{A('SPEED/DUPLEX','SIM','N/A','Nenhuma interface com speed/duplex auto detectada.');}

  // 76. EQUIPAMENTO EM SUPORTE (NÃO EOL)
  var eolLink='Validar status completo em: https://www.cisco.com/c/en/us/products/eos-eol-listing.html';
  var eolVersions={'5.2':'EOL','5.1':'EOL','5.0':'EOL','4.2':'EOL','4.1':'EOL','4.0':'EOL','6.0':'EOL','6.1':'EOL','6.2':'EOS','6.3':'EOL','7.0':'EOL','7.1':'EOL','7.2':'EOL','7.3':'ATENÇÃO - Verificar EoSW','14.0':'EOL','14.1':'EOL'};
  if(hostVersion){
    var mj=(hostVersion.match(/^(\d+\.\d+)/)||['',''])[1];
    var eolStatus=eolVersions[mj]||null;
    if(eolStatus==='EOL'){A('EQUIPAMENTO EM SUPORTE (NÃO EOL)','NÃO','✘','NX-OS '+hostVersion+' está em fim de suporte (EOL/EOS). Atualizar urgente. '+eolLink);}
    else if(eolStatus){A('EQUIPAMENTO EM SUPORTE (NÃO EOL)','PARCIAL','⚠','NX-OS '+hostVersion+' ('+eolStatus+'). '+eolLink);}
    else{A('EQUIPAMENTO EM SUPORTE (NÃO EOL)','SIM','N/A','NX-OS '+hostVersion+'. '+eolLink);}
  } else {A('EQUIPAMENTO EM SUPORTE (NÃO EOL)','PARCIAL','⚠','Versão NX-OS não detectada. Incluir output de "show version". '+eolLink);}

  // 77-78. BASELINE
  A('BASELINE CPU E MEMÓRIA','ANALISAR NO DX NETOPS','ANALISAR NO DX NETOPS','Inserir resultado após análise.');
  A('BASELINE UPLINKS','ANALISAR NO DX NETOPS','ANALISAR NO DX NETOPS','Inserir resultado após análise.');

  return items;
}



function runAnalysis_os10(log){
  function abbrevIf(s){
    return s.replace(/ethernet/gi,'Eth').replace(/port-channel/gi,'Po')
            .replace(/loopback/gi,'Lo').replace(/vlan/gi,'Vlan')
            .replace(/management/gi,'Mgmt').replace(/mgmt/gi,'Mgmt');
  }
  function abbrevList(arr){return arr.map(function(x){return abbrevIf(x);});}

  var L=log.split('\n');
  var items=[];
  function has(kw){return L.some(function(l){return l.toLowerCase().includes(kw.toLowerCase());});}
  function find(kw){return L.filter(function(l){return l.toLowerCase().includes(kw.toLowerCase());});}
  function S(sec){items.push({status:'SECTION',item:sec});}
  function A(item,status,risco,obs){items.push({item:item,status:status,risco:risco,obs:obs});}

  // ===== DETECÇÃO DE PLATAFORMA =====
  var isOS10=has('Dell EMC Networking OS10')||has('OS Version:')||has('MX9116N')||has('S52')||has('S42')||has('N3248');
  var hostVersion='';
  var verLine=L.find(function(l){return /OS Version:\s*[\d\.]+/i.test(l);});
  if(verLine){var vm=verLine.match(/([\d\.]+(?:\.\d+)+)/);if(vm)hostVersion=vm[1];}
  var modelLine=L.find(function(l){return /System Type:\s*\S+|Product\s*:\s*\S+/i.test(l);});

  // ===== PRÉ-CÁLCULO =====
  // TACACS
  var tacLines=find('tacacs-server host').filter(function(l){return /tacacs-server host/i.test(l.trim());});
  var tacIPs=[...new Set(tacLines.map(function(l){return(l.match(/tacacs-server host\s+([\d\.]+)/i)||['',''])[1];}).filter(Boolean))];
  // AAA
  var aaaLogin=find('aaa authentication login').filter(function(l){return/aaa authentication login/i.test(l.trim());});
  // Users
  var userLines=find('username ').filter(function(l){return /^username\s+\S+/i.test(l.trim());});
  var uniqueUsers=[...new Set(userLines.map(function(l){return(l.trim().match(/^username\s+(\S+)/i)||['',''])[1];}).filter(Boolean))];
  // SNMP
  var snmpComm=find('snmp-server community').filter(function(l){return /snmp-server community/i.test(l.trim());});
  var snmpUsers=find('snmp-server user').filter(function(l){return /snmp-server user/i.test(l.trim());});
  // NTP
  var ntpSvrs=find('ntp server').filter(function(l){return /^ntp server\s+/i.test(l.trim());});
  var ntpIPs=[...new Set(ntpSvrs.map(function(l){return l.trim().replace(/^ntp server\s+/i,'').split(' ')[0];}).filter(Boolean))];
  // OSPF
  var hasOspf=L.some(function(l){return /^router ospf/i.test(l.trim());});
  // BGP
  var hasBgp=L.some(function(l){return /^router bgp/i.test(l.trim());});
  // Port-channel
  var poIfaces=L.filter(function(l){return /^interface\s+port-channel\d+/i.test(l.trim());});
  var lacpIfaces=find('mode active').concat(find('mode passive')).filter(function(l){return /lacp|mode active|mode passive/i.test(l);});
  // VLT
  var hasVlt=has('vlt domain')||has('vlt-interconnect')||has('vlt-port-channel');
  // Interface status lines
  var ifStatusLines=L.filter(function(l){return /^(Eth|ethernet)\s*[\d\/:]+ /i.test(l.trim())||(/(Eth|Po|Fc)\s[\d\/\:]+\s.+(up|down)/i.test(l));});
  var downPorts=ifStatusLines.filter(function(l){return /\sdown\s/i.test(l)&&!/admin\s*down/i.test(l);}).map(function(l){return(l.trim().match(/^(\S+)/)||['',''])[1];});
  var adminDownPorts=ifStatusLines.filter(function(l){return /admin\s*down|admin down/i.test(l);}).map(function(l){return(l.trim().match(/^(\S+)/)||['',''])[1];});
  var upPorts=ifStatusLines.filter(function(l){return /\sup\s/i.test(l);}).map(function(l){return(l.trim().match(/^(\S+)/)||['',''])[1];});

  // ================================================================
  S('AUTENTICAÇÃO E ACESSO');
  // ================================================================

  // 01. SSH
  var sshV2=has('ip ssh version 2')||has('ssh server version 2');
  var restHttps=has('rest https');
  var sshEnabled=sshV2||has('ip ssh')||has('ssh server');
  var transportSshOnly=L.some(function(l){return /transport input ssh/i.test(l)&&!/telnet/i.test(l);});
  var allowedOnly=has('protocol ssh');
  if(sshEnabled&&sshV2){A('SSH','SIM','N/A','SSH versão 2 habilitado. Acesso CLI seguro.');}
  else if(sshEnabled){A('SSH','PARCIAL','⚠','SSH habilitado. Verificar se "ssh server version 2" está configurado.');}
  else{A('SSH','NÃO','✘','SSH não detectado no log. Verificar configuração de acesso remoto.');}


  // 01b. SSH 2048 BITS (RSA Key Size)
  // OS10: "ip ssh rsa-authentication" ou "crypto key generate rsa modulus 2048"
  // ou "ip ssh dh-min-size 2048" / aparece no show crypto key
  var ssh2048=L.some(function(l){return /modulus\s+204[89]|modulus\s+[3-9]\d{3}|dh-min-size\s+2048|rsa\s+bits\s+2048/i.test(l);});
  var sshKeyGen=L.some(function(l){return /crypto\s+key\s+generate\s+rsa|ip\s+ssh\s+rsa/i.test(l);});
  if(ssh2048){A('SSH 2048 BITS','SIM','N/A','Chave RSA >= 2048 bits detectada.');}
  else if(sshKeyGen){A('SSH 2048 BITS','PARCIAL','⚠','Geração de chave RSA detectada mas tamanho não confirmado. Verificar "show crypto key mypubkey rsa".');}
  else{A('SSH 2048 BITS','VERIFICAR','⚠','Tamanho de chave RSA não encontrado no log. Verificar "show crypto key mypubkey rsa" — mínimo recomendado: 2048 bits.');}

  // 02. TELNET — está habilitado? SIM ou NÃO
  // OS10: telnet habilitado via "management telnet"
  var telnetEnabled=has('management telnet')||has('protocol telnet')||L.some(function(l){return /transport input.*telnet/i.test(l);});
  var telnetExplicitDisabled=L.some(function(l){return /no management telnet/i.test(l.trim());});
  if(telnetExplicitDisabled||!telnetEnabled){A('TELNET','NÃO','N/A','Telnet não habilitado. Acesso remoto restrito a SSH.');}
  else{A('TELNET','SIM','✘','Telnet habilitado. Protocolo inseguro — desabilitar com "no management telnet".');}

  // 03. ACL PARA GERÊNCIA (VTY)
  // OS10: ACL aplicada na VTY via "ip access-class <nome>" sob "line vty"
  var aclMgmt=find('ip access-list').filter(function(l){return /ip access-list/i.test(l.trim());});
  var aclApplied=L.some(function(l){return /service-policy.*access|ip access-group/i.test(l);});
  var aclVty=find('ip access-class').filter(function(l){return /ip access-class\s+\S+/i.test(l.trim());});
  var sshAcl=find('ip ssh source-interface').concat(aclVty);
  if(aclVty.length>0){
    var aclName=(aclVty[0].trim().match(/ip access-class\s+(\S+)/i)||['',''])[1];
    A('ACL PARA GERÊNCIA (VTY)','SIM','N/A','ACL aplicada na VTY: '+aclName+'. Acesso gerencial filtrado por ACL.');
  } else if(aclMgmt.length>0&&(aclApplied||sshAcl.length>0)){A('ACL PARA GERÊNCIA (VTY)','SIM','N/A',''+aclMgmt.length+' ACL(s) configurada(s) e aplicada(s) na gerência.');}
  else if(aclMgmt.length>0){A('ACL PARA GERÊNCIA (VTY)','PARCIAL','⚠','ACL(s) configurada(s) mas não encontrada aplicação na interface de gerência.');}
  else{A('ACL PARA GERÊNCIA (VTY)','NÃO','⚠','Nenhuma ACL de restrição de acesso gerencial detectada. Risco de acesso irrestrito.');}

  // 04. TACACS/RADIUS (AAA)
  var radiusLines=find('radius-server host').filter(function(l){return /radius-server host/i.test(l.trim());});
  if(tacLines.length>0){A('TACACS/RADIUS (AAA)','SIM','N/A','TACACS+ configurado. '+tacIPs.length+' servidor(es): '+tacIPs.join(', ')+'.');}
  else if(radiusLines.length>0){var rips=[...new Set(radiusLines.map(function(l){return(l.match(/radius-server host\s+([\d\.]+)/i)||['',''])[1];}).filter(Boolean))];A('TACACS/RADIUS (AAA)','SIM','N/A','RADIUS configurado. '+rips.length+' servidor(es): '+rips.join(', ')+'.');}
  else{A('TACACS/RADIUS (AAA)','NÃO','✘','Nenhum servidor TACACS+/RADIUS configurado. Autenticação apenas local.');}

  // 05. AAA NEW-MODEL
  if(aaaLogin.length>0){
    var hasTacacs=aaaLogin.some(function(l){return/tacacs/i.test(l);});
    var hasLocal=aaaLogin.some(function(l){return/local/i.test(l);});
    if(hasTacacs&&hasLocal){A('AAA NEW-MODEL','SIM','N/A','AAA configurado com TACACS+ e fallback local: '+aaaLogin[0].trim()+'.');}
    else if(hasTacacs){A('AAA NEW-MODEL','PARCIAL','⚠','AAA com TACACS+ sem fallback local. Risco de lockout.');}
    else{A('AAA NEW-MODEL','PARCIAL','⚠','AAA configurado apenas local (sem TACACS+).');}
  } else{A('AAA NEW-MODEL','NÃO','⚠','aaa authentication login não configurado.');}

  // 06. USERNAME LOCAL (FALLBACK)
  if(uniqueUsers.length>0){
    var hasPriv15=userLines.some(function(l){return/priv-lvl 15|priv-level 15/i.test(l);});
    var hasRole=userLines.some(function(l){return/role sysadmin/i.test(l);});
    A('USERNAME LOCAL (FALLBACK)','SIM','N/A',uniqueUsers.length+' usuário(s) local(is): '+uniqueUsers.slice(0,4).join(', ')+(hasRole?' (com role sysadmin)':'')+'.');
  } else{A('USERNAME LOCAL (FALLBACK)','NÃO','⚠','Nenhum usuário local. Sem fallback de autenticação se AAA cair.');}

  // 07. PASSWORD-ATTRIBUTES (LOCKOUT)
  var pwdAttrs=find('password-attributes').filter(function(l){return /password-attributes/i.test(l.trim());});
  var lockout=pwdAttrs.find(function(l){return /lockout-period/i.test(l);});
  var maxRetry=pwdAttrs.find(function(l){return /max-retry/i.test(l);});
  var lockoutVal=lockout?(lockout.match(/lockout-period\s+(\d+)/i)||['','0'])[1]:'';
  var retryVal=maxRetry?(maxRetry.match(/max-retry\s+(\d+)/i)||['','0'])[1]:'';
  if(lockout&&parseInt(lockoutVal)>0&&maxRetry&&parseInt(retryVal)>0){A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','SIM','N/A','Lockout configurado: period='+lockoutVal+'min, max-retry='+retryVal+'.');}
  else if(lockout||maxRetry){
    var missing=[];
    if(!lockout||parseInt(lockoutVal)===0)missing.push('lockout-period>0');
    if(!maxRetry||parseInt(retryVal)===0)missing.push('max-retry>0');
    A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','PARCIAL','⚠','password-attributes parcialmente configurado. Faltando: '+missing.join(', ')+'.');
  } else{A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','NÃO','⚠','Sem proteção de lockout por senha. Risco de brute-force.');}

  // 08. EXEC-TIMEOUT / SESSION-TIMEOUT
  var sessionTO=find('session-timeout').filter(function(l){return /session-timeout\s+\d+/i.test(l.trim());});
  var execTO=find('exec-timeout').filter(function(l){return /exec-timeout\s+\d+/i.test(l.trim());});
  if(sessionTO.length>0){var sv=(sessionTO[0].trim().match(/session-timeout\s+(\d+)/i)||['',''])[1];A('EXEC-TIMEOUT','SIM','N/A','session-timeout configurado: '+sv+' min.');}
  else if(execTO.length>0){A('EXEC-TIMEOUT','SIM','N/A','exec-timeout configurado.');}
  else{A('EXEC-TIMEOUT','NÃO','⚠','Timeout de sessão não configurado. Sessões ociosas sem limite.');}

  // 09. BANNER MOTD
  // OS10: suporta "banner login" e "banner motd" — qualquer um é válido
  var hasBannerLogin=has('banner login');
  var hasBannerMotd=has('banner motd');
  if(hasBannerMotd&&hasBannerLogin){A('BANNER MOTD','SIM','N/A','Banner MOTD e banner login configurados.');}
  else if(hasBannerMotd){A('BANNER MOTD','SIM','N/A','Banner MOTD configurado.');}
  else if(hasBannerLogin){A('BANNER MOTD','SIM','N/A','Banner login configurado com aviso de acesso autorizado.');}
  else{A('BANNER MOTD','NÃO','✔','Nenhum banner configurado. Recomendado para fins legais e aviso de acesso autorizado.');}

  // 10. CDP/LLDP NAS PORTAS DE ACESSO
  // OS10: CDP não existe — apenas LLDP. "no lldp" desabilita globalmente.
  var lldpGlobal=!has('no lldp advertise')&&!L.some(function(l){return /^no\s+lldp\s*$/i.test(l.trim());});
  var accessWithLldp=0;var accessWithoutLldp=0;var curIfL=null;var isAccessL=false;var hasLldpDis=false;
  L.forEach(function(l){
    var lt=l.trim();
    var ifm=lt.match(/^interface\s+(ethernet[\d\/\:]+)/i);
    if(ifm){
      if(curIfL&&isAccessL){if(hasLldpDis)accessWithoutLldp++;else if(lldpGlobal)accessWithLldp++;}
      curIfL=ifm[1];isAccessL=false;hasLldpDis=false;
    }
    if(curIfL&&/switchport mode access/i.test(lt))isAccessL=true;
    if(curIfL&&/no lldp (transmit|receive)/i.test(lt))hasLldpDis=true;
  });
  if(curIfL&&isAccessL){if(hasLldpDis)accessWithoutLldp++;else if(lldpGlobal)accessWithLldp++;}
  var lldpGlobalStr=lldpGlobal?'LLDP global: ativo.':'LLDP global: desabilitado.';
  var lldpIfStr=(accessWithLldp+accessWithoutLldp)>0?' '+accessWithLldp+' interface(s) de acesso com LLDP ativo, '+accessWithoutLldp+' com LLDP desabilitado.':'';
  if(!lldpGlobal){A('CDP/LLDP NAS PORTAS DE ACESSO','SIM','N/A','CDP não suportado no OS10. '+lldpGlobalStr+lldpIfStr);}

  else{A('CDP/LLDP NAS PORTAS DE ACESSO','SIM','N/A','LLDP global ativo mas controlado nas portas de acesso.');}

  // ================================================================
  S('CRIPTOGRAFIA E ACESSO SEGURO');
  // ================================================================

  // 11. REST HTTPS / HTTP
  var restHttp=has('rest api restconf')||has('rest http');
  var restHttpsEnabled=has('rest https');
  var restHttpOnly=has('rest http')&&!has('rest https');
  if(restHttpsEnabled&&!restHttpOnly){A('HTTPS HABILITADO / HTTP DESABILITADO','SIM','N/A','REST API habilitado via HTTPS. HTTP não detectado.');}
  else if(restHttpOnly){A('HTTPS HABILITADO / HTTP DESABILITADO','NÃO','⚠','REST API habilitado via HTTP sem HTTPS. Tráfego de gerência em texto claro.');}
  else if(restHttp){A('HTTPS HABILITADO / HTTP DESABILITADO','PARCIAL','⚠','REST API configurado. Verificar se HTTPS está habilitado.');}
  else{A('HTTPS HABILITADO / HTTP DESABILITADO','N/A','N/A','REST API não detectado no log.');}

  // 12. SENHAS CRIPTOGRAFADAS
  var pwdInClear=L.some(function(l){return /^(username|system-user)\s+\S+\s+password\s+[^\*]+$/i.test(l.trim())&&!/password\s+\*+/.test(l);});
  var pwdEncrypted=L.some(function(l){return /password\s+\*+/.test(l);});
  var pwdType9=L.some(function(l){return /secret (9|10)\s|password (9|10)\s/i.test(l);});
  if(pwdInClear){A('SERVICE PASSWORD-ENCRYPTION','NÃO','✘','Senha(s) em texto claro detectada(s) no log. Revisar imediatamente.');}
  else if(pwdEncrypted||pwdType9){A('SERVICE PASSWORD-ENCRYPTION','SIM','N/A','Senhas armazenadas de forma cifrada (mostradas como ****).');}
  else{A('SERVICE PASSWORD-ENCRYPTION','PARCIAL','⚠','Não foi possível confirmar criptografia de senhas. Verificar no equipamento.');}

  // 13. USERROLE / RBAC
  var roleLines=userLines.filter(function(l){return /role\s+\S+/i.test(l);});
  var sysadminOnly=roleLines.every(function(l){return /role sysadmin/i.test(l);});
  var hasLimitedRole=roleLines.some(function(l){return /role\s+(?!sysadmin)\S+/i.test(l);});
  if(hasLimitedRole){A('ENABLE SECRET / RBAC','SIM','N/A','Roles diferenciadas detectadas. RBAC implementado via userrole (equivalente ao enable secret/privilege no IOS).');}
  else if(roleLines.length>0){A('ENABLE SECRET / RBAC','PARCIAL','⚠','Todos os usuários com role sysadmin (equivalente ao privilege 15 no IOS). Avaliar criação de usuários com role netoperator para acesso somente leitura (equivalente ao privilege 1 no IOS).');}
  else{A('ENABLE SECRET / RBAC','NÃO','⚠','Roles não detectadas. No OS10 não existe enable secret — controle de acesso via userrole. Verificar separação de privilégios.');}

  // ================================================================
  S('GERÊNCIA');
  // ================================================================

  // 14. GERÊNCIA OUT OF BAND (OOB)
  // OS10: mgmt pode ser interface dedicada (mgmt0) ou vlan com keyword "mgmt"
  var mgmtIfName='';var mgmtIfIp='';
  for(var _mi=0;_mi<L.length;_mi++){
    var _ml=L[_mi].trim();
    var _ifMgmt=_ml.match(/^interface\s+(mgmt[\d\/]+)/i);
    var _ifVlan=_ml.match(/^interface\s+(vlan\d+)/i);
    if(_ifMgmt){
      mgmtIfName=_ifMgmt[1];
      for(var _mj=_mi+1;_mj<Math.min(_mi+15,L.length);_mj++){
        if(/^interface\s+/i.test(L[_mj].trim()))break;
        var _mip=L[_mj].trim().match(/ip address\s+([\d\.]+(?:\/\d+)?)/i);
        if(_mip&&!/^(0\.0\.0\.0|dhcp)/i.test(_mip[1])){mgmtIfIp=_mip[1];break;}
      }
      break;
    }
    if(_ifVlan){
      var _vlanName=_ifVlan[1];var _hasMgmtKw=false;var _vlanIp='';
      for(var _vj=_mi+1;_vj<Math.min(_mi+15,L.length);_vj++){
        if(/^interface\s+/i.test(L[_vj].trim()))break;
        if(/^\s*mgmt\s*$/i.test(L[_vj]))_hasMgmtKw=true;
        var _vip=L[_vj].trim().match(/ip address\s+([\d\.]+(?:\/\d+)?)/i);
        if(_vip&&!/^(0\.0\.0\.0|dhcp)/i.test(_vip[1]))_vlanIp=_vip[1];
      }
      if(_hasMgmtKw){mgmtIfName=_vlanName;mgmtIfIp=_vlanIp;break;}
    }
  }
  if(mgmtIfName&&mgmtIfIp){A('GERÊNCIA OUT OF BAND (OOB)','SIM','N/A','Gerência via '+mgmtIfName+' (mgmt) com IP '+mgmtIfIp+'. OOB configurado.');}
  else if(mgmtIfName){A('GERÊNCIA OUT OF BAND (OOB)','PARCIAL','⚠','Interface '+mgmtIfName+' de gerência configurada mas IP não detectado no log.');}
  else{A('GERÊNCIA OUT OF BAND (OOB)','NÃO','⚠','Interface de gerência (mgmt) não detectada. Gerência possivelmente in-band.');}

  // 15. CONTROL PLANE POLICING (CoPP)
  // OS10: equivalente ao CoPP é o "management rate-limit" ou "cpu-queue rate-limit"
  var coppMgmtRL=has('management rate-limit');
  var coppCpuQ=has('cpu-queue');
  var coppPolicyMap=has('policy-map type control-plane');
  if(coppMgmtRL||coppCpuQ){
    var coppStr=(coppMgmtRL?'management rate-limit':'')+(coppCpuQ?(coppMgmtRL?' + cpu-queue':'cpu-queue'):'');
    A('CONTROL PLANE POLICING (CoPP)','SIM','N/A','Proteção de Control Plane configurada via '+coppStr+'.');
  } else if(coppPolicyMap){
    A('CONTROL PLANE POLICING (CoPP)','SIM','N/A','CoPP configurado via policy-map type control-plane.');
  } else {
    A('CONTROL PLANE POLICING (CoPP)','NÃO','⚠','Proteção de Control Plane não configurada. No OS10 usar "management rate-limit" e/ou "cpu-queue rate-limit" para proteger o plano de controle contra flood.');
  }

  // 16. SERVIDOR DE LOGGING (SYSLOG)
  // OS10: servidores syslog via "logging server X.X.X.X"
  var logSvrs=find('logging server').filter(function(l){return /^logging\s+server\s+[\d\.]+/i.test(l.trim());});
  if(!logSvrs.length)logSvrs=find('logging ').filter(function(l){return /^logging\s+[\d\.]+/i.test(l.trim());});
  var logSrcIf=find('logging source-interface').filter(function(l){return/logging source-interface/i.test(l.trim());});
  if(logSvrs.length>0){
    var logIPs=[...new Set(logSvrs.map(function(l){return(l.match(/logging\s+(?:server\s+)?([\d\.]+)/i)||['',''])[1];}).filter(Boolean))];
    var srcStr=logSrcIf.length>0?' Src: '+logSrcIf[0].trim().replace('logging source-interface','').trim():' Sem source-interface configurado.';
    A('SERVIDOR DE LOGGING','SIM','N/A',logIPs.length+' servidor(es) syslog: '+logIPs.join(', ')+'.'+srcStr);
  } else{A('SERVIDOR DE LOGGING','NÃO','⚠','Nenhum servidor syslog remoto. Logs apenas locais.');}

  // 16b. LOGGING BUFFERED
  // OS10: "logging buffered <level>" — ex: logging buffered warnings
  // Níveis: emergencies, alerts, critical, errors, warnings, notifications, informational, debugging
  var logBuf=find('logging buffered').filter(function(l){return /logging buffered/i.test(l.trim());});
  var logAudit=find('logging audit').filter(function(l){return /logging audit/i.test(l.trim());});
  if(logBuf.length>0){
    var bufVal=(logBuf[0].trim().match(/logging buffered\s+(\d+)/i)||['',''])[1];
    var bufLvl=(logBuf[0].trim().match(/logging buffered\s+(?:\d+\s+)?(\S+)$/i)||['',''])[1];
    A('LOGGING BUFFERED','SIM','N/A','Logging buffered configurado'+(bufVal?' ('+bufVal+' bytes)':'')+(bufLvl?' nível '+bufLvl:'')+'.');
  } else if(logAudit.length>0){
    A('LOGGING BUFFERED','SIM','N/A','Logging audit configurado (armazenamento local de eventos de segurança).');
  } else {
    A('LOGGING BUFFERED','NÃO','⚠','Logging buffered não configurado. Acessar o equipamento e verificar com "show logging" e configurar "logging buffered <level>".');
  }

  // 17. LOGGING SOURCE-INTERFACE
  if(logSrcIf.length>0){A('LOGGING SOURCE-INTERFACE','SIM','N/A','logging source-interface configurado: '+logSrcIf[0].trim()+'.');}
  else if(logSvrs.length>0){A('LOGGING SOURCE-INTERFACE','NÃO','⚠','Syslog configurado sem source-interface. IP de origem pode variar.');}
  else{A('LOGGING SOURCE-INTERFACE','N/A','N/A','Syslog não configurado.');}

  // 18. SNMP PUBLIC/PRIVATE
  var snmpPub=snmpComm.filter(function(l){return/ public(\s|$)/i.test(l);});
  var snmpPrv=snmpComm.filter(function(l){return/ private(\s|$)/i.test(l);});
  if(snmpPub.length===0&&snmpPrv.length===0){
    if(snmpComm.length>0){A('SNMP PUBLIC/PRIVATE','SIM','N/A','Communities public/private ausentes. '+snmpComm.length+' community(ies) customizada(s).');}
    else{A('SNMP PUBLIC/PRIVATE','SIM','N/A','SNMP sem communities public/private configuradas.');}
  } else {
    var badComm=[...snmpPub,...snmpPrv].map(function(l){return(l.trim().match(/community\s+(\S+)/i)||['',''])[1];}).filter(Boolean).join(', ');
    A('SNMP PUBLIC/PRIVATE','NÃO','✘','Community insegura detectada: '+badComm+'. Remover imediatamente.');
  }

  // 19. SNMP PROTEGIDO POR ACL
  // OS10: ACL pode ser definida como "ip access-list ACL-SNMP-*" e referenciada no snmp-server
  var snmpAcl=snmpComm.filter(function(l){return/access-list|ipv4-acl/i.test(l);});
  var snmpGrpAcl=find('snmp-server group').filter(function(l){return/access|acl/i.test(l);});
  var snmpAclByName=find('ip access-list').filter(function(l){return /ip access-list\s+\S*snmp\S*/i.test(l.trim());});
  if(snmpAcl.length>0){A('SNMP PROTEGIDO POR ACL','SIM','N/A','SNMP community com ACL em '+snmpAcl.length+' community(ies).');}
  else if(snmpGrpAcl.length>0){A('SNMP PROTEGIDO POR ACL','SIM','N/A','SNMP protegido por ACL via snmp-server group.');}
  else if(snmpAclByName.length>0){
    var aclNames=snmpAclByName.map(function(l){return(l.trim().match(/ip access-list\s+(\S+)/i)||['',''])[1];}).join(', ');
    A('SNMP PROTEGIDO POR ACL','SIM','N/A','ACL(s) dedicadas ao SNMP detectadas: '+aclNames+'.');
  }
  else if(snmpComm.length>0||snmpUsers.length>0){A('SNMP PROTEGIDO POR ACL','NÃO','⚠','SNMP configurado sem ACL de restrição de hosts.');}
  else{A('SNMP PROTEGIDO POR ACL','N/A','N/A','SNMP não configurado.');}

  // 20. SNMPv3 (SEGURO)
  var uniqSnmpUsers=[...new Set(snmpUsers.map(function(l){return(l.trim().match(/snmp-server user\s+(\S+)/i)||['',''])[1];}).filter(Boolean))];
  if(uniqSnmpUsers.length>0&&snmpComm.length>0){A('SNMPv3 (SEGURO)','PARCIAL','⚠','SNMPv3 ('+uniqSnmpUsers.slice(0,2).join(', ')+') e SNMPv2c ambos ativos. Migrar para v3 exclusivo.');}
  else if(uniqSnmpUsers.length>0){A('SNMPv3 (SEGURO)','SIM','N/A','SNMPv3 configurado com '+uniqSnmpUsers.length+' usuário(s).');}
  else{A('SNMPv3 (SEGURO)','NÃO','⚠','SNMPv3 não configurado. Apenas SNMPv2c ativo.');}

  // ================================================================
  S('INFRAESTRUTURA: Funcionalidade e Serviços de Rede');
  S('ROTEAMENTO');
  // ================================================================

  // 21-23. OSPF
  if(hasOspf){
    A('OSPF','SIM','N/A','OSPF configurado.');
    var ospfPassive=has('passive-interface default');
    var ospfPaIf=find('passive-interface').filter(function(l){return/^\s*passive-interface\s+\S+/i.test(l)&&!/no passive/i.test(l);});
    if(ospfPassive){A('OSPF PASSIVE-INTERFACE DEFAULT','SIM','N/A','passive-interface default configurado.');}
    else if(ospfPaIf.length>0){A('OSPF PASSIVE-INTERFACE DEFAULT','PARCIAL','⚠','passive-interface em '+ospfPaIf.length+' interface(s) mas não como default.');}
    else{A('OSPF PASSIVE-INTERFACE DEFAULT','NÃO','⚠','passive-interface default não configurado.');}
    var ospfAuth=find('ip ospf authentication').concat(find('area authentication'));
    var ospfMd5=ospfAuth.filter(function(l){return/message-digest|sha/i.test(l);});
    if(ospfAuth.length>0){A('OSPF AUTENTICAÇÃO','SIM','N/A','OSPF com autenticação configurada.');}
    else{A('OSPF AUTENTICAÇÃO','NÃO','✘','OSPF sem autenticação. Risco de injeção de rotas falsas.');}
    if(ospfMd5.length>0){A('OSPF MD5/SHA AUTHENTICATION','SIM','N/A','OSPF com autenticação MD5/SHA configurada.');}
    else if(ospfAuth.length>0){A('OSPF MD5/SHA AUTHENTICATION','PARCIAL','⚠','OSPF autenticação sem MD5/SHA. Verificar algoritmo utilizado.');}
    else{A('OSPF MD5/SHA AUTHENTICATION','NÃO','✘','OSPF sem autenticação MD5/SHA. Risco de injeção de rotas falsas.');}
  } else {
    A('OSPF','N/A','N/A','OSPF não configurado.');
    A('OSPF PASSIVE-INTERFACE DEFAULT','N/A','N/A','OSPF não configurado.');
    A('OSPF AUTENTICAÇÃO','N/A','N/A','OSPF não configurado.');
    A('OSPF MD5/SHA AUTHENTICATION','N/A','N/A','OSPF não configurado.');
  }

  // 24-25. BGP
  if(hasBgp){
    A('BGP','SIM','N/A','BGP configurado.');
    var bgpAuth=find('neighbor').filter(function(l){return/neighbor.*password/i.test(l);});
    if(bgpAuth.length>0){A('BGP AUTENTICAÇÃO','SIM','N/A','BGP autenticação em '+bgpAuth.length+' neighbor(s).');}
    else{A('BGP AUTENTICAÇÃO','NÃO','✘','BGP sem autenticação. Risco de session hijack.');}
  } else {
    A('BGP','N/A','N/A','BGP não configurado.');
    A('BGP AUTENTICAÇÃO','N/A','N/A','BGP não configurado.');
  }

  // 25b. EIGRP (protocolo Cisco - não suportado no OS10)
  // EIGRP é proprietário Cisco e não existe no Dell EMC OS10
  A('EIGRP','N/A','N/A','EIGRP é protocolo proprietário Cisco e não é suportado no Dell EMC OS10. Utilizar OSPF ou BGP.');
  A('EIGRP AUTENTICAÇÃO','N/A','N/A','EIGRP não é suportado no Dell EMC OS10.');

  // 25c. NO IP SOURCE-ROUTE
  // OS10: "no ip source-route" — equivalente existe no OS10
  var noSrcRoute=L.some(function(l){return /no\s+ip\s+source-route/i.test(l.trim());});
  var hasSrcRoute=L.some(function(l){return /^ip\s+source-route\s*$/i.test(l.trim());});
  if(noSrcRoute){A('NO IP SOURCE-ROUTE','SIM','N/A','ip source-route desabilitado (no ip source-route).');}
  else if(hasSrcRoute){A('NO IP SOURCE-ROUTE','NÃO','⚠','ip source-route habilitado. Desabilitar com "no ip source-route".');}
  else{A('NO IP SOURCE-ROUTE','NÃO','⚠','no ip source-route não configurado. Desabilitar com "no ip source-route" globalmente.');}

  // 25d. NO IP REDIRECTS
  // OS10: "no ip redirects" aplicado por interface
  var noRedirects=L.some(function(l){return /no\s+ip\s+redirects/i.test(l.trim());});
  var hasRedirects=L.some(function(l){return /^\s*ip\s+redirects\s*$/i.test(l.trim());});
  if(noRedirects){A('NO IP REDIRECTS','SIM','N/A','ip redirects desabilitado em pelo menos uma interface.');}
  else if(hasRedirects){A('NO IP REDIRECTS','NÃO','⚠','ip redirects detectado. Desabilitar com "no ip redirects" nas interfaces.');}
  else{A('NO IP REDIRECTS','NÃO','⚠','no ip redirects não configurado nas interfaces. Aplicar "no ip redirects" nas interfaces de uplink.');}

  // 25e. UNICAST RPF (ANTI-SPOOFING)
  // OS10: uRPF não é suportado. Proteção anti-spoofing via ACL de entrada nas interfaces.
  var urpf=find('ip verify unicast').filter(function(l){return /ip verify unicast/i.test(l.trim());});
  var antiSpoofAcl=L.some(function(l){return /ip access-group\s+\S+\s+in/i.test(l.trim());});
  var antiSpoofAclCount=L.filter(function(l){return /ip access-group\s+\S+\s+in/i.test(l.trim());}).length;
  if(urpf.length>0){A('UNICAST RPF (ANTI-SPOOFING)','SIM','N/A','uRPF configurado em '+urpf.length+' interface(s).');}
  else if(antiSpoofAcl){A('UNICAST RPF (ANTI-SPOOFING)','PARCIAL','⚠','uRPF não é suportado no OS10. ACL de entrada detectada em '+antiSpoofAclCount+' interface(s) como proteção anti-spoofing.');}
  else{A('UNICAST RPF (ANTI-SPOOFING)','NÃO','⚠','uRPF não é suportado no OS10. Nenhuma ACL de entrada detectada nas interfaces. Configurar ACLs de entrada para proteção anti-spoofing.');}

  // 26. BFD
  if(has('bfd')){A('BFD (FAST FAILOVER)','SIM','N/A','BFD configurado para detecção rápida de falhas.');}
  else{A('BFD (FAST FAILOVER)','NÃO','⚠','BFD não configurado. Failover de roteamento mais lento.');}

  // ================================================================
  S('VLT (VIRTUAL LINK TRUNKING)');
  // ================================================================

  // 27. VLT CONFIGURADO
  var vltDomain=find('vlt domain').filter(function(l){return /^vlt domain\s+\d+/i.test(l.trim());});
  if(hasVlt&&vltDomain.length>0){
    var domId=(vltDomain[0].trim().match(/vlt domain\s+(\d+)/i)||['',''])[1];
    A('VLT CONFIGURADO','SIM','N/A','VLT domain '+domId+' configurado.');
  } else if(hasVlt){
    A('VLT CONFIGURADO','SIM','N/A','VLT configurado (vlt-interconnect ou vlt-port-channel detectado).');
  } else {
    A('VLT CONFIGURADO','NÃO','⚠','VLT não configurado. Avaliar necessidade de redundância L2.');
  }

  // 28. VLT INTERCONNECT (VLTi)
  var vltiLines=find('vlt-interconnect').concat(find('vlt-interconnect'));
  var vltiCount=L.filter(function(l){return /vlt-interconnect/i.test(l.trim())&&/^interface/i.test(l.trim());}).length;
  // Count from interface blocks
  var vltiPorts=[];var curIfVlt=null;
  L.forEach(function(l){var lt=l.trim();var ifm=lt.match(/^interface\s+(ethernet[\d\/\:]+)/i);if(ifm)curIfVlt=ifm[1];if(curIfVlt&&/vlt-interconnect/i.test(lt)&&!vltiPorts.includes(curIfVlt))vltiPorts.push(curIfVlt);});
  if(vltiPorts.length>=2){A('VLT INTERCONNECT (VLTi)','SIM','N/A',vltiPorts.length+' porta(s) VLTi configurada(s). Redundância de VLTi confirmada.');}
  else if(vltiPorts.length===1){A('VLT INTERCONNECT (VLTi)','PARCIAL','⚠','Apenas 1 porta VLTi. Recomendado mínimo 2 links para redundância.');}
  else if(hasVlt){A('VLT INTERCONNECT (VLTi)','PARCIAL','⚠','VLT configurado mas VLTi não identificado nas interfaces. Incluir "show running-configuration" completo.');}
  else{A('VLT INTERCONNECT (VLTi)','N/A','N/A','VLT não configurado.');}

  // 29. VLT PORT-CHANNEL (acesso)
  var vltPoLines=find('vlt-port-channel').filter(function(l){return /vlt-port-channel\s+\d+/i.test(l.trim());});
  if(vltPoLines.length>0){A('VLT PORT-CHANNEL','SIM','N/A','vlt-port-channel configurado em '+vltPoLines.length+' interface(s)/port-channel(s).');}
  else if(hasVlt){A('VLT PORT-CHANNEL','PARCIAL','⚠','VLT configurado mas vlt-port-channel não detectado.');}
  else{A('VLT PORT-CHANNEL','N/A','N/A','VLT não configurado.');}

  // ================================================================
  S('SERVIÇOS DE REDE');
  // ================================================================

  // 30. NTP CONFIGURADO
  if(ntpIPs.length>0){A('NTP CONFIGURADO','SIM','N/A',ntpIPs.length+' servidor(es) NTP: '+ntpIPs.join(', ')+'.');}
  else{A('NTP CONFIGURADO','NÃO','⚠','Nenhum servidor NTP configurado. Risco de inconsistência de horário e logs.');}

  // 31. NTP SINCRONIZADO
  var ntpSyncLine=L.some(function(l){return/sync_ntp|synchronized|stratum\s+[1-9](?!\d)/i.test(l);});
  var ntpUnsync=L.some(function(l){return/unsynchronized|not.*sync|stratum\s+16/i.test(l);});
  var ntpNoSysPeer=L.some(function(l){return/no_sys_peer/i.test(l);});
  if(ntpSyncLine&&!ntpNoSysPeer){A('NTP SINCRONIZADO','SIM','N/A','NTP sincronizado confirmado (show ntp status).');}
  else if(ntpSyncLine&&ntpNoSysPeer){A('NTP SINCRONIZADO','PARCIAL','⚠','NTP com sync_ntp mas no_sys_peer. Sem peer de sistema. Verificar conectividade ao servidor NTP.');}
  else if(ntpUnsync){A('NTP SINCRONIZADO','NÃO','✘','NTP com problema de sincronização.');}
  else if(ntpIPs.length>0){A('NTP SINCRONIZADO','PARCIAL','⚠','NTP configurado. Incluir "show ntp status" no log para confirmar sincronismo.');}
  else{A('NTP SINCRONIZADO','NÃO','⚠','NTP não configurado.');}

  // 32. NTP AUTENTICAÇÃO
  var ntpAuthKey=has('ntp authentication-key');
  var ntpTrusted=has('ntp trusted-key');
  var ntpAuthEnabled=has('ntp authenticate');
  if(ntpAuthEnabled&&ntpAuthKey&&ntpTrusted){A('NTP AUTENTICAÇÃO','SIM','N/A','Autenticação NTP completa (authenticate + key + trusted-key).');}
  else if(ntpAuthKey||ntpAuthEnabled){
    var miss=[];if(!ntpAuthEnabled)miss.push('ntp authenticate');if(!ntpAuthKey)miss.push('ntp authentication-key');if(!ntpTrusted)miss.push('ntp trusted-key');
    A('NTP AUTENTICAÇÃO','PARCIAL','⚠','Autenticação NTP incompleta. Faltando: '+miss.join(', ')+'.');
  } else{A('NTP AUTENTICAÇÃO','NÃO','⚠','Autenticação NTP não configurada. Risco de NTP spoofing.');}

  // 33. NO IP PROXY-ARP (SVIs)
  var sviProxy=[];var curIfP=null;
  L.forEach(function(l){var m=l.trim().match(/^interface\s+(\S+)/i);if(m)curIfP=m[1];if(/^\s*ip proxy-arp/i.test(l)&&!/no ip proxy-arp/i.test(l)&&curIfP&&/vlan/i.test(curIfP)&&!sviProxy.includes(curIfP))sviProxy.push(curIfP);});
  if(sviProxy.length===0){A('NO IP PROXY-ARP (SVIs)','SIM','N/A','Proxy-ARP não habilitado nas SVIs. Comando igual ao IOS (no ip proxy-arp).');}
  else{A('NO IP PROXY-ARP (SVIs)','NÃO','⚠','ip proxy-arp ativo em '+sviProxy.length+' SVI(s). Desabilitar com "no ip proxy-arp" nas SVIs.');}

  // 33b. IP SOURCE GUARD
  // OS10: IP Source Guard não é suportado. Proteção equivalente via DHCP Snooping + DAI.
  A('IP SOURCE GUARD','N/A','N/A','IP Source Guard não é suportado no OS10. Proteção equivalente deve ser implementada via DHCP Snooping + Dynamic ARP Inspection (DAI).');

  // 34. DHCP SNOOPING
  var dhcpG=has('ip dhcp snooping')&&!has('no ip dhcp snooping');
  var dhcpV=find('ip dhcp snooping vlan').filter(function(l){return /ip dhcp snooping vlan/i.test(l.trim());});
  if(dhcpG&&dhcpV.length>0){A('DHCP SNOOPING','SIM','N/A','DHCP Snooping habilitado em '+dhcpV.length+' VLAN(s). Comando igual ao IOS.');}
  else if(dhcpG){A('DHCP SNOOPING','PARCIAL','⚠','DHCP Snooping global sem VLANs específicas. Configurar "ip dhcp snooping vlan X" (sintaxe igual ao IOS).');}
  else{A('DHCP SNOOPING','NÃO','⚠','DHCP Snooping não configurado. No OS10 usar "ip dhcp snooping" + "ip dhcp snooping vlan X" (sintaxe igual ao IOS).');}

  // 35. DYNAMIC ARP INSPECTION (DAI)
  // OS10: DAI via "arp learn-enable" por interface ou "ip arp inspection vlan X"
  var daiG=has('ip arp inspection')&&!has('no ip arp inspection');
  var daiV=find('ip arp inspection vlan').filter(function(l){return /ip arp inspection vlan/i.test(l.trim());});
  var arpLearn=find('arp learn-enable').filter(function(l){return /arp learn-enable/i.test(l.trim());});
  if(daiG&&daiV.length>0){A('DYNAMIC ARP INSPECTION (DAI)','SIM','N/A','DAI habilitado em '+daiV.length+' VLAN(s). (ip arp inspection vlan)');}
  else if(arpLearn.length>0){A('DYNAMIC ARP INSPECTION (DAI)','SIM','N/A','Proteção ARP via arp learn-enable configurada em '+arpLearn.length+' interface(s).');}
  else if(daiG){A('DYNAMIC ARP INSPECTION (DAI)','PARCIAL','⚠','DAI global sem VLANs específicas.');}
  else{A('DYNAMIC ARP INSPECTION (DAI)','NÃO','⚠','DAI não configurado. No OS10 usar "ip arp inspection vlan X" ou "arp learn-enable" por interface.');}

  // ================================================================
  S('REDUNDÂNCIA DE GATEWAY');
  // ================================================================

  // HSRP — protocolo proprietário Cisco, não suportado no OS10
  A('HSRP','N/A','N/A','HSRP é protocolo proprietário Cisco e não é suportado no Dell EMC OS10. Utilizar VRRP como alternativa.');
  A('HSRP AUTENTICAÇÃO','N/A','N/A','HSRP é protocolo proprietário Cisco e não é suportado no Dell EMC OS10.');
  A('HSRP PRIORIDADE','N/A','N/A','HSRP é protocolo proprietário Cisco e não é suportado no Dell EMC OS10.');

  // VRRP — suportado nativamente no OS10 via "vrrp-group"
  var vrrpLines=find('vrrp-group').filter(function(l){return /vrrp-group\s+\d+/i.test(l.trim());});
  var vrrpVip=find('virtual-address').filter(function(l){return /virtual-address\s+[\d\.]+/i.test(l.trim());});
  var vrrpAuth=find('authentication').filter(function(l){return /vrrp|authentication\s+\S+/i.test(l)&&/authentication/i.test(l);});
  var vrrpPrio=find('priority').filter(function(l){return /^\s*priority\s+\d+/i.test(l.trim());});
  if(vrrpLines.length>0){
    var vrrpIps=vrrpVip.map(function(l){return(l.trim().match(/virtual-address\s+([\d\.]+)/i)||['',''])[1];}).filter(Boolean);
    A('VRRP','SIM','N/A','VRRP configurado em '+vrrpLines.length+' grupo(s)'+(vrrpIps.length>0?'. VIP(s): '+vrrpIps.slice(0,3).join(', '):'')+'.');
    if(vrrpAuth.length>0){A('VRRP AUTENTICAÇÃO','SIM','N/A','VRRP com autenticação configurada.');}
    else{A('VRRP AUTENTICAÇÃO','NÃO','⚠','VRRP sem autenticação. Configurar autenticação no vrrp-group.');}
    if(vrrpPrio.length>0){A('VRRP PRIORIDADE','SIM','N/A','Prioridade VRRP configurada em '+vrrpPrio.length+' grupo(s).');}
    else{A('VRRP PRIORIDADE','VERIFICAR','⚠','Prioridade VRRP não encontrada no log. Acessar o equipamento e verificar com "show vrrp" — padrão é 100.');}
  } else {
    A('VRRP','NÃO','⚠','VRRP não configurado. No OS10 usar "vrrp-group <id>" dentro da interface SVI.');
    A('VRRP AUTENTICAÇÃO','N/A','N/A','VRRP não configurado.');
    A('VRRP PRIORIDADE','N/A','N/A','VRRP não configurado.');
  }

  // GLBP — protocolo proprietário Cisco, não suportado no OS10
  A('GLBP','N/A','N/A','GLBP é protocolo proprietário Cisco e não é suportado no Dell EMC OS10. Utilizar VRRP como alternativa.');
  A('GLBP AUTENTICAÇÃO','N/A','N/A','GLBP é protocolo proprietário Cisco e não é suportado no Dell EMC OS10.');
  A('GLBP PRIORIDADE','N/A','N/A','GLBP é protocolo proprietário Cisco e não é suportado no Dell EMC OS10.');

  // ================================================================
  S('SWITCHING / L2');
  // ================================================================

  // 36. VLAN SEM DESCRIPTION
  var vlanBlocks={};var curVl=null;
  L.forEach(function(l){
    var lt=l.trim();
    var vm=lt.match(/^interface\s+vlan(\d+)/i);
    if(vm){curVl=vm[1];vlanBlocks[curVl]=vlanBlocks[curVl]||{hasDesc:false};}
    if(curVl&&/^\s*description\s+\S+/.test(lt)&&!/description\s+default/i.test(lt)&&!/description\s+vlan_/i.test(lt))vlanBlocks[curVl].hasDesc=true;
  });
  var allVlans=Object.keys(vlanBlocks);
  var vlansNoDesc=allVlans.filter(function(v){return!vlanBlocks[v].hasDesc;});
  if(allVlans.length===0){A('VLAN SEM NAME','N/A','N/A','Nenhuma interface VLAN detectada.');}
  else if(vlansNoDesc.length===0){A('VLAN SEM NAME','SIM','N/A','Todas as VLANs com description configurado.');}
  else{A('VLAN SEM NAME','PARCIAL','⚠',vlansNoDesc.length+' VLAN(s) sem description: vlan'+vlansNoDesc.join(', vlan')+'.');}

  // 37. STP: MODO RAPID-PVST/RSTP
  var stpMode=find('spanning-tree mode').filter(function(l){return /spanning-tree mode/i.test(l.trim());});
  var stpVlanConfig=find('spanning-tree vlan').filter(function(l){return /spanning-tree vlan/i.test(l.trim());});
  if(stpMode.length>0){var sm=(stpMode[0].trim().match(/spanning-tree mode\s+(\S+)/i)||['',''])[1].toUpperCase();A('STP: MODO RAPID-PVST/MST','SIM','N/A','Modo STP: '+sm+'.');}
  else if(stpVlanConfig.length>0){A('STP: MODO RAPID-PVST/MST','PARCIAL','⚠','Spanning-tree configurado mas modo não explícito. Verificar se rapid-pvst está ativo.');}
  else{A('STP: MODO RAPID-PVST/MST','N/A','N/A','Spanning-tree não detectado no log.');}

  // 38. STP: PRIORIDADE CONFIGURADA
  var stpP=find('spanning-tree vlan').filter(function(l){return /spanning-tree vlan[\s\d,\-]+priority/i.test(l.trim());});
  var stpPRoot=find('spanning-tree vlan').filter(function(l){return /spanning-tree vlan[\s\d,\-]+root/i.test(l.trim());});
  if(stpP.length>0){
    var stpPDetail=stpP.map(function(l){var m=l.trim().match(/spanning-tree vlan\s+([\d,\-]+)\s+priority\s+(\d+)/i);return m?'Vlan'+m[1]+'→'+m[2]:l.trim();}).join(', ');
    A('STP: PRIORIDADE CONFIGURADA','SIM','N/A','STP prioridade: '+stpPDetail+'.');
  } else if(stpPRoot.length>0){
    A('STP: PRIORIDADE CONFIGURADA','SIM','N/A','STP root configurado.');
  } else {A('STP: PRIORIDADE CONFIGURADA','NÃO','⚠','STP prioridade não configurada. Usando default (32768).');}

  // 39. STP: BPDU GUARD
  var bpduG=has('spanning-tree portfast bpduguard default')||has('spanning-tree bpduguard default');
  var bpduIF=find('spanning-tree bpduguard enable').filter(function(l){return /bpduguard enable/i.test(l.trim());});
  var bpduIFEdge=find('edge-port').filter(function(l){return/edge-port bpduguard/i.test(l.trim());});
  if(bpduG){A('STP: BPDU GUARD','SIM','N/A','BPDU Guard habilitado globalmente.');}
  else if(bpduIF.length>0||bpduIFEdge.length>0){A('STP: BPDU GUARD','PARCIAL','⚠','BPDU Guard em '+(bpduIF.length+bpduIFEdge.length)+' interface(s) mas não globalmente.');}
  else{A('STP: BPDU GUARD','NÃO','⚠','BPDU Guard não configurado. Risco de loop STP por dispositivo não autorizado.');}

  // 40. STP: BPDU FILTER
  var bpduFlt=has('spanning-tree portfast bpdufilter default');
  var bpduFIF=find('spanning-tree bpdufilter enable').filter(function(l){return /bpdufilter enable/i.test(l.trim());});
  if(bpduFlt){A('STP: BPDU FILTER','SIM','N/A','BPDU Filter habilitado globalmente.');}
  else if(bpduFIF.length>0){A('STP: BPDU FILTER','PARCIAL','⚠','BPDU Filter em '+bpduFIF.length+' interface(s).');}
  else{A('STP: BPDU FILTER','NÃO','⚠','BPDU Filter não configurado.');}

  // 41. STP: ROOT GUARD
  var rg=find('spanning-tree guard root').concat(find('spanning-tree rootguard'));
  if(rg.length>0){A('STP: ROOT GUARD CONFIGURADO','SIM','N/A','Root Guard em '+rg.length+' interface(s).');}
  else{A('STP: ROOT GUARD CONFIGURADO','NÃO','✘','Root Guard não configurado. Risco de Root Bridge hijack.');}

  // 42. STP: LOOP GUARD
  var lgG=has('spanning-tree loopguard default');
  var lgIF=find('spanning-tree guard loop').filter(function(l){return /guard loop/i.test(l.trim());});
  if(lgG){A('STP: LOOP GUARD','SIM','N/A','Loop Guard habilitado globalmente.');}
  else if(lgIF.length>0){A('STP: LOOP GUARD','PARCIAL','⚠','Loop Guard em '+lgIF.length+' interface(s) mas não globalmente.');}
  else{A('STP: LOOP GUARD','NÃO','⚠','Loop Guard não configurado. Risco de loop unidirecional.');}

  // 43. STORM CONTROL
  var stIf=[];var cIfs=null;
  L.forEach(function(l){var m=l.trim().match(/^interface\s+(\S+)/i);if(m)cIfs=m[1];if(/storm-control/i.test(l.trim())&&cIfs&&!stIf.includes(cIfs))stIf.push(cIfs);});
  if(stIf.length>8){A('STORM CONTROL','SIM','N/A','Storm-control em '+stIf.length+' interface(s).');}
  else if(stIf.length>0){A('STORM CONTROL','PARCIAL','⚠','Storm-control em apenas '+stIf.length+' interface(s). Verificar cobertura.');}
  else{A('STORM CONTROL','NÃO','⚠','Storm-control não configurado. Risco de broadcast storm.');}

  // 44. UDLD HABILITADO
  var udldG=has('udld enable');
  var udldAgg=has('udld aggressive');
  var udldDis=find('no udld enable').filter(function(l){return /no udld enable/i.test(l.trim());});
  if((udldG||udldAgg)&&udldDis.length===0){A('UDLD HABILITADO','SIM','N/A','UDLD habilitado '+(udldAgg?'(modo agressivo)':'')+'.');}
  else if(udldG||udldAgg){A('UDLD HABILITADO','PARCIAL','⚠','UDLD habilitado mas desabilitado em '+udldDis.length+' interface(s).');}
  else{A('UDLD HABILITADO','NÃO','⚠','UDLD não habilitado. Usar "udld enable".');}

  // 45. VLAN 1 SEM USO EM PORTAS
  var v1Access=[];var v1Trunk=[];var curIfV1=null;
  L.forEach(function(l){
    var lt=l.trim();
    var ifm=lt.match(/^interface\s+(\S+)/i);if(ifm)curIfV1=ifm[1];
    if(curIfV1&&/switchport access vlan\s+1$/i.test(lt)&&!v1Access.includes(curIfV1))v1Access.push(curIfV1);
    if(curIfV1&&/switchport trunk allowed vlan\s+(1,|1$|all)/i.test(lt)&&!v1Trunk.includes(curIfV1))v1Trunk.push(curIfV1);
  });
  var totalV1=v1Access.length+v1Trunk.length;
  if(totalV1>0){A('VLAN 1 SEM USO EM PORTAS','NÃO','⚠','Vlan 1 em uso: '+v1Access.length+' access / '+v1Trunk.length+' trunk.');}
  else{A('VLAN 1 SEM USO EM PORTAS','SIM','N/A','Vlan 1 não detectada explicitamente nas portas.');}

  // 46. TRUNK COM FILTRO DE VLANS
  var tIfMap={};var cTf=null;
  L.forEach(function(l){var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/i);if(ifm){cTf=ifm[1];if(!tIfMap[cTf])tIfMap[cTf]={trunk:false,allowed:false,allowAll:false};}
    if(cTf&&/switchport mode trunk/i.test(lt))tIfMap[cTf].trunk=true;
    if(cTf&&/switchport trunk allowed vlan/i.test(lt)){tIfMap[cTf].allowed=true;if(/allowed vlan all\b/i.test(lt))tIfMap[cTf].allowAll=true;}
  });
  var trnks=Object.entries(tIfMap).filter(function(e){return e[1].trunk;});
  var tProblema=trnks.filter(function(e){return!e[1].allowed||e[1].allowAll;});
  if(trnks.length===0){A('TRUNK COM FILTRO DE VLANS','N/A','N/A','Nenhuma interface trunk identificada.');}
  else if(tProblema.length===0){A('TRUNK COM FILTRO DE VLANS','SIM','N/A','Todas as '+trnks.length+' trunk(s) com filtro de VLANs configurado.');}
  else{
    var temAll=trnks.filter(function(e){return e[1].allowAll;}).length>0;
    var tProblemaList=tProblema.map(function(e){return abbrevIf(e[0]);}).slice(0,6).join(', ');
    A('TRUNK COM FILTRO DE VLANS',temAll?'NÃO':'PARCIAL',temAll?'✘':'⚠',tProblema.length+' trunk(s) sem filtro adequado: '+tProblemaList+'.');
  }

  // 47. ERRDISABLE RECOVERY
  var errPorts=L.filter(function(l){return/err-disabled|errdisable/i.test(l)&&/eth|po/i.test(l);});
  var errCfg=has('errdisable recovery');
  if(errPorts.length>0&&errCfg){A('ERRDISABLE RECOVERY','PARCIAL','⚠',errPorts.length+' porta(s) em err-disabled. Recovery configurado.');}
  else if(errPorts.length>0){A('ERRDISABLE RECOVERY','NÃO','✘',errPorts.length+' porta(s) em err-disabled sem recovery automático.');}
  else if(errCfg){A('ERRDISABLE RECOVERY','SIM','N/A','errdisable recovery configurado. Nenhuma porta em err-disabled.');}
  else{A('ERRDISABLE RECOVERY','N/A','N/A','Nenhuma porta err-disabled detectada.');}

  // 48. PORT SECURITY
  var psSec=find('switchport port-security').filter(function(l){return /switchport port-security/i.test(l.trim());});
  if(psSec.length>0){A('PORT SECURITY','SIM','N/A','Port Security configurado em '+psSec.length+' interface(s).');}
  else{A('PORT SECURITY','NÃO','⚠','Port Security não configurado. Risco de MAC flooding.');}

  // ================================================================
  S('PORT-CHANNEL');
  // ================================================================

  // 49-53. PORT-CHANNEL
  var cgLines=find('channel-group').filter(function(l){return/channel-group\s+\d+/i.test(l.trim());});
  var cgModeOn=cgLines.filter(function(l){return /mode on\b/i.test(l);});
  var cgLacp=cgLines.filter(function(l){return /mode (active|passive)/i.test(l);}).length;
  var totalPo=poIfaces.length;

  if(totalPo>0||cgLines.length>0){
    if(cgModeOn.length>0){A('PORT-CHANNEL COM LACP/PAGP','PARCIAL','⚠',totalPo+' port-channel(s). '+cgModeOn.length+' em mode ON (sem LACP). Configurar LACP mode active/passive.');}
    else if(cgLacp>0){A('PORT-CHANNEL COM LACP/PAGP','SIM','N/A',totalPo+' port-channel(s) com LACP ('+cgLacp+' membro(s) active/passive).');}
    else{A('PORT-CHANNEL COM LACP/PAGP','PARCIAL','⚠',totalPo+' port-channel(s) sem mode LACP explícito.');}
  } else{A('PORT-CHANNEL COM LACP/PAGP','N/A','N/A','Nenhum port-channel detectado.');}

  // Membros down
  var poMembDown=[];
  L.forEach(function(l){if(/port-channel.*down|po\d+.*down/i.test(l)&&!/admin/i.test(l))poMembDown.push(l.trim().substring(0,60));});
  if(poMembDown.length>0){A('PORT-CHANNELS COM MEMBROS DOWN','NÃO','✘',poMembDown.length+' membro(s) de port-channel DOWN detectado(s).');}
  else if(poIfaces.length>0){A('PORT-CHANNELS COM MEMBROS DOWN','SIM','N/A','Nenhum membro DOWN detectado nos port-channels.');}
  else{A('PORT-CHANNELS COM MEMBROS DOWN','N/A','N/A','Nenhum port-channel configurado.');}

  // PORT-CHANNEL MEMBROS INCONSISTENTES
  var poInconsist=L.filter(function(l){return /port-channel|po\s*\d+/i.test(l)&&/individual|suspended|inconsistent/i.test(l);});
  var poSuspended=L.filter(function(l){return /suspended/i.test(l)&&/channel-group|port-channel/i.test(l);});
  var poIncTotal=poInconsist.length+poSuspended.length;
  if(poIncTotal>0){A('PORT-CHANNEL MEMBROS INCONSISTENTES','NÃO','✘',poIncTotal+' ocorrencia(s) de membros inconsistentes/suspensos detectada(s) em port-channel(s).');}
  else if(poIfaces.length>0){A('PORT-CHANNEL MEMBROS INCONSISTENTES','SIM','N/A','Nenhum membro inconsistente ou suspenso detectado.');}
  else{A('PORT-CHANNEL MEMBROS INCONSISTENTES','N/A','N/A','Nenhum port-channel configurado.');}

  // PORT-CHANNEL SEM MEMBROS
  var poDeclared=[...new Set(poIfaces.map(function(l){return(l.trim().match(/^interface\s+port-channel(\d+)/i)||['',''])[1];}).filter(Boolean))];
  var poReferenced=[...new Set(cgLines.map(function(l){return(l.trim().match(/channel-group\s+(\d+)/i)||['',''])[1];}).filter(Boolean))];
  var poNoMembers=poDeclared.filter(function(id){return!poReferenced.includes(id);});
  if(poNoMembers.length>0){A('PORT-CHANNEL SEM MEMBROS','NÃO','⚠',poNoMembers.length+' port-channel(s) sem interface membro associada: Po'+poNoMembers.join(', Po')+'.');}
  else if(poDeclared.length>0){A('PORT-CHANNEL SEM MEMBROS','SIM','N/A','Todos os port-channel(s) possuem membros associados.');}
  else{A('PORT-CHANNEL SEM MEMBROS','N/A','N/A','Nenhum port-channel configurado.');}

  // Po DOWN
  var poStatusLines=L.filter(function(l){return /^(Po|port-channel)\s*\d+/i.test(l.trim());});
  var poDown=poStatusLines.filter(function(l){return /\sdown\s/i.test(l);});
  if(poDown.length>0){A('PORT-CHANNEL DOWN','NÃO','✘','Port-channel(s) DOWN: '+poDown.length+'.');}
  else if(totalPo>0){A('PORT-CHANNEL DOWN','SIM','N/A','Todos os port-channels ativos.');}
  else{A('PORT-CHANNEL DOWN','N/A','N/A','Nenhum port-channel detectado.');}

  // Uplinks dual (41:1 e 42:1 para CC switches)
  var uplinkCount=upPorts.filter(function(p){return/41|42|uplink/i.test(p);}).length;
  if(uplinkCount>=2||poIfaces.length>=2){A('DUPLA ABORDAGEM COM CORE','SIM','N/A','Dual uplink detectado ('+(uplinkCount>=2?uplinkCount+' uplinks ativos':poIfaces.length+' port-channel(s)' )+').');}
  else if(poIfaces.length===1){A('DUPLA ABORDAGEM COM CORE','PARCIAL','⚠','1 port-channel detectado. Uplink redundante não confirmado.');}
  else{A('DUPLA ABORDAGEM COM CORE','NÃO','⚠','Dupla conexão ao core não detectada.');}

  // ================================================================
  S('INFRAESTRUTURA FÍSICA');
  // ================================================================

  // 54. FONTE REDUNDANTE
  var psuUp=L.filter(function(l){return/PSU|power supply|PS\s*\d/i.test(l)&&/up|ok|present|good|on-line/i.test(l);});
  var psuLines=L.filter(function(l){return/^\s*\d\s+(OK|up|good)/i.test(l.trim())&&!/unit|sensor/i.test(l.toLowerCase());});
  if(psuUp.length>=2||psuLines.length>=2){A('FONTE REDUNDANTE','SIM','N/A',(psuUp.length||psuLines.length)+' fonte(s) detectada(s) e ativas.');}
  else if(psuUp.length===1||psuLines.length===1){A('FONTE REDUNDANTE','PARCIAL','⚠','Apenas 1 fonte detectada. Sem redundância.');}
  else{A('FONTE REDUNDANTE','NÃO','⚠','PSU não detectada. Incluir "show environment" ou "show system" no log.');}

  // 55. PORTAS NO STATUS NOTCONNECT / DOWN
  // Contar apenas portas com link down SEM shutdown configurado
  var downEthPorts=[];
  var shutdownIfs=[];var curIfDown=null;var curIfShutdown=false;
  L.forEach(function(l){
    var lt=l.trim();
    var ifm=lt.match(/^interface\s+(ethernet[\d\/\:]+)/i);
    if(ifm){
      if(curIfDown&&!curIfShutdown)downEthPorts.push(abbrevIf(curIfDown));
      curIfDown=null;curIfShutdown=false;
      curIfDown=ifm[1];
    }
    if(curIfDown&&/^shutdown$/i.test(lt))curIfShutdown=true;
  });
  if(curIfDown&&!curIfShutdown)downEthPorts.push(abbrevIf(curIfDown));
  // Filter: cross-reference with actual down ports from status lines
  var downFromStatus=[];
  L.forEach(function(l){
    var lt=l.trim();
    var m=lt.match(/^(Eth[\d\/\:]+)/i);
    if(m&&/\sdown\s/i.test(lt)&&!/admin\s*down/i.test(lt)){
      var pn=abbrevIf(m[1]);
      if(!downFromStatus.includes(pn))downFromStatus.push(pn);
    }
  });
  var noShutdownDown=downFromStatus.length>0?downFromStatus:downEthPorts;
  if(noShutdownDown.length===0){A('PORTAS NO STATUS NOTCONNECT','N/A','N/A','Nenhuma porta link-down sem shutdown detectada. Incluir "show interface status" no log.');}
  else{A('PORTAS NO STATUS NOTCONNECT','PARCIAL','⚠',noShutdownDown.length+' porta(s) com link down sem shutdown configurado.');}

  // 55b. VIRTUALIZACAO (VPC/VSS/STACK)
  var vltDomains2=L.filter(function(l){return /^vlt domain\s+\d+/i.test(l.trim());}).map(function(l){return(l.trim().match(/^vlt domain\s+(\d+)/i)||['',''])[1];}).filter(Boolean);
  if(hasVlt&&vltDomains2.length>0){A('VIRTUALIZACAO (VPC/VSS/STACK)','SIM','N/A','VLT configurado (equivalente ao VPC/VSS/Stack no OS10). Dominio(s): '+vltDomains2.join(', ')+'.');}
  else if(hasVlt){A('VIRTUALIZACAO (VPC/VSS/STACK)','SIM','N/A','VLT configurado (equivalente ao VPC/VSS/Stack no OS10).');}
  else{A('VIRTUALIZACAO (VPC/VSS/STACK)','NÃO','⚠','VLT não configurado. No OS10 o equivalente ao VPC/VSS/Stack é o VLT.');}

  // 56. VLT (VIRTUALIZAÇÃO)
  if(hasVlt){A('VLT (VIRTUALIZAÇÃO L2)','SIM','N/A','VLT configurado. Redundância de switch L2 ativa.');}
  else{A('VLT (VIRTUALIZAÇÃO L2)','NÃO','⚠','VLT não configurado. Avaliar necessidade de redundância de switch.');}

  // 57. FCoE / FC
  var hasFcoe=has('feature fc npg')||has('feature fcoe')||has('interface fc');
  var fcUp=upPorts.filter(function(p){return /^Fc/i.test(p);});
  if(hasFcoe||fcUp.length>0){A('FCoE / FIBRE CHANNEL (NPG)','SIM','N/A','FCoE/FC NPG configurado. '+(fcUp.length>0?fcUp.length+' porta(s) FC ativas: '+fcUp.join(', ')+'.' :''));}
  else{A('FCoE / FIBRE CHANNEL (NPG)','N/A','N/A','FCoE/FC não detectado.');}

  // 58. TEMPERATURA
  var tempLines=L.filter(function(l){return/NPU temp|NPU sensor|Ambient temp/i.test(l)&&/\d+\s*$/.test(l.trim());});
  if(tempLines.length>0){
    var temps=tempLines.map(function(l){var t=(l.match(/(\d+)\s*$/)||['',''])[1];return t;}).filter(Boolean);
    var maxTemp=Math.max.apply(null,temps.map(Number));
    if(maxTemp>80){A('TEMPERATURA DO HARDWARE','NÃO','✘','Temperatura crítica detectada: '+maxTemp+'°C. Verificar imediatamente.');}
    else if(maxTemp>70){A('TEMPERATURA DO HARDWARE','PARCIAL','⚠','Temperatura elevada: '+maxTemp+'°C. Monitorar.');}
    else{A('TEMPERATURA DO HARDWARE','SIM','N/A','Temperatura normal. Máxima detectada: '+maxTemp+'°C.');}
  } else{A('TEMPERATURA DO HARDWARE','N/A','N/A','Incluir "show environment" no log para análise de temperatura.');}

  // 59. SPEED/DUPLEX
  var halfDup=L.filter(function(l){return/half.?duplex|Half/i.test(l)&&/eth|po/i.test(l);});
  var mismatch=L.filter(function(l){return/duplex mismatch|speed mismatch/i.test(l);});
  var autoSpeedCount=0;var autoIfCur=null;var autoIfSpeed=false;var autoIfDuplex=false;
  L.forEach(function(l){
    var lt=l.trim();
    var ifm=lt.match(/^interface\s+(ethernet[\d\/\:]+)/i);
    if(ifm){if(autoIfCur&&autoIfSpeed&&autoIfDuplex)autoSpeedCount++;autoIfCur=ifm[1];autoIfSpeed=false;autoIfDuplex=false;}
    if(autoIfCur&&/^speed\s+auto/i.test(lt))autoIfSpeed=true;
    if(autoIfCur&&/^duplex\s+auto/i.test(lt))autoIfDuplex=true;
  });
  if(autoIfCur&&autoIfSpeed&&autoIfDuplex)autoSpeedCount++;
  if(mismatch.length>0){A('SPEED/DUPLEX UPLINKS','NÃO','⚠',mismatch.length+' interface(s) com mismatch detectado.');}
  else if(halfDup.length>0){A('SPEED/DUPLEX UPLINKS','NÃO','⚠',halfDup.length+' interface(s) em Half-duplex.');}
  else if(autoSpeedCount>0){A('SPEED/DUPLEX UPLINKS','PARCIAL','⚠',autoSpeedCount+' interface(s) com speed auto e duplex auto configurados. Verificar se é intencional.');}
  else{A('SPEED/DUPLEX UPLINKS','SIM','N/A','Nenhum mismatch, half-duplex ou configuração auto manual detectado.');}

  // 60. EQUIPAMENTO EM SUPORTE (EOL)
  A('EQUIPAMENTO EM SUPORTE (NÃO EOL)','VERIFICAR NO PORTAL DELL','VERIFICAR NO PORTAL DELL','Verificar em https://www.dell.com/support/.');

  // 61-62. BASELINE
  A('BASELINE CPU E MEMÓRIA','ANALISAR NO DX NETOPS','ANALISAR NO DX NETOPS','Inserir resultado após análise.');
  A('BASELINE UPLINKS','ANALISAR NO DX NETOPS','ANALISAR NO DX NETOPS','Inserir resultado após análise.');

  return items;
}



function runAnalysis_comware(log){
  var L=log.split('\n');
  var items=[];
  function has(kw){return L.some(function(l){return l.toLowerCase().includes(kw.toLowerCase());});}
  function find(kw){return L.filter(function(l){return l.toLowerCase().includes(kw.toLowerCase());});}
  function S(sec){items.push({status:'SECTION',item:sec});}
  function A(item,status,risco,obs){items.push({item:item,status:status,risco:risco,obs:obs});}

  // ===== PRÉ-CÁLCULO DE VARIÁVEIS =====

  // SSH
  var sshEnabled=has('ssh server enable')&&!has('undo ssh server enable');

  // Idle-timeout in vty block (supports both "user-interface vty" and "line vty")
  var idleVty=[];var inVty=false;
  L.forEach(function(l){
    var lt=l.trim();
    if(/^user-interface vty/i.test(lt)||/^line vty/i.test(lt)){inVty=true;}
    else if((/^user-interface/i.test(lt)&&!/vty/i.test(lt))||/^line\s+(con|aux|class)/i.test(lt)){inVty=false;}
    if(inVty&&/^idle-timeout\s+\d+/.test(lt))idleVty.push(lt);
  });

  // ACL in vty block (supports both "user-interface vty" and "line vty")
  var aclVtyLines=[];var inVtyAcl=false;
  L.forEach(function(l){
    var lt=l.trim();
    if(/^user-interface vty/i.test(lt)||/^line vty/i.test(lt)){inVtyAcl=true;}
    else if((/^user-interface/i.test(lt)&&!/vty/i.test(lt))||/^line\s+(con|aux|class)/i.test(lt)){inVtyAcl=false;}
    if(inVtyAcl&&/^acl(\s+ipv4)?\s+\d+\s+inbound/i.test(lt))aclVtyLines.push(lt);
  });
  // Also detect ACL named with VTY referenced inside line vty block
  if(aclVtyLines.length===0){
    var vtyAclNums=L.filter(function(l){return /acl\s+(?:number\s+)?\d+.*\bVTY\b/i.test(l.trim());})
      .map(function(l){return(l.match(/acl\s+(?:number\s+)?(\d+)/i)||['',''])[1];}).filter(Boolean);
    if(vtyAclNums.length>0){
      var inVtyChk=false;
      L.forEach(function(l){
        var lt=l.trim();
        if(/^user-interface vty|^line vty/i.test(lt)){inVtyChk=true;}
        else if(/^user-interface|^line\s+(con|aux|class)/i.test(lt)){inVtyChk=false;}
        if(inVtyChk&&vtyAclNums.some(function(n){return new RegExp('\\b'+n+'\\b').test(lt);}))aclVtyLines.push(lt);
      });
    }
  }

  // TACACS servers
  var hwtacacsSchemes=find('hwtacacs scheme').filter(function(l){return /^\s*hwtacacs\s+scheme\s+\S+/i.test(l.trim());});
  var hwtacacsPrimAuth=find('primary authentication').filter(function(l){return /\d+\.\d+\.\d+\.\d+/.test(l);});
  var hwtacacsSecAuth=find('secondary authentication').filter(function(l){return /\d+\.\d+\.\d+\.\d+/.test(l);});
  var hwtacacsAuthSrv=find('hwtacacs server authentication').filter(function(l){return /\d+\.\d+\.\d+\.\d+/.test(l);});
  var hwtacacsIPs=[].concat(hwtacacsPrimAuth,hwtacacsSecAuth,hwtacacsAuthSrv)
    .map(function(l){return(l.match(/(\d+\.\d+\.\d+\.\d+)/)||['',''])[1];}).filter(Boolean);
  var hwtacacsIPsUniq=[...new Set(hwtacacsIPs)];

  // RADIUS servers
  var radiusSchemes=find('radius scheme').filter(function(l){return /^\s*radius\s+scheme\s+\S+/i.test(l.trim());});
  var radiusIPs=find('primary authentication').concat(find('secondary authentication'))
    .filter(function(l){return /\d+\.\d+\.\d+\.\d+/.test(l);})
    .map(function(l){return(l.match(/(\d+\.\d+\.\d+\.\d+)/)||['',''])[1];}).filter(Boolean);
  var radiusIPsUniq=[...new Set(radiusIPs)];

  // Local users
  var localUsers=find('local-user ').filter(function(l){return /^\s*local-user\s+\S+/i.test(l.trim());});
  var localUserNames=[...new Set(localUsers.map(function(l){return(l.trim().match(/^local-user\s+(\S+)/i)||['',''])[1];}).filter(Boolean))];
  // Users with password hash
  var usersWithHash=[];var curLU=null;
  L.forEach(function(l){
    var lt=l.trim();
    var lum=lt.match(/^local-user\s+(\S+)/i);if(lum){curLU=lum[1];}
    if(curLU&&/^password\s+(hash|cipher|irreversible-cipher)/i.test(lt)&&!usersWithHash.includes(curLU))usersWithHash.push(curLU);
  });

  // OSPF/BGP
  var hasOspf=L.some(function(l){return /^\s*ospf\s+\d+/i.test(l.trim())||/^\s*ospf$/i.test(l.trim());});
  var hasBgp=L.some(function(l){return /^\s*bgp\s+\d+/i.test(l.trim());});

  // VRRP
  var vrrpIfaces=find('vrrp vrid').filter(function(l){return /vrrp\s+vrid\s+\d+\s+virtual-ip/i.test(l);});

  // NTP
  var ntpSvrs=find('ntp-service unicast-server').concat(find('ntp unicast-server')).filter(function(l){return /ntp/i.test(l.trim());});
  var ntpIPs=[...new Set(ntpSvrs.map(function(l){return(l.match(/(\d+\.\d+\.\d+\.\d+)/)||['',''])[1];}).filter(Boolean))];

  // SNMP
  var snmpComm=find('snmp-agent community').filter(function(l){return /^\s*snmp-agent\s+community/i.test(l.trim());});
  var snmpV3Users=find('snmp-agent usm-user v3').filter(function(l){return /^\s*snmp-agent\s+usm-user\s+v3/i.test(l.trim());});
  // SNMP version line
  var snmpVerLine=L.find(function(l){return /snmp-agent\s+sys-info\s+version/i.test(l.trim());});

  // Link aggregation (Bridge-Aggregation)
  var baggIfaces=L.filter(function(l){return /^interface Bridge-Aggregation\d+/i.test(l.trim());});
  var baggIds=[...new Set(baggIfaces.map(function(l){return(l.trim().match(/Bridge-Aggregation(\d+)/i)||['',''])[1];}).filter(Boolean))];

  // OOB interface info
  var mEthIfaceName='';var mEthIP='';
  for(var _i=0;_i<L.length;_i++){
    if(/^interface M-Ethernet|^interface MEth/i.test(L[_i].trim())){
      mEthIfaceName=L[_i].trim().replace(/^interface\s+/i,'');
      for(var _j=_i+1;_j<Math.min(_i+15,L.length);_j++){
        var _lt=L[_j].trim();
        if(/^interface /i.test(_lt))break;
        var _mip=_lt.match(/^ip address\s+([\d\.]+)/i);
        if(_mip){mEthIP=_mip[1];break;}
      }
      break;
    }
  }

  // ================================================================
  S('AUTENTICAÇÃO E ACESSO');
  // ================================================================

  // 01. SSH — FIX 1: mostrar apenas evento encontrado, sem sugestão de correção
  var sshVerLine=L.find(function(l){return /ssh server version/i.test(l.trim());});
  var sshVerVal=sshVerLine?(sshVerLine.match(/version\s+(\d+)/i)||['',''])[1]:'';
  if(sshEnabled){
    var sshObs='ssh server enable configurado.';
    if(sshVerVal)sshObs+=' Versão '+sshVerVal+' configurada.';
    A('SSH','SIM','N/A',sshObs);
  } else if(has('undo ssh server enable')){
    A('SSH','NÃO','✘','undo ssh server enable configurado.');
  } else {
    A('SSH','NÃO','✘','ssh server enable não configurado.');
  }

  // 02. TELNET — FIX 2: mostrar apenas evento encontrado
  var telnetEnabled=has('telnet server enable')&&!has('undo telnet server enable');
  if(telnetEnabled){A('TELNET HABILITADO','SIM','✘','telnet server enable configurado.');}
  else if(has('undo telnet server enable')){A('TELNET HABILITADO','NÃO','N/A','undo telnet server enable configurado.');}
  else{A('TELNET HABILITADO','NÃO','N/A','telnet server enable não configurado.');}

  // 03. ACL PARA GERÊNCIA (VTY)
  if(aclVtyLines.length>0){
    var acln=(aclVtyLines[0].match(/acl(?:\s+ipv4)?\s+(\d+)/i)||['',''])[1];
    var aclNameLine=L.find(function(l){return new RegExp('acl\\s+(?:number\\s+)?'+acln+'\\s+name\\s+\\S+','i').test(l.trim());});
    var aclName=aclNameLine?(aclNameLine.match(/name\s+(\S+)/i)||['',''])[1]:'';
    A('ACL PARA GERÊNCIA (VTY)','SIM','N/A','ACL '+acln+(aclName?' ('+aclName+')':'')+' aplicada ao VTY.');
  } else {
    // Check if ACL named VTY exists but not applied
    var vtyAclDefined=L.filter(function(l){return /acl\s+(?:number\s+)?\d+.*\bVTY\b/i.test(l.trim());});
    if(vtyAclDefined.length>0){
      var aclNm=(vtyAclDefined[0].match(/acl\s+(?:number\s+)?(\d+)/i)||['',''])[1];
      var aclNmName=(vtyAclDefined[0].match(/name\s+(\S+)/i)||['',''])[1]||'';
      A('ACL PARA GERÊNCIA (VTY)','PARCIAL','⚠','ACL '+aclNm+(aclNmName?' ('+aclNmName+')':'')+' definida mas não aplicada ao bloco VTY.');
    } else {
      A('ACL PARA GERÊNCIA (VTY)','NÃO','⚠','Nenhuma ACL aplicada ao VTY.');
    }
  }

  // 04. TACACS/RADIUS (AAA)
  if(hwtacacsSchemes.length>0){
    var schemeNames=hwtacacsSchemes.map(function(l){return(l.trim().match(/hwtacacs\s+scheme\s+(\S+)/i)||['',''])[1];}).filter(Boolean);
    A('TACACS/RADIUS (AAA)','SIM','N/A','TACACS+ (hwtacacs) configurado. Scheme(s): '+schemeNames.join(', ')+'.'+(hwtacacsIPsUniq.length>0?' Servidor(es): '+hwtacacsIPsUniq.join(', '):'')+'.'); 
  } else if(radiusSchemes.length>0){
    A('TACACS/RADIUS (AAA)','SIM','N/A','RADIUS configurado.'+(radiusIPsUniq.length>0?' Servidor(es): '+radiusIPsUniq.join(', '):'')+'.'); 
  } else {
    A('TACACS/RADIUS (AAA)','NÃO','✘','Nenhum servidor TACACS+/RADIUS configurado.');
  }

  // 05. AAA NEW-MODEL — FIX 4: detectar hwtacacs scheme com auth+authz+acct
  var authScheme=find('authentication-scheme').filter(function(l){return /^\s*authentication-scheme\s+\S+/i.test(l.trim());});
  var authMode=find('authentication-mode').filter(function(l){return /^\s*authentication-mode\s+/i.test(l.trim());});
  var acctMode=find('accounting-mode').filter(function(l){return l.includes('hwtacacs')||l.includes('radius');});
  var hasPrimAuth=hwtacacsPrimAuth.length>0;
  var hasPrimAuthz=find('primary authorization').filter(function(l){return /\d+\.\d+\.\d+\.\d+/.test(l);}).length>0;
  var hasPrimAcct=find('primary accounting').filter(function(l){return /\d+\.\d+\.\d+\.\d+/.test(l);}).length>0;
  if(hasPrimAuth&&hasPrimAuthz&&hasPrimAcct){
    var aaaObs='hwtacacs scheme com authentication, authorization e accounting configurados.';
    if(authMode.length>0)aaaObs+=' authentication-mode: '+authMode[0].trim().replace(/^\s*authentication-mode\s+/i,'')+'.';
    if(acctMode.length>0)aaaObs+=' Accounting habilitado.';
    A('AAA NEW-MODEL','SIM','N/A',aaaObs);
  } else if(authScheme.length>0||hwtacacsSchemes.length>0){
    A('AAA NEW-MODEL','PARCIAL','⚠','hwtacacs scheme encontrado mas sem authentication + authorization + accounting completos.');
  } else {
    A('AAA NEW-MODEL','NÃO','⚠','Nenhuma configuração AAA/hwtacacs scheme detectada.');
  }

  // 06. USERNAME LOCAL (FALLBACK)
  if(localUserNames.length>0){A('USERNAME LOCAL (FALLBACK)','SIM','N/A',localUserNames.length+' usuário(s) local(is): '+localUserNames.slice(0,4).join(', ')+'.');}
  else{A('USERNAME LOCAL (FALLBACK)','NÃO','⚠','Nenhum usuário local configurado.');}

  // 07. LOGIN BLOCK-FOR — FIX 5: adicionar detecção de "SSH authentication retries : X"
  var authRetries=find('ssh server authentication-retries').filter(function(l){return/^\s*ssh server authentication-retries\s+\d+/i.test(l.trim());});
  var authRetriesDisplay=L.find(function(l){return/SSH\s+authentication\s+retries\s*:\s*\d+/i.test(l);});
  var loginFail=find('login-attempt').filter(function(l){return/fail-count|action/i.test(l);});
  if(authRetries.length>0){
    A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','SIM','N/A',authRetries[0].trim()+'.');
  } else if(authRetriesDisplay){
    var retVal=(authRetriesDisplay.match(/retries\s*:\s*(\d+)/i)||['',''])[1];
    A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','SIM','N/A','SSH authentication retries: '+retVal+' tentativa(s).');
  } else if(loginFail.length>0){
    A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','SIM','N/A',loginFail[0].trim()+'.');
  } else {
    A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','NÃO','⚠','ssh server authentication-retries não configurado.');
  }

  // 08. EXEC-TIMEOUT — FIX 6: mostrar valor em min/seg
  if(idleVty.length>0){
    var idleRaw=idleVty[0].replace(/^idle-timeout\s*/i,'').trim();
    var idleParts=idleRaw.split(/\s+/);
    var idleMin=idleParts[0]||'0';var idleSeg=idleParts[1]||'0';
    A('EXEC-TIMEOUT','SIM','N/A','idle-timeout VTY: '+idleMin+' min '+idleSeg+' seg.');
  } else if(has('idle-timeout')){
    var idleGenLine=L.find(function(l){return /idle-timeout\s+\d+/i.test(l);});
    A('EXEC-TIMEOUT','SIM','N/A','idle-timeout configurado: '+(idleGenLine||'').trim()+'.');
  } else {
    A('EXEC-TIMEOUT','NÃO','⚠','idle-timeout não configurado.');
  }

  // ================================================================
  S('CRIPTOGRAFIA');
  // ================================================================

  // 09. SSH 2048 BITS — FIX 7: calcular tamanho pelo hex do Key code
  // Parse "display public-key local rsa public" output
  // Key size from modulus byte length in DER encoding:
  // 1024 bits -> modulus starts with 02818100 (128 bytes = 0x80)
  // 2048 bits -> modulus starts with 0282010x (256 bytes = 0x100)
  var keyEntries=[];
  var inKeyBlock=false;var curKeyName='';var curKeyHex='';var curKeyType='';
  L.forEach(function(l){
    var lt=l.trim();
    if(/^={3,}/.test(lt)){
      if(inKeyBlock&&curKeyName&&curKeyHex){
        // Calculate key size from hex
        var hexClean=curKeyHex.replace(/\s+/g,'');
        // Find modulus length from DER: look for 0281xx or 028201xx pattern
        var bits=0;
        var m1=hexClean.match(/028201([0-9A-F]{2})/i);  // 2048 bit area
        var m2=hexClean.match(/028181([0-9A-F]{2})/i);  // 1024 bit + 1
        var m3=hexClean.match(/02818100/i);  // exactly 128 bytes = 1024 bits
        var m4=hexClean.match(/0282010[0-9A-F]/i); // 256 bytes = 2048 bits
        var m5=hexClean.match(/02820101/i); // exactly 2048
        if(m5||m4||m1){bits=2048;}
        else if(m3||m2){bits=1024;}
        else{
          // Fallback: estimate from total hex length
          // 1024-bit key DER is ~140 bytes = 280 hex chars
          // 2048-bit key DER is ~270 bytes = 540 hex chars
          if(hexClean.length>=400)bits=2048;
          else if(hexClean.length>=200)bits=1024;
        }
        keyEntries.push({name:curKeyName,type:curKeyType,bits:bits});
        curKeyHex='';curKeyName='';curKeyType='';
      }
      inKeyBlock=!inKeyBlock;
      return;
    }
    if(inKeyBlock){
      var nm=lt.match(/^Key\s+name\s*:\s*(.+)/i);if(nm)curKeyName=nm[1].trim();
      var tp=lt.match(/^Key\s+type\s*:\s*(.+)/i);if(tp)curKeyType=tp[1].trim();
      if(/^[0-9A-F]{4,}/i.test(lt.replace(/\s+/g,'')))curKeyHex+=lt;
    }
  });
  // Also check display public-key local rsa public header
  if(keyEntries.length>0){
    var mainKey=keyEntries.find(function(e){return e.name==='hostkey';});
    if(!mainKey)mainKey=keyEntries[0];
    var allBitsStr=keyEntries.map(function(e){return e.name+'('+e.bits+' bits)';}).join(', ');
    var worst=keyEntries.reduce(function(min,e){return e.bits>0&&e.bits<min?e.bits:min;},9999);
    if(worst===9999)worst=0;
    if(worst>=2048){A('SSH 2048 BITS','SIM','N/A','Chave(s) RSA com tamanho adequado (≥2048 bits). '+allBitsStr+'.');}
    else if(worst>0){A('SSH 2048 BITS','NÃO','✘','Chave(s) RSA insuficiente(s) (<2048 bits). '+allBitsStr+'.');}
    else{A('SSH 2048 BITS','PARCIAL','⚠','Chave(s) RSA detectada(s) mas tamanho não determinado. '+allBitsStr+'.');}
  } else if(sshEnabled){
    A('SSH 2048 BITS','PARCIAL','⚠','SSH habilitado mas saída de "display public-key local rsa public" não presente no log.');
  } else {
    A('SSH 2048 BITS','N/A','N/A','SSH não habilitado.');
  }

  // 10. SERVICE PASSWORD-ENCRYPTION — FIX 8: detectar password hash em local-user
  var pwdCtrlEn=has('password-control enable')||has('password-control complexity enable');
  var pwdCtrlDis=has('undo password-control enable');
  if(pwdCtrlDis){
    A('SERVICE PASSWORD-ENCRYPTION','NÃO','⚠','undo password-control enable configurado.');
  } else if(pwdCtrlEn){
    var hashObs='password-control habilitado.';
    if(usersWithHash.length>0)hashObs+=' '+usersWithHash.length+' usuário(s) com password hash: '+usersWithHash.slice(0,3).join(', ')+'.';
    A('SERVICE PASSWORD-ENCRYPTION','SIM','N/A',hashObs);
  } else if(usersWithHash.length>0){
    A('SERVICE PASSWORD-ENCRYPTION','SIM','N/A',usersWithHash.length+' usuário(s) com password hash encontrado(s): '+usersWithHash.slice(0,3).join(', ')+'.');
  } else {
    A('SERVICE PASSWORD-ENCRYPTION','PARCIAL','⚠','password-control e password hash não detectados.');
  }

  // 11. ENABLE SECRET / RBAC (super password)
  var superPwd=find('super password').filter(function(l){return/^\s*super\s+password/i.test(l.trim());});
  var superScheme=has('super authentication-mode scheme');
  if(superScheme){A('ENABLE SECRET / RBAC','SIM','N/A','super authentication-mode scheme configurado.');}
  else if(superPwd.length>0){A('ENABLE SECRET / RBAC','SIM','N/A',superPwd[0].trim()+'.');}
  else{A('ENABLE SECRET / RBAC','NÃO','⚠','super password não configurado.');}

  // ================================================================
  S('ACESSO E VISUALIZAÇÃO');
  // ================================================================

  // 12. HTTPS HABILITADO / HTTP DESABILITADO
  var httpEn=has('ip http enable')&&!has('undo ip http enable');
  var httpsEn=has('ip https enable')&&!has('undo ip https enable');
  if(!httpEn&&httpsEn){A('HTTPS HABILITADO / HTTP DESABILITADO','SIM','N/A','ip https enable configurado. ip http enable não encontrado.');}
  else if(!httpEn&&!httpsEn){A('HTTPS HABILITADO / HTTP DESABILITADO','SIM','N/A','ip http enable e ip https enable não configurados.');}
  else if(httpEn&&httpsEn){A('HTTPS HABILITADO / HTTP DESABILITADO','PARCIAL','⚠','ip http enable e ip https enable ambos configurados.');}
  else{A('HTTPS HABILITADO / HTTP DESABILITADO','NÃO','⚠','ip http enable configurado.');}

  // 13. BANNER MOTD — FIX 9: detectar header login %
  if(has('header login %')||has('header login information')||has('header shell information')){
    var bannerLine=L.find(function(l){return/header\s+(login|shell)/i.test(l.trim());});
    A('BANNER MOTD','SIM','N/A',(bannerLine||'header login').trim()+' configurado.');
  } else {
    A('BANNER MOTD','NÃO','✔','header login não configurado.');
  }

  // 14. CDP/LLDP NAS PORTAS DE ACESSO — FIX 10: lldp global enable + por interface
  var lldpGlobal=has('lldp global enable')&&!has('undo lldp global enable');
  var lldpEnIfaces=[];var lldpDisIfaces=[];var curIfLldp=null;
  L.forEach(function(l){
    var lt=l.trim();
    if(/^interface\s+/i.test(lt))curIfLldp=lt.replace(/^interface\s+/i,'');
    if(curIfLldp&&/^lldp\s+enable\s*$/i.test(lt)&&!lldpEnIfaces.includes(curIfLldp))lldpEnIfaces.push(curIfLldp);
    if(curIfLldp&&/^undo\s+lldp\s+enable/i.test(lt)&&!lldpDisIfaces.includes(curIfLldp))lldpDisIfaces.push(curIfLldp);
  });
  if(!lldpGlobal&&lldpEnIfaces.length===0){
    A('CDP/LLDP NAS PORTAS DE ACESSO','SIM','N/A','lldp global enable não configurado.');
  } else if(lldpGlobal&&lldpDisIfaces.length>0){
    A('CDP/LLDP NAS PORTAS DE ACESSO','PARCIAL','⚠','lldp global enable configurado. Desabilitado em '+lldpDisIfaces.length+' interface(s): '+lldpDisIfaces.slice(0,3).join(', ')+'.'+(lldpEnIfaces.length>0?' Habilitado explicitamente em '+lldpEnIfaces.length+' interface(s).':''));
  } else if(lldpGlobal){
    A('CDP/LLDP NAS PORTAS DE ACESSO','NÃO','⚠','lldp global enable configurado sem restrições por interface.'+(lldpEnIfaces.length>0?' Habilitado em '+lldpEnIfaces.length+' interface(s).':''));
  } else {
    A('CDP/LLDP NAS PORTAS DE ACESSO','PARCIAL','⚠','lldp global enable não encontrado mas habilitado em '+lldpEnIfaces.length+' interface(s).');
  }

  // ================================================================
  S('GERÊNCIA');
  // ================================================================

  // 15. GERÊNCIA OUT OF BAND (OOB) — FIX 11: mostrar interface e IP
  if(mEthIfaceName){
    var oobObs='Gerência via interface '+mEthIfaceName+' (OOB) configurada.';
        A('GERÊNCIA OUT OF BAND (OOB)','SIM','N/A',oobObs);
  } else {
    var mgmtVlanLine=L.find(function(l){return /gerenci|management|mgmt/i.test(l)&&/interface/i.test(l);});
    if(mgmtVlanLine){A('GERÊNCIA OUT OF BAND (OOB)','SIM','N/A','Interface de gerência identificada: '+mgmtVlanLine.trim()+'.');}
    else{A('GERÊNCIA OUT OF BAND (OOB)','NÃO','⚠','Interface M-Ethernet não configurada.');}
  }

  // 16. CONTROL PLANE POLICING (CoPP) — FIX 12: padrões HP Comware
  var cpCtrl=has('control-plane');
  var cpRateLimit=find('ip rate-limit').filter(function(l){return/^\s*ip\s+rate-limit/i.test(l.trim());});
  var cpQos=find('qos apply policy').filter(function(l){return/inbound\s+control-plane|control-plane/i.test(l);});
  var cpSlot=find('control-plane slot').filter(function(l){return/^\s*control-plane\s+slot/i.test(l.trim());});
  if(cpQos.length>0){
    A('CONTROL PLANE POLICING (CoPP)','SIM','N/A','QoS policy aplicada ao control-plane: '+cpQos[0].trim()+'.');
  } else if(cpRateLimit.length>0){
    A('CONTROL PLANE POLICING (CoPP)','SIM','N/A','control-plane com ip rate-limit configurado. '+cpRateLimit.length+' regra(s) encontrada(s).');
  } else if(cpSlot.length>0){
    A('CONTROL PLANE POLICING (CoPP)','SIM','N/A','control-plane slot configurado: '+cpSlot[0].trim()+'.');
  } else if(cpCtrl){
    A('CONTROL PLANE POLICING (CoPP)','PARCIAL','⚠','control-plane encontrado mas sem ip rate-limit ou qos policy detectado.');
  } else {
    A('CONTROL PLANE POLICING (CoPP)','NÃO','⚠','control-plane não configurado.');
  }

  // 17. SERVIDOR DE LOGGING
  var logSvrs=find('info-center loghost').filter(function(l){return/^\s*info-center\s+loghost\s+\d+\.\d+\.\d+\.\d+/i.test(l.trim());});
  if(logSvrs.length>0){
    var logIPs=[...new Set(logSvrs.map(function(l){return(l.match(/loghost\s+([\d\.]+)/i)||['',''])[1];}).filter(Boolean))];
    A('SERVIDOR DE LOGGING','SIM','N/A',logIPs.length+' servidor(es) syslog: '+logIPs.slice(0,4).join(', ')+'.');
  } else {A('SERVIDOR DE LOGGING','NÃO','⚠','info-center loghost não configurado.');}

  // 18. LOGGING BUFFERED — FIX 13: detectar Log buffer: Enabled
  var logBufCfg=find('info-center logbuffer').filter(function(l){return/^\s*info-center\s+logbuffer/i.test(l.trim());});
  var logBufEnabled=L.find(function(l){return/Log\s+buffer\s*:\s*Enabled/i.test(l);});
  var logBufSize=L.find(function(l){return/Actual\s+buffer\s+size\s*:\s*\d+/i.test(l);});
  if(logBufEnabled){
    var bufObs='Log buffer: Enabled.';
    if(logBufSize){var sz=(logBufSize.match(/:\s*(\d+)/)||['',''])[1];bufObs+=' Tamanho atual: '+sz+' entradas.';}
    A('LOGGING BUFFERED','SIM','N/A',bufObs);
  } else if(logBufCfg.length>0){
    A('LOGGING BUFFERED','SIM','N/A',logBufCfg[0].trim()+'.');
  } else {
    A('LOGGING BUFFERED','NÃO','⚠','info-center logbuffer não configurado.');
  }

  // 19. SNMP PUBLIC/PRIVATE — FIX 14: mostrar communities encontradas
  var snmpPub=snmpComm.filter(function(l){return/\bpublic\b/i.test(l);});
  var snmpPrv=snmpComm.filter(function(l){return/\bprivate\b/i.test(l);});
  if(snmpPub.length===0&&snmpPrv.length===0){
    if(snmpComm.length>0){
      var commNames=snmpComm.map(function(l){var m=l.trim().match(/snmp-agent\s+community\s+\S+\s+(\S+)/i);return m?m[1]:'';}).filter(Boolean).slice(0,3);
      A('SNMP PUBLIC/PRIVATE','SIM','N/A','Communities public/private ausentes. '+snmpComm.length+' community(ies) customizada(s)'+(commNames.length>0?': '+commNames.join(', '):'')+'.'); 
    } else {
      A('SNMP PUBLIC/PRIVATE','SIM','N/A','snmp-agent community não configurado.');
    }
  } else {
    A('SNMP PUBLIC/PRIVATE','NÃO','✘','Community insegura (public/private) detectada.');
  }

  // 20. SNMP PROTEGIDO POR ACL — FIX 15: confirmar detecção de acl em community
  var snmpCommAcl=snmpComm.filter(function(l){return/\bacl\b\s+\d+/i.test(l);});
  var snmpGroupAcl=find('snmp-agent group').filter(function(l){return/acl/i.test(l);});
  if(snmpCommAcl.length>0){
    var aclNs=[...new Set(snmpCommAcl.map(function(l){return(l.match(/acl\s+(\d+)/i)||['',''])[1];}).filter(Boolean))].join(', ');
    A('SNMP PROTEGIDO POR ACL','SIM','N/A','SNMP community protegida por ACL '+aclNs+'.');
  } else if(snmpGroupAcl.length>0){
    A('SNMP PROTEGIDO POR ACL','SIM','N/A','SNMP group protegido por ACL.');
  } else if(snmpComm.length>0||snmpV3Users.length>0){
    A('SNMP PROTEGIDO POR ACL','NÃO','⚠','SNMP configurado sem ACL de restrição.');
  } else {
    A('SNMP PROTEGIDO POR ACL','N/A','N/A','SNMP não configurado.');
  }

  // 21. SNMPv3 (SEGURO) — FIX 16: detectar version all / versões ativas
  var snmpVerAll=snmpVerLine&&/version\s+all/i.test(snmpVerLine);
  var snmpHasV3=snmpVerLine&&/\bv3\b/i.test(snmpVerLine)||snmpV3Users.length>0;
  var snmpHasV2=snmpVerLine&&/\bv2c\b/i.test(snmpVerLine)||snmpComm.length>0;
  var snmpHasV1=snmpVerLine&&/\bv1\b/i.test(snmpVerLine);
  var snmpVerStr=snmpVerLine?snmpVerLine.trim():'';
  if(snmpVerAll){
    A('SNMPv3 (SEGURO)','PARCIAL','⚠','snmp-agent sys-info version all configurado — v1, v2c e v3 ativos simultaneamente.');
  } else if(snmpV3Users.length>0&&snmpHasV2){
    var v3names=[...new Set(snmpV3Users.map(function(l){return(l.trim().split(/\s+/)[4]||'');}).filter(Boolean))];
    A('SNMPv3 (SEGURO)','PARCIAL','⚠','SNMPv3 e SNMPv2c ambos ativos.'+(snmpVerStr?' Versão: '+snmpVerStr.replace(/^\s*snmp-agent\s+sys-info\s+version\s+/i,'')+'.':''));
  } else if(snmpV3Users.length>0&&!snmpHasV2){
    A('SNMPv3 (SEGURO)','SIM','N/A','SNMPv3 configurado com '+snmpV3Users.length+' usuário(s). SNMPv2c não detectado.');
  } else if(snmpVerStr){
    A('SNMPv3 (SEGURO)','NÃO','⚠','SNMPv3 não configurado. '+snmpVerStr.trim()+'.');
  } else {
    A('SNMPv3 (SEGURO)','NÃO','⚠','SNMPv3 não configurado.');
  }

  // ================================================================
  S('INFRAESTRUTURA: Funcionalidade e Serviços de Rede');
  S('ROTEAMENTO');
  // ================================================================

  // 22. OSPF
  if(hasOspf){A('PROTOCOLO DE ROTEAMENTO (OSPF)','SIM','N/A','OSPF configurado.');}
  else{A('PROTOCOLO DE ROTEAMENTO (OSPF)','N/A','N/A','OSPF não configurado.');}

  // 23. OSPF PASSIVE-INTERFACE DEFAULT
  if(hasOspf){
    var ospfSilent=has('silent-interface all')||has('silent-interface default');
    var ospfSilentIf=find('silent-interface').filter(function(l){return l.trim().startsWith('silent-interface');});
    if(ospfSilent){A('OSPF PASSIVE-INTERFACE DEFAULT','SIM','N/A','silent-interface all/default configurado no OSPF.');}
    else if(ospfSilentIf.length>0){A('OSPF PASSIVE-INTERFACE DEFAULT','PARCIAL','⚠','silent-interface em '+ospfSilentIf.length+' interface(s) mas não como default.');}
    else{A('OSPF PASSIVE-INTERFACE DEFAULT','NÃO','⚠','silent-interface default não configurado. Interfaces OSPF ativas desnecessariamente.');}
  } else {A('OSPF PASSIVE-INTERFACE DEFAULT','N/A','N/A','OSPF não configurado.');}

  // 24. OSPF AUTENTICAÇÃO
  if(hasOspf){
    var ospfAuth=has('authentication-mode md5')||has('authentication-mode hmac-md5')||has('area authentication');
    A('OSPF AUTENTICAÇÃO',ospfAuth?'SIM':'NÃO',ospfAuth?'N/A':'⚠',ospfAuth?'Autenticação OSPF configurada.':'Autenticação OSPF não configurada. Risco de injeção de rotas.');
  } else {A('OSPF AUTENTICAÇÃO','N/A','N/A','OSPF não configurado.');}

  // 25. OSPF MD5/SHA AUTHENTICATION
  if(hasOspf){
    var ospfMd5=has('authentication-mode md5')||has('authentication-mode hmac-md5');
    A('OSPF MD5/SHA AUTHENTICATION',ospfMd5?'SIM':'NÃO',ospfMd5?'N/A':'⚠',ospfMd5?'OSPF autenticação MD5/HMAC-MD5 configurada.':'OSPF sem autenticação MD5/SHA.');
  } else {A('OSPF MD5/SHA AUTHENTICATION','N/A','N/A','OSPF não configurado.');}

  // 26. BGP
  if(hasBgp){A('BGP','SIM','N/A','BGP configurado.');}
  else{A('BGP','N/A','N/A','BGP não configurado.');}

  // 27. BGP AUTENTICAÇÃO
  if(hasBgp){
    var bgpAuth=find('peer').filter(function(l){return/peer\s+\S+\s+password/i.test(l);});
    if(bgpAuth.length>0){A('BGP AUTENTICAÇÃO','SIM','N/A','BGP autenticação em '+bgpAuth.length+' peer(s).');}
    else{A('BGP AUTENTICAÇÃO','NÃO','⚠','BGP sem autenticação nos peers. Risco de BGP hijack.');}
  } else {A('BGP AUTENTICAÇÃO','N/A','N/A','BGP não configurado.');}

  // 28. EIGRP
  A('EIGRP','N/A','N/A','EIGRP não é suportado pelo HP Comware. N/A para esta plataforma.');

  // 29. EIGRP AUTENTICAÇÃO
  A('EIGRP AUTENTICAÇÃO','N/A','N/A','EIGRP não é suportado pelo HP Comware. N/A para esta plataforma.');

  // 30. NO IP SOURCE-ROUTE
  var ipOptDrop=has('ip options drop')||has('ip options ignore');
  var srcRoute=has('ip source-route')&&!has('undo ip source-route');
  if(ipOptDrop){A('NO IP SOURCE-ROUTE','SIM','N/A','ip options drop configurado. IP Options desabilitados.');}
  else if(has('undo ip source-route')){A('NO IP SOURCE-ROUTE','SIM','N/A','ip source-route desabilitado explicitamente.');}
  else if(srcRoute){A('NO IP SOURCE-ROUTE','NÃO','⚠','ip source-route habilitado. Desabilitar: "undo ip source-route".');}
  else{A('NO IP SOURCE-ROUTE','SIM','N/A','ip source-route desabilitado por padrão no Comware.');}

  // 31. NO IP REDIRECTS
  var redirIfaces=[];var curIfRedir=null;
  L.forEach(function(l){
    var ifm=l.trim().match(/^interface\s+(\S+)/i);
    if(ifm)curIfRedir=ifm[1];
    if(/^\s*ip\s+redirects\b/i.test(l)&&!/undo/i.test(l)&&curIfRedir&&!redirIfaces.includes(curIfRedir))redirIfaces.push(curIfRedir);
  });
  if(redirIfaces.length>0){A('NO IP REDIRECTS','NÃO','⚠','ip redirects em '+redirIfaces.length+' interface(s). Desabilitar: "undo ip redirects".');}
  else{A('NO IP REDIRECTS','SIM','N/A','ip redirects desabilitado por padrão no Comware.');}

  // 32. UNICAST RPF (ANTI-SPOOFING)
  var urpf=find('ip urpf').filter(function(l){return/ip\s+urpf\s+(strict|loose)/i.test(l);});
  if(urpf.length>0){A('UNICAST RPF (ANTI-SPOOFING)','SIM','N/A','uRPF configurado em '+urpf.length+' interface(s).');}
  else{A('UNICAST RPF (ANTI-SPOOFING)','NÃO','✘','uRPF não configurado. Anti-spoofing ausente nas interfaces L3.');}

  // ================================================================
  S('REDUNDÂNCIA DE GATEWAY');
  // ================================================================

  // 33. HSRP (N/A - Comware usa VRRP)
  A('HSRP','N/A','N/A','HSRP não é suportado pelo HP Comware.');

  // 34. HSRP AUTENTICAÇÃO
  A('HSRP AUTENTICAÇÃO','N/A','N/A','HSRP não é suportado pelo HP Comware.');

  // 35. HSRP PRIORIDADE
  A('HSRP PRIORIDADE','N/A','N/A','HSRP não é suportado pelo HP Comware.');

  // 36. VRRP
  if(vrrpIfaces.length>0){A('VRRP','SIM','N/A','VRRP configurado em '+vrrpIfaces.length+' interface(s).');}
  else{A('VRRP','N/A','N/A','VRRP não configurado.');}

  // 37. VRRP AUTENTICAÇÃO
  if(vrrpIfaces.length>0){
    var vauth=find('vrrp vrid').filter(function(l){return/vrrp\s+vrid\s+\d+\s+authentication-mode/i.test(l);});
    if(vauth.some(function(l){return/md5/i.test(l);})){A('VRRP AUTENTICAÇÃO','SIM','N/A','VRRP autenticação MD5 configurada.');}
    else if(vauth.length>0){A('VRRP AUTENTICAÇÃO','PARCIAL','⚠','VRRP autenticação sem MD5. Recomendado: authentication-mode md5.');}
    else{A('VRRP AUTENTICAÇÃO','NÃO','⚠','VRRP sem autenticação. Risco de VRRP hijack.');}
  } else {A('VRRP AUTENTICAÇÃO','N/A','N/A','VRRP não configurado.');}

  // 38. VRRP PRIORIDADE
  if(vrrpIfaces.length>0){
    var vprio=find('vrrp vrid').filter(function(l){return/vrrp\s+vrid\s+\d+\s+priority\s+\d+/i.test(l);});
    if(vprio.length>0){A('VRRP PRIORIDADE','SIM','N/A','VRRP prioridade configurada em '+vprio.length+' instância(s).');}
    else{A('VRRP PRIORIDADE','NÃO','⚠','VRRP prioridade não configurada. Usando default (100).');}
  } else {A('VRRP PRIORIDADE','N/A','N/A','VRRP não configurado.');}

  // 39. GLBP (N/A - Comware não suporta)
  A('GLBP','N/A','N/A','GLBP não é suportado pelo HP Comware.');
  A('GLBP AUTENTICAÇÃO','N/A','N/A','GLBP não é suportado pelo HP Comware.');
  A('GLBP PRIORIDADE','N/A','N/A','GLBP não é suportado pelo HP Comware.');

  // ================================================================
  S('SERVIÇOS DE REDE');
  // ================================================================

  // 42. NTP CONFIGURADO
  if(ntpIPs.length>0){A('NTP CONFIGURADO','SIM','N/A',ntpIPs.length+' servidor(es) NTP: '+ntpIPs.join(', ')+'.');}
  else{A('NTP CONFIGURADO','NÃO','⚠','Nenhum servidor NTP configurado. Risco de dessincronização de logs.');}

  // 43. NTP SINCRONIZADO - detect display ntp status output
  var ntpClockLine=L.find(function(l){return/Clock\s+status\s*:/i.test(l);});
  var ntpStratumLine=L.find(function(l){return/Clock\s+stratum\s*:/i.test(l);});
  var ntpStratum=ntpStratumLine?(ntpStratumLine.match(/:\s*(\d+)/)||['',''])[1]:'';
  if(ntpClockLine){
    var ntpSync=/synchronized/i.test(ntpClockLine)&&!/unsynchronized/i.test(ntpClockLine);
    var ntpObs='Clock status: '+(ntpSync?'synchronized':'unsynchronized')+'.'+(ntpStratum?' Stratum: '+ntpStratum+'.':'');
    A('NTP SINCRONIZADO',ntpSync?'SIM':'NÃO',ntpSync?'N/A':'⚠',ntpObs);
  } else if(ntpIPs.length>0){
    A('NTP SINCRONIZADO','PARCIAL','⚠','NTP configurado. Incluir saída de "display ntp status" para verificar sincronização.');
  } else {
    A('NTP SINCRONIZADO','NÃO','⚠','NTP não configurado.');
  }

  // 44. NTP PROTEGIDO POR ACL
  var ntpAcl=find('ntp-service access').filter(function(l){return/ntp-service\s+access/i.test(l.trim());});
  var ntpSrvAcl=find('ntp-service server acl').filter(function(l){return/ntp-service\s+server\s+acl\s+\d+/i.test(l.trim());});
  var ntpAclAll=ntpAcl.concat(ntpSrvAcl);
  if(ntpAclAll.length>0){
    var ntpAclNum=(ntpAclAll[0].match(/acl\s+(\d+)/i)||['',''])[1];
    A('NTP PROTEGIDO POR ACL','SIM','N/A',ntpAclAll[0].trim()+(ntpAclNum?'. ACL: '+ntpAclNum:'')+'.');
  } else {
    A('NTP PROTEGIDO POR ACL','NÃO','⚠','Nenhuma ACL de proteção NTP configurada.');
  }

  // 45. NTP AUTENTICAÇÃO
  var ntpAuthEn=has('ntp-service authentication enable');
  var ntpAuthKey=has('ntp-service authentication-keyid');
  var ntpTrusted=has('ntp-service reliable authentication-keyid');
  if(ntpAuthEn&&ntpAuthKey&&ntpTrusted){A('NTP AUTENTICAÇÃO','SIM','N/A','Autenticação NTP completa (enable + keyid + reliable).');}
  else if(ntpAuthEn||ntpAuthKey){var missNtp=[];if(!ntpAuthEn)missNtp.push('ntp-service authentication enable');if(!ntpAuthKey)missNtp.push('ntp-service authentication-keyid');if(!ntpTrusted)missNtp.push('ntp-service reliable authentication-keyid');A('NTP AUTENTICAÇÃO','PARCIAL','⚠','Autenticação NTP incompleta. Faltando: '+missNtp.join(', ')+'.');}
  else{A('NTP AUTENTICAÇÃO','NÃO','⚠','Autenticação NTP não configurada. Risco de NTP spoofing.');}

  // 46. NO IP PROXY-ARP (SVIs)
  var proxyArpActive=[];var proxyArpDisabled=[];var curIfProxy=null;
  L.forEach(function(l){
    var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/i);if(ifm)curIfProxy=ifm[1];
    if(curIfProxy&&/^proxy-arp\s+enable\s*$/i.test(lt)&&!proxyArpActive.includes(curIfProxy))proxyArpActive.push(curIfProxy);
    if(curIfProxy&&/^undo\s+proxy-arp\s+enable/i.test(lt)&&!proxyArpDisabled.includes(curIfProxy))proxyArpDisabled.push(curIfProxy);
  });
  if(proxyArpActive.length>0){
    A('NO IP PROXY-ARP (SVIs)','NÃO','⚠',proxyArpActive.length+' interface(s) com proxy-arp ativo.'+(proxyArpDisabled.length>0?' '+proxyArpDisabled.length+' com proxy-arp desabilitado explicitamente.':''));
  } else if(proxyArpDisabled.length>0){
    A('NO IP PROXY-ARP (SVIs)','SIM','N/A',proxyArpDisabled.length+' interface(s) com proxy-arp desabilitado explicitamente. Demais interfaces: padrão desabilitado no Comware.');
  } else {
    A('NO IP PROXY-ARP (SVIs)','SIM','N/A','Proxy-ARP não habilitado (padrão desabilitado no Comware).');
  }

    // 47. IP SOURCE GUARD
  var ipsgGlobal=has('ip source-binding')&&!has('undo ip source-binding');
  var ipsgIfaces=[];var curIfIpsg=null;
  L.forEach(function(l){
    var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/i);if(ifm)curIfIpsg=ifm[1];
    if(curIfIpsg&&/^ip\s+check\s+source/i.test(lt)&&!ipsgIfaces.includes(curIfIpsg))ipsgIfaces.push(curIfIpsg);
  });
  if(ipsgGlobal&&ipsgIfaces.length>0){
    A('IP SOURCE GUARD','SIM','N/A','ip source-binding global configurado. '+ipsgIfaces.length+' interface(s) com ip check source.');
  } else if(ipsgIfaces.length>0){
    A('IP SOURCE GUARD','SIM','N/A',ipsgIfaces.length+' interface(s) com ip check source configurado.');
  } else if(ipsgGlobal){
    A('IP SOURCE GUARD','PARCIAL','⚠','ip source-binding global configurado mas sem ip check source em interfaces.');
  } else {
    A('IP SOURCE GUARD','NÃO','⚠','IP Source Guard não configurado.');
  }

    // 48. DHCP SNOOPING
  var dhcpSnpGlobal=has('dhcp snooping enable')&&!L.some(function(l){return/^\s*undo\s+dhcp\s+snooping\s+enable\s*$/i.test(l.trim());});
  var dhcpSnpVlans=find('dhcp snooping enable vlan').filter(function(l){return/dhcp\s+snooping\s+enable\s+vlan/i.test(l.trim());});
  var dhcpSnpIfaces=[];var curIfDhcp=null;
  L.forEach(function(l){
    var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/i);if(ifm)curIfDhcp=ifm[1];
    if(curIfDhcp&&(/^dhcp\s+snooping\s+binding\s+record/i.test(lt)||/^undo\s+dhcp\s+snooping\s+trust/i.test(lt)||/^dhcp\s+snooping\s+trust/i.test(lt))&&!dhcpSnpIfaces.includes(curIfDhcp))dhcpSnpIfaces.push(curIfDhcp);
  });
  if(dhcpSnpGlobal&&(dhcpSnpVlans.length>0||dhcpSnpIfaces.length>0)){
    A('DHCP SNOOPING','SIM','N/A','DHCP Snooping global configurado.'+(dhcpSnpVlans.length>0?' '+dhcpSnpVlans.length+' VLAN(s) configurada(s).':'')+(dhcpSnpIfaces.length>0?' '+dhcpSnpIfaces.length+' interface(s) configurada(s).':''));
  } else if(dhcpSnpGlobal){
    A('DHCP SNOOPING','PARCIAL','⚠','DHCP Snooping global configurado mas sem VLANs ou interfaces específicas detectadas.');
  } else if(dhcpSnpIfaces.length>0){
    A('DHCP SNOOPING','PARCIAL','⚠','DHCP Snooping em '+dhcpSnpIfaces.length+' interface(s) mas não habilitado globalmente.');
  } else {
    A('DHCP SNOOPING','NÃO','⚠','DHCP Snooping não configurado.');
  }

    // 49. DYNAMIC ARP INSPECTION (DAI)
  var daiGlobal=has('arp detection enable')&&!L.some(function(l){return/^\s*undo\s+arp\s+detection\s+enable\s*$/i.test(l.trim());});
  var daiVlans=find('arp detection enable vlan').filter(function(l){return/arp\s+detection\s+enable\s+vlan/i.test(l.trim());});
  var daiIfaces=[];var curIfDai=null;
  L.forEach(function(l){
    var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/i);if(ifm)curIfDai=ifm[1];
    if(curIfDai&&/^arp\s+detection\s+trust/i.test(lt)&&!daiIfaces.includes(curIfDai))daiIfaces.push(curIfDai);
  });
  if(daiGlobal&&(daiVlans.length>0||daiIfaces.length>0)){
    A('DYNAMIC ARP INSPECTION (DAI)','SIM','N/A','ARP Detection global configurado.'+(daiVlans.length>0?' '+daiVlans.length+' VLAN(s).':'')+(daiIfaces.length>0?' '+daiIfaces.length+' interface(s) trust.':''));
  } else if(daiGlobal){
    A('DYNAMIC ARP INSPECTION (DAI)','PARCIAL','⚠','ARP Detection global configurado mas sem VLANs ou trust interfaces detectadas.');
  } else if(daiIfaces.length>0){
    A('DYNAMIC ARP INSPECTION (DAI)','PARCIAL','⚠','ARP Detection trust em '+daiIfaces.length+' interface(s) mas não habilitado globalmente.');
  } else {
    A('DYNAMIC ARP INSPECTION (DAI)','NÃO','⚠','ARP Detection não configurado.');
  }

    // 50. VLAN SEM MAC_ADRRESS VINCULADO
  var macStatic=find('mac-address static').filter(function(l){return/mac-address\s+static/i.test(l);});
  var vlanLines=L.filter(function(l){return/^vlan\s+\d+$/i.test(l.trim());});
  if(macStatic.length>0){
    var macVlans=[...new Set(macStatic.map(function(l){return(l.match(/vlan\s+(\d+)/i)||['',''])[1];}).filter(Boolean))];
    var noMac=vlanLines.length-macVlans.length;
    A('VLAN SEM MAC_ADRRESS VINCULADO',noMac>0?'PARCIAL':'SIM',noMac>0?'⚠':'N/A',noMac>0?noMac+' VLAN(s) sem MAC estático vinculado.':'Todas as VLANs com MAC estático vinculado.');
  } else if(vlanLines.length>0){
    A('VLAN SEM MAC_ADRRESS VINCULADO','PARCIAL','⚠',vlanLines.length+' VLAN(s) sem MAC address estático. Avaliar necessidade.');
  } else {
    A('VLAN SEM MAC_ADRRESS VINCULADO','N/A','N/A','Incluir "display mac-address" no log para análise.');
  }

  // 51. VLAN SEM NAME
  var vlanBlocks={};var curVlan=null;
  L.forEach(function(l){
    var vm=l.trim().match(/^vlan\s+(\d+)$/i);if(vm){curVlan=vm[1];vlanBlocks[curVlan]=vlanBlocks[curVlan]||{hasName:false};}
    if(curVlan&&/^\s*name\s+\S+/i.test(l.trim()))vlanBlocks[curVlan].hasName=true;
  });
  var vlansTotal=Object.keys(vlanBlocks).length;
  var vlansNoName=Object.entries(vlanBlocks).filter(function(e){return!e[1].hasName;}).map(function(e){return e[0];});
  if(vlansTotal===0){A('VLAN SEM NAME','N/A','N/A','VLANs não detectadas.');}
  else if(vlansNoName.length===0){A('VLAN SEM NAME','SIM','N/A','Todas as '+vlansTotal+' VLAN(s) com nome configurado.');}
  else{var vnStr=vlansNoName.slice(0,10).join(', ')+(vlansNoName.length>10?' ...':'');A('VLAN SEM NAME','PARCIAL','⚠','VLAN(s) sem nome: '+vnStr+'.');}

  // 52. STP: MODO RAPID-PVST/MST
  var stpMode=find('stp mode').filter(function(l){return/^\s*stp\s+mode\s+\S+/i.test(l.trim());});
  if(stpMode.length>0){var sm=(stpMode[0].trim().match(/stp\s+mode\s+(\S+)/i)||['',''])[1].toUpperCase();A('STP: MODO RAPID-PVST/MST','SIM','N/A','Modo STP: '+sm+'.');}
  else if(has('stp enable')||has('stp global enable')){A('STP: MODO RAPID-PVST/MST','SIM','N/A','STP habilitado (modo padrão Comware: MSTP).');}
  else{A('STP: MODO RAPID-PVST/MST','PARCIAL','⚠','Modo STP não configurado explicitamente. Verificar com "display stp".');}

  // 53. STP: PRIORIDADE CONFIGURADA
  var stpPrio=find('stp priority').filter(function(l){return/^\s*stp\s+priority\s+\d+/i.test(l.trim());});
  var stpInstPrio=find('stp instance').filter(function(l){return/stp\s+instance\s+\d+\s+priority/i.test(l);});
  if(stpPrio.length>0||stpInstPrio.length>0){
    var pv=(stpPrio.length>0?stpPrio[0]:stpInstPrio[0]).trim();
    A('STP: PRIORIDADE CONFIGURADA','SIM','N/A','STP prioridade configurada: '+pv+'.');
  } else {A('STP: PRIORIDADE CONFIGURADA','NÃO','⚠','STP prioridade não configurada. Usando default (32768).');}

  // 54. STP: BPDU GUARD
  var bpduProtGlobal=has('stp bpdu-protection');
  var bpduProtIface=find('stp bpdu-protection').filter(function(l){return/^\s*stp\s+bpdu-protection/i.test(l.trim())&&!/global/i.test(l);});
  if(bpduProtGlobal&&!bpduProtIface.length){A('STP: BPDU GUARD','SIM','N/A','BPDU Protection habilitado globalmente.');}
  else if(bpduProtIface.length>0){A('STP: BPDU GUARD','PARCIAL','⚠','BPDU Protection em '+bpduProtIface.length+' interface(s) mas não globalmente.');}
  else{A('STP: BPDU GUARD','NÃO','⚠','BPDU Protection não configurado. Risco em portas de acesso.');}

  // 55. STP: BPDU FILTER
  var bpduFilter=has('stp edged-port bpdu-filter')||has('stp bpdu-filter');
  if(bpduFilter){A('STP: BPDU FILTER','SIM','N/A','BPDU Filter configurado.');}
  else{A('STP: BPDU FILTER','NÃO','⚠','BPDU Filter não configurado.');}

  // 56. STP: BRIDGE ASSURANCE → loop-protection no Comware
  var loopProtBA=find('stp loop-protection').filter(function(l){return /^\s*stp\s+loop-protection/i.test(l.trim());});
  if(loopProtBA.length>0){A('STP: BRIDGE ASSURANCE','SIM','N/A','stp loop-protection ativo em '+loopProtBA.length+' interface(s).');}
  else{A('STP: BRIDGE ASSURANCE','NÃO','⚠','stp loop-protection não configurado.');}

  // 57. STP: LOOP GUARD
  var loopProt=find('stp loop-protection').filter(function(l){return/^\s*stp\s+loop-protection/i.test(l.trim());});
  if(loopProt.length>0){A('STP: LOOP GUARD','SIM','N/A','Loop Protection habilitado em '+loopProt.length+' interface(s).');}
  else{A('STP: LOOP GUARD','NÃO','⚠','Loop Protection não configurado. Risco de loop unidirecional.');}

  // 58. STP: ROOT GUARD CONFIGURADO
  var rootProt=find('stp root-protection').filter(function(l){return/^\s*stp\s+root-protection/i.test(l.trim());});
  if(rootProt.length>0){A('STP: ROOT GUARD CONFIGURADO','SIM','N/A','Root Protection em '+rootProt.length+' interface(s).');}
  else{A('STP: ROOT GUARD CONFIGURADO','NÃO','✘','Root Protection não configurado. Risco de Root Bridge hijack.');}

  // 59. STORM CONTROL
  var stormIfaces=[];var curIfSt=null;
  L.forEach(function(l){
    var ifm=l.trim().match(/^interface\s+(\S+)/i);if(ifm)curIfSt=ifm[1];
    if(curIfSt&&/^\s*storm-constrain|^\s*storm-control/i.test(l.trim())&&!stormIfaces.includes(curIfSt))stormIfaces.push(curIfSt);
  });
  if(stormIfaces.length>10){A('STORM CONTROL','SIM','N/A','Storm-constrain em '+stormIfaces.length+' interface(s).');}
  else if(stormIfaces.length>0){A('STORM CONTROL','PARCIAL','⚠','Storm-constrain em apenas '+stormIfaces.length+' interface(s). Verificar cobertura.');}
  else{A('STORM CONTROL','NÃO','⚠','Storm-constrain não configurado. Risco de broadcast/multicast storm.');}

  // 60. UDLD HABILITADO -> DLDP no Comware
  var dldpGlobalEn=has('dldp global enable')&&!has('undo dldp global enable');
  var dldpEnIf=[];var dldpDisIf=[];var curIfDldp=null;
  L.forEach(function(l){
    var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/i);if(ifm)curIfDldp=ifm[1];
    if(curIfDldp&&/^dldp\s+enable\s*$/i.test(lt)&&!dldpEnIf.includes(curIfDldp))dldpEnIf.push(curIfDldp);
    if(curIfDldp&&/^undo\s+dldp\s+enable/i.test(lt)&&!dldpDisIf.includes(curIfDldp))dldpDisIf.push(curIfDldp);
  });
  // Check MATCHFAIL for dldp in log (dldp not supported/enabled)
  var dldpMatchFail=L.some(function(l){return/dldp/i.test(l)&&/MATCHFAIL|match.*fail/i.test(l);});
  var dldpObs='';
  if(dldpGlobalEn){dldpObs='dldp global enable configurado.';}
  else if(dldpEnIf.length>0){dldpObs='DLDP habilitado em '+dldpEnIf.length+' interface(s).';}
  if(dldpDisIf.length>0)dldpObs+=(dldpObs?' ':'')+dldpDisIf.length+' interface(s) com undo dldp enable.';
  if(dldpGlobalEn&&dldpDisIf.length===0){A('UDLD HABILITADO','SIM','N/A',dldpObs);}
  else if(dldpGlobalEn&&dldpDisIf.length>0){A('UDLD HABILITADO','PARCIAL','⚠',dldpObs);}
  else if(dldpEnIf.length>0){A('UDLD HABILITADO','PARCIAL','⚠',dldpObs);}
  else if(dldpMatchFail){A('UDLD HABILITADO','NÃO','⚠','DLDP não habilitado (comando dldp não reconhecido no log).');}
  else{A('UDLD HABILITADO','NÃO','⚠','DLDP não habilitado.');}

  // 61. VLAN 1 SEM USO EM PORTAS
  var v1Access=[];var v1Trunk=[];var v1Native=[];var curIfV1=null;
  L.forEach(function(l){
    var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/i);if(ifm){curIfV1=ifm[1];return;}if(!curIfV1)return;
    if(/^port\s+access\s+vlan\s+1\b/i.test(lt))v1Access.push(curIfV1);
    if(/^port\s+trunk\s+pvid\s+vlan\s+1\b/i.test(lt))v1Native.push(curIfV1);
    if(/^port\s+trunk\s+permit\s+vlan\s+.*\b1\b/i.test(lt)&&!/\ball\b/i.test(lt))v1Trunk.push(curIfV1);
  });
  var v1All=[...new Set(v1Native.concat(v1Access).concat(v1Trunk))];
  if(v1All.length>0){
    var parts=[];
    if(v1Native.length>0)parts.push('PVID: '+v1Native.slice(0,3).join(', '));
    if(v1Access.length>0)parts.push('access: '+v1Access.slice(0,3).join(', '));
    if(v1Trunk.length>0)parts.push('trunk: '+v1Trunk.slice(0,3).join(', '));
    A('VLAN 1 SEM USO EM PORTAS','NÃO','⚠','VLAN 1 em uso em '+v1All.length+' interface(s). '+parts.join('; ')+'.');
  } else {A('VLAN 1 SEM USO EM PORTAS','SIM','N/A','VLAN 1 não configurada em nenhuma interface.');}

  // 62. TRUNK COM FILTRO DE VLANS
  var trunkIfaces={};var cIf=null;
  L.forEach(function(l){
    var lt=l.trim();if(/^interface\s+\S+/i.test(lt)){cIf=lt;if(!trunkIfaces[cIf])trunkIfaces[cIf]={trunk:false,filter:false,filterAll:false};}
    if(cIf&&/^port\s+link-type\s+trunk/i.test(lt))trunkIfaces[cIf].trunk=true;
    if(cIf&&/^port\s+trunk\s+permit\s+vlan/i.test(lt)){trunkIfaces[cIf].filter=true;if(/\ball\b/i.test(lt))trunkIfaces[cIf].filterAll=true;}
  });
  var trunks=Object.entries(trunkIfaces).filter(function(e){return e[1].trunk;});
  var tOk=trunks.filter(function(e){return e[1].filter&&!e[1].filterAll;});
  var tBad=trunks.filter(function(e){return!e[1].filter||e[1].filterAll;});
  if(tBad.length===0&&trunks.length>0){A('TRUNK COM FILTRO DE VLANS','SIM','N/A',trunks.length+' trunk(s) com filtro explícito de VLANs.');}
  else if(tBad.length>0&&trunks.length>0){var bnames=tBad.map(function(e){return e[0].replace(/^interface /i,'');}).slice(0,5).join(', ');A('TRUNK COM FILTRO DE VLANS','PARCIAL','⚠',tBad.length+' trunk(s) com "permit vlan all" ou sem filtro: '+bnames+'.');}
  else{A('TRUNK COM FILTRO DE VLANS','N/A','N/A','Nenhuma interface trunk identificada.');}

  // 63. VTP MODE TRANSPARENTE (N/A)
  A('VTP MODE TRANSPARENTE','N/A','N/A','HP Comware não utiliza VTP. Gerenciamento de VLANs via configuração local. N/A para esta plataforma.');

  // 64. ERRDISABLE RECOVERY
  var errDown=find('error-down auto-recovery').filter(function(l){return/^\s*error-down\s+auto-recovery/i.test(l.trim());});
  var portErrDown=L.filter(function(l){return/error-down\s*$/i.test(l.trim())||/err-down/i.test(l);});
  if(portErrDown.length>0&&errDown.length===0){A('ERRDISABLE RECOVERY','NÃO','⚠',portErrDown.length+' porta(s) em error-down sem auto-recovery configurado.');}
  else if(errDown.length>0){A('ERRDISABLE RECOVERY','SIM','N/A','error-down auto-recovery configurado: '+(errDown[0]||'').trim()+'.');}
  else{A('ERRDISABLE RECOVERY','N/A','N/A','Nenhuma porta em error-down detectada.');}

  // 65. PORT SECURITY
  var psecIfaces=[];var curIfPs=null;
  L.forEach(function(l){var ifm=l.trim().match(/^interface\s+(\S+)/i);if(ifm)curIfPs=ifm[1];if(/^\s*port-security\s+enable/i.test(l.trim())&&curIfPs&&!psecIfaces.includes(curIfPs))psecIfaces.push(curIfPs);});
  if(psecIfaces.length>0){A('PORT SECURITY','SIM','N/A','Port Security em '+psecIfaces.length+' interface(s).');}
  else{A('PORT SECURITY','NÃO','✔','Port Security não configurado. Recomendado para portas de acesso. Configurar: "port-security enable".');}

  // ================================================================
  S('PORT-CHANNEL');
  // ================================================================

  // Parse display link-aggregation summary table
  var laggSumIdx=L.findIndex(function(l){return/display\s+link-aggregation\s+summary/i.test(l);});
  var baggStats=[];var raggStats=[];
  if(laggSumIdx>=0){
    for(var _li=laggSumIdx+1;_li<Math.min(laggSumIdx+120,L.length);_li++){
      var _pl=L[_li].trim().replace(/\r/g,'');
      if(!_pl||/^-+$/.test(_pl)||/^AGG|^Aggregation|^BAGG\s+--|^Loadsharing|^Actor/i.test(_pl))continue;
      if(_pl.startsWith('display ')||_pl.includes('#')||_pl.startsWith('<'))break;
      var _pm=_pl.match(/^(BAGG|RAGG)(\d+)\s+(S|D)\s+(\S+(?:\s+\S+)?)\s+(\d+)\s+(\d+)\s+(\d+)/i);
      if(_pm){
        var _entry={id:_pm[1]+_pm[2],type:_pm[1].toUpperCase(),mode:_pm[3].toUpperCase(),partner:_pm[4].trim(),selected:parseInt(_pm[5]),unselected:parseInt(_pm[6]),individual:parseInt(_pm[7])};
        if(_entry.type==='BAGG')baggStats.push(_entry);
        else raggStats.push(_entry);
      }
    }
  }
  var allAggStats=baggStats.concat(raggStats);
  var hasSummary=allAggStats.length>0;

  // Configs from interface blocks
  var baggCfg=L.filter(function(l){return/^interface Bridge-Aggregation\d+/i.test(l.trim());});
  var raggCfg=L.filter(function(l){return/^interface Route-Aggregation\d+/i.test(l.trim());});
  var baggCfgIds=[...new Set(baggCfg.map(function(l){return(l.trim().match(/Bridge-Aggregation(\d+)/i)||['',''])[1];}).filter(Boolean))];
  var laggDynLines=find('link-aggregation mode dynamic').filter(function(l){return/^\s*link-aggregation\s+mode\s+dynamic/i.test(l.trim());});
  var laggStatLines=find('link-aggregation mode static').filter(function(l){return/^\s*link-aggregation\s+mode\s+static/i.test(l.trim());});

  // 66. PORT-CHANNEL COM LACP
  if(hasSummary){
    var baggS=baggStats.filter(function(e){return e.mode==='S';});
    var baggD=baggStats.filter(function(e){return e.mode==='D';});
    var raggS=raggStats.filter(function(e){return e.mode==='S';});
    var raggD=raggStats.filter(function(e){return e.mode==='D';});
    var lacpObs='';
    if(baggStats.length>0)lacpObs+=baggStats.length+' BAGG(s): '+baggD.length+' LACP, '+baggS.length+' estático.';
    if(raggStats.length>0)lacpObs+=(lacpObs?' ':'')+raggStats.length+' RAGG(s): '+raggD.length+' LACP, '+raggS.length+' estático.';
    var hasStatic=(baggS.length+raggS.length)>0;
    A('PORT-CHANNEL COM LACP',hasStatic?'PARCIAL':'SIM',hasStatic?'⚠':'N/A',lacpObs||'Nenhum aggregation detectado na tabela.');
  } else if(baggCfgIds.length>0){
    var staticCnt=baggCfgIds.length-laggDynLines.length;
    A('PORT-CHANNEL COM LACP',staticCnt>0?'PARCIAL':'SIM',staticCnt>0?'⚠':'N/A',baggCfgIds.length+' BAGG(s): '+laggDynLines.length+' LACP, '+staticCnt+' estático.');
  } else {
    A('PORT-CHANNEL COM LACP','NÃO','⚠','Nenhum Bridge-Aggregation detectado.');
  }

  // 67. PORT-CHANNELS COM MEMBROS DOWN (Unselected > 0)
  if(hasSummary){
    var membDown=allAggStats.filter(function(e){return e.unselected>0;});
    var baggMD=membDown.filter(function(e){return e.type==='BAGG';});
    var raggMD=membDown.filter(function(e){return e.type==='RAGG';});
    if(membDown.length>0){
      var mdObs='';
      if(baggMD.length>0)mdObs+=baggMD.length+' BAGG(s) com porta(s) Unselected.';
      if(raggMD.length>0)mdObs+=(mdObs?' ':'')+raggMD.length+' RAGG(s) com porta(s) Unselected.';
      A('PORT-CHANNELS COM MEMBROS DOWN','PARCIAL','⚠',mdObs);
    } else {A('PORT-CHANNELS COM MEMBROS DOWN','SIM','N/A','Nenhum membro Unselected detectado.');}
  } else {A('PORT-CHANNELS COM MEMBROS DOWN','N/A','N/A','Incluir "display link-aggregation summary" para análise.');}

  // 68. PORT-CHANNEL DOWN (Selected=0 + Unselected=0 + partner None)
  if(hasSummary){
    var aggDown=allAggStats.filter(function(e){return e.selected===0&&e.unselected===0&&/none/i.test(e.partner);});
    var baggDn=aggDown.filter(function(e){return e.type==='BAGG';});
    var raggDn=aggDown.filter(function(e){return e.type==='RAGG';});
    if(aggDown.length>0){
      var dnObs='';
      if(baggDn.length>0)dnObs+=baggDn.length+' BAGG(s) sem membros ativos.';
      if(raggDn.length>0)dnObs+=(dnObs?' ':'')+raggDn.length+' RAGG(s) sem membros ativos.';
      A('PORT-CHANNEL DOWN','NÃO','✘',dnObs);
    } else {A('PORT-CHANNEL DOWN','SIM','N/A','Todos os aggregations com membros ativos.');}
  } else {A('PORT-CHANNEL DOWN','N/A','N/A','Incluir "display link-aggregation summary" para análise.');}

  // 69. PORT-CHANNEL MEMBROS INCONSISTENTES (Selected>0 mas Unselected>0)
  if(hasSummary){
    var aggInc=allAggStats.filter(function(e){return e.selected>0&&e.unselected>0;});
    var baggInc=aggInc.filter(function(e){return e.type==='BAGG';});
    var raggInc=aggInc.filter(function(e){return e.type==='RAGG';});
    if(aggInc.length>0){
      var incObs='';
      if(baggInc.length>0)incObs+=baggInc.length+' BAGG(s) com membros parcialmente inconsistentes.';
      if(raggInc.length>0)incObs+=(incObs?' ':'')+raggInc.length+' RAGG(s) com membros parcialmente inconsistentes.';
      A('PORT-CHANNEL MEMBROS INCONSISTENTES','PARCIAL','⚠',incObs);
    } else {A('PORT-CHANNEL MEMBROS INCONSISTENTES','SIM','N/A','Nenhuma inconsistência LACP detectada.');}
  } else {A('PORT-CHANNEL MEMBROS INCONSISTENTES','N/A','N/A','Incluir "display link-aggregation summary" para análise.');}

  // 70. PORT-CHANNEL SEM MEMBROS (Selected=0 + Unselected=0)
  if(hasSummary){
    var aggNoMem=allAggStats.filter(function(e){return e.selected===0&&e.unselected===0;});
    var baggNM=aggNoMem.filter(function(e){return e.type==='BAGG';});
    var raggNM=aggNoMem.filter(function(e){return e.type==='RAGG';});
    if(aggNoMem.length>0){
      var nmObs='';
      if(baggNM.length>0)nmObs+=baggNM.length+' BAGG(s) sem nenhuma porta associada.';
      if(raggNM.length>0)nmObs+=(nmObs?' ':'')+raggNM.length+' RAGG(s) sem nenhuma porta associada.';
      A('PORT-CHANNEL SEM MEMBROS','NÃO','✘',nmObs);
    } else {A('PORT-CHANNEL SEM MEMBROS','SIM','N/A','Todos os aggregations com portas associadas.');}
  } else {A('PORT-CHANNEL SEM MEMBROS','N/A','N/A','Incluir "display link-aggregation summary" para análise.');}

    // ================================================================
  S('INFRAESTRUTURA FÍSICA');
  // ================================================================

  // 71. FONTE REDUNDANTE
  var psuNormal=L.filter(function(l){return/^\s*PSU\s+\S+\s+state:\s*Normal/i.test(l.trim());});
  var psuFault=L.filter(function(l){return/^\s*PSU\s+\S+\s+state:\s*Fault/i.test(l.trim());});
  var psuAbsent=L.filter(function(l){return/^\s*PSU\s+\S+\s+state:\s*Absent/i.test(l.trim());});
  var psuModel='';
  var psuModelLine=L.find(function(l){return/DEVICE_NAME.*power\s+supply|DEVICE_NAME.*PSU/i.test(l);});
  if(psuModelLine){var pmm=psuModelLine.match(/:\s*(.+)/);if(pmm)psuModel=pmm[1].trim();}
  var psuTotal=psuNormal.length+psuFault.length;
  if(psuTotal>=2){
    var psuObs=(psuModel?psuModel+'. ':'')+psuNormal.length+' Normal'+(psuFault.length>0?', '+psuFault.length+' Fault ⚠':'')+'.';
    A('FONTE REDUNDANTE',psuFault.length>0?'PARCIAL':'SIM',psuFault.length>0?'⚠':'N/A',psuObs);
  } else if(psuTotal===1){
    A('FONTE REDUNDANTE','PARCIAL','⚠',(psuModel?psuModel+'. ':'')+'Apenas 1 fonte ativa. Verificar redundância.');
  } else if(psuNormal.length===0&&psuFault.length===0){
    // Fallback to old detection
    var psuFallback=L.filter(function(l){return/power\s+supply|PSU/i.test(l)&&/present|normal|ok|good|active/i.test(l);});
    if(psuFallback.length>=2){A('FONTE REDUNDANTE','SIM','N/A',psuFallback.length+' fonte(s) detectada(s).');}
    else{A('FONTE REDUNDANTE','NÃO','⚠','PSU não detectada.');}
  } else {
    A('FONTE REDUNDANTE','NÃO','⚠','PSU não detectada.');
  }

  // 72. PORTAS NÃO UTILIZADAS EM SHUTDOWN
  var physIfacesShut=[];var physIfacesNoShut=[];var cif2=null;var cif2Shut=false;
  L.forEach(function(l){
    var lt=l.trim();
    if(/^interface (GigabitEthernet|Ten-GigabitEthernet|FortyGigE|HundredGigE|Ethernet)/i.test(lt)){
      if(cif2){if(cif2Shut)physIfacesShut.push(cif2);else physIfacesNoShut.push(cif2);}
      cif2=lt.replace(/^interface\s+/i,'');cif2Shut=false;
    } else if(/^interface\s+/i.test(lt)&&cif2){
      if(cif2Shut)physIfacesShut.push(cif2);else physIfacesNoShut.push(cif2);
      cif2=null;cif2Shut=false;
    } else if(cif2&&/^shutdown\s*$/i.test(lt)){cif2Shut=true;}
    else if(lt==='#'&&cif2){if(cif2Shut)physIfacesShut.push(cif2);else physIfacesNoShut.push(cif2);cif2=null;cif2Shut=false;}
  });
  if(cif2){if(cif2Shut)physIfacesShut.push(cif2);else physIfacesNoShut.push(cif2);}
  if(physIfacesNoShut.length>0){
    A('PORTAS NÃO UTILIZADAS EM SHUTDOWN','PARCIAL','⚠',physIfacesNoShut.length+' interface(s) física(s) sem shutdown.'+(physIfacesShut.length>0?' '+physIfacesShut.length+' com shutdown.':''));
  } else if(physIfacesShut.length>0){
    A('PORTAS NÃO UTILIZADAS EM SHUTDOWN','SIM','N/A',physIfacesShut.length+' interface(s) com shutdown. Todas as físicas desabilitadas.');
  } else {
    A('PORTAS NÃO UTILIZADAS EM SHUTDOWN','N/A','N/A','Nenhuma interface física detectada.');
  }

  // 73. VIRTUALIZAÇÃO (IRF/Stack)
  var irfMember=find('irf member').filter(function(l){return/^\s*irf\s+member\s+\d+/i.test(l.trim());});
  var irfDomain=find('irf domain').filter(function(l){return/^\s*irf\s+domain\s+\d+/i.test(l.trim());});
  if(irfMember.length>0||irfDomain.length>0){A('VIRTUALIZACAO (VPC/VSS/STACK)','SIM','N/A','IRF (Intelligent Resilient Framework) configurado. '+(irfDomain.length>0?'Domain: '+(irfDomain[0]||'').trim():'')+'.');}
  else{A('VIRTUALIZACAO (VPC/VSS/STACK)','NÃO','⚠','IRF não configurado. Avaliar necessidade de redundância via IRF.');}

  // 74. DUPLA ABORDAGEM COM CORE
  if(baggIds.length>=2){A('DUPLA ABORDAGEM COM CORE','SIM','N/A',baggIds.length+' Bridge-Aggregation(s) detectado(s). Uplinks redundantes.');}
  else if(baggIds.length===1){A('DUPLA ABORDAGEM COM CORE','PARCIAL','⚠','Apenas 1 Bridge-Aggregation. Sem redundância de uplink.');}
  else{A('DUPLA ABORDAGEM COM CORE','NÃO','⚠','Nenhum uplink redundante detectado.');}

  // 75. SPEED/DUPLEX
  var sdAutoIfaces=[];var sdHalfIfaces=[];var sdForcedIfaces=[];var curIfSd=null;
  L.forEach(function(l){var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/i);if(ifm){curIfSd=ifm[1];return;}if(!curIfSd)return;
    if(/^speed\s+auto\b|^duplex\s+auto\b/i.test(lt)&&!sdAutoIfaces.includes(curIfSd))sdAutoIfaces.push(curIfSd);
    if(/^duplex\s+half\b/i.test(lt)&&!sdHalfIfaces.includes(curIfSd))sdHalfIfaces.push(curIfSd);
    if(/^speed\s+\d+\b|^duplex\s+full\b/i.test(lt)&&!sdForcedIfaces.includes(curIfSd))sdForcedIfaces.push(curIfSd);
  });
  if(sdHalfIfaces.length>0){A('SPEED/DUPLEX','NÃO','⚠',sdHalfIfaces.length+' interface(s) em half-duplex.');}
  else if(sdAutoIfaces.length>0&&sdForcedIfaces.length===0){A('SPEED/DUPLEX','PARCIAL','⚠',sdAutoIfaces.length+' interface(s) com speed/duplex auto explícito. Nenhuma com speed forçado.');}
  else if(sdAutoIfaces.length>0){A('SPEED/DUPLEX','PARCIAL','⚠',sdAutoIfaces.length+' interface(s) com auto. '+sdForcedIfaces.length+' com speed/duplex forçado.');}
  else if(sdForcedIfaces.length>0){A('SPEED/DUPLEX','SIM','N/A',sdForcedIfaces.length+' interface(s) com speed/duplex forçado. Nenhuma em auto ou half-duplex.');}
  else{A('SPEED/DUPLEX','PARCIAL','⚠','Nenhuma configuração de speed/duplex explícita. Todas em auto-negociação (padrão Comware).');}

  // 76-78. STATIC
  A('EQUIPAMENTO EM SUPORTE (NÃO EOL)','VERIFICAR NO PORTAL HP','VERIFICAR NO PORTAL HP','Verificar no portal HPE/HP Networks.');
  A('BASELINE CPU E MEMÓRIA','ANALISAR NO DX NETOPS','ANALISAR NO DX NETOPS','Inserir resultado após análise.');
  A('BASELINE UPLINKS','ANALISAR NO DX NETOPS','ANALISAR NO DX NETOPS','Inserir resultado após análise.');

  return items;
}



function runAnalysis_huawei(log){
  // Abreviar nomes de interfaces VRP
  function abbrevIf(s){
    return s.replace(/GigabitEthernet/gi,'GE').replace(/XGigabitEthernet/gi,'XGE')
            .replace(/10GE/gi,'10GE').replace(/40GE/gi,'40GE').replace(/100GE/gi,'100GE')
            .replace(/Eth-Trunk/gi,'Eth-Trunk').replace(/MEth/gi,'MEth')
            .replace(/LoopBack/gi,'Lo').replace(/Vlanif/gi,'Vlanif');
  }
  function abbrevList(arr){return arr.map(function(x){return abbrevIf(x);});}

  var L=log.split('\n');
  function has(kw){return L.some(function(l){return l.toLowerCase().includes(kw.toLowerCase());});}
  function find(kw){return L.filter(function(l){return l.toLowerCase().includes(kw.toLowerCase());});}
  function hasRe(re){return L.some(function(l){return re.test(l);});}
  function findRe(re){return L.filter(function(l){return re.test(l);});}

  var res=[];
  function S(name){res.push({item:name,status:'SECTION',risco:'',obs:''});}
  function A(item,status,risco,obs){res.push({item:item,status:status,risco:risco,obs:obs});}

  // Detectar modelo e tipo de equipamento
  var modelLine=L.find(function(l){return/HUAWEI\s+(CE|S\d|AR)/i.test(l)||/VRP.*software.*Version/i.test(l);});
  var vrpVersion=L.find(function(l){return/VRP.*software.*Version/i.test(l);});
  var isRouter=L.some(function(l){return/HUAWEI\s+(AR|NE)/i.test(l);});
  var isCE12800=L.some(function(l){return/CE12[89]\d\d/i.test(l);});
  var vrpVer=(vrpVersion||'').match(/Version\s+([\d\.]+)/i);
  var vrpVerStr=vrpVer?vrpVer[1]:'';
  var hostLine=L.find(function(l){return/^<[\w\-]+>|^\[[\w\-]+\]/.test(l.trim());});
  var hostname=hostLine?(hostLine.match(/[<\[]([\w\-]+)[>\]]/)||['',''])[1]:'';

  // Pré-cálculo de variáveis globais
  var hasTacacs=has('hwtacacs enable')||has('hwtacacs server template');
  var hasRadius=has('radius-server template')||has('radius template');
  var hasAaa=has('authentication-scheme')&&has('authorization-scheme');
  // OSPF/BGP: detectar apenas blocos de config, ignorar output de display
  var inDisplayBlock=false;
  var hasOspf=false;var hasBgp=false;
  L.forEach(function(l){
    var lt=l.trim();
    if(/^[<\[]\S+[>\]]\s*display/i.test(lt))inDisplayBlock=true;
    if(inDisplayBlock&&(/^[<\[]\S+[>\]]/i.test(lt)&&!/display/i.test(lt)))inDisplayBlock=false;
    if(inDisplayBlock&&/^#$/.test(lt))inDisplayBlock=false;
    if(!inDisplayBlock){
      if(/^ospf\s+\d+/i.test(lt))hasOspf=true;
      if(/^bgp\s+\d+/i.test(lt))hasBgp=true;
    }
  });
  var hasVrrp=L.some(function(l){return/vrrp vrid\s+\d+/i.test(l.trim());});
  var hasStack=L.some(function(l){return/(Master|Standby)\s+\d+.*uptime/i.test(l);});

  // Eth-Trunk
  var ethTrunks=[...new Set(L.filter(function(l){return/^interface Eth-Trunk\d+/i.test(l.trim());}).map(function(l){return(l.trim().match(/Eth-Trunk\d+/)||[''])[0];}))];
  var lacpTrunks=L.filter(function(l){return/mode lacp-static/i.test(l.trim());});

  // ================================================================
  S('ACESSO E AUTENTICAÇÃO');
  // ================================================================

  // 01. SSH
  var stelnet=L.some(function(l){
    var lt=l.trim();
    return /^stelnet\s+server\s+enable/i.test(lt)
      ||/^stelnet\s+ipv4\s+server\s+enable/i.test(lt)
      ||/^stelnet\s+ipv6\s+server\s+enable/i.test(lt)
      ||/^ssh\s+server\s+enable/i.test(lt)
      ||/service-type\s+stelnet/i.test(lt);
  });
  var sshUser=has('ssh user')&&has('service-type stelnet');
  if(stelnet){A('SSH','SIM','N/A','STelnet habilitado (SSH VRP).');}
  else{A('SSH','NÃO','✘','STelnet não habilitado, acesso remoto inseguro.');}

  // 02. TELNET — verificar estado final (último comando wins)
  var telnetState='unknown';
  L.forEach(function(l){
    var lt=l.trim();
    if(/^telnet\s+server\s+disable$/i.test(lt)
      ||/^telnet\s+ipv6\s+server\s+disable$/i.test(lt)
      ||/^telnet\s+ipv4\s+server\s+disable$/i.test(lt)
      ||/^undo\s+telnet\s+server\s+enable/i.test(lt))telnetState='disabled';
    else if(/^telnet\s+server\s+enable$/i.test(lt)
      ||/^telnet\s+ipv6\s+server\s+enable$/i.test(lt)
      ||/^telnet\s+ipv4\s+server\s+enable$/i.test(lt))telnetState='enabled';
    else if(/^telnet\s+server$/i.test(lt)&&telnetState==='unknown')telnetState='enabled';
    // Usuário com service-type telnet = Telnet habilitado para esse usuário
    else if(/service-type\s+telnet/i.test(lt))telnetState='enabled';
  });
  var telnetDis=telnetState==='disabled';
  var telnetEn=telnetState==='enabled';
  if(telnetDis){A('TELNET','NÃO','N/A','Telnet não habilitado.');}
  else if(telnetEn){A('TELNET','SIM','✘','Telnet habilitado, protocolo inseguro, desabilitar com "telnet server disable".');}
  else{A('TELNET','NÃO','N/A','Telnet não habilitado.');}

  // 03. ACL PARA GERÊNCIA (VTY)
  var vtyAcl=false;var inVty=false;
  L.forEach(function(l){var lt=l.trim();if(/^user-interface vty/i.test(lt))inVty=true;if(inVty&&/^acl\s+\d+\s+inbound|^acl\s+number/i.test(lt))vtyAcl=true;if(/^user-interface\s+(con|aux)|^\#/i.test(lt))inVty=false;});
  if(vtyAcl){A('ACL PARA GERÊNCIA (VTY)','SIM','N/A','ACL aplicada na interface VTY.');}
  else{A('ACL PARA GERÊNCIA (VTY)','NÃO','✘','ACL não configurada no user-interface VTY, acesso irrestrito.');}

  // 04. TACACS/RADIUS (AAA)
  if(hasTacacs){
    var tacSvrs=[...new Set(find('hwtacacs server authentication').map(function(l){return(l.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)||['',''])[1];}).filter(Boolean))];
    var tacObs='HWTACACS configurado. '+tacSvrs.length+' servidor(es): '+tacSvrs.join(', ')+'.';
    if(tacSvrs.length===1)tacObs+=' Necessário configurar outro servidor de backup.';
    A('TACACS/RADIUS (AAA)','SIM','N/A',tacObs);
  } else if(hasRadius){
    var radSvrs=[...new Set(find('radius-server authentication').map(function(l){return(l.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)||['',''])[1];}).filter(Boolean))];
    A('TACACS/RADIUS (AAA)','SIM','N/A','RADIUS configurado. '+radSvrs.length+' servidor(es): '+radSvrs.join(', ')+'.');
  } else {A('TACACS/RADIUS (AAA)','NÃO','✘','HWTACACS/RADIUS não configurado, autenticação apenas local.');}

  // 05. AAA NEW-MODEL
  if(hasAaa){
    var authScheme=find('authentication-scheme').filter(function(l){return!/default/i.test(l);})[0]||'';
    A('AAA NEW-MODEL','SIM','N/A','AAA configurado.');
  } else {A('AAA NEW-MODEL','NÃO','✘','AAA não configurado.');}

  // 06. USERNAME LOCAL (FALLBACK)
  var localUsers=find('local-user').filter(function(l){return/^local-user\s+\S+$/i.test(l.trim())&&!/^undo\s+local-user/i.test(l.trim())&&!/policy\s+security/i.test(l);});
  var localPasswd=find('local-user').filter(function(l){return/password/i.test(l)&&!/^undo\s+local-user/i.test(l.trim());});
  if(localUsers.length>0||localPasswd.length>0){
    var unames=[...new Set(find('local-user').filter(function(l){return!/^undo\s+local-user/i.test(l.trim())&&!/policy\s+security/i.test(l);}).map(function(l){return(l.trim().match(/local-user\s+(\S+)/i)||['',''])[1];}).filter(Boolean))];
    if(unames.length>0){A('USERNAME LOCAL (FALLBACK)','SIM','N/A',unames.length+' usuário(s) local(is): '+unames.join(', ')+'.');}
    else{A('USERNAME LOCAL (FALLBACK)','PARCIAL','⚠','Usuários locais configurados via AAA, verificar fallback local.');}
  } else {A('USERNAME LOCAL (FALLBACK)','NÃO','⚠','Nenhum usuário local configurado, sem fallback de autenticação.');}

  // 07. LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)
  // ACL no VTY
  var vtyHasAcl=false;var inVtyLB=false;
  L.forEach(function(l){var lt=l.trim();
    if(/^user-interface vty/i.test(lt))inVtyLB=true;
    if(inVtyLB&&/^acl\s+\d+\s+inbound|^acl\s+\d+\s+outbound/i.test(lt))vtyHasAcl=true;
    if(/^user-interface\s+con|^#$/i.test(lt))inVtyLB=false;
  });
  // Lockout por tentativas falhas
  var hasFailedTimes=L.some(function(l){return/failed-times\s+\d+/i.test(l.trim());});
  var hasBlockTime=L.some(function(l){return/block-time\s+\d+/i.test(l.trim());});
  var hasLockout=hasFailedTimes&&hasBlockTime;
  if(vtyHasAcl&&hasLockout){
    A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','SIM','N/A','ACL no VTY e lockout por tentativas falhas configurados (failed-times + block-time).');
  } else if(vtyHasAcl&&!hasLockout){
    A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','PARCIAL','✘','ACL no VTY configurada, mas sem lockout por tentativas falhas, configurar failed-times e block-time no AAA.');
  } else if(!vtyHasAcl&&hasLockout){
    A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','PARCIAL','✘','Lockout por tentativas falhas configurado, mas sem ACL no VTY.');
  } else{
    A('LOGIN BLOCK-FOR (ANTI BRUTE-FORCE)','NÃO','✘','Sem proteção contra brute-force, configurar ACL no VTY e failed-times no AAA.');
  }

  // 08. EXEC-TIMEOUT
  var idleVty=[];var inVty2=false;
  L.forEach(function(l){var lt=l.trim();if(/^user-interface vty/i.test(lt))inVty2=true;if(inVty2&&/^idle-timeout\s+\d+/i.test(lt))idleVty.push(lt);if(/^user-interface\s+con|\#/i.test(lt))inVty2=false;});
  if(idleVty.length>0){A('EXEC-TIMEOUT','SIM','N/A','idle-timeout configurado no VTY: '+idleVty[0]+'.');}
  else{A('EXEC-TIMEOUT','NÃO','⚠','idle-timeout não configurado no VTY, sessões sem timeout.');}

  // 09. SSH 2048 BITS
  var sshPubkey=find('ssh server publickey').filter(function(l){return/rsa/i.test(l);})[0]||'';
  var cryptoKeyHex=L.filter(function(l){return/^\s*[0-9A-F]{8}(\s+[0-9A-F]{8})+/i.test(l.trim());}).join(' ').replace(/\s+/g,'').toUpperCase();
  var rsaBits=0;
  if(cryptoKeyHex.indexOf('02820201')>=0)rsaBits=4096;
  else if(cryptoKeyHex.indexOf('02820101')>=0)rsaBits=2048;
  else if(cryptoKeyHex.indexOf('30820109')>=0)rsaBits=2048;
  else if(cryptoKeyHex.indexOf('028181')>=0)rsaBits=1024;
  else if(cryptoKeyHex.indexOf('3081B9')>=0)rsaBits=1024;
  if(rsaBits>=2048){A('SSH 2048 BITS','SIM','N/A','Chave RSA 2048 configurada.');}
  else if(rsaBits>0){A('SSH 2048 BITS','NÃO','⚠','Chave RSA de apenas '+rsaBits+' bits, recomendado mínimo 2048 bits.');}
  else if(stelnet){A('SSH 2048 BITS','SIM','N/A','Chave 2048 bits configurada.');}
  else{A('SSH 2048 BITS','N/A','N/A','SSH não habilitado.');}

  // 10. SERVICE PASSWORD-ENCRYPTION
  var cipherPasswd=find('password cipher').length>0||find('password irreversible-cipher').length>0;
  var plainPasswd=find('password simple').length>0||find('set authentication password simple').length>0;
  if(cipherPasswd&&!plainPasswd){A('SERVICE PASSWORD-ENCRYPTION','SIM','N/A','Senhas com cipher configuradas.');}
  else if(plainPasswd){A('SERVICE PASSWORD-ENCRYPTION','NÃO','✘','Senhas em texto simples (password simple) detectadas, usar cipher.');}
  else{A('SERVICE PASSWORD-ENCRYPTION','N/A','N/A','Configuração de senhas não detectada.');}

  // 11. ENABLE SECRET / RBAC
  var superPwd=has('super password')||has('super level');
  var superAaa=L.some(function(l){return/super.*authentication-mode|aaa.*authorization.*super/i.test(l);});
  var hasAuthScheme=has('authentication-scheme')&&!L.every(function(l){return!/authentication-scheme (?!default)/i.test(l);});
  if(superAaa||hasAuthScheme){A('ENABLE SECRET / RBAC','SIM','N/A','Acesso privilegiado controlado via AAA.');}
  else if(superPwd){A('ENABLE SECRET / RBAC','SIM','N/A','Super password configurado.');}
  else{A('ENABLE SECRET / RBAC','NÃO','✘','Super password e AAA de autorização não configurados, acesso privilegiado sem proteção.');}

  // 12. HTTPS HABILITADO / HTTP DESABILITADO
  var httpsEn=has('http secure-server enable')||has('https server enable');
  var httpDis=has('undo http server enable')||!has('http server enable');
  if(httpsEn&&httpDis){A('HTTPS HABILITADO / HTTP DESABILITADO','SIM','N/A','HTTPS habilitado e HTTP desabilitado.');}
  else if(httpsEn){A('HTTPS HABILITADO / HTTP DESABILITADO','PARCIAL','⚠','HTTPS habilitado mas HTTP também pode estar ativo.');}
  else if(has('http server enable')){A('HTTPS HABILITADO / HTTP DESABILITADO','NÃO','⚠','HTTP habilitado sem HTTPS, acesso web inseguro.');}
  else{A('HTTPS HABILITADO / HTTP DESABILITADO','SIM','N/A','HTTP/HTTPS não detectado, acesso web não disponível.');}

  // 13. BANNER MOTD
  var hasHeaderLogin=has('header login information');
  var hasHeaderShell=has('header shell information');
  var bannerObs='';
  if(hasHeaderLogin&&hasHeaderShell)bannerObs='Header login e shell configurados.';
  else if(hasHeaderLogin)bannerObs='Header login configurado.';
  else if(hasHeaderShell)bannerObs='Header shell configurado.';
  else bannerObs='Header login e shell não configurados.';
  if(hasHeaderLogin||hasHeaderShell){A('BANNER MOTD','SIM','N/A',bannerObs);}
  else{A('BANNER MOTD','NÃO','✔',bannerObs);}

  // 14. CDP/LLDP NAS PORTAS DE ACESSO
  var lldpGlobal=has('lldp enable')&&!L.some(function(l){return/^undo lldp enable$/i.test(l.trim());});
  // Coletar interfaces com lldp enable (habilitado por interface)
  var lldpIfEn=[];var lldpIfDisList=[];var curIfLldp=null;
  L.forEach(function(l){
    var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/i);if(ifm)curIfLldp=ifm[1];
    if(curIfLldp&&/^lldp enable$/i.test(lt)&&!lldpIfEn.includes(curIfLldp))lldpIfEn.push(curIfLldp);
    if(curIfLldp&&/^undo lldp enable$/i.test(lt)&&!lldpIfDisList.includes(curIfLldp))lldpIfDisList.push(curIfLldp);
  });
  if(!lldpGlobal&&lldpIfEn.length===0){
    A('CDP/LLDP NAS PORTAS DE ACESSO','SIM','N/A','LLDP não habilitado globalmente.');
  } else if(!lldpGlobal&&lldpIfEn.length>0){
    A('CDP/LLDP NAS PORTAS DE ACESSO','PARCIAL','⚠','LLDP não habilitado globalmente, habilitado em '+lldpIfEn.length+' interface(s): '+abbrevList(lldpIfEn).join(', ')+'.');
  } else if(lldpGlobal&&lldpIfDisList.length>0){
    A('CDP/LLDP NAS PORTAS DE ACESSO','PARCIAL','⚠','LLDP habilitado globalmente, desabilitado em '+lldpIfDisList.length+' interface(s): '+abbrevList(lldpIfDisList).join(', ')+'.');
  } else{
    A('CDP/LLDP NAS PORTAS DE ACESSO','NÃO','⚠','LLDP habilitado globalmente, nenhuma interface com undo lldp enable, considerar desabilitar nas portas de acesso.');
  }

  // ================================================================
  S('GERÊNCIA');
  // ================================================================

  // 15. GERÊNCIA OUT OF BAND (OOB)
  var hasMEth=L.some(function(l){return/^interface MEth/i.test(l.trim());});
  var hasMgmtVrf=has('vpn-instance Management')||has('vpn-instance Mgmt-Vrf')||has('vpn-instance __LOCAL_OAM_VPN__');
  if(hasMEth){A('GERÊNCIA OUT OF BAND (OOB)','SIM','N/A','Interface MEth (OOB) configurada.');}
  else if(hasMgmtVrf){A('GERÊNCIA OUT OF BAND (OOB)','SIM','N/A','VPN-instance de gerência configurada.');}
  else{A('GERÊNCIA OUT OF BAND (OOB)','NÃO','⚠','Interface de gerência dedicada (OOB) não detectada.');}

  // 16. CONTROL PLANE POLICING (CoPP)
  var cpuDefend=has('cpu-defend policy')||has('cpu-defend enable');
  var cpCar=has('cpcar');
  if(cpuDefend||cpCar){A('CONTROL PLANE POLICING (CoPP)','SIM','N/A','cpu-defend configurado.');}
  else{A('CONTROL PLANE POLICING (CoPP)','NÃO','✘','cpu-defend não configurado, control plane sem proteção.');}

  // 17. SERVIDOR DE LOGGING
  var logSvrs=find('info-center loghost').filter(function(l){return/info-center loghost\s+[\d\.]+/i.test(l.trim());});
  if(logSvrs.length>0){
    var logIPs=[...new Set(logSvrs.map(function(l){return(l.match(/info-center loghost\s+([\d\.]+)/i)||['',''])[1];}).filter(Boolean))];
    A('SERVIDOR DE LOGGING','SIM','N/A',logIPs.length+' servidor(es) syslog: '+logIPs.join(', ')+'.');
  } else {A('SERVIDOR DE LOGGING','NÃO','⚠','Nenhum servidor syslog remoto configurado, logs apenas locais.');}

  // 18. LOGGING BUFFERED
  var logBuf=has('info-center enable')||has('info-center logbuffer');
  if(logBuf){A('LOGGING BUFFERED','SIM','N/A','Logging buffered configurado.');}
  else{A('LOGGING BUFFERED','NÃO','⚠','info-center não habilitado, logs locais sem buffer.');}

  // ================================================================
  S('SNMP');
  // ================================================================

  // 19. SNMP PUBLIC/PRIVATE
  var snmpComm=find('snmp-agent community').filter(function(l){return l.trim().startsWith('snmp-agent community');});
  var snmpPub=snmpComm.filter(function(l){return/\bpublic\b/i.test(l);});
  var snmpPriv=snmpComm.filter(function(l){return/\bprivate\b/i.test(l);});
  if(snmpPub.length>0||snmpPriv.length>0){A('SNMP PUBLIC/PRIVATE','SIM','✘','Community insegura detectada: '+(snmpPub.length>0?'"public"':'')+(snmpPriv.length>0?' "private"':'')+', substituir por uma community forte.');}
  else if(snmpComm.length>0){A('SNMP PUBLIC/PRIVATE','NÃO','N/A',snmpComm.length+' community(ies) configurada(s) com nome personalizado.');}
  else{A('SNMP PUBLIC/PRIVATE','N/A','N/A','SNMP community não detectada.');}

  // 20. SNMP PROTEGIDO POR ACL
  var snmpAcl=snmpComm.filter(function(l){return/acl\s+\d+/i.test(l);});
  if(snmpAcl.length>0){A('SNMP PROTEGIDO POR ACL','SIM','N/A','SNMP community protegida por ACL.');}
  else if(snmpComm.length>0){A('SNMP PROTEGIDO POR ACL','NÃO','⚠','SNMP community sem ACL, acesso irrestrito ao SNMP.');}
  else{A('SNMP PROTEGIDO POR ACL','N/A','N/A','SNMP não configurado.');}

  // 21. SNMPv3
  var snmpV3=find('snmp-agent usm-user v3').filter(function(l){return l.trim().startsWith('snmp-agent usm-user v3');});
  var snmpV3Auth=snmpV3.filter(function(l){return/authentication-mode/i.test(l);});
  if(snmpV3Auth.length>0){A('SNMPv3 (SEGURO)','SIM','N/A','SNMPv3 configurado com autenticação.');}
  else if(snmpV3.length>0){A('SNMPv3 (SEGURO)','PARCIAL','⚠','SNMPv3 configurado sem autenticação explícita.');}
  else if(has('snmp-agent sys-info version v3')){A('SNMPv3 (SEGURO)','PARCIAL','⚠','SNMPv3 habilitado mas sem usuário v3 configurado.');}
  else{A('SNMPv3 (SEGURO)','NÃO','✘','SNMPv3 não configurado, recomendado usar SNMPv3 com autenticação e privacidade.');}

  // ================================================================
  S('ROTEAMENTO');
  // ================================================================

  // 22-25. OSPF
  if(hasOspf){
    A('PROTOCOLO DE ROTEAMENTO (OSPF)','SIM','N/A','OSPF configurado.');
    var ospfSilent=has('silent-interface');
    var ospfSilentIf=find('silent-interface').filter(function(l){return/^\s*silent-interface/i.test(l);});
    if(has('silent-interface all')){A('OSPF PASSIVE-INTERFACE DEFAULT','SIM','N/A','silent-interface all configurado no OSPF.');}
    else if(ospfSilentIf.length>0){A('OSPF PASSIVE-INTERFACE DEFAULT','PARCIAL','⚠',ospfSilentIf.length+' interface(s) silenciosa(s) configuradas, mas não como padrão global.');}
    else{A('OSPF PASSIVE-INTERFACE DEFAULT','NÃO','⚠','silent-interface não configurado, todas as interfaces participam do OSPF.');}
    var ospfAuthArea=find('authentication-mode').filter(function(l){return/area.*authentication|authentication-mode md5/i.test(l);});
    var ospfMd5=ospfAuthArea.some(function(l){return/md5/i.test(l);});
    var ospfIfNoAuth=[];var curIfOs=null;
    L.forEach(function(l){var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/);if(ifm)curIfOs=ifm[1];if(curIfOs&&/ospf\s+\d+\s+area/i.test(lt)&&!ospfIfNoAuth.includes(curIfOs))ospfIfNoAuth.push(curIfOs);if(curIfOs&&/authentication-mode md5/i.test(lt)){var idx=ospfIfNoAuth.indexOf(curIfOs);if(idx>=0)ospfIfNoAuth.splice(idx,1);}});
    var ospfNoAuthStr=ospfIfNoAuth.length>0?' Interfaces sem autenticação: '+abbrevList(ospfIfNoAuth).join(', ')+'.':'';
    if(ospfMd5){A('OSPF AUTENTICAÇÃO','SIM','N/A','OSPF autenticação MD5 configurada.'+ospfNoAuthStr);A('OSPF MD5/SHA AUTHENTICATION','SIM','N/A','OSPF com autenticação MD5.');}
    else if(ospfAuthArea.length>0){A('OSPF AUTENTICAÇÃO','PARCIAL','✘','OSPF autenticação sem MD5.'+ospfNoAuthStr);A('OSPF MD5/SHA AUTHENTICATION','NÃO','✘','OSPF sem MD5.');}
    else{A('OSPF AUTENTICAÇÃO','NÃO','✘','OSPF sem autenticação, risco de injeção de rotas.'+ospfNoAuthStr);A('OSPF MD5/SHA AUTHENTICATION','NÃO','✘','OSPF sem autenticação MD5.');}
  } else {A('PROTOCOLO DE ROTEAMENTO (OSPF)','N/A','N/A','OSPF não configurado.');A('OSPF PASSIVE-INTERFACE DEFAULT','N/A','N/A','OSPF não configurado.');A('OSPF AUTENTICAÇÃO','N/A','N/A','OSPF não configurado.');A('OSPF MD5/SHA AUTHENTICATION','N/A','N/A','OSPF não configurado.');}

  // 26-27. BGP
  if(hasBgp){
    A('BGP','SIM','N/A','BGP configurado.');
    var bgpNeighbors=[...new Set(find('peer').filter(function(l){return/peer\s+[\d\.]+\s+as-number/i.test(l);}).map(function(l){return(l.match(/peer\s+([\d\.]+)/i)||['',''])[1];}).filter(Boolean))];
    var bgpAuthN=[...new Set(find('peer').filter(function(l){return/peer.*password/i.test(l);}).map(function(l){return(l.match(/peer\s+([\d\.]+)/i)||['',''])[1];}).filter(Boolean))];
    var bgpNoAuth=bgpNeighbors.filter(function(n){return!bgpAuthN.includes(n);});
    var bgpObs=(bgpAuthN.length>0?'Autenticação em: '+bgpAuthN.join(', ')+'. ':'')+(bgpNoAuth.length>0?'Sem autenticação: '+bgpNoAuth.join(', ')+'.':'BGP sem autenticação MD5.');
    A('BGP AUTENTICAÇÃO',bgpNoAuth.length===0&&bgpAuthN.length>0?'SIM':bgpAuthN.length>0?'PARCIAL':'NÃO',bgpNoAuth.length===0&&bgpAuthN.length>0?'N/A':'⚠',bgpObs);
  } else {A('BGP','N/A','N/A','BGP não configurado.');A('BGP AUTENTICAÇÃO','N/A','N/A','BGP não configurado.');}

  // 28-29. EIGRP — N/A no VRP
  A('EIGRP','N/A','N/A','EIGRP não suportado no VRP Huawei.');
  A('EIGRP AUTENTICAÇÃO','N/A','N/A','EIGRP não suportado no VRP Huawei.');

  // 30. NO IP SOURCE-ROUTE
  A('NO IP SOURCE-ROUTE','N/A','N/A','Source routing desabilitado por padrão no VRP Huawei.');

  // 31. NO IP REDIRECTS
  var redirWithNo=[];var redirWithout=[];var curIfR=null;
  L.forEach(function(l){var lt=l.trim();var m=lt.match(/^interface\s+(\S+)/);if(m)curIfR=m[1];if(curIfR&&/^undo icmp redirect/i.test(lt)&&!redirWithNo.includes(curIfR))redirWithNo.push(curIfR);});
  var l3Ifaces=[];var curIfL3=null;var hasIpAddr=false;
  L.forEach(function(l){var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/i);if(ifm){if(curIfL3&&hasIpAddr&&!l3Ifaces.includes(curIfL3))l3Ifaces.push(curIfL3);curIfL3=ifm[1];hasIpAddr=false;}if(curIfL3&&/^ip address/i.test(lt))hasIpAddr=true;if(/^#$/.test(lt)&&curIfL3){if(hasIpAddr&&!l3Ifaces.includes(curIfL3))l3Ifaces.push(curIfL3);curIfL3=null;hasIpAddr=false;}});
  l3Ifaces=l3Ifaces.filter(function(i){return!/^LoopBack/i.test(i);});
  redirWithNo=redirWithNo.filter(function(i){return!/^LoopBack/i.test(i);});
  redirWithout=l3Ifaces.filter(function(i){return!redirWithNo.includes(i);});
  var redirObs='';
  if(redirWithNo.length===0&&redirWithout.length===0){redirObs='ICMP redirect desabilitado por padrão.';}
  else if(redirWithout.length===0){redirObs=redirWithNo.length+' interface(s) com undo icmp redirect configurado.';}
  else if(redirWithNo.length===0){redirObs='Nenhuma interface com undo icmp redirect configurado.';}
  else{redirObs=redirWithNo.length+' interface(s) com undo icmp redirect, '+redirWithout.length+' sem configuração.';}
  if(redirWithNo.length===0&&redirWithout.length===0){A('NO IP REDIRECTS','SIM','N/A','ICMP redirect desabilitado por padrão.');}
  else if(redirWithout.length===0){A('NO IP REDIRECTS','SIM','N/A',redirObs);}
  else if(redirWithNo.length>0){A('NO IP REDIRECTS','PARCIAL','✘',redirObs);}
  else{A('NO IP REDIRECTS','NÃO','✘',redirObs);}

  // 32. UNICAST RPF
  var urpf=has('urpf')||has('unicast-reverse-path');
  if(urpf){A('UNICAST RPF (ANTI-SPOOFING)','SIM','N/A','uRPF configurado.');}
  else{A('UNICAST RPF (ANTI-SPOOFING)','NÃO','✘','uRPF não configurado, anti-spoofing ausente.');}

  // ================================================================
  S('REDUNDÂNCIA L3');
  // ================================================================

  // 33-35. HSRP — N/A no VRP
  A('HSRP','N/A','N/A','HSRP não suportado no VRP Huawei. Usar VRRP.');
  A('HSRP AUTENTICAÇÃO','N/A','N/A','HSRP não suportado no VRP Huawei.');
  A('HSRP PRIORIDADE','N/A','N/A','HSRP não suportado no VRP Huawei.');

  // 36-38. VRRP
  if(hasVrrp){
    var vrrpIfMap={};var curIfVr=null;
    L.forEach(function(l){var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/);if(ifm)curIfVr=ifm[1];if(curIfVr&&/vrrp vrid\s+\d+/i.test(lt)){if(!vrrpIfMap[curIfVr])vrrpIfMap[curIfVr]={auth:false,prio:false};}if(curIfVr&&vrrpIfMap[curIfVr]){if(/vrrp.*authentication/i.test(lt))vrrpIfMap[curIfVr].auth=true;if(/vrrp.*priority/i.test(lt))vrrpIfMap[curIfVr].prio=true;}});
    var vrrpAll=Object.keys(vrrpIfMap);
    var vrrpNoAuth=vrrpAll.filter(function(i){return!vrrpIfMap[i].auth;});
    var vrrpNoPrio=vrrpAll.filter(function(i){return!vrrpIfMap[i].prio;});
    A('VRRP','SIM','N/A','VRRP em '+vrrpAll.length+' interface(s): '+abbrevList(vrrpAll).join(', ')+'.');
    A('VRRP AUTENTICAÇÃO',vrrpNoAuth.length===0?'SIM':'NÃO',vrrpNoAuth.length===0?'N/A':'⚠',vrrpNoAuth.length===0?'VRRP autenticação configurada.':'VRRP sem autenticação em: '+abbrevList(vrrpNoAuth).join(', ')+'.');
    A('VRRP PRIORIDADE',vrrpNoPrio.length===0?'SIM':'NÃO',vrrpNoPrio.length===0?'N/A':'⚠',vrrpNoPrio.length===0?'VRRP prioridade configurada.':'VRRP sem prioridade em: '+abbrevList(vrrpNoPrio).join(', ')+'.');
  } else {A('VRRP','N/A','N/A','VRRP não configurado.');A('VRRP AUTENTICAÇÃO','N/A','N/A','VRRP não configurado.');A('VRRP PRIORIDADE','N/A','N/A','VRRP não configurado.');}

  // 39-41. GLBP — N/A no VRP
  A('GLBP','N/A','N/A','GLBP não suportado no VRP Huawei. Usar VRRP.');
  A('GLBP AUTENTICAÇÃO','N/A','N/A','GLBP não suportado no VRP Huawei.');
  A('GLBP PRIORIDADE','N/A','N/A','GLBP não suportado no VRP Huawei.');

  // ================================================================
  S('NTP');
  // ================================================================

  // 42. NTP
  var ntpExtSvrs=[...new Set(
    find('ntp-service unicast-server').concat(find('ntp unicast-server'))
    .map(function(l){return(l.match(/unicast-server\s+([\d\.]+)/i)||['',''])[1];})
    .filter(Boolean)
  )];
  var ntpClockLocal=has('ntp refclock-master')||has('ntp-service refclock-master');
  if(ntpExtSvrs.length>0){
    A('NTP CONFIGURADO','SIM','N/A','NTP configurado. Servidores: '+ntpExtSvrs.join(', ')+'.');
  } else if(ntpClockLocal){
    A('NTP CONFIGURADO','PARCIAL','⚠','Clock local configurado como referência (ntp refclock-master), sem servidor NTP externo.');
  } else {
    A('NTP CONFIGURADO','NÃO','⚠','NTP não configurado.');
  }

  // 43. NTP SINCRONIZADO
  var ntpSync=L.some(function(l){return/clock status:\s*synchronized/i.test(l);});
  if(ntpSync){A('NTP SINCRONIZADO','SIM','N/A','Clock sincronizado.');}
  else if(L.some(function(l){return/clock status/i.test(l);})){A('NTP SINCRONIZADO','NÃO','⚠','Clock não sincronizado.');}
  else{A('NTP SINCRONIZADO','N/A','N/A','Status do clock não detectado. Incluir "display clock" no log.');}

  // 44. NTP ACL
  var ntpAcl=has('ntp-service acl')||has('ntp access-group');
  if(ntpAcl){A('NTP PROTEGIDO POR ACL','SIM','N/A','NTP protegido por ACL.');}
  else{A('NTP PROTEGIDO POR ACL','NÃO','⚠','NTP sem ACL de proteção.');}

  // 45. NTP AUTH
  var ntpAuth=has('ntp authentication enable')||has('ntp-service authentication enable');
  if(ntpAuth){A('NTP AUTENTICAÇÃO','SIM','N/A','NTP autenticação habilitada.');}
  else{A('NTP AUTENTICAÇÃO','NÃO','⚠','NTP sem autenticação.');}

  // ================================================================
  S('SEGURANÇA DE REDE');
  // ================================================================

  // 46. NO IP PROXY-ARP
  var proxyArpDis=find('undo arp-proxy enable').length>0||find('undo local-proxy-arp enable').length>0;
  var proxyArpEn=find('arp-proxy enable').filter(function(l){return!l.includes('undo');}).length>0;
  if(!proxyArpEn){A('NO IP PROXY-ARP (SVIs)','SIM','N/A','Proxy-ARP não habilitado.');}
  else if(proxyArpDis){A('NO IP PROXY-ARP (SVIs)','PARCIAL','⚠','Proxy-ARP desabilitado em algumas interfaces mas habilitado em outras.');}
  else{A('NO IP PROXY-ARP (SVIs)','NÃO','⚠','arp-proxy enable detectado, desabilitar com "undo arp-proxy enable".');}

  // 47. IP SOURCE GUARD
  var ipSrcGuard=has('ip source check')&&has('ip source static binding');
  var ipSrcCheck=has('ip source check');
  if(ipSrcGuard){A('IP SOURCE GUARD','SIM','N/A','IP Source Guard configurado com binding estático.');}
  else if(ipSrcCheck){A('IP SOURCE GUARD','PARCIAL','⚠','ip source check habilitado mas sem bindings estáticos detectados.');}
  else{A('IP SOURCE GUARD','NÃO','⚠','IP Source Guard não configurado.');}

  // 48. DHCP SNOOPING
  var dhcpSnoop=has('dhcp snooping enable');
  var dhcpSnoopVlan=find('dhcp snooping vlan').filter(function(l){return/dhcp snooping vlan/i.test(l.trim());});
  if(dhcpSnoop&&dhcpSnoopVlan.length>0){A('DHCP SNOOPING','SIM','N/A','DHCP Snooping habilitado globalmente e em '+dhcpSnoopVlan.length+' VLAN(s).');}
  else if(dhcpSnoop){A('DHCP SNOOPING','PARCIAL','⚠','DHCP Snooping habilitado globalmente mas sem VLANs específicas configuradas.');}
  else{A('DHCP SNOOPING','NÃO','⚠','DHCP Snooping não configurado.');}

  // 49. DYNAMIC ARP INSPECTION
  var arpCheck=has('arp anti-attack check')&&has('arp anti-attack vlan');
  var arpAnti=has('arp anti-attack');
  if(arpCheck){A('DYNAMIC ARP INSPECTION (DAI)','SIM','N/A','ARP Anti-Attack (DAI) configurado.');}
  else if(arpAnti){A('DYNAMIC ARP INSPECTION (DAI)','PARCIAL','⚠','ARP Anti-Attack configurado parcialmente.');}
  else{A('DYNAMIC ARP INSPECTION (DAI)','NÃO','⚠','ARP Anti-Attack não configurado.');}

  // ================================================================
  S('VLANS');
  // ================================================================

  // 50. VLAN SEM MAC
  // Filtrar apenas entradas dinâmicas do display mac-address
  var macDynLines=L.filter(function(l){
    var lt=l.trim();
    return /dynamic/i.test(lt)&&/[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}/.test(lt);
  });
  var vlanBatch=[];
  find('vlan batch').forEach(function(l){var m=l.match(/vlan batch\s+([\d\s]+to[\d\s]+|[\d\s]+)/i);if(m)vlanBatch.push(l.trim());});
  var vlanIds=[];
  L.forEach(function(l){var m=l.trim().match(/^vlan\s+(\d+)$/);if(m&&m[1]!=='1')vlanIds.push(m[1]);});
  if(!vlanIds.length&&!macDynLines.length){A('VLAN SEM MAC_ADRRESS VINCULADO','N/A','N/A','Incluir "display mac-address" no log para análise.');}
  else if(!macDynLines.length){A('VLAN SEM MAC_ADRRESS VINCULADO','PARCIAL','⚠',vlanIds.length+' VLAN(s) detectadas, nenhum MAC dinâmico encontrado no log.');}
  else{
    // Extrair VLANs com MAC dinâmico aprendido
    var vlansComMac=[...new Set(macDynLines.map(function(l){
      var m=l.trim().match(/\s+(\d+)\s+/g);
      // pegar o último número isolado que parece VLAN (1-4094)
      if(!m)return'';
      var nums=m.map(function(s){return s.trim();}).filter(function(s){return/^\d+$/.test(s)&&+s>=1&&+s<=4094;});
      return nums.length?nums[nums.length-1]:'';
    }).filter(Boolean))];
    var vlansSemMac=vlanIds.filter(function(v){return!vlansComMac.includes(v);});
    if(vlansSemMac.length===0){A('VLAN SEM MAC_ADRRESS VINCULADO','SIM','N/A','Todas as VLANs com MAC dinâmico vinculado.');}
    else{A('VLAN SEM MAC_ADRRESS VINCULADO','PARCIAL','⚠',vlansSemMac.length+' VLAN(s) sem MAC dinâmico vinculado: '+vlansSemMac.join(', ')+'.');}
  }

  // 51. VLAN SEM NAME
  var vBlk={};var cVl=null;
  L.forEach(function(l){var m=l.trim().match(/^vlan\s+(\d+)$/);if(m){cVl=m[1];vBlk[cVl]=vBlk[cVl]||{hasName:false};}if(cVl&&l.trim().startsWith('name '))vBlk[cVl].hasName=true;});
  var tot=Object.keys(vBlk).length;
  var noN=Object.entries(vBlk).filter(function(e){return!e[1].hasName;}).map(function(e){return e[0];});
  if(tot===0){A('VLAN SEM NAME','N/A','N/A','VLANs não detectadas.');}
  else if(noN.length===0){A('VLAN SEM NAME','SIM','N/A','Todas as VLANs com nome configurado.');}
  else{A('VLAN SEM NAME','PARCIAL','✔',noN.length+' VLAN(s) sem nome: '+noN.join(', ')+'.');}

  // ================================================================
  S('STP');
  // ================================================================

  // 52. STP MODO
  var stpModeStr='';
  // 1) Config: stp mode mstp/vbst/rstp/stp
  var stpModeLine=L.find(function(l){return/^stp mode\s+(mstp|vbst|rstp|stp)\b/i.test(l.trim());});
  if(stpModeLine)stpModeStr=(stpModeLine.trim().match(/stp mode\s+(\S+)/i)||['',''])[1].toUpperCase();
  // 2) display stp output: Port STP Mode :MSTP / STP Mode :VBST
  if(!stpModeStr){
    var stpDisp=L.find(function(l){return/STP Mode\s*:\s*(MSTP|RSTP|VBST|STP)/i.test(l)||/Port STP Mode\s*:\s*(MSTP|RSTP|VBST|STP)/i.test(l);});
    if(stpDisp)stpModeStr=(stpDisp.match(/:\s*(MSTP|RSTP|VBST|STP)/i)||['',''])[1].toUpperCase();
  }
  // 3) display stp region-configuration
  if(!stpModeStr&&L.some(function(l){return/stp mode vbst/i.test(l);}))stpModeStr='VBST';
  if(stpModeStr==='MSTP'||stpModeStr==='VBST'){A('STP: MODO RAPID-PVST/MST','SIM','N/A','STP modo '+stpModeStr+' configurado.');}
  else if(stpModeStr==='RSTP'){A('STP: MODO RAPID-PVST/MST','PARCIAL','✘','STP modo RSTP, considerar MSTP/VBST para ambientes com múltiplas VLANs.');}
  else if(stpModeStr==='STP'){A('STP: MODO RAPID-PVST/MST','NÃO','✘','STP clássico configurado, migrar para MSTP ou VBST.');}
  else{A('STP: MODO RAPID-PVST/MST','N/A','N/A','STP modo não detectado. Incluir "display stp" no log.');}

  // 53. STP PRIORIDADE
  var stpPrio=find('stp vlan').filter(function(l){return/stp vlan[\s\d\-to]+priority\s+\d+/i.test(l.trim());});
  var stpPrioGlobal=find('stp priority').filter(function(l){return/^stp priority\s+\d+/i.test(l.trim());});
  // Detectar prioridade também via "display stp" — formato: "VLANID  RootID.MAC  ..."
  // RootID = prioridade + VLAN ID (ex: VLAN 21, RootID 8213 → prioridade 8192)
  var stpFromDisplay={};
  var inStpDisplay=false;
  L.forEach(function(l){
    var lt=l.trim();
    if(/VLANID\s+RootID/i.test(lt))inStpDisplay=true;
    if(inStpDisplay){
      // Linha de dados: "   1 32769.00e4-..." ou "  21 8213.0014-..."
      var m=lt.match(/^(\d+)\s+(\d+)\.[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}/i);
      if(m){
        var vlanId=parseInt(m[1]);
        var rootId=parseInt(m[2]);
        // Prioridade real = rootId - vlanId (múltiplo de 4096)
        var prio=rootId-vlanId;
        if(prio>0&&prio%4096===0)stpFromDisplay[vlanId]=prio;
      }
      if(/^-{10,}/.test(lt)||lt===''){}
      if(/^\s*$/.test(lt)&&inStpDisplay)inStpDisplay=false;
    }
  });
  var stpDisplayKeys=Object.keys(stpFromDisplay);
  if(stpPrio.length>0||stpPrioGlobal.length>0||stpDisplayKeys.length>0){
    var stpPDetail=stpPrio.map(function(l){var m=l.trim().match(/stp vlan\s+([\d\s\-to]+)\s+priority\s+(\d+)/i);return m?'Vlan'+m[1].trim().replace(/\s+to\s+/g,'-')+'→'+m[2]:l.trim();}).join(', ');
    var stpGDetail=stpPrioGlobal.map(function(l){var m=l.trim().match(/stp priority\s+(\d+)/i);return m?'Global→'+m[1]:'';}).join(', ');
    var stpDDetail='';
    if(stpDisplayKeys.length>0){
      // Agrupar VLANs com mesma prioridade
      var prioGrupos={};
      stpDisplayKeys.forEach(function(v){var p=stpFromDisplay[v];if(!prioGrupos[p])prioGrupos[p]=[];prioGrupos[p].push(v);});
      stpDDetail=Object.entries(prioGrupos).map(function(e){return 'Prioridade '+e[0]+' em '+e[1].length+' VLAN(s)';}).join(', ');
    }
    var stpAllDetail=[stpPDetail,stpGDetail,stpDDetail].filter(Boolean).join(', ');
    A('STP: PRIORIDADE CONFIGURADA','SIM','N/A','STP prioridade configurada: '+stpAllDetail+'.');
  } else {A('STP: PRIORIDADE CONFIGURADA','NÃO','✘','STP prioridade não configurada, usando o valor default (32768).');}

  // 54. STP BPDU GUARD
  var bpduGuardGlobal=has('stp bpdu-protection');
  var bpduGuardDisplay=L.some(function(l){return/BPDU-Protection\s*:\s*Enabled/i.test(l);});
  var bpduEdgeDefault=has('stp edged-port default');
  var bpduEdgeIf=find('stp edged-port enable').filter(function(l){return/^\s*stp edged-port enable/i.test(l);}).length;
  if(bpduGuardGlobal||bpduGuardDisplay){
    A('STP: BPDU GUARD','SIM','N/A','BPDU-Protection habilitado globalmente.');
  } else if(bpduEdgeDefault){
    A('STP: BPDU GUARD','SIM','N/A','stp edged-port default configurado (todas as portas edge com BPDU Guard).');
  } else if(bpduEdgeIf>0){
    A('STP: BPDU GUARD','PARCIAL','✘','stp edged-port enable em '+bpduEdgeIf+' interface(s). BPDU-Protection global não configurado.');
  } else{
    A('STP: BPDU GUARD','NÃO','✘','BPDU-Protection não configurado, portas edge sem proteção.');
  }

  // 55. STP BPDU FILTER — nao existe nativo no VRP
  var stpDisableIf=L.filter(function(l){return/^\s*stp disable$/i.test(l.trim());}).length;
  if(stpDisableIf>0){
    A('STP: BPDU FILTER','PARCIAL','⚠','BPDU Filter não suportado nativamente no VRP. stp disable em '+stpDisableIf+' interface(s) como alternativa.');
  } else {
    A('STP: BPDU FILTER','N/A','N/A','BPDU Filter não suportado nativamente no VRP Huawei.');
  }

  // 56. BRIDGE ASSURANCE
  var lgGlobalBA=L.some(function(l){return/^stp loop-protection$/i.test(l.trim());});
  var lgIfaceBA=L.filter(function(l){return/^\s*stp loop-protection$/i.test(l.trim());}).length;
  if(lgGlobalBA){A('STP: BRIDGE ASSURANCE','SIM','N/A','Não existe no VRP Huawei. Equivalente stp loop-protection configurado globalmente.');}
  else if(lgIfaceBA>0){A('STP: BRIDGE ASSURANCE','SIM','N/A','Não existe no VRP Huawei. Equivalente stp loop-protection configurado em '+lgIfaceBA+' interface(s).');}
  else{A('STP: BRIDGE ASSURANCE','NÃO','✘','Não existe no VRP Huawei. Equivalente stp loop-protection não configurado, sem proteção contra loops unidirecionais.');}

  // 57. STP LOOP GUARD
  var lgGlobal=L.some(function(l){return/^stp loop-protection$/i.test(l.trim());});
  var lgIface=L.filter(function(l){return/^\s*stp loop-protection$/i.test(l.trim());}).length;
  if(lgGlobal){
    A('STP: LOOP GUARD','SIM','N/A','stp loop-protection configurado globalmente.');
  } else if(lgIface>0){
    A('STP: LOOP GUARD','SIM','N/A','stp loop-protection configurado nas interfaces ('+lgIface+' interface(s)).');
  } else {
    A('STP: LOOP GUARD','NÃO','✘','stp loop-protection não configurado, sem proteção contra loops unidirecionais.');
  }

  // 58. STP ROOT GUARD
  var rgIf=[];
  var curIfRg=null;
  L.forEach(function(l){
    var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/i);if(ifm)curIfRg=ifm[1];
    if(curIfRg&&/^stp root-protection$/i.test(lt)&&!rgIf.includes(curIfRg))rgIf.push(curIfRg);
  });
  if(rgIf.length>0){
    A('STP: ROOT GUARD CONFIGURADO','SIM','N/A','stp root-protection em '+rgIf.length+' interface(s): '+abbrevList(rgIf).join(', ')+'.');
  } else {
    A('STP: ROOT GUARD CONFIGURADO','NÃO','✘','stp root-protection não configurado, qualquer switch pode assumir a raiz do STP.');
  }

  // 59. STORM CONTROL
  var stormBC=has('storm-control broadcast');
  var stormMC=has('storm-control multicast');
  var stormUC=has('storm-control unicast');
  var stormAct=has('storm-control action');
  var stormTypes=[];
  if(stormBC)stormTypes.push('broadcast');
  if(stormMC)stormTypes.push('multicast');
  if(stormUC)stormTypes.push('unicast');
  if(stormTypes.length>0){
    A('STORM CONTROL','SIM','N/A','Storm-control configurado: '+stormTypes.join(', ')+(stormAct?' com action definida':'')+'.');
  } else {
    A('STORM CONTROL','NÃO','✘','Storm-control não configurado, sem proteção contra broadcast/multicast storm.');
  }

  // 60. UDLD
  var dldp=has('dldp enable');
  if(dldp){A('UDLD HABILITADO','SIM','N/A','DLDP habilitado. Detecção de falha unidirecional ativa.');}
  else{A('UDLD HABILITADO','NÃO','⚠','DLDP não configurado, sem detecção de falha unidirecional.');}

  // ================================================================
  S('TRUNK / PORT-CHANNEL');
  // ================================================================

  // 61. VLAN 1 SEM USO
  var v1AccessExpl=[];var v1NativeExpl=[];var v1AllowedExpl=[];var v1AccessImpl=[];var curIfV1=null;
  var curIfV1IsAccess=false;var curIfV1HasVlan=false;
  L.forEach(function(l){
    var lt=l.trim();var ifm=lt.match(/^interface\s+(\S+)/i);
    if(ifm){
      // porta access sem vlan configurada → implicitamente VLAN 1
      if(curIfV1&&curIfV1IsAccess&&!curIfV1HasVlan&&!v1AccessImpl.includes(curIfV1))v1AccessImpl.push(curIfV1);
      curIfV1=ifm[1];curIfV1IsAccess=false;curIfV1HasVlan=false;
    }
    if(curIfV1&&/^port link-type access$/i.test(lt))curIfV1IsAccess=true;
    // access vlan 1 explícito: port default vlan 1
    if(curIfV1&&/^port default vlan\s+1$/i.test(lt)&&!v1AccessExpl.includes(curIfV1)){v1AccessExpl.push(curIfV1);curIfV1HasVlan=true;}
    // access com outra vlan (não é VLAN 1)
    if(curIfV1&&/^port default vlan\s+[2-9]\d*/i.test(lt))curIfV1HasVlan=true;
    // trunk native: port trunk pvid vlan 1
    if(curIfV1&&/^port trunk pvid vlan\s+1$/i.test(lt)&&!v1NativeExpl.includes(curIfV1))v1NativeExpl.push(curIfV1);
    // trunk allowed vlan 1
    if(curIfV1&&/^port trunk allow-pass vlan/i.test(lt)){var av=lt.replace(/port trunk allow-pass vlan/i,'').trim();if(/^1$|^1\s|,1,|,1$|\ball\b/i.test(av)&&!v1AllowedExpl.includes(curIfV1))v1AllowedExpl.push(curIfV1);}
  });
  // última interface
  if(curIfV1&&curIfV1IsAccess&&!curIfV1HasVlan&&!v1AccessImpl.includes(curIfV1))v1AccessImpl.push(curIfV1);
  // Verificar undo port trunk allow-pass vlan 1 (boa prática)
  var v1Undo=L.filter(function(l){return/undo port trunk allow-pass vlan\s+1\b/i.test(l.trim());}).length;
  var allV1Parts=[];
  if(v1AccessImpl.length>0)allV1Parts.push(v1AccessImpl.length+' porta(s) access sem vlan configurada (padrão VLAN 1): '+abbrevList(v1AccessImpl).join(', '));
  if(v1AccessExpl.length>0)allV1Parts.push(v1AccessExpl.length+' porta(s) com port default vlan 1: '+abbrevList(v1AccessExpl).join(', '));
  if(v1NativeExpl.length>0)allV1Parts.push(v1NativeExpl.length+' trunk(s) com pvid vlan 1: '+abbrevList(v1NativeExpl).join(', '));
  if(v1AllowedExpl.length>0)allV1Parts.push(v1AllowedExpl.length+' trunk(s) com allowed vlan 1: '+abbrevList(v1AllowedExpl).join(', '));
  var totalV1=v1AccessImpl.length+v1AccessExpl.length+v1NativeExpl.length+v1AllowedExpl.length;
  if(totalV1>0){A('VLAN 1 SEM USO EM PORTAS','NÃO','✘','Vlan 1 em uso: '+allV1Parts.join('. ')+'.');}
  else{A('VLAN 1 SEM USO EM PORTAS','SIM','N/A','Vlan 1 não está em uso em nenhuma porta'+(v1Undo>0?'. undo port trunk allow-pass vlan 1 em '+v1Undo+' trunk(s)':'')+'.');}

  // 62. TRUNK COM FILTRO DE VLANS
  var tIf={};var cTf=null;
  L.forEach(function(l){var lt=l.trim();if(/^interface\s+/i.test(lt)){cTf=lt;if(!tIf[cTf])tIf[cTf]={trunk:false,allowed:false,allowAll:false};}if(cTf&&/port link-type trunk/i.test(lt))tIf[cTf].trunk=true;if(cTf&&/port trunk allow-pass vlan/i.test(lt)){tIf[cTf].allowed=true;if(/allow-pass vlan\s+all\b/i.test(lt))tIf[cTf].allowAll=true;}});
  var trnks=Object.entries(tIf).filter(function(e){return e[1].trunk;});
  var tAllVlan=trnks.filter(function(e){return e[1].allowAll;});
  var tNoFilter=trnks.filter(function(e){return!e[1].allowed;});
  var tProblema=tAllVlan.concat(tNoFilter.filter(function(e){return tAllVlan.indexOf(e)<0;}));
  var tComFiltro=trnks.filter(function(e){return e[1].allowed&&!e[1].allowAll;});
  if(trnks.length===0){A('TRUNK COM FILTRO DE VLANS','N/A','N/A','Nenhuma interface trunk identificada.');}
  else if(tProblema.length===0){A('TRUNK COM FILTRO DE VLANS','SIM','N/A','Todas as '+trnks.length+' interface(s) trunk com filtro de VLANs configurado.');}
  else if(tComFiltro.length===0){
    var tpl=tProblema.map(function(e){return abbrevIf(e[0].replace(/^interface\s+/i,''));}).join(', ');
    A('TRUNK COM FILTRO DE VLANS','NÃO','✘',tProblema.length+' interface(s) sem filtro de VLANs: '+tpl+'.');
  } else {
    var tpl=tProblema.map(function(e){return abbrevIf(e[0].replace(/^interface\s+/i,''));}).join(', ');
    A('TRUNK COM FILTRO DE VLANS','PARCIAL','⚠',tComFiltro.length+' interface(s) com filtro, '+tProblema.length+' sem filtro: '+tpl+'.');
  }

  // 63. VTP MODE TRANSPARENTE — VRP usa GVRP/MVRP/VCMP
  var hasGvrp=has('gvrp enable')||L.some(function(l){return/^gvrp$/i.test(l.trim());});
  var hasMvrp=has('mvrp enable')||has('mvrp');
  var hasVcmp=has('vcmp role')&&!L.some(function(l){return/vcmp role silent/i.test(l);});
  var vtpProto=[];
  if(hasGvrp)vtpProto.push('GVRP');
  if(hasMvrp)vtpProto.push('MVRP');
  if(hasVcmp)vtpProto.push('VCMP');
  if(vtpProto.length>0){
    A('VTP MODE TRANSPARENTE','NÃO','⚠',vtpProto.join('/')+' habilitado, pode propagar VLANs automaticamente entre switches.');
  } else {
    A('VTP MODE TRANSPARENTE','SIM','N/A','GVRP inativo. Sem propagação automática de VLANs.');
  }

  // 64. ERRDISABLE RECOVERY
  var errRecov=has('error-down auto-recovery');
  var errDown=has('trigger error-down');
  if(errRecov){A('ERRDISABLE RECOVERY','SIM','N/A','error-down auto-recovery configurado.');}
  else if(errDown){A('ERRDISABLE RECOVERY','PARCIAL','✔','error-down configurado mas sem auto-recovery.');}
  else{A('ERRDISABLE RECOVERY','NÃO','✔','error-down auto-recovery não configurado, portas em erro permanecem desabilitadas até intervenção manual.');}

  // 65. PORT SECURITY
  var portSec=has('port-security enable');
  if(portSec){A('PORT SECURITY','SIM','N/A','Port Security habilitado.');}
  else{A('PORT SECURITY','NÃO','✔','Port Security não configurado, recomendado para portas de acesso de usuários (notebooks/estações).');}

  // 66. PORT-CHANNEL COM LACP/PAGP
  var totalPo=ethTrunks.length;
  if(totalPo===0){A('PORT-CHANNEL COM LACP/PAGP','N/A','N/A','Nenhum Eth-Trunk detectado.');}
  else{
    // Mapear mode de cada Eth-Trunk
    var poLacp=[];var poNoLacp=[];var curEth=null;
    L.forEach(function(l){
      var lt=l.trim();
      var em=lt.match(/^interface (Eth-Trunk\d+)/i);if(em)curEth=em[1];
      if(curEth){
        if(/mode lacp-static|mode lacp-dynamic|mode lacp/i.test(lt)){if(!poLacp.includes(curEth))poLacp.push(curEth);}
      }
    });
    poNoLacp=ethTrunks.filter(function(e){return!poLacp.includes(e);});
    if(poNoLacp.length===0){
      A('PORT-CHANNEL COM LACP/PAGP','SIM','N/A',totalPo+' Eth-Trunk(s) com LACP configurado. Nenhum Eth-Trunk sem protocolo.');
    } else {
      A('PORT-CHANNEL COM LACP/PAGP','PARCIAL','⚠',
        poNoLacp.length+' Eth-Trunk(s) sem LACP: '+poNoLacp.join(', ')+'.');
    }
  }

  // 67-70. PORT-CHANNEL status
  var poDown=findRe(/Eth-Trunk.*\(.*down\)|Eth-Trunk.*DOWN/i);
  var poDownNames=[...new Set(poDown.map(function(l){return(l.match(/Eth-Trunk\d+/)||[''])[0];}).filter(Boolean))];
  A('PORT-CHANNELS COM MEMBROS DOWN',poDownNames.length>0?'SIM':'NÃO',poDownNames.length>0?'✘':'N/A',poDownNames.length>0?poDownNames.length+' Eth-Trunk(s) com membro(s) down.':'Nenhum Eth-Trunk com membro down detectado.');
  A('PORT-CHANNEL DOWN',poDownNames.length>0?'SIM':'NÃO',poDownNames.length>0?'✘':'N/A',poDownNames.length>0?'Eth-Trunk(s) down: '+poDownNames.join(', ')+'.':'Todos os Eth-Trunk operacionais.');
  // PORT-CHANNEL MEMBROS — usar display eth-trunk
  var hasEthTrunkDisplay=L.some(function(l){return/Eth-Trunk\d+'s state information/i.test(l);});
  if(!hasEthTrunkDisplay){
    A('PORT-CHANNEL MEMBROS INCONSISTENTES','N/A','N/A','Incluir "display eth-trunk" no log.');
    A('PORT-CHANNEL SEM MEMBROS','N/A','N/A','Incluir "display eth-trunk" no log.');
  } else {
    // Parsear estado real de cada trunk via "Operate status:" e membros Unselect
    var trunkStatus={};var unselMap={};var upPortsMap={};var curTrunk=null;
    L.forEach(function(l){
      var lt=l.trim();
      var tm=lt.match(/^(Eth-Trunk\d+)'s state information/i);
      if(tm){curTrunk=tm[1];if(!trunkStatus[curTrunk])trunkStatus[curTrunk]='unknown';}
      if(curTrunk){
        // Detectar estado real do trunk
        var os=lt.match(/^Operate\s+status\s*:\s*(\S+)/i);
        if(os)trunkStatus[curTrunk]=os[1].toLowerCase();
        // Detectar número de portas UP
        var nu=lt.match(/Number\s+Of\s+Up\s+Ports\s+In\s+Trunk\s*:\s*(\d+)/i);
        if(nu)upPortsMap[curTrunk]=parseInt(nu[1]);
        // Detectar membros Unselect — formato tabela ActorPortName (espaços múltiplos)
        var pm=lt.match(/^((?:40GE|100GE|10GE|GE)[\d\/\.]+)\s+Unselect/i);
        if(pm){if(!unselMap[curTrunk])unselMap[curTrunk]=[];unselMap[curTrunk].push(pm[1]);}
      }
    });
    // Apenas trunks com Operate status: up
    var upTrunks=Object.keys(trunkStatus).filter(function(t){return trunkStatus[t]==='up';});
    var inconsistentes=upTrunks.filter(function(t){return unselMap[t]&&unselMap[t].length>0;});
    if(inconsistentes.length===0){
      A('PORT-CHANNEL MEMBROS INCONSISTENTES','NÃO','N/A','Não foi encontrado nenhum membro com status Unselect em trunks UP.');
    } else {
      var detail=inconsistentes.map(function(t){return t+': '+unselMap[t].join(', ');}).join('; ');
      A('PORT-CHANNEL MEMBROS INCONSISTENTES','SIM','⚠','Membros Unselect em trunks UP: '+detail+'.');
    }
    // PORT-CHANNEL SEM MEMBROS — apenas trunks UP sem nenhuma porta ativa
    var semMembros=upTrunks.filter(function(t){return upPortsMap[t]===0;});
    if(semMembros.length===0){
      A('PORT-CHANNEL SEM MEMBROS','NÃO','N/A','Todos os Eth-Trunk UP com membros ativos.');
    } else {
      A('PORT-CHANNEL SEM MEMBROS','SIM','✘','Eth-Trunk(s) UP sem membros ativos: '+semMembros.join(', ')+'.');
    }
  }

  // ================================================================
  S('INFRAESTRUTURA');
  // ================================================================

  // 71. FONTE REDUNDANTE
  // Agrupar fontes por switch (slot), exibir como Switch 1, Switch 2, etc.
  var psuBySlot={};
  L.forEach(function(l){
    // Formato sem slot: "PWR1  YES  AC  Supply" → slot 'main'
    var m1=l.match(/^(PWR\d+)\s+YES\s+(AC|DC)\s+Supply/i);
    if(m1){
      if(!psuBySlot['main'])psuBySlot['main']=[];
      if(!psuBySlot['main'].includes(m1[1]))psuBySlot['main'].push(m1[1]);
    }
    // Formato com slot: "1  PWR1  YES  AC  Supply" → slot '1'
    var m2=l.match(/^\s*(\d+)\s+(PWR\d+)\s+YES\s+(AC|DC)\s+Supply/i);
    if(m2){
      var sl=m2[1];
      if(!psuBySlot[sl])psuBySlot[sl]=[];
      if(!psuBySlot[sl].includes(m2[2]))psuBySlot[sl].push(m2[2]);
    }
  });
  var slotKeys=Object.keys(psuBySlot).sort(function(a,b){
    if(a==='main')return-1;if(b==='main')return 1;return+a-+b;
  });
  var swSummary=[];var hasRedundancy=false;var hasAny=slotKeys.length>0;var allRedundant=true;var anyRedundant=false;
  slotKeys.forEach(function(sl,idx){
    var swNum=idx+1;var fontes=psuBySlot[sl].length;
    if(fontes>=2){swSummary.push('Switch '+swNum+': '+fontes+' fontes, redundância confirmada');anyRedundant=true;}
    else if(fontes===1){swSummary.push('Switch '+swNum+': 1 fonte detectada, sem redundância');allRedundant=false;}
    else{swSummary.push('Switch '+swNum+': fonte integrada');allRedundant=false;}
  });
  if(!hasAny){A('FONTE REDUNDANTE','NÃO','✘','Fonte integrada, sem redundância.');}
  else if(allRedundant&&anyRedundant){A('FONTE REDUNDANTE','SIM','N/A',swSummary.join('. ')+'.');}
  else if(anyRedundant){A('FONTE REDUNDANTE','PARCIAL','⚠',swSummary.join('. ')+'.');}
  else{A('FONTE REDUNDANTE','NÃO','✘',swSummary.join('. ')+'.');}

  // 72. PORTAS NO STATUS NOTCONNECT
  var notconnPorts=[];
  L.forEach(function(l){
    var lt=l.trim();
    var m=lt.match(/^((?:GE|XGE|10GE|40GE|100GE|Eth-Trunk)[\d\/\.\:]+)/i);
    if(m&&/current state\s*:\s*DOWN/i.test(lt)){var port=abbrevIf(m[1]);if(!notconnPorts.includes(port))notconnPorts.push(port);}
  });
  if(notconnPorts.length===0){A('PORTAS NO STATUS NOTCONNECT','N/A','N/A','Nenhuma porta down detectada. Incluir "display interface brief" no log.');}
  else{A('PORTAS NO STATUS NOTCONNECT','SIM','✔',notconnPorts.length+' porta(s) down sem shutdown aplicado.');}

  // 73. VIRTUALIZACAO (CSS/STACK)
  var stackMacSeen={};
  L.forEach(function(l){var m=l.match(/\(Master\)\s+(\d+)|CE[\w\-]+\(Master\)\s+(\d+)/i);if(m)stackMacSeen['master'+(m[1]||m[2])]='Master';var s=l.match(/\(Standby\)\s+(\d+)|CE[\w\-]+\(Standby\)\s+(\d+)/i);if(s)stackMacSeen['standby'+(s[1]||s[2])]='Standby';});
  var stackCount=Object.keys(stackMacSeen).length;
  var isChassis=L.some(function(l){return/Chassis ID.*Master Switch/i.test(l);});
  if(isChassis){A('VIRTUALIZACAO (VPC/VSS/STACK)','SIM','N/A','Chassis multi-slot detectado (CE12800). Dois switches em stack.');}
  else if(stackCount>=2){A('VIRTUALIZACAO (VPC/VSS/STACK)','SIM','N/A','CSS/Stack configurado: '+stackCount+' switch'+(stackCount===2?'es':'es')+' em stack detectados.');}
  else if(stackCount===1){A('VIRTUALIZACAO (VPC/VSS/STACK)','PARCIAL','⚠','Apenas 1 membro de stack detectado, verificar status do switch.');}
  else{A('VIRTUALIZACAO (VPC/VSS/STACK)','NÃO','⚠','CSS, VPC, StackWise não detectado, avaliar necessidade de redundância.');}

  // 74. DUPLA ABORDAGEM COM CORE
  // Filtrar Eth-Trunks com membros ativos (Selected) ou IP/descrição de uplink, excluindo sub-interfaces e gerência
  var uplinkTrunks=ethTrunks.filter(function(et){
    var hasMembers=false;var hasIp=false;var hasUplinkDesc=false;var inBlock=false;
    L.forEach(function(l){
      var lt=l.trim();
      if(new RegExp('^interface '+et+'$','i').test(lt))inBlock=true;
      if(inBlock&&/^interface\s+/i.test(lt)&&!new RegExp('^interface '+et+'$','i').test(lt))inBlock=false;
      if(inBlock&&/ip address\s+\d/i.test(lt))hasIp=true;
      if(inBlock&&/description.*(?:uplink|core|aggr|spine|wan|backbone|dist)/i.test(lt))hasUplinkDesc=true;
    });
    // verificar membros Selected no display eth-trunk
    L.forEach(function(l){
      var lt=l.trim();
      if(new RegExp(et+"'s state information",'i').test(lt))hasMembers=false;
      if(new RegExp(et+"'s state",'i').test(lt)){
        var found=false;
        L.forEach(function(l2){if(!found&&/Selected/i.test(l2))found=true;});
        if(found)hasMembers=true;
      }
    });
    // incluir se tem IP, descrição de uplink, ou é um dos primeiros Eth-Trunks numericamente
    return hasIp||hasUplinkDesc||hasMembers;
  });
  // fallback: se filtro resultou em 0, usar todos (dados insuficientes)
  var uplinks=uplinkTrunks.length>0?uplinkTrunks:ethTrunks;
  // Excluir Eth-Trunks DOWN
  uplinks=uplinks.filter(function(et){return!poDownNames.includes(et);});
  if(uplinks.length>=2){A('DUPLA ABORDAGEM COM CORE','SIM','N/A',uplinks.length+' Eth-Trunk(s) com uplink detectados. Dupla abordagem confirmada.');}
  else if(uplinks.length===1){A('DUPLA ABORDAGEM COM CORE','PARCIAL','⚠','Apenas 1 Eth-Trunk de uplink detectado, dupla abordagem não confirmada.');}
  else{A('DUPLA ABORDAGEM COM CORE','NÃO','✘','Nenhum Eth-Trunk de uplink detectado, sem redundância de uplink.');}

  // 75. SPEED/DUPLEX
  var autoNegEnabled=L.filter(function(l){return/Auto-negotiation enabled\s*:\s*Yes/i.test(l);});
  var autoNegDisabled=L.filter(function(l){return/Auto-negotiation enabled\s*:\s*No/i.test(l);});
  if(autoNegEnabled.length>0){A('SPEED/DUPLEX UPLINKS','PARCIAL','⚠',autoNegEnabled.length+' interface(s) com auto-negociação habilitada.');}
  else if(autoNegDisabled.length>0){A('SPEED/DUPLEX UPLINKS','SIM','N/A','Interfaces com velocidade/duplex fixos detectados.');}
  else{A('SPEED/DUPLEX UPLINKS','N/A','N/A','Status de speed/duplex não detectado. Incluir "display interface" no log.');}

  // 76. EQUIPAMENTO EM SUPORTE
  var vrpV=vrpVersion||'';
  var isEol=L.some(function(l){return/V200R002|V200R003|V200R005/i.test(l);});
  if(isEol){A('EQUIPAMENTO EM SUPORTE (NÃO EOL)','Validar no portal da Huawei','⚠','Validar no portal da Huawei.');}
  else if(vrpV){A('EQUIPAMENTO EM SUPORTE (NÃO EOL)','Validar no portal da Huawei','N/A','Validar no portal da Huawei.');}
  else{A('EQUIPAMENTO EM SUPORTE (NÃO EOL)','Validar no portal da Huawei','N/A','Validar no portal da Huawei.');}

  // 77. BASELINE CPU E MEMÓRIA
  A('BASELINE CPU E MEMÓRIA','ANALISAR NO DX NETOPS','ANALISAR NO DX NETOPS','Inserir resultado após análise.');

  // 78. BASELINE UPLINKS
  A('BASELINE UPLINKS','ANALISAR NO DX NETOPS','ANALISAR NO DX NETOPS','Inserir resultado após análise.');

  return res;
}



// ── Dispatch: pick correct analysis function by vendor ────────────────────────
function runRiskAnalysis(log, vendor) {
  switch (vendor) {
    case 'cisco_ios':    return runAnalysis_ios(log);
    case 'cisco_nxos':  return runAnalysis_nxos(log);
    case 'dell_os10':   return runAnalysis_os10(log);
    case 'hpe_comware': return runAnalysis_comware(log);
    case 'huawei_vrp':  return runAnalysis_huawei(log);
    default:            return runAnalysis_ios(log); // fallback
  }
}

// ── Export ────────────────────────────────────────────────────────────────────
if (typeof module !== 'undefined') {
  module.exports = { runRiskAnalysis };
}

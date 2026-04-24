// Magneto — Risk Assessment Excel Generator
// Uses xlsx-js-style (drop-in for SheetJS with cell styling)
// Already in package.json — just run: npm install
import { createRequire } from 'module';
const _req = createRequire(import.meta.url);
const XLSX: any = _req('xlsx-js-style');

export interface RiskItem { status: string; item: string; risco?: string; obs?: string; }
export interface DeviceAssessment {
  hostname: string; ip: string; vendor: string; model: string;
  osVersion: string; serial?: string; items: RiskItem[]; [key: string]: any;
}

// ── Exact colours from reference xlsx files ───────────────────────────────────
const C = {
  PH:'461E5F', BI:'1F4E79', RED:'FF0000', AMB:'FFC000',
  GRN:'70AD47', GRY:'D9D9D9', WHT:'FFFFFF', BLK:'000000',
  GT:'555555', AP:'6B0AC9', AT:'2E0060', D1:'D9D9D9', D2:'BFBFBF',
  OOB:'2E4057', IB:'1B4332',
};

// ── Style factories ───────────────────────────────────────────────────────────
const fill  = (rgb: string) => ({ patternType:'solid', fgColor:{ rgb } });
const font  = (rgb: string, bold=false, sz=10) => ({ name:'Calibri', color:{rgb}, bold, sz });
const alnh  = (horizontal='left') => ({ horizontal, vertical:'center', wrapText:false });
const alnhw = (horizontal='left') => ({ horizontal, vertical:'center', wrapText:true });
const border = { top:{style:'thin'}, left:{style:'thin'}, bottom:{style:'thin'}, right:{style:'thin'} };
const NC = 'Não configurado';

// Cell factory
function cell(v: any, style: any = {}): any {
  const t = (v === null || v === undefined) ? 's' :
            typeof v === 'number' ? 'n' : 's';
  const val = (v === null || v === undefined || v === '') ? NC : v;
  return { v: val, t, s: style };
}

// ── Worksheet helpers ─────────────────────────────────────────────────────────
function setCell(ws: any, ref: string, v: any, style: any) {
  ws[ref] = cell(v, style);
}

function mergeRange(ws: any, r1: number, c1: number, r2: number, c2: number) {
  if (!ws['!merges']) ws['!merges'] = [];
  ws['!merges'].push({ s:{ r:r1, c:c1 }, e:{ r:r2, c:c2 } });
}

function col(n: number): string {
  // Convert 0-based column index to letter(s)
  let r = '';
  n++;
  while (n > 0) { r = String.fromCharCode(65 + (n-1)%26) + r; n = Math.floor((n-1)/26); }
  return r;
}

function ref(r: number, c: number): string { return col(c) + (r+1); }

function updateRef(ws: any) {
  const cells = Object.keys(ws).filter(k => !k.startsWith('!'));
  if (!cells.length) { ws['!ref'] = 'A1'; return; }
  let minR=9999,minC=9999,maxR=0,maxC=0;
  for (const k of cells) {
    const m = k.match(/^([A-Z]+)(\d+)$/);
    if (!m) continue;
    const c = m[1].split('').reduce((acc,ch)=>acc*26+ch.charCodeAt(0)-64,0)-1;
    const r = parseInt(m[2])-1;
    minR=Math.min(minR,r); minC=Math.min(minC,c);
    maxR=Math.max(maxR,r); maxC=Math.max(maxC,c);
  }
  ws['!ref'] = ref(minR,minC)+':'+ref(maxR,maxC);
}

// ─────────────────────────────────────────────────────────────────────────────
// MATRIZ DE RISCOS
// ─────────────────────────────────────────────────────────────────────────────
function riscoStyle(r='') {
  if (r.includes('\u2715')||/ALTO/i.test(r))      return {val:'\u2715  ALTO', rgb:C.RED, fc:C.WHT};
  if (r.includes('\u26a0')||/M\u00c9DIA|MEDIO/i.test(r)) return {val:'\u26a0  M\u00c9DIA',rgb:C.AMB,fc:C.BLK};
  if (r.includes('\u2714')||/BAIXA|BAIXO/i.test(r)) return {val:'\u2714  BAIXA',rgb:C.GRN,fc:C.WHT};
  return {val:'N/A', rgb:C.GRY, fc:C.BLK};
}

async function buildMatriz(devices: DeviceAssessment[]): Promise<Buffer> {
  const wb = XLSX.utils.book_new();

  for (let idx=0; idx<devices.length; idx++) {
    const dev = devices[idx];
    const hn  = dev.hostname || `Device_${idx+1}`;
    let name  = hn.slice(0,31);
    let dup=0;
    while (wb.SheetNames.includes(name)) name = hn.slice(0,28)+`_${++dup}`;

    const ws: any = {};

    // Col widths [A=14.43, B=41.71, C=21.86, D=14.43, E=55.86]
    ws['!cols'] = [{wch:14.43},{wch:41.71},{wch:21.86},{wch:14.43},{wch:55.86}];

    // ── Legenda (rows 3-7, Excel row index 2-6) ────────────────────────────
    const legS = { fill:fill(C.PH), font:font(C.WHT,false,11), alignment:alnh('center') };
    setCell(ws, 'B3', 'LEGENDA', legS);
    mergeRange(ws, 2, 1, 2, 4); // B3:E3

    const legendItems: [number,string,string,string][] = [
      [4,'\u2715  ALTO', C.RED, C.WHT],
      [5,'\u26a0  M\u00c9DIA',C.AMB, C.BLK],
      [6,'\u2714  BAIXA',C.GRN, C.WHT],
      [7,'N/A',          C.GRY, C.GT],
    ];
    for (const [row,val,fg,fc] of legendItems) {
      const r = row-1; // 0-based
      setCell(ws, ref(r,1), val, { fill:fill(fg), font:font(fc,false,11), alignment:alnh('center') });
      mergeRange(ws, r, 1, r, 4);
    }

    // ── Device name (row 9) ────────────────────────────────────────────────
    const phS = { fill:fill(C.PH), font:font(C.WHT,false,11), alignment:alnh('center') };
    setCell(ws, 'B9', hn, phS); mergeRange(ws, 8, 1, 8, 4);
    setCell(ws, 'B10', 'HARDENING: Requisitos de Seguran\u00e7a', phS);
    mergeRange(ws, 9, 1, 9, 4);

    // ── Items ──────────────────────────────────────────────────────────────
    let curR = 10; // 0-based → row 11
    let inH = true;

    for (const item of (dev.items || [])) {
      if (item.status === 'SECTION') {
        const nm = item.item || '';
        if (/INFRAESTRUTURA|ROTEAMENTO|REDUND|SERVI|SWITCH|PORT.CHAN|F\u00cdSICA/i.test(nm)) inH=false;
        const color = inH ? C.PH : C.BI;
        const sS = { fill:fill(color), font:font(C.WHT,false,11), alignment:alnh() };
        const isTop = /HARDENING|INFRAESTRUTURA/i.test(nm);
        if (isTop) {
          setCell(ws, ref(curR,1), nm, {...sS, alignment:alnh('center')});
          mergeRange(ws, curR, 1, curR, 4);
        } else {
          setCell(ws, ref(curR,1), nm,                   sS);
          setCell(ws, ref(curR,2), 'STATUS',             sS);
          setCell(ws, ref(curR,3), 'RISCO',              sS);
          setCell(ws, ref(curR,4), 'OBSERVA\u00c7\u00c3O', sS);
        }
        curR++; continue;
      }
      const rs = riscoStyle(item.risco||'');
      setCell(ws, ref(curR,1), item.item,   { font:font(C.BLK,false,10), alignment:alnh('left'), border });
      setCell(ws, ref(curR,2), item.status, { font:font(C.BLK,true,10),  alignment:alnh('center'), border });
      setCell(ws, ref(curR,3), rs.val, { fill:fill(rs.rgb), font:font(rs.fc,true,10), alignment:alnh('center'), border });
      setCell(ws, ref(curR,4), item.obs||'', { font:font(C.BLK,false,10), alignment:alnhw('left'), border });
      curR++;
    }

    updateRef(ws);
    XLSX.utils.book_append_sheet(wb, ws, name);
  }

  return Buffer.from(XLSX.write(wb, { type:'buffer', bookType:'xlsx' }));
}

// ─────────────────────────────────────────────────────────────────────────────
// ASSESSMENT NETWORK (26 sheets)
// ─────────────────────────────────────────────────────────────────────────────
async function buildAssessment(devices: DeviceAssessment[], label: string): Promise<Buffer> {
  const wb = XLSX.utils.book_new();

  const VL: any = {cisco_ios:'Cisco',cisco_nxos:'Cisco',dell_os10:'Dell',hpe_comware:'HP',huawei_vrp:'Huawei'};
  const OT: any = {cisco_ios:'IOS',cisco_nxos:'NX-OS',dell_os10:'OS10',hpe_comware:'HP Comware',huawei_vrp:'Huawei VRP'};
  const nv = (d:any,k:string) => { const x=d?.[k]; return(x==null||x==='')?NC:String(x); };
  const vl = (d:any,k:string):any[] => Array.isArray(d?.[k])?d[k]:[];

  const HF = { font:font(C.WHT,true,10), fill:fill(C.AP), alignment:alnh('center'), border };
  const TF = { font:{name:'Calibri',bold:true,size:16,color:{rgb:C.AT}}, alignment:alnh('center') };
  const SF = { font:font(C.WHT,true,10), fill:fill(C.AP), alignment:alnh('center') };
  const DF = (ri:number) => ({ font:font(C.BLK,false,9), fill:fill(ri%2===0?C.D1:C.D2), alignment:{vertical:'center'}, border });

  function mkWs(name:string, title:string, sub:string, hs:string[], widths:number[]): any {
    const ws:any = {};
    ws['!cols'] = [{wch:2}, ...widths.map(w=>({wch:w}))];
    // Row 1: title
    setCell(ws, ref(0,1), title, TF);
    mergeRange(ws, 0, 1, 0, hs.length);
    // Row 2: subtitle/label
    setCell(ws, ref(1,1), sub, SF);
    mergeRange(ws, 1, 1, 1, hs.length);
    // Row 3: col headers
    hs.forEach((h,i) => setCell(ws, ref(2,i+1), h, HF));
    return ws;
  }

  function addDataRows(ws:any, startR:number, rows:any[][]): number {
    rows.forEach((row,ri) => {
      row.forEach((val,ci) => {
        setCell(ws, ref(startR+ri, ci+1), val, DF(ri));
      });
    });
    return startR + rows.length;
  }

  function hostBlock(ws:any, row:number, hn:string, nc:number) {
    setCell(ws, ref(row,1), hn, SF);
    mergeRange(ws, row, 1, row, nc);
  }

  function addColHdrs(ws:any, row:number, hs:string[]) {
    hs.forEach((h,i) => setCell(ws, ref(row,i+1), h, HF));
  }

  function sht(name:string, title:string, hs:string[], rows:any[][], ws:number[]) {
    const w = mkWs(name, title, label, hs, ws);
    if (rows.length) addDataRows(w, 3, rows);
    updateRef(w); XLSX.utils.book_append_sheet(wb, w, name);
  }

  function shtH(name:string, title:string, hs:string[], blocks:{hostname:string;rows:any[][]}[], ws:number[]) {
    const w = mkWs(name, title, label, hs, ws);
    const nc = hs.length;
    let row = 3;
    for (const {hostname,rows} of blocks) {
      hostBlock(w, row, hostname, nc); row++;
      addColHdrs(w, row, hs);          row++;
      const data = rows.length ? rows : [Array(nc).fill(NC)];
      row = addDataRows(w, row, data) + 1;
    }
    updateRef(w); XLSX.utils.book_append_sheet(wb, w, name);
  }

  sht('Inventário','Inventário',['Hostname','Tipo','Fabricante','Part Number','Serial Number'],
    devices.map(d=>[nv(d,'hostname'),'Switch',VL[d.vendor]||'Cisco',nv(d,'model'),nv(d,'serial')]),[22,14,14,22,22]);
  sht('EOL','End of Life',['Hostname','Part Number','EOL','Observação / Link'],
    devices.map(d=>[nv(d,'hostname'),nv(d,'model'),NC,'https://www.cisco.com/c/en/us/products/switches/']),[22,22,14,60]);
  sht('Versões de Softwares','Versões de Software',['Hostname','Fabricante','Modelo','Tipo Imagem','Versão'],
    devices.map(d=>[nv(d,'hostname'),VL[d.vendor]||'Cisco',nv(d,'model'),OT[d.vendor]||'IOS',nv(d,'osVersion')]),[22,14,22,14,20]);
  sht('Software Recomendados','Versões de Software Recomendadas',['Hostname','Fabricante','Modelo','Tipo Imagem','Versão atual','Versão recomendada'],
    devices.map(d=>[nv(d,'hostname'),VL[d.vendor]||'Cisco',nv(d,'model'),OT[d.vendor]||'IOS',nv(d,'osVersion'),NC]),[22,14,22,14,20,22]);

  // IP DE GERÊNCIA
  {
    const w = mkWs('IP DE GERÊNCIA','IP de Gerência',label,['Hostname','IP','Mask','Gateway','Interface'],[22,18,16,18,18]);
    const nc=5; let row=3;
    const oobS = (rgb:string) => ({ font:font(C.WHT,true,11), fill:fill(rgb), alignment:alnh('center'), border });
    setCell(w, ref(row,1),'OUT-OF-BAND (mgmt0)',oobS(C.OOB)); mergeRange(w,row,1,row,nc); row++;
    addColHdrs(w,row,['Hostname','IP','Mask','Gateway','Interface']); row++;
    row=addDataRows(w,row,devices.map(d=>[nv(d,'hostname'),nv(d,'ip'),NC,NC,nv(d,'mgmtIntf')]))+1;
    setCell(w,ref(row,1),'IN-BAND (Vlan / Interface)',oobS(C.IB)); mergeRange(w,row,1,row,nc); row++;
    addColHdrs(w,row,['Hostname','IP','Mask','Gateway','Interface']); row++;
    addDataRows(w,row,devices.map(d=>[nv(d,'hostname'),nv(d,'ip'),NC,NC,NC]));
    updateRef(w); XLSX.utils.book_append_sheet(wb,w,'IP DE GERÊNCIA');
  }

  shtH('CDP','CDP - Cisco Discovery Protocol',['Device ID','IP','Local Intf','Hold-time','Capability','Platform','Port ID'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'cdp').map((c:any)=>[c.devId||NC,c.ip||NC,c.localIf||NC,c.hold||NC,c.cap||NC,c.plat||NC,c.remIf||NC])})),[40,16,16,10,20,22,16]);
  shtH('LLDP','LLDP - Link Layer Discovery Protocol',['Device ID','Local Intf','Hold-time','Capability','Port ID'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'lldp').map((l:any)=>[l.devId||NC,l.localIf||NC,l.hold||NC,l.cap||NC,l.remIf||NC])})),[40,16,10,16,16]);
  shtH('VLANS','VLANs',['VLAN ID','Name','Status'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'vlans').map((v:any)=>[v.id||NC,v.name||NC,v.status||NC])})),[10,30,12]);
  shtH('VTP','VLAN Trunking Protocol (VTP)',['VTP Versão','VTP Domain Name','VTP Mode','Nº VLANs','Config Revision','Password'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:[[nv(d,'vtpVer'),nv(d,'vtpDomain'),nv(d,'vtpMode'),nv(d,'vtpVlans'),nv(d,'vtpRev'),nv(d,'vtpPwd')]]})),[10,22,14,10,14,22]);
  shtH('STP','Spanning Tree Protocol',['VLAN','Root Bridge ID','Cost','Root Port'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'stp').map((s:any)=>[s.vlan||NC,`${s.rootPri||''} ${s.rootMac||''}`.trim()||NC,s.cost||NC,s.rootPort||NC])})),[14,28,10,14]);
  shtH('INT_VLAN','Interfaces VLAN (SVIs)',['Vlan ID','Description','IP','Mask','IP Helper'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'intVlan').map((v:any)=>[v.vid||NC,v.desc||NC,v.ip||NC,v.mask||NC,(v.helper||[]).join(', ')||NC])})),[12,34,16,16,24]);
  shtH('HSRP','HSRP - Hot Standby Router Protocol',['Platform','Interface','Grp','Pri','P','State','Active','Standby','Virtual IP'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'hsrp').map((h:any)=>[h.platform||NC,h.intf||NC,h.grp||NC,h.pri||NC,h.p||NC,h.state||NC,h.active||NC,h.standby||NC,h.vip||NC])})),[10,14,8,8,6,10,16,16,16]);
  shtH('VRRP','VRRP - Virtual Router Redundancy Protocol',['VRID','Interface','State','Type','Virtual IP'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'vrrp').map((v:any)=>[v.vrid||NC,v.intf||NC,v.state||NC,v.type||NC,v.vip||NC])})),[10,16,12,12,16]);
  shtH('GLBP','GLBP - Gateway Load Balancing Protocol',['Interface','Grp','Pri','State','Virtual IP','Active Router','Standby Router'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'glbp').map((g:any)=>[g.intf||NC,g.grp||NC,g.pri||NC,g.state||NC,g.vip||NC,g.active||NC,g.standby||NC])})),[14,8,8,10,16,16,16]);
  shtH('INT_STATUS','Status das Interfaces',['Port','Description','Status','Vlan','Duplex','Speed','Type'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'intSt').map((r:any)=>[r.port||NC,r.desc||NC,r.status||NC,r.vlan||NC,r.duplex||NC,r.speed||NC,r.type||NC])})),[12,35,12,10,8,8,20]);
  shtH('PORT-CHANNEL','Port-Channel / EtherChannel',['Port-Channel Local','Portas Local','Vizinho','Port-Channel Remoto','Portas Remotas','Status','Protocol'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'portch').map((p:any)=>[p.po||NC,p.members||NC,p.vizinho||NC,p.poRemoto||NC,p.portasRemotas||NC,p.status||NC,p.proto||NC])})),[18,40,36,20,20,10,10]);
  shtH('TRUNK','Interfaces Trunk',['PORT','MODE','ENCAPSULATION','STATUS','VLANS ALLOWED','NATIVE VLAN'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'trunk').map((t:any)=>[t.port||NC,t.mode||NC,t.encap||NC,t.status||NC,t.vlans||NC,t.native||NC])})),[14,10,14,14,50,12]);
  shtH('STATIC ROUTE','Rotas Estáticas',['Rede / Prefixo','Via (Next-Hop)','Interface','Nome'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'staticRt').map((r:any)=>[r.net||NC,r.via||NC,r.intf||NC,r.name||NC])})),[22,18,18,24]);

  // OSPF custom block
  {
    const nc=6;
    const w=mkWs('OSPF','OSPF',label,['Process ID','Router ID','Ref BW','Áreas','Interfaces Ativas','Redistribute'],[14,16,14,16,40,30]);
    let row=3;
    for(const d of devices){
      hostBlock(w,row,nv(d,'hostname'),nc); row++;
      addColHdrs(w,row,['Process ID','Router ID','Ref BW','Áreas','Interfaces Ativas','Redistribute']); row++;
      const procs=vl(d,'ospfProcs');
      const data=procs.length?procs.map((p:any)=>[p.pid||NC,p.rid||NC,p.refBw||NC,(p.areas||[]).join(',')||NC,(p.activeIfs||[]).join(',')||NC,(p.redistribute||[]).join(',')||NC]):[Array(nc).fill(NC)];
      row=addDataRows(w,row,data)+1;
    }
    updateRef(w); XLSX.utils.book_append_sheet(wb,w,'OSPF');
  }

  shtH('VIZINHANÇA OSPF','Vizinhança OSPF',['Neighbor ID','Pri','State','Dead/Up Time','Address','Interface'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'ospfNeighbors').map((n:any)=>[n.neighborId||NC,n.pri||NC,n.state||NC,n.time||NC,n.address||NC,n.intf||NC])})),[16,6,14,12,16,16]);
  shtH('EIGRP','EIGRP - Enhanced Interior Gateway Routing Protocol',['Process','H','Address','Interface','Hold','Uptime','SRTT','RTO','Q Cnt','Seq Num'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'eigrp').map((e:any)=>[e.proc||NC,e.h||NC,e.addr||NC,e.intf||NC,e.hold||NC,e.uptime||NC,e.srtt||NC,e.rto||NC,e.qcnt||NC,e.seq||NC])})),[10,6,18,16,8,12,8,8,8,8]);
  shtH('VIZINHANÇA EIGRP','Vizinhança EIGRP',['H','Address','Interface','Hold','Up Time','SRTT','RTO','Q Cnt','Seq'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'eigrpNeighbors').map((n:any)=>[n.h||NC,n.address||NC,n.intf||NC,n.hold||NC,n.uptime||NC,n.srtt||NC,n.rto||NC,n.qcnt||NC,n.seq||NC])})),[6,16,16,8,12,8,8,8,8]);
  shtH('BGP','BGP - Border Gateway Protocol',['Router ID','Local AS','Neighbor','V','AS','MsgRcvd','MsgSent','TblVer','InQ','OutQ','Up/Down','State/PfxRcd'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'bgp').map((b:any)=>[b.rid||NC,b.localAs||NC,b.neighbor||NC,b.v||NC,b.as||NC,b.msgRcvd||NC,b.msgSent||NC,b.tblVer||NC,b.inQ||NC,b.outQ||NC,b.upDown||NC,b.state||NC])})),[16,10,16,4,10,10,10,10,6,6,12,14]);
  shtH('VIZINHANÇA BGP','Vizinhança BGP',['Router ID','Local AS','Neighbor','V','AS','MsgRcvd','MsgSent','Up/Down','State/PfxRcd'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'bgpNeighbors').map((n:any)=>[n.rid||NC,n.localAs||NC,n.neighbor||NC,n.v||NC,n.as||NC,n.msgRcvd||NC,n.msgSent||NC,n.upDown||NC,n.state||NC])})),[16,10,16,4,10,10,10,12,14]);
  shtH('ARP','ARP - Address Resolution Protocol',['IP Address','Mac Address','Age(min)','Type','Interface'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'arpTable').map((a:any)=>[a.ip||NC,a.mac||NC,a.age||NC,a.type||NC,a.intf||NC])})),[18,18,10,10,20]);
  shtH('MAC','MAC - Media Access Control',['VLAN','Mac Address','Type','Interface'],
    devices.map(d=>({hostname:nv(d,'hostname'),rows:vl(d,'macTable').map((m:any)=>[m.vlan||NC,m.mac||NC,m.type||NC,m.intf||NC])})),[10,18,10,20]);

  return Buffer.from(XLSX.write(wb, { type:'buffer', bookType:'xlsx' }));
}

export async function generateRiskExcel(devices: DeviceAssessment[]): Promise<Buffer> {
  return buildMatriz(devices);
}
export async function generateAssessmentExcel(devices: DeviceAssessment[], label='Magneto NTG'): Promise<Buffer> {
  return buildAssessment(devices, label);
}

import express from 'express';
import multer from 'multer';
import { createServer as createViteServer } from 'vite';
import { parseRawData } from './src/server/services/parser.ts';
import { applyLayout } from './src/server/services/layout.ts';
import { generateDrawioXml } from './src/server/services/drawio.ts';
import { COMMAND_PROFILES } from './src/server/services/profiles.ts';
import { executeCommands } from './src/server/services/ssh.ts';
import { generateRiskExcel, generateAssessmentExcel } from './src/server/services/risk-excel.ts';
import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const _require = createRequire(import.meta.url);

// Risk analysis engines (one per vendor)
const { runRiskAnalysis } = _require('./src/server/services/risk-analysis.cjs');

// Assessment full parser — extracts CDP, VLANs, STP, trunk, port-channel, BGP, OSPF, etc.
const { parseAssessmentDevice } = _require('./src/server/services/assessment-parser.cjs');

const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 * 1024, files: 200 }
});

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '100mb' }));
  app.use(express.urlencoded({ limit: '100mb', extended: true }));

  // API Routes
  app.get('/api/profiles', (req, res) => {
    res.json(COMMAND_PROFILES);
  });

  app.post('/api/discovery', async (req, res) => {
    const { ip, username, password, vendor, customCommands } = req.body;
    
    try {
      // Flatten all commands to execute
      let allCommands = [
        ...(customCommands.l1 || []),
        ...(customCommands.l2 || []),
        ...(customCommands.l3 || []),
        ...(customCommands.hardware || [])
      ].filter(Boolean);

      // Prepend pagination disable commands based on vendor
      if (vendor === 'cisco_ios' || vendor === 'cisco_nxos') {
        allCommands.unshift('terminal length 0');
      } else if (vendor === 'aruba_os') {
        allCommands.unshift('no paging');
      } else if (vendor === 'hpe_comware') {
        allCommands.unshift('screen-length disable');
      } else if (vendor === 'juniper_junos') {
        allCommands.unshift('set cli screen-length 0');
      } else if (vendor === 'huawei_vrp') {
        allCommands.unshift('screen-length 0 temporary');
      }

      let rawOutputs: Record<string, string> = {};
      let rawText = '';

      const ipList = ip.split(/[,;\s]+/).map((i: string) => i.trim()).filter(Boolean);

      for (const singleIp of ipList) {
        try {
          // Execute real SSH commands for each IP
          const outputs = await executeCommands(singleIp, username, password, allCommands);
          
          Object.entries(outputs).forEach(([cmd, out]) => {
            const key = `[${singleIp}] ${cmd}`;
            rawOutputs[key] = out;
            rawText += `--- COMMAND: ${key} ---\n${out}\n`;
          });
        } catch (sshError: any) {
          console.error(`SSH Error for ${singleIp}:`, sshError);
          return res.status(500).json({ 
            error: `Falha na conexão SSH com ${singleIp}. Verifique se o IP é acessível e se as credenciais estão corretas. Detalhes: ${sshError.message}` 
          });
        }
      }

      const topology = parseRawData(rawText, vendor);
      const positionedTopology = applyLayout(topology);
      const xml = generateDrawioXml(positionedTopology);

      res.json({ xml, topology: positionedTopology, rawOutputs });
    } catch (error: any) {
      console.error('Discovery Error:', error);
      res.status(500).json({ error: 'Erro interno ao processar a topologia.' });
    }
  });

  app.post('/api/upload', upload.array('files'), (req, res) => {
    try {
      const vendor = req.body.vendor || 'cisco_ios';
      const files = req.files as Express.Multer.File[];
      
      if (!files || files.length === 0) {
        return res.status(400).json({ error: 'Nenhum arquivo enviado.' });
      }

      // Concatenate all file contents into a single raw text string
      let rawText = '';
      let rawOutputs: Record<string, string> = {};

      files.forEach(file => {
        const content = file.buffer.toString('utf-8');
        rawText += `--- FILE: ${file.originalname} ---\n${content}\n\n`;
        rawOutputs[`File: ${file.originalname}`] = content;
      });

      const topology = parseRawData(rawText, vendor);
      const positionedTopology = applyLayout(topology);
      const xml = generateDrawioXml(positionedTopology);

      res.json({ xml, topology: positionedTopology, rawOutputs });
    } catch (error: any) {
      console.error('Upload Error:', error);
      res.status(500).json({ error: `Erro interno ao processar arquivos: ${error.message}` });
    }
  });

  // ── Risk Assessment: analyse log text ──────────────────────────────────────
  // POST /api/risk-analysis
  // Body: { log: string, vendor: string, hostname?: string, ip?: string, model?: string, osVersion?: string }
  // Returns: { items: RiskItem[] }
  app.post('/api/risk-analysis', (req: any, res: any) => {
    try {
      const { log, vendor, hostname, ip, model, osVersion } = req.body;
      if (!log) return res.status(400).json({ error: 'log is required' });
      const items = runRiskAnalysis(log, vendor || 'cisco_ios');
      res.json({ items, hostname, ip, model, osVersion, vendor });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── Risk Assessment: export Excel ───────────────────────────────────────────
  // POST /api/risk-excel
  // Body: { devices: DeviceAssessment[] }
  // Returns: xlsx file stream
  app.post('/api/risk-excel', async (req: any, res: any) => {
    try {
      const { devices } = req.body;
      if (!devices?.length) return res.status(400).json({ error: 'devices array required' });
      const buf = await generateRiskExcel(devices);
      const date = new Date().toISOString().slice(0, 10);
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="Magneto_Assessment_${date}.xlsx"`);
      res.send(buf);
    } catch (err: any) {
      console.error('Risk Excel error:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ── Assessment Network: export Excel (Assessment format) ─────────────────
  app.post('/api/assessment-excel', async (req: any, res: any) => {
    try {
      const { devices, label } = req.body;
      if (!devices?.length) return res.status(400).json({ error: 'devices array required' });
      const buf = await generateAssessmentExcel(devices, label || 'Magneto NTG');
      const date = new Date().toISOString().slice(0, 10);
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="Assessment_${date}.xlsx"`);
      res.send(buf);
    } catch (err: any) {
      console.error('Assessment Excel error:', err);
      res.status(500).json({ error: err.message });
    }
  });
  // POST /api/risk-upload  (multipart, field: logs[])
  // Auto-detects vendor — runs both runRiskAnalysis (Matriz) AND parseAssessmentDevice (Assessment)
  // Returns: { devices: DeviceAssessment[] }  — ready for both risk-excel and assessment-excel
  app.post('/api/risk-upload', upload.array('logs'), (req: any, res: any) => {
    try {
      const files = req.files as Express.Multer.File[];
      if (!files?.length) return res.status(400).json({ error: 'Nenhum arquivo enviado.' });

      function detectVendor(log: string): string {
        if (/dell emc smartfabric|os10|dell networking os/i.test(log))    return 'dell_os10';
        if (/huawei versatile routing|vrp software|huawei.*version/i.test(log) ||
            /\[.*\]$/m.test(log) && /display version/i.test(log))          return 'huawei_vrp';
        if (/comware software|hp.*comware|hpe.*comware|h3c/i.test(log))   return 'hpe_comware';
        if (/cisco nexus|nxos|nx-os|n[0-9][kk]-|feature vpc/i.test(log)) return 'cisco_nxos';
        return 'cisco_ios';
      }

      const devices = files.map(file => {
        const log    = file.buffer.toString('utf-8');
        const vendor = detectVendor(log);

        // ── 1. Risk analysis items (Matriz de Riscos) ─────────────────────
        const items = runRiskAnalysis(log, vendor);

        // ── 2. Full assessment parse (CDP, VLANs, STP, trunk, port-channel, BGP...) ─
        let parsed: any = {};
        try {
          parsed = parseAssessmentDevice(log);
        } catch (e: any) {
          console.warn('[risk-upload] parseAssessmentDevice failed:', e.message);
        }

        // ── 3. Map parsed fields to DeviceAssessment ──────────────────────
        const hostname  = parsed.hostname  || file.originalname.replace(/\.(txt|log)$/i, '');
        const ip        = parsed.mgmtIp    || parsed.ip || '';
        const model     = parsed.model     || '';
        const osVersion = parsed.ios_ver   || '';
        const serial    = parsed.serial    || '';

        return {
          // Core fields
          hostname, ip, vendor, model, osVersion, serial, items,
          // Metadata
          mgmtIntf:    parsed.mgmtIntf    || '',
          mgmtMask:    parsed.mgmtMask    || '',
          mgmtType:    parsed.mgmtType    || '',
          defaultGw:   parsed.defaultGw   || '',
          uptime:      parsed.uptime      || '',
          image:       parsed.image       || '',
          // Assessment data tables
          cdp:             parsed.cdp             || [],
          lldp:            parsed.lldp            || [],
          vlans:           parsed.vlans           || [],
          vtpVer:          parsed.vtpVer          || '',
          vtpDomain:       parsed.vtpDomain       || '',
          vtpMode:         parsed.vtpMode         || '',
          vtpVlans:        parsed.vtpVlans        || '',
          vtpRev:          parsed.vtpRev          || '',
          vtpPwd:          parsed.vtpPwd          || '',
          stp:             parsed.stp             || [],
          intVlan:         parsed.intVlan         || [],
          hsrp:            parsed.hsrp            || [],
          vrrp:            parsed.vrrp            || [],
          glbp:            parsed.glbp            || [],
          portch:          parsed.portch          || [],
          trunk:           parsed.trunk           || [],
          staticRt:        parsed.staticRt        || [],
          ospfProcs:       parsed.ospfProcs       || [],
          ospfNeighbors:   parsed.ospfNeighbors   || [],
          eigrp:           parsed.eigrp           || [],
          eigrpNeighbors:  parsed.eigrpNeighbors  || [],
          bgp:             parsed.bgp             || [],
          bgpNeighbors:    parsed.bgpNeighbors    || [],
          intSt:           parsed.intSt           || [],
          arpTable:        parsed.arpTable        || [],
          macTable:        parsed.macTable        || [],
          stackMembers:    parsed.stackMembers    || [],
        };
      });

      res.json({ devices });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Vite middleware
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();

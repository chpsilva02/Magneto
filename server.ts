import express from 'express';
import multer from 'multer';
import { createServer as createViteServer } from 'vite';
import { parseRawData } from './src/server/services/parser.ts';
import { applyLayout } from './src/server/services/layout.ts';
import { generateDrawioXml } from './src/server/services/drawio.ts';
import { COMMAND_PROFILES } from './src/server/services/profiles.ts';
import { executeCommands } from './src/server/services/ssh.ts';
import path from 'path';

const upload = multer({ storage: multer.memoryStorage() });

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

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

import Database from 'better-sqlite3';
import { TopologyNode, TopologyLink } from '../../shared/types.ts';

export class TopologyDatabase {
  private db: Database.Database;

  constructor() {
    this.db = new Database(':memory:');
    this.initSchema();
  }

  private initSchema() {
    this.db.exec(`
      CREATE TABLE devices (
        id TEXT PRIMARY KEY,
        hostname TEXT,
        ip TEXT,
        vendor TEXT,
        hardware_model TEXT,
        role TEXT,
        is_root BOOLEAN DEFAULT 0
      );

      CREATE TABLE physical_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_device TEXT,
        local_port TEXT,
        target_device TEXT,
        remote_port TEXT,
        protocol TEXT,
        remote_ip TEXT,
        remote_model TEXT
      );

      CREATE TABLE l2_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_device TEXT,
        local_port TEXT,
        vlan TEXT,
        role TEXT,
        state TEXT
      );

      CREATE TABLE l3_routes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_device TEXT,
        destination TEXT,
        next_hop TEXT,
        interface TEXT,
        protocol TEXT
      );

      CREATE TABLE l3_neighbors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_device TEXT,
        neighbor_ip TEXT,
        local_port TEXT,
        protocol TEXT,
        state TEXT,
        as_number TEXT
      );
    `);
  }

  public upsertDevice(device: Partial<TopologyNode>) {
    const stmt = this.db.prepare(`
      INSERT INTO devices (id, hostname, ip, vendor, hardware_model, role, is_root)
      VALUES (@id, @hostname, @ip, @vendor, @hardware_model, @role, @is_root)
      ON CONFLICT(id) DO UPDATE SET
        ip = CASE WHEN excluded.ip != '' THEN excluded.ip ELSE devices.ip END,
        hardware_model = CASE WHEN excluded.hardware_model != 'Unknown' THEN excluded.hardware_model ELSE devices.hardware_model END,
        role = CASE WHEN excluded.role != 'access' THEN excluded.role ELSE devices.role END,
        is_root = CASE WHEN excluded.is_root = 1 THEN 1 ELSE devices.is_root END
    `);
    
    stmt.run({
      id: device.id,
      hostname: device.hostname || device.id,
      ip: device.ip || '',
      vendor: device.vendor || 'unknown',
      hardware_model: device.hardware_model || 'Unknown',
      role: device.role || 'access',
      is_root: device.isRoot ? 1 : 0
    });
  }

  public insertPhysicalLink(source: string, localPort: string, target: string, remotePort: string, protocol: string, remoteIp?: string, remoteModel?: string) {
    const stmt = this.db.prepare(`
      INSERT INTO physical_links (source_device, local_port, target_device, remote_port, protocol, remote_ip, remote_model)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(source, localPort, target, remotePort, protocol, remoteIp || null, remoteModel || null);
  }

  public insertL2Link(source: string, localPort: string, vlan: string, role: string, state: string) {
    const stmt = this.db.prepare(`
      INSERT INTO l2_links (source_device, local_port, vlan, role, state)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(source, localPort, vlan, role, state);
  }

  public insertL3Route(source: string, destination: string, nextHop: string, intf: string, protocol: string) {
    const stmt = this.db.prepare(`
      INSERT INTO l3_routes (source_device, destination, next_hop, interface, protocol)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(source, destination, nextHop, intf, protocol);
  }

  public insertL3Neighbor(source: string, neighborIp: string, localPort: string, protocol: string, state: string, asNumber?: string) {
    const stmt = this.db.prepare(`
      INSERT INTO l3_neighbors (source_device, neighbor_ip, local_port, protocol, state, as_number)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(source, neighborIp, localPort, protocol, state, asNumber || null);
  }

  public getDevices(): TopologyNode[] {
    const stmt = this.db.prepare('SELECT * FROM devices');
    const rows = stmt.all() as any[];
    return rows.map(row => ({
      id: row.id,
      hostname: row.hostname,
      ip: row.ip,
      vendor: row.vendor,
      hardware_model: row.hardware_model,
      role: row.role,
      isRoot: row.is_root === 1
    }));
  }

  public getDeduplicatedPhysicalLinks(): any[] {
    // Inteligência em nível de banco de dados para deduplicar links bidirecionais
    // e agrupar protocolos (ex: cdp e lldp na mesma porta)
    const stmt = this.db.prepare(`
      WITH OrderedLinks AS (
        SELECT 
          CASE WHEN source_device < target_device THEN source_device ELSE target_device END as dev_a,
          CASE WHEN source_device < target_device THEN target_device ELSE source_device END as dev_b,
          CASE WHEN source_device < target_device THEN local_port ELSE remote_port END as port_a,
          CASE WHEN source_device < target_device THEN remote_port ELSE local_port END as port_b,
          protocol
        FROM physical_links
      )
      SELECT 
        dev_a as source,
        dev_b as target,
        port_a as src_port,
        port_b as dst_port,
        GROUP_CONCAT(DISTINCT protocol) as protocols
      FROM OrderedLinks
      GROUP BY dev_a, dev_b, port_a, port_b
    `);
    
    return stmt.all();
  }

  public getL2LinksByPort(): any[] {
    const stmt = this.db.prepare(`
      SELECT 
        source_device, 
        local_port, 
        vlan, 
        role, 
        CASE WHEN COUNT(DISTINCT state) > 1 THEN 'Mixed' ELSE MAX(state) END as state
      FROM l2_links
      GROUP BY source_device, local_port, vlan, role
    `);
    return stmt.all();
  }

  public getL3Routes(): any[] {
    return this.db.prepare('SELECT * FROM l3_routes').all();
  }

  public getL3Neighbors(): any[] {
    return this.db.prepare('SELECT * FROM l3_neighbors').all();
  }
}

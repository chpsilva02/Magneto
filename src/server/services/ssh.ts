import { Client } from 'ssh2';

export async function executeCommands(ip: string, username: string, password: string, commands: string[]): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    const results: Record<string, string> = {};
    let output = '';
    let isResolved = false;

    const cleanup = () => {
      if (!isResolved) {
        isResolved = true;
        conn.end();
        results['session'] = output;
        resolve(results);
      }
    };

    conn.on('ready', () => {
      conn.shell({ term: 'vt100' }, (err, stream) => {
        if (err) {
          if (!isResolved) {
            isResolved = true;
            conn.end();
            reject(err);
          }
          return;
        }

        stream.on('close', () => {
          cleanup();
        }).on('data', (data: any) => {
          output += data.toString();
        }).stderr.on('data', (data: any) => {
          output += data.toString();
        });

        // Send all commands separated by newline
        for (const cmd of commands) {
          stream.write(cmd + '\n');
        }
        
        // Send exit commands to gracefully close the session
        stream.write('exit\n');
        stream.write('quit\n');

        // Fallback timeout to close the stream if the device doesn't disconnect automatically
        setTimeout(() => {
          stream.close();
          cleanup();
        }, 20000); // 20 seconds max for the whole session
      });
    }).on('error', (err) => {
      if (!isResolved) {
        isResolved = true;
        reject(err);
      }
    }).connect({
      host: ip,
      port: 22,
      username: username,
      password: password,
      readyTimeout: 15000, // 15 seconds timeout
      algorithms: {
        // Allow older algorithms often found in legacy network devices
        kex: [
          'diffie-hellman-group1-sha1',
          'diffie-hellman-group14-sha1',
          'diffie-hellman-group-exchange-sha1',
          'diffie-hellman-group-exchange-sha256',
          'ecdh-sha2-nistp256',
          'ecdh-sha2-nistp384',
          'ecdh-sha2-nistp521',
          'curve25519-sha256',
          'curve25519-sha256@libssh.org'
        ],
        cipher: [
          'aes128-ctr', 'aes192-ctr', 'aes256-ctr',
          'aes128-gcm', 'aes128-gcm@openssh.com',
          'aes256-gcm', 'aes256-gcm@openssh.com',
          'aes256-cbc', 'aes192-cbc', 'aes128-cbc',
          '3des-cbc'
        ]
      }
    });
  });
}

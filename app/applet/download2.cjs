const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const url = 'https://github.com/chpsilva02/Magneto/archive/refs/heads/main.zip';
const dest = path.join(__dirname, 'repo.zip');

const file = fs.createWriteStream(dest);
https.get(url, (response) => {
  if (response.statusCode === 301 || response.statusCode === 302) {
    https.get(response.headers.location, (res) => {
      res.pipe(file);
      file.on('finish', () => {
        file.close(() => {
          console.log('Downloaded zip');
          execSync(`npx -y extract-zip repo.zip ${__dirname}`);
          console.log('Extracted');
        });
      });
    });
  } else {
    response.pipe(file);
    file.on('finish', () => {
      file.close(() => {
        console.log('Downloaded zip');
        execSync(`npx -y extract-zip repo.zip ${__dirname}`);
        console.log('Extracted');
      });
    });
  }
}).on('error', (err) => {
  fs.unlink(dest, () => {});
  console.error(err.message);
});

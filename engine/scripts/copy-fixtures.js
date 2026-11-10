// Copies the JSON fixture data next to the compiled fixture loader.
// Written with plain loops so the build step stays easy to read.
const fs = require('fs');
const path = require('path');

const sourceDir = path.join(__dirname, '..', 'fixtures');
const targetDir = path.join(__dirname, '..', 'dist', 'fixtures');

if (!fs.existsSync(targetDir)) {
  fs.mkdirSync(targetDir, { recursive: true });
}

const entries = fs.readdirSync(sourceDir);
let copied = 0;
for (let i = 0; i < entries.length; i++) {
  const name = entries[i];
  if (path.extname(name) !== '.json') {
    continue;
  }
  fs.copyFileSync(path.join(sourceDir, name), path.join(targetDir, name));
  copied = copied + 1;
}
console.log('copy-fixtures: copied ' + copied + ' JSON fixture file(s)');

const fs = require('fs');
const path = require('path');
const target = path.join(__dirname, '..', 'dist');
if (fs.existsSync(target)) {
  fs.rmSync(target, { recursive: true, force: true });
  console.log('clean: removed dist/');
} else {
  console.log('clean: nothing to remove');
}

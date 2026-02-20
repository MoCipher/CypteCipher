const { execSync } = require('child_process');
const path = require('path');
try {
  // smoke: ensure electron module can be required
  const electron = require('electron');
  console.log('electron available:', !!electron);
  console.log('Electron smoke test passed');
  process.exit(0);
} catch (e) {
  console.error('Electron smoke test failed', e.message);
  process.exit(1);
}

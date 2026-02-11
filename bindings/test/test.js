const { execSync } = require('child_process');
const path = require('path');
try {
  // Build the CLI
  console.log('building CLI...');
  execSync('npm run build-cli', { cwd: path.join(__dirname, '..'), stdio: 'inherit' });

  // Locate the built binary
  const binName = process.platform === 'win32' ? 'cryptec_cli.exe' : 'cryptec_cli';
  const targetDir = path.join(__dirname, '..', '..', 'target', 'release');
  const bin = path.join(targetDir, binName);

  // Run version
  const ver = execSync(`"${bin}" version`).toString().trim();
  console.log('cli version output:', ver);

  // Generate mnemonic and get an address
  const mnemonic = execSync(`"${bin}" gen-mnemonic`).toString().trim();
  console.log('mnemonic:', mnemonic.split(' ').slice(0,3).join(' ')+ '...');
  const addr = execSync(`"${bin}" bdk-new-addr "${mnemonic}"`).toString().trim();
  console.log('receive address:', addr);
  console.log('Node integration tests passed');
  process.exit(0);
} catch (e) {
  console.error('Node integration test failed', e.message);
  process.exit(1);
}

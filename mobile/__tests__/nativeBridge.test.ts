import nativeBridge from '../src/nativeBridge';

test('generate mnemonic and derive address', async () => {
  const m = await nativeBridge.generateMnemonic(128);
  expect(typeof m).toBe('string');
  const addr = nativeBridge.firstReceiveAddressFromMnemonic(m);
  expect(typeof addr).toBe('string');
  expect(addr.length).toBeGreaterThan(0);
});

test('create and sign psbt mock', async () => {
  const mn = await nativeBridge.generateMnemonic(128);
  const psbt = await nativeBridge.createPsbtMock(mn, 'tb1qexampleaddress', 5000);
  expect(psbt).toBeTruthy();
  const signed = await nativeBridge.signPsbtMock(mn, psbt);
  expect(signed).toBeTruthy();
});

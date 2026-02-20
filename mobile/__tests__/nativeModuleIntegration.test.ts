import { NativeModules } from 'react-native';
import nativeBridge from '../src/nativeBridge';

describe('native module integration (shim)', () => {
  afterEach(() => {
    jest.resetModules();
  });

  test('JS mock used when NativeModules not available', async () => {
    const mn = await nativeBridge.generateMnemonic(128);
    expect(typeof mn).toBe('string');
    const addr = nativeBridge.firstReceiveAddressFromMnemonic(mn);
    expect(typeof addr).toBe('string');
  });

  test('uses NativeModules when present (mocked)', async () => {
    (NativeModules as any).Cryptec = {
      generate_mnemonic: (s: number) => 'abandon abandon abandon ...',
      first_receive_address: (m: string) => 'tb1qnative',
      create_psbt: (m: string, t: string, s: number) => 'psbt-native',
      sign_psbt: (m: string, p: string) => 'signed-native'
    };

    const m = await nativeBridge.generateMnemonic(128);
    expect(m).toContain('abandon');
    const addr = nativeBridge.firstReceiveAddressFromMnemonic('x');
    expect(addr).toBe('tb1qnative');

    const psbt = await nativeBridge.createPsbtMock('x', 'tb1qnative', 1000);
    expect(psbt).toBe('psbt-native');

    const signed = await nativeBridge.signPsbtMock('x', 'psbt-native');
    expect(signed).toBe('signed-native');
  });
});

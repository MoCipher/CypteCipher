import React, { useEffect, useState } from 'react';
import { View, Text, Button, StyleSheet, TextInput, Alert } from 'react-native';
import nativeBridge from '../nativeBridge';

export default function WalletHome({ route }: any) {
  const { mnemonic } = route.params || {};
  const [address, setAddress] = useState('');
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('1000');

  useEffect(() => {
    const addr = nativeBridge.firstReceiveAddressFromMnemonic(mnemonic);
    setAddress(addr);
  }, [mnemonic]);

  const createPsbt = async () => {
    const psbt = await nativeBridge.createPsbtMock(mnemonic, to, parseInt(amount || '0', 10));
    Alert.alert('PSBT created (mock)', psbt);
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Wallet</Text>
      <Text style={styles.label}>Receive address (first):</Text>
      <Text style={styles.addr}>{address}</Text>

      <Text style={styles.section}>Send (mock)</Text>
      <TextInput placeholder="to address" style={styles.input} value={to} onChangeText={setTo} />
      <TextInput placeholder="satoshis" style={styles.input} value={amount} onChangeText={setAmount} keyboardType="numeric" />
      <Button title="Create PSBT (mock)" onPress={createPsbt} />

      <View style={{ height: 24 }} />
      <Button title="Export mnemonic (copy)" onPress={() => Alert.alert('Mnemonic', mnemonic)} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 20 },
  title: { fontSize: 20, fontWeight: '600', marginBottom: 12 },
  label: { fontWeight: '500', marginTop: 8 },
  addr: { marginVertical: 8, color: '#333' },
  section: { marginTop: 16, fontWeight: '600' },
  input: { borderWidth: 1, borderColor: '#ddd', padding: 8, marginVertical: 8, borderRadius: 6 }
});

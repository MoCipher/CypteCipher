import React, { useState } from 'react';
import { View, Text, Button, StyleSheet, TextInput } from 'react-native';
import nativeBridge from '../nativeBridge';

export default function Onboarding({ navigation }: any) {
  const [mnemonic, setMnemonic] = useState('');

  const createNew = async () => {
    const m = await nativeBridge.generateMnemonic(128);
    setMnemonic(m);
    navigation.navigate('Wallet', { mnemonic: m });
  };

  const importExisting = () => {
    if (!mnemonic) return;
    navigation.navigate('Wallet', { mnemonic });
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>CrypteCipher — Onboarding</Text>
      <Button title="Create new wallet" onPress={createNew} />
      <Text style={styles.or}>— or —</Text>
      <TextInput
        style={styles.input}
        placeholder="paste mnemonic phrase to import"
        value={mnemonic}
        onChangeText={setMnemonic}
        multiline
      />
      <Button title="Import wallet" onPress={importExisting} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 20, justifyContent: 'center' },
  title: { fontSize: 20, fontWeight: '600', marginBottom: 20 },
  or: { textAlign: 'center', marginVertical: 12, color: '#666' },
  input: { borderWidth: 1, borderColor: '#ddd', padding: 8, marginBottom: 12, borderRadius: 6 }
});

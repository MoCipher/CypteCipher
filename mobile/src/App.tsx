import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import Onboarding from './screens/Onboarding';
import WalletHome from './screens/WalletHome';

const Stack = createNativeStackNavigator();

export default function App() {
  return (
    <NavigationContainer>
      <Stack.Navigator initialRouteName="Onboarding">
        <Stack.Screen name="Onboarding" component={Onboarding} options={{ title: 'Welcome' }} />
        <Stack.Screen name="Wallet" component={WalletHome} options={{ title: 'Wallet' }} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}

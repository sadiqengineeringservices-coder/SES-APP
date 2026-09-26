/**
 * Minimal session shell. The original screens (Clients/Projects/Expenses/
 * Payments) mount inside <FinanceApp/> once a hardened session exists.
 * Authentication state is NOT decided here alone — every data operation is
 * re-authorized in the main process against the session token.
 */
import React, { useEffect, useState } from 'react';
import { sessionStore } from './store/session';
import LoginScreen from './components/screens/LoginScreen';
import FinanceApp from './components/screens/FinanceApp';

export default function App() {
  const [, force] = useState(0);
  useEffect(() => sessionStore.subscribe(() => force((x) => x + 1)), []);
  const { session } = sessionStore.snapshot();
  return session ? <FinanceApp /> : <LoginScreen />;
}

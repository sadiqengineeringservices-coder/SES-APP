import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

/**
 * SECURITY: legacy localStorage-backed stores and any cloud client were
 * removed during hardening. This app never talks to the network; all state
 * flows through the encrypted per-user store in the Electron main process.
 */
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

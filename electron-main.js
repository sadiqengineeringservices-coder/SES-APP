const { app, BrowserWindow, ipcMain, session } = require('electron');
const path = require('path');
// Hardened IPC: narrow, session-bound operations only (see electron/ipc.js).
const { registerIpcHandlers } = require('./electron/ipc');

let mainWindow;

// Defense-in-depth: this application is 100% offline. Block every outbound
// request and any navigation away from the bundled UI. No telemetry can leak
// even if a renderer bug or malicious import tried to trigger one.
app.on('web-contents-created', (_event, contents) => {
  contents.on('will-navigate', (e) => e.preventDefault());
  contents.on('will-frame-load', (e) => e.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});
session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
  const allow =
    details.url.startsWith('file://') ||
    details.url.startsWith('devtools://') ||
    details.url.startsWith('chrome-extension://') ||
    (!app.isPackaged && details.url.startsWith('http://localhost'));
  callback(allow ? {} : { cancel: true });
});

function applyWindowSecurity() {
  // Deny all permission requests (camera/mic/notifications/etc.) in production.
  try {
    session.defaultSession.setPermissionRequestHandler((_wc, _p, cb) => cb(false));
  } catch (e) { /* best effort */ }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    icon: path.join(__dirname, 'icon.ico'),
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,   // renderer cannot touch main-process objects
      nodeIntegration: false,   // no Node.js inside the renderer
      sandbox: true,            // OS-level sandbox for the renderer
      webviewTag: false,
      allowRunningInsecureContent: false,
      experimentalFeatures: false,
      spellcheck: false,        // no text leaves the machine via services
    },
  });

  mainWindow.once('ready-to-show', () => mainWindow.show());

  // Determines whether to serve local development or compiled Vite assets
  if (app.isPackaged) {
    mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html'));
  } else {
    mainWindow.loadURL('http://localhost:5173');
    // DevTools stay available during development only.
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  }
}

if (!app.requestSingleInstanceLock()) {
  // A second instance could race on the encrypted store — refuse to run.
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(() => {
    applyWindowSecurity();
    createWindow();

    // Register the hardened auth / data / backup / export IPC handlers.
    registerIpcHandlers(ipcMain);

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}

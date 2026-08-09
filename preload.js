const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('desktopAPI', {
  // Get the currently chosen data folder.
  getDataFolder: () => ipcRenderer.invoke('ses:get-data-folder'),

  // Prompt the user to pick / change the data folder.
  chooseDataFolder: () => ipcRenderer.invoke('ses:choose-data-folder'),

  // Save the full tables to Excel + JSON in the chosen folder.
  saveData: (tables) => ipcRenderer.invoke('ses:save-data', tables),

  // Native "Save As" dialog for a JSON backup.
  saveJsonAs: (tables) => ipcRenderer.invoke('ses:save-json-as', tables),

  // Native "Open" dialog for a JSON restore.
  openJson: () => ipcRenderer.invoke('ses:open-json'),
});

// Keep the legacy offlineAPI for backward compatibility (not used by screens).
contextBridge.exposeInMainWorld('offlineAPI', {
  saveEntry: (numericValue) => ipcRenderer.invoke('save-entry', { numericValue })
});

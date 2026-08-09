# Task: Convert web app into 100% offline Windows desktop app

Goal: Wrap the existing React+Vite app (already offline via localStorage) into a
Windows desktop application using Electron, with:
- Local storage saved as Excel (.xlsx) files in a user-chosen folder
- JSON backup/restore (native file dialogs)
- .exe installer + .bat launcher
- App icon on window/taskbar
- NO changes to existing UI or functionality

## Steps
- [x] Analyze project structure and existing offline data layer
- [x] Confirm plan with user
- [x] Copy `SES Logo.ico` -> `icon.ico` (referenced by build config)
- [x] Install `xlsx` (SheetJS) dependency for Excel export
- [x] Create `electron/export.js` (Excel + JSON backup logic in main process)
- [x] Update `electron-main.js` (folder selection, IPC for Excel/JSON save/load)
- [x] Update `preload.js` (expose desktop API to renderer)
- [x] Update `src/electron.d.ts` (type definitions for new API)
- [x] Create `src/lib/excelBridge.ts` (renderer hook watching localStorage -> IPC)
- [x] Update `src/main.tsx` (initialize excel bridge)
- [x] Update `src/components/screens/SettingsScreen.tsx` (Data Folder section + native dialogs)
- [x] Update `package.json` (fix icon path, add xlsx dep, build config)
- [x] Build static bundle (`npm run build`)
- [x] Build .exe installer (`electron-builder`)
- [x] Update `Start-App.bat` launcher
- [x] Verify desktop app launches with icon and works offline

## Deliverables
- `dist-electron\SES Offline Workshop Setup 1.0.0.exe` — Windows installer (80.9 MB)
- `dist-electron\win-unpacked\SES Offline Workshop.exe` — Portable unpacked app (180 MB)
- `Start-App.bat` — Simple launcher
- App icon applied to window + taskbar (from `SES Logo.ico`)

## How it works
- On first launch, the Settings screen lets the user choose a data folder.
- All data is auto-saved to `SES_Backup_<date>.xlsx` (4 sheets: Clients, Projects,
  Expenses, Payments) and `SES_Backup_<date>.json` in that folder whenever data changes.
- Backup/Restore use native Windows Save/Open dialogs.
- The original UI, functions, and features are completely unchanged.

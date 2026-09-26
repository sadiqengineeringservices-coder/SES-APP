export {};

declare global {
  interface Window {
    /**
     * Hardened desktop API — narrow, session-bound operations only.
     * There is intentionally NO fs/path/shell/generic-file access exposed.
     */
    desktopAPI: {
      register(username: string, password: string, displayName?: string): Promise<any>;
      login(username: string, password: string): Promise<any>;
      logout(token: string): Promise<any>;
      sessionInfo(token: string): Promise<any>;
      listUsers(): Promise<any>;
      changePassword(token: string, currentPassword: string, newPassword: string): Promise<any>;
      loadData(token: string, userId: string): Promise<any>;
      saveData(token: string, userId: string, data: unknown): Promise<any>;
      createSecureBackup(token: string, userId: string, password: string): Promise<any>;
      importSecureBackup(token: string, userId: string, password: string): Promise<any>;
      exportExcel(token: string, userId: string): Promise<any>;
    };
  }
}

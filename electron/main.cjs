const { app, BrowserWindow, dialog, ipcMain } = require("electron");
const { spawn } = require("node:child_process");
const path = require("node:path");

const isDev = !app.isPackaged;
let apiProcess = null;

function startApi() {
  const projectRoot = isDev ? path.join(__dirname, "..") : path.join(process.resourcesPath, "app");
  apiProcess = spawn("python3", ["web_backend.py", "--port", "8765"], {
    cwd: projectRoot,
    stdio: "inherit",
  });

  apiProcess.on("exit", (code) => {
    if (code !== 0 && code !== null) {
      console.error(`ГРИФ API exited with code ${code}`);
    }
  });
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 720,
    title: "ГРИФ",
    backgroundColor: "#171713",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  if (isDev) {
    win.loadURL("http://127.0.0.1:5173");
  } else {
    win.loadFile(path.join(process.resourcesPath, "app", "dist", "web", "index.html"));
  }
}

ipcMain.handle("dialog:openImage", async () => {
  const result = await dialog.showOpenDialog({
    title: "Открыть образ диска",
    properties: ["openFile"],
    filters: [
      { name: "Disk images", extensions: ["img", "raw", "dd", "iso", "bin"] },
      { name: "All files", extensions: ["*"] },
    ],
  });
  return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle("dialog:saveImage", async () => {
  const result = await dialog.showSaveDialog({
    title: "Куда сохранить образ",
    defaultPath: "flash-image.img",
    filters: [
      { name: "Disk images", extensions: ["img", "raw", "dd"] },
      { name: "All files", extensions: ["*"] },
    ],
  });
  return result.canceled ? null : result.filePath;
});

app.whenReady().then(() => {
  startApi();
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("before-quit", () => {
  if (apiProcess) {
    apiProcess.kill();
    apiProcess = null;
  }
});

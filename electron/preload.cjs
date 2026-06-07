const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("hexCorruptor", {
  openImageDialog: () => ipcRenderer.invoke("dialog:openImage"),
  saveImageDialog: () => ipcRenderer.invoke("dialog:saveImage"),
});

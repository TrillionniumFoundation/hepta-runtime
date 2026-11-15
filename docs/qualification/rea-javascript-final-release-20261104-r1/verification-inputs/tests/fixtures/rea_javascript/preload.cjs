const { ipcRenderer: renderer, contextBridge: bridge } = require("electron");
bridge.exposeInMainWorld("config", {
  get: (key) => renderer.invoke("cfg:get", key),
  set: (value) => renderer.send("cfg:set", value),
});
renderer.on("cfg:changed", (_event, value) => value);
function shadow(renderer) { renderer.invoke("shadowed-channel"); }
const decoy = 'ipcMain.handle("string-only", () => true)';
// ipcRenderer.send("comment-only");
const pattern = /ipcRenderer\.invoke\("regexp-only"\)/;
require("node:fs").writeFileSync("HEPTA_AST_EXECUTION_MARKER", "must never execute");

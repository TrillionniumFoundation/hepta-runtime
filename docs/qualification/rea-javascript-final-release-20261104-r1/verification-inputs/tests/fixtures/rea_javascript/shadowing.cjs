let mutable = require("electron").ipcRenderer;
mutable = { send() {} };
mutable.send("reassigned-not-electron");
const fake = require("electron-lookalike");
fake.ipcMain.handle("fake-module", () => true);
function shadowRequire(require) { require("shadowed-require"); }
exports.real = 1;
module.exports.other = 2;
exports[globalThis.exportName] = 3;
function shadowExports(exports, module) {
  exports.bad = 4;
  module.exports.bad = 5;
}

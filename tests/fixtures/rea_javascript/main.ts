import { ipcMain as main, BrowserWindow } from "electron";
import type { Payload } from "./types";
import { answer } from "./util.js";
export { answer as reexported } from "./util.js";
export const apiVersion: number = 1;
main.handle("cfg:get", (_event: unknown, key: string): Payload => ({ key, value: answer }));
main.on("cfg:set", (_event: unknown, value: number) => value);
const window = new BrowserWindow({ webPreferences: { preload: "./preload.cjs" } });
window.webContents.send("cfg:changed", { value: answer });
function shadow(main: { handle: Function }) {
  main.handle("shadowed-channel", () => true);
}
export default function start() { return apiVersion; }

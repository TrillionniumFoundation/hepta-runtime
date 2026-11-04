import { ipcRenderer as channel } from "electron";
import { type Payload } from "./types";
export const View = (props: { label: string }) => <section>{props.label}</section>;
channel.invoke("cfg:get", "π");
const astral = "🧪";
channel.send("unicode:\u03c0", astral);
function fake(channel: { send: Function }) { channel.send("shadowed-renderer"); }

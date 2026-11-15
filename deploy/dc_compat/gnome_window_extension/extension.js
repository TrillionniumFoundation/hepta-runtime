// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Meta from 'gi://Meta';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import {WindowController} from './logic.js';
import {BridgeService, readPrivateConfig} from './service.js';

export default class HeptaWindowExtension extends Extension {
    enable() {
        const path = GLib.build_filenamev([GLib.get_user_config_dir(), 'hepta-runtime', 'gnome-window-bridge.json']);
        const config = readPrivateConfig(path);
        const controller = new WindowController({
            session: GLib.uuid_string_random().replaceAll('-', ''),
            version: '46',
            locked: () => Main.sessionMode.isLocked || Main.sessionMode.isGreeter || Boolean(Main.screenShield?.locked),
            windows: () => global.get_window_actors().map(actor => {
                const window = actor.meta_window;
                const rectangle = window.get_frame_rect();
                return {sequence: window.get_stable_sequence(), title: window.get_title(),
                    overrideRedirect: window.is_override_redirect(),
                    appId: window.get_gtk_application_id() || window.get_wm_class() || '',
                    pid: window.get_pid(), focused: window.has_focus(),
                    minimized: window.minimized, workspace: window.get_workspace()?.index() ?? null,
                    monitor: window.get_monitor(), frame: {x: rectangle.x, y: rectangle.y, width: rectangle.width, height: rectangle.height},
                    clientType: window.get_client_type() === Meta.WindowClientType.WAYLAND ? 'wayland' : 'x11',
                    meta: window, isFocused: () => window.has_focus()};
            }),
            activate: window => Main.activateWindow(window.meta, global.get_current_time()),
        });
        this._bridge = new BridgeService(Gio.DBus.session, config, controller);
    }

    disable() {
        this._bridge?.close();
        this._bridge = null;
    }
}

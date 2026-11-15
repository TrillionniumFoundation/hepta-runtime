// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import {tokenMatches} from './logic.js';

export const BUS_NAME = 'org.hepta.Runtime.WindowBridge';
export const OBJECT_PATH = '/org/hepta/Runtime/WindowBridge';
export const INTERFACE = 'org.hepta.Runtime.WindowBridge1';
export const XML = `<node><interface name="${INTERFACE}">
<method name="GetCapabilities"><arg type="s" direction="in" name="token"/><arg type="s" direction="out" name="json"/></method>
<method name="ListWindows"><arg type="s" direction="in" name="token"/><arg type="s" direction="out" name="json"/></method>
<method name="FocusWindow"><arg type="s" direction="in" name="token"/><arg type="s" direction="in" name="window_id"/><arg type="s" direction="in" name="request_id"/><arg type="s" direction="out" name="json"/></method>
</interface></node>`;

export function readPrivateConfig(path) {
    const file = Gio.File.new_for_path(path);
    const info = file.query_info('standard::type,standard::is-symlink,standard::size,unix::uid,unix::mode', Gio.FileQueryInfoFlags.NOFOLLOW_SYMLINKS, null);
    const uid = Gio.Credentials.new().get_unix_user();
    if (info.get_file_type() !== Gio.FileType.REGULAR || info.get_is_symlink() ||
        info.get_attribute_uint32('unix::uid') !== uid ||
        (info.get_attribute_uint32('unix::mode') & 0o077) !== 0 || info.get_size() > 8192)
        throw new Error('Window bridge configuration must be a private owned regular file');
    const [ok, contents] = file.load_contents(null);
    if (!ok)
        throw new Error('Cannot read window bridge configuration');
    const config = JSON.parse(new TextDecoder().decode(contents));
    if (config.version !== 1 || !/^[0-9a-f]{64}$/.test(config.token) ||
        typeof config.profile_id !== 'string' || config.profile_id.length < 1 || config.profile_id.length > 128)
        throw new Error('Invalid window bridge configuration');
    return config;
}

export class BridgeService {
    constructor(connection, config, controller) {
        this.connection = connection;
        this.config = config;
        this.controller = controller;
        this.uid = Gio.Credentials.new().get_unix_user();
        this.exported = Gio.DBusExportedObject.wrapJSObject(XML, this);
        this.exported.export(connection, OBJECT_PATH);
        this.owner = Gio.bus_own_name_on_connection(connection, BUS_NAME,
            Gio.BusNameOwnerFlags.DO_NOT_QUEUE, null, () => this.close());
    }

    async _authorized(token, invocation) {
        if (!this.exported || !tokenMatches(this.config.token, token))
            throw new Error('Window bridge authentication refused');
        const sender = invocation.get_sender();
        const uid = await new Promise((resolve, reject) => {
            this.connection.call('org.freedesktop.DBus', '/org/freedesktop/DBus',
                'org.freedesktop.DBus', 'GetConnectionUnixUser', new GLib.Variant('(s)', [sender]),
                new GLib.VariantType('(u)'), Gio.DBusCallFlags.NONE, 2000, null,
                (connection, result) => {
                    try { resolve(connection.call_finish(result).deep_unpack()[0]); }
                    catch (error) { reject(error); }
                });
        });
        if (uid !== this.uid)
            throw new Error('Window bridge caller must be the desktop user');
        if (!this.exported)
            throw new Error('Window bridge was disabled');
    }

    async _invoke(parameters, invocation, operation) {
        try {
            await this._authorized(parameters[0], invocation);
            const value = operation();
            const json = JSON.stringify(value);
            if (json.length > 8 * 1024 * 1024)
                throw new Error('Window bridge response exceeds its bound');
            invocation.return_value(new GLib.Variant('(s)', [json]));
        } catch (error) {
            // Only policy messages originate here. Never echo supplied tokens,
            // titles, arbitrary arguments or a Shell exception stack.
            const allowed = /^(Desktop is locked|Window is not a current|Focus request ID|Focus receipt was evicted|Focus sequence|A current bridge sequence|Invalid focus sequence|Window bridge authentication|Window bridge caller|Window bridge was disabled|Window inventory exceeds|Duplicate compositor|Invalid compositor)/;
            const message = allowed.test(String(error.message)) ? String(error.message) : 'Window bridge operation refused';
            invocation.return_dbus_error('org.hepta.Runtime.WindowBridge.Error.Refused', message);
        }
    }

    GetCapabilitiesAsync(parameters, invocation) {
        void this._invoke(parameters, invocation, () => ({...this.controller.capabilities(), profile_id: this.config.profile_id}));
    }

    ListWindowsAsync(parameters, invocation) {
        void this._invoke(parameters, invocation, () => this.controller.list());
    }

    FocusWindowAsync(parameters, invocation) {
        void this._invoke(parameters, invocation, () => this.controller.focus(parameters[1], parameters[2]));
    }

    close() {
        if (this.exported) {
            this.exported.unexport();
            this.exported = null;
        }
        if (this.owner) {
            const owner = this.owner;
            this.owner = 0;
            Gio.bus_unown_name(owner);
        }
    }
}

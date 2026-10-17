// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
// No Shell/GI imports: the exact policy is exercised with synthetic windows.
export function tokenMatches(expected, actual) {
    if (typeof expected !== 'string' || !/^[0-9a-f]{64}$/.test(expected) ||
        typeof actual !== 'string' || actual.length !== 64)
        return false;
    let different = 0;
    for (let index = 0; index < 64; index++)
        different |= expected.charCodeAt(index) ^ actual.charCodeAt(index);
    return different === 0;
}

export class WindowController {
    constructor({session, windows, activate, locked, version = '46', maxReceipts = 2048}) {
        if (!/^[0-9a-f]{32}$/.test(session))
            throw new Error('Invalid bridge session');
        this.session = session;
        this._windows = windows;
        this._activate = activate;
        this._locked = locked;
        this.version = version;
        this.maxReceipts = maxReceipts;
        this._receipts = new Map();
        this.nextFocusSequence = 1;
    }

    capabilities() {
        return {protocol: 1, bridge_session: this.session, shell_version: this.version,
            locked: Boolean(this._locked()), scope: 'GNOME compositor windows, Wayland and X11',
            features: {window_list: !this._locked(), window_focus: !this._locked()},
            next_focus_sequence: this.nextFocusSequence,
            cached_focus_receipts: this._receipts.size};
    }

    _current() {
        if (this._locked())
            throw new Error('Desktop is locked; window access refused');
        const windows = this._windows();
        if (!Array.isArray(windows) || windows.length > 4096)
            throw new Error('Window inventory exceeds the safety bound');
        const result = new Map();
        for (const window of windows) {
            if (window.overrideRedirect)
                continue;
            const number = String(window.sequence);
            if (!/^[0-9]{1,10}$/.test(number))
                throw new Error('Invalid compositor window identity');
            const id = this.session + ':' + number;
            if (result.has(id))
                throw new Error('Duplicate compositor window identity');
            result.set(id, window);
        }
        return result;
    }

    list() {
        const windows = [];
        for (const [identity, window] of this._current()) {
            windows.push({window_id: identity, title: String(window.title ?? '').slice(0, 16384),
                app_id: String(window.appId ?? '').slice(0, 4096), pid: window.pid ?? null,
                focused: Boolean(window.focused), minimized: Boolean(window.minimized),
                workspace: window.workspace ?? null, monitor: window.monitor ?? null,
                frame: window.frame, client_type: window.clientType ?? 'unknown'});
        }
        return {bridge_session: this.session, windows, scope: 'GNOME compositor windows, Wayland and X11'};
    }

    focus(identity, nonce) {
        // Check lock even for receipt reads; do not disclose metadata while locked.
        if (this._locked())
            throw new Error('Desktop is locked; window access refused');
        if (typeof nonce !== 'string' || !nonce.startsWith(this.session + ':') ||
            !/^[1-9][0-9]{0,15}$/.test(nonce.slice(33)))
            throw new Error('A current bridge sequence request ID is required');
        const sequence = Number(nonce.slice(33));
        if (!Number.isSafeInteger(sequence))
            throw new Error('Invalid focus sequence');
        const previous = this._receipts.get(nonce);
        if (previous) {
            if (previous.window_id !== identity)
                throw new Error('Focus request ID already belongs to another window');
            return {...previous, replayed: false, receipt_reused: true};
        }
        if (sequence < this.nextFocusSequence)
            throw new Error('Focus receipt was evicted; old request ID is sealed and cannot replay');
        if (sequence !== this.nextFocusSequence || sequence >= Number.MAX_SAFE_INTEGER)
            throw new Error('Focus sequence is stale or out of order; no activation submitted');
        const window = this._current().get(identity);
        if (!window)
            throw new Error('Window is not a current identity in this bridge session');
        const receipt = {window_id: identity, request_id: nonce, bridge_session: this.session,
            submitted: true, outcome: 'unknown', replayed: false, receipt_reused: false};
        this._receipts.set(nonce, receipt);
        this.nextFocusSequence++;
        // A monotonic floor seals old request IDs even after their result was
        // evicted. Bounding result memory never blocks admission of new focus.
        while (this._receipts.size > this.maxReceipts)
            this._receipts.delete(this._receipts.keys().next().value);
        try {
            this._activate(window);
            receipt.outcome = 'activation_submitted';
            receipt.focus_observed = Boolean(window.isFocused());
        } catch (_error) {
            // An activation may have happened before a later API failed. A reused
            // nonce returns this uncertainty instead of attempting it again.
            receipt.focus_observed = false;
        }
        return {...receipt};
    }
}

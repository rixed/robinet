/* The administration interface.
 *
 * Everything here goes through the REST API; this file knows nothing about the
 * simulator beyond what /api serves. A widget is identified by the pair
 * (simulation id, widget id), which is how the API addresses it too.
 *
 * On failure the guiding rule is: never show something that looks current when
 * it is not. A simulation that cannot be reached leaves the last known values
 * on screen, but says so, marks them stale, and stops offering controls that
 * would not work -- rather than quietly presenting yesterday's numbers, or an
 * empty list that reads as "there is nothing here".
 */

/* A property value arrives as JSON of its own type -- a number stays a number.
 * The inputs are text, so each one keeps a [text] rendering to edit, and
 * [encode] turns that back into the JSON the setter expects. */
const asText = (v) =>
    v === null || v === undefined ? '' :
    typeof v === 'string' ? v : JSON.stringify(v)

const encode = (p) => {
    switch (p.kind.type) {
        case 'bool':
            return JSON.stringify(p.draft === true || p.draft === 'true')
        case 'int': case 'float': case 'range': {
            const n = Number(p.draft)
            /* Send what was typed rather than guessing, and let the setter say
             * what is wrong with it. */
            return JSON.stringify(Number.isNaN(n) || p.draft === '' ? String(p.draft) : n)
        }
        default:
            return JSON.stringify(String(p.draft))
    }
}

/* Two kinds of failure, which want opposite treatment:
 *  - 'offline': no answer at all. Everything is suspect, keep retrying.
 *  - 'refused': the server answered, and said no. Only the thing we asked for
 *    failed; it belongs next to that thing, and retrying would just fail again.
 */
class ApiError extends Error {
    constructor(kind, status, message) {
        super(message)
        this.kind = kind
        this.status = status
    }
}

const api = async (path, options) => {
    let resp
    try {
        resp = await fetch('/api' + path, options)
    } catch (e) {
        /* fetch only rejects when the request got no answer at all. */
        throw new ApiError('offline', 0, 'no answer from the simulator')
    }
    let body = null
    try { body = await resp.json() } catch (e) { /* no body, or not JSON */ }
    if (!resp.ok)
        throw new ApiError('refused', resp.status,
                           (body && body.error) ||
                           `${resp.status} ${resp.statusText}`)
    return body
}

document.addEventListener('alpine:init', () => {
    Alpine.data('admin', () => ({
        sims: [],
        /* simulation id -> { widget id -> widget } */
        widgets: {},
        /* simulation id -> root widget id */
        roots: {},
        /* "simId/widgetId" of the folded subtrees */
        folded: new Set(),
        selected: null,

        props: [],
        /* 'loading' until we know, so that "this widget has none" is only ever
         * said about a widget we actually managed to ask about. */
        propsState: 'loading',
        propsError: null,

        /* 'connecting' | 'online' | 'offline' */
        conn: 'connecting',
        lastError: null,
        lastOk: null,
        /* seconds between polls when all is well, and the growing wait between
         * attempts when it is not */
        period: 1,
        backoff: 1,
        maxBackoff: 20,
        nextTryAt: null,
        /* bumped every second purely so that the countdown re-renders */
        tock: 0,
        live: true,
        /* simulation id -> the reason its last command was refused */
        simError: {},

        /* Which simulation serves this page: the one that must never be
         * paused. It is the only one whose httpd widget we are talking to, so
         * we recognise it by that. */
        servingId: null,

        /*
         * Connection state
         */

        get online() { return this.conn === 'online' },
        get offline() { return this.conn === 'offline' },
        /* Something is on screen, but we can no longer vouch for it. */
        get stale() { return this.conn === 'offline' && this.lastOk !== null },

        get retryIn() {
            this.tock /* re-evaluate me every second */
            if (!this.nextTryAt) return 0
            return Math.max(0, Math.ceil((this.nextTryAt - Date.now()) / 1000))
        },

        get lastOkText() {
            this.tock
            if (!this.lastOk) return 'never'
            const secs = Math.round((Date.now() - this.lastOk) / 1000)
            if (secs < 2) return 'a moment ago'
            if (secs < 60) return secs + 's ago'
            return Math.floor(secs / 60) + 'min ago'
        },

        /* Every exchange with the server goes through here, so that the
         * connection state is decided in one place rather than at each call
         * site. Returns { ok, value } or { ok: false, error }. */
        async exchange(fn) {
            try {
                const value = await fn()
                this.conn = 'online'
                this.lastOk = Date.now()
                this.lastError = null
                this.backoff = 1
                return { ok: true, value }
            } catch (error) {
                if (error.kind === 'offline') {
                    this.conn = 'offline'
                    this.lastError = error.message
                } else {
                    /* It answered, so we are not offline -- it just said no. */
                    this.conn = 'online'
                    this.lastOk = Date.now()
                }
                return { ok: false, error }
            }
        },

        /*
         * Polling
         */

        async start() {
            setInterval(() => { this.tock++ }, 1000)
            await this.reload()
            this.schedule()
        },

        schedule() {
            const delay = this.offline ? this.backoff : this.period
            this.nextTryAt = Date.now() + delay * 1000
            clearTimeout(this.timer)
            this.timer = setTimeout(() => this.tick(), delay * 1000)
        },

        async tick() {
            if (this.live) {
                const wasOffline = this.offline
                await this.poll()
                if (wasOffline && this.online)
                    /* The topology may have changed while we could not see it,
                     * so come back with a full reload rather than a refresh. */
                    await this.reload()
                else if (this.offline)
                    this.backoff = Math.min(this.backoff * 2, this.maxBackoff)
            }
            this.schedule()
        },

        /* Ask again straight away, whatever the backoff had planned. */
        async retryNow() {
            this.backoff = 1
            clearTimeout(this.timer)
            await this.poll()
            if (this.online) await this.reload()
            this.schedule()
        },

        /* The cheap poll: clocks, and the selected widget's values. */
        async poll() {
            const r = await this.exchange(() => api('/simulations'))
            if (r.ok) this.sims = r.value
            /* Ask for the properties even when the first call just failed:
             * skipping it would leave the panel reporting itself as loaded,
             * which is the one thing it must not do when it is not. */
            if (this.selected) await this.loadProps()
        },

        /* Everything: the simulations and their widget trees. Needed whenever
         * the shape of things may have changed. */
        async reload() {
            const r = await this.exchange(() => api('/simulations'))
            if (!r.ok) return
            const sims = r.value
            const widgets = {}, roots = {}
            let serving = null
            for (const s of sims) {
                const list = await this.exchange(() =>
                    api(`/simulations/${s.id}/widgets`))
                if (!list.ok) return   /* it went away mid-reload; try later */
                const byId = {}
                for (const w of list.value) byId[w.id] = w
                widgets[s.id] = byId
                roots[s.id] = s.root
                if (serving === null &&
                    list.value.some(w => w.name.startsWith('httpd:')))
                    serving = s.id
            }
            this.sims = sims
            this.widgets = widgets
            this.roots = roots
            this.servingId = serving
            /* These describe attempts that are now history. */
            this.simError = {}
            /* A widget we were looking at may be gone. */
            if (this.selected && !this.get(this.selected.sim, this.selected.id))
                this.selected = null
            if (!this.selected && sims.length) {
                /* Open on something more interesting than a root if we can:
                 * the first simulation that is not the one serving us. */
                const s = sims.find(s => s.id !== serving) || sims[0]
                await this.select(s.id, s.root)
            } else if (this.selected) {
                /* Refresh the copy we hold, in case its relations changed. */
                const w = this.get(this.selected.sim, this.selected.id)
                this.selected = Object.assign({ sim: this.selected.sim }, w)
                await this.loadProps({ full: true })
            }
        },

        /*
         * Navigation
         */

        widgetsOf(simId) { return this.widgets[simId] || {} },
        get(simId, id) { return this.widgetsOf(simId)[id] },
        nameOf(id) {
            const w = this.selected && this.get(this.selected.sim, id)
            return w ? w.name : '#' + id
        },

        isSelected(simId, id) {
            return this.selected &&
                   this.selected.sim === simId && this.selected.id === id
        },

        async select(simId, id) {
            const w = this.get(simId, id)
            if (!w) return
            this.selected = Object.assign({ sim: simId }, w)
            /* Drop the previous widget's values rather than leaving them under
             * the new widget's name while the request is in flight. */
            this.props = []
            this.propsState = 'loading'
            this.propsError = null
            await this.loadProps({ full: true })
        },

        /* From the root down to the selected widget's parent. */
        ancestors() {
            const out = []
            let w = this.selected && this.get(this.selected.sim, this.selected.parent)
            while (w) {
                out.unshift(w)
                w = w.parent === null ? null : this.get(this.selected.sim, w.parent)
            }
            return out
        },

        children() {
            if (!this.selected) return []
            return this.selected.children
                       .map(id => this.get(this.selected.sim, id))
                       .filter(w => w)
        },

        /* Peers are split evenly to either side, so that a widget's picture is
         * laid out the same way every time it is visited. */
        peersLeft() {
            const p = (this.selected && this.selected.peers) || []
            return p.slice(0, Math.ceil(p.length / 2))
        },
        peersRight() {
            const p = (this.selected && this.selected.peers) || []
            return p.slice(Math.ceil(p.length / 2))
        },

        /*
         * The tree in the left column, flattened so that folding needs no
         * recursive component: each row carries its depth.
         */
        tree(simId) {
            const out = []
            const root = this.get(simId, this.roots[simId])
            if (!root) return out
            const walk = (w, depth) => {
                const key = simId + '/' + w.id
                const open = !this.folded.has(key)
                out.push({ w, depth, hasKids: w.children.length > 0, open })
                if (open)
                    for (const id of w.children) {
                        const c = this.get(simId, id)
                        if (c) walk(c, depth + 1)
                    }
            }
            walk(root, 0)
            return out
        },

        toggle(simId, id) {
            const key = simId + '/' + id
            if (this.folded.has(key)) this.folded.delete(key)
            else this.folded.add(key)
            /* Alpine does not track Set mutation: hand it a new one. */
            this.folded = new Set(this.folded)
        },

        /*
         * Properties
         */

        /* [full] adopts every value the simulator reports, editable fields
         * included. Without it -- which is how the once-a-second poll asks --
         * only the values that are merely displayed are refreshed, and the
         * fields one can type in are left strictly alone.
         *
         * Anything else makes editing impossible: a poll landing between two
         * keystrokes would put the old value back. A field showing a value a
         * few seconds old matters far less than being able to change it, and
         * the Refresh button is there to read the lot again. */
        async loadProps({ full = false } = {}) {
            if (!this.selected) {
                this.props = []
                this.propsState = 'loading'
                return
            }
            const { sim, id } = this.selected
            const r = await this.exchange(() =>
                api(`/simulations/${sim}/widgets/${id}/properties`))
            if (!r.ok) {
                /* Keep whatever we have, marked stale by the banner, rather
                 * than emptying the table -- an empty table reads as "this
                 * widget has no properties", which is a different statement. */
                this.propsState = 'failed'
                this.propsError = r.error.message
                if (r.error.status === 404) await this.reload()
                return
            }
            this.mergeProps(r.value, full)
            this.propsState = 'loaded'
            this.propsError = null
        },

        /* Fold what the simulator just said into what is on screen, reusing
         * the property objects the inputs are bound to: replacing them would
         * reset the inputs just as surely as overwriting their drafts. */
        mergeProps(incoming, full) {
            const known = {}
            for (const p of this.props) known[p.name] = p
            const merged = incoming.map(p => {
                const old = known[p.name]
                if (!old) {
                    p.text = asText(p.value)
                    p.draft = p.text
                    p.dirty = false
                    p.error = null
                    return p
                }
                /* An editable field: not ours to touch unless asked. */
                if (!full && !old.read_only) return old
                old.value = p.value
                old.text = asText(p.value)
                old.descr = p.descr
                old.kind = p.kind
                old.read_only = p.read_only
                /* Something typed but not accepted yet outlives even an
                 * explicit refresh: it is the reader's, not ours to drop. */
                if (!old.dirty) { old.draft = old.text ; old.error = null }
                return old
            })
            /* Reassigning the array re-runs the x-for; when the same objects
             * come back in the same order there is nothing to redraw. */
            const same = merged.length === this.props.length &&
                         merged.every((p, i) => p === this.props[i])
            if (!same) this.props = merged
        },

        async save(p) {
            if (p.read_only || p.draft === p.text) { p.dirty = false ; return }
            const { sim, id } = this.selected
            const r = await this.exchange(() => api(
                `/simulations/${sim}/widgets/${id}/properties/${encodeURIComponent(p.name)}`,
                { method: 'PUT', body: encode(p) }))
            if (!r.ok) {
                /* Say which of the two happened: "the simulator refused 1e9"
                 * and "we never reached the simulator" call for different
                 * things from whoever is reading. */
                p.error = r.error.kind === 'offline'
                    ? 'not saved: no answer from the simulator'
                    : r.error.message
                p.dirty = true
                return
            }
            p.value = r.value.value
            p.text = asText(r.value.value)
            p.draft = p.text
            p.dirty = false
            p.error = null
        },

        /*
         * Clock control
         */

        async control(sim, action) {
            const r = await this.exchange(() =>
                api(`/simulations/${sim.id}/${action}`, { method: 'POST' }))
            /* Alpine does not see mutation of a nested object: replace it. */
            this.simError = Object.assign({}, this.simError,
                { [sim.id]: r.ok ? null
                          : r.error.kind === 'offline'
                            ? 'no answer from the simulator'
                            : r.error.message })
            if (r.ok) await this.poll()
        },
    }))
})

/* The administration interface.
 *
 * Everything here goes through the REST API; this file knows nothing about the
 * simulator beyond what /api serves. A widget is identified by the pair
 * (simulation id, widget id), which is how the API addresses it too.
 */

const api = async (path, options) => {
    const resp = await fetch('/api' + path, options)
    let body = null
    try { body = await resp.json() } catch (e) { /* no body, or not JSON */ }
    if (!resp.ok) {
        const msg = (body && body.error) || (resp.status + ' ' + resp.statusText)
        throw new Error(msg)
    }
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
        error: null,
        live: true,
        period: 1,
        /* Which simulation serves this page: the one that must never be
         * paused. It is the only one whose httpd widget we are talking to, so
         * we recognise it by that. */
        servingId: null,

        async start() {
            await this.reload()
            /* Poll rather than push: opache answers whole responses, so there
             * is no streaming to be had. */
            setInterval(() => { if (this.live) this.refresh() }, this.period * 1000)
        },

        /* Full reload: the list of simulations and every widget tree. Only
         * needed when the shape of things may have changed. */
        async reload() {
            try {
                this.sims = await api('/simulations')
                for (const s of this.sims) {
                    const list = await api(`/simulations/${s.id}/widgets`)
                    const byId = {}
                    for (const w of list) byId[w.id] = w
                    this.widgets[s.id] = byId
                    this.roots[s.id] = s.root
                    if (this.servingId === null &&
                        list.some(w => w.name.startsWith('httpd:')))
                        this.servingId = s.id
                }
                if (!this.selected && this.sims.length) {
                    /* Open on something more interesting than a root if we can:
                     * the first simulation that is not the one serving us. */
                    const s = this.sims.find(s => s.id !== this.servingId)
                                || this.sims[0]
                    this.select(s.id, s.root)
                }
                this.error = null
            } catch (e) {
                this.error = e.message
            }
        },

        /* Cheap refresh: clocks, and the selected widget's values. */
        async refresh() {
            try {
                this.sims = await api('/simulations')
                if (this.selected) await this.loadProps()
                this.error = null
            } catch (e) {
                this.error = e.message
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
            await this.loadProps()
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

        async loadProps() {
            if (!this.selected) return
            const { sim, id } = this.selected
            try {
                const ps = await api(`/simulations/${sim}/widgets/${id}/properties`)
                /* Keep the draft the user is editing, so that a refresh landing
                 * mid-edit does not yank the field from under them. */
                const drafts = {}
                for (const p of this.props) if (p.dirty) drafts[p.name] = p.draft
                for (const p of ps) {
                    p.draft = (p.name in drafts) ? drafts[p.name] : p.value
                    p.dirty = p.name in drafts
                    p.error = null
                }
                this.props = ps
            } catch (e) {
                this.error = e.message
            }
        },

        async save(p) {
            if (p.read_only || p.draft === p.value) { p.dirty = false ; return }
            const { sim, id } = this.selected
            try {
                /* The body *is* the value: property values are strings all the
                 * way down to the setter. */
                const updated = await api(
                    `/simulations/${sim}/widgets/${id}/properties/${encodeURIComponent(p.name)}`,
                    { method: 'PUT', body: p.draft })
                p.value = updated.value
                p.draft = updated.value
                p.dirty = false
                p.error = null
            } catch (e) {
                /* Whatever the setter refused, say so next to the field rather
                 * than in the status bar: it belongs to this property. */
                p.error = e.message
                p.dirty = true
            }
        },

        /*
         * Clock control
         */

        async control(sim, action) {
            try {
                await api(`/simulations/${sim.id}/${action}`, { method: 'POST' })
                await this.refresh()
            } catch (e) {
                this.error = e.message
            }
        },
    }))
})

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

/* What the input is built from: for a value that may be absent, the kind of
 * the value it may hold. */
const baseKind = (kind) => kind.type === 'optional' ? kind.of : kind

/* What the field must show for a value that came from the simulator. A value
 * that is not set keeps whatever was in the field: the input is only disabled,
 * so ticking the box back hands the reader what they had. */
const draftFor = (p, text) =>
    p.kind.type === 'optional' && p.value === null ? p.draft : text

const encode = (p) => {
    /* Unticked is a value in itself: there is none. */
    if (p.kind.type === 'optional' && !p.enabled) return 'null'
    switch (baseKind(p.kind).type) {
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

/* A count reads better with its thousands apart, and a duration in the unit it
 * happens to be in. */
const num = (n) => Number(n).toLocaleString()

const dur = (s) => {
    if (s < 1e-3) return (s * 1e6).toFixed(0) + 'us'
    if (s < 1) return (s * 1e3).toFixed(s < 1e-2 ? 1 : 0) + 'ms'
    if (s < 60) return s.toFixed(s < 10 ? 2 : 1) + 's'
    if (s < 3600) return Math.floor(s / 60) + 'min ' + (s % 60).toFixed(0) + 's'
    return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'min'
}

/* The speeds the buttons walk through: powers of two around real time, with
 * "as fast as it can" off the top of the ladder. Any other speed can still be
 * set through the API; the buttons then move to the neighbouring rung. */
const speeds = [ 1/64, 1/32, 1/16, 1/8, 1/4, 1/2, 1, 2, 4, 8, 16, 32, 64, 128,
                 256, 512, 1024 ]

/* Halves and doubles read better as fractions than as 0.0156. */
const ratioText = (r) => {
    if (r >= 1) return String(Number(r.toFixed(4)))
    const inv = 1 / r
    return Math.abs(inv - Math.round(inv)) < 1e-6 ? '1/' + Math.round(inv)
                                                  : String(Number(r.toFixed(4)))
}

/* How long a value that just moved stays lit. Shorter than the poll, so that
 * something changing on every refresh pulses rather than staying lit -- which
 * would say no more than a steady colour does. */
const highlightMs = 400

/* Rows arrive in whatever order the simulator's hash table held them, which is
 * neither stable nor meaningful. Order them by their parameters, comparing
 * numbers as numbers so that port 9 comes before port 10. The names are
 * already in the same order in every row of a metric, the simulator keeping
 * them sorted. */
const compareParams = (a, b) => {
    const ea = Object.entries(a), eb = Object.entries(b)
    for (let i = 0; i < Math.min(ea.length, eb.length); i++) {
        const [ka, va] = ea[i], [kb, vb] = eb[i]
        if (ka !== kb) return ka < kb ? -1 : 1
        if (va !== vb) {
            if (typeof va === 'number' && typeof vb === 'number') return va - vb
            return String(va) < String(vb) ? -1 : 1
        }
    }
    return ea.length - eb.length
}

/* Every kind of metric is a family, keyed by the parameters of the events it
 * measures, so all of them read as rows -- usually just the one, since most
 * metrics take no parameters. This turns any of them into those rows, so that
 * the page can render a metric without knowing which kind it is: a headline
 * figure, the detail behind it, and when the metric was last touched.
 *
 * The kinds differ only in what those figures mean: a counter totals, a gauge
 * holds a current value between two bounds, an atomic counts occurrences, and
 * a timed is a distribution of durations with some still running. */
const metricView = (m, units) => {
    if (!m || !m.kind) return { rows: [], last: null }
    /* What the figures are counted in, when the property says: a counter of
     * bytes reads "1,234 bytes". A duration already knows what it is and is
     * written as one, so it has nothing to take from here. */
    const suffix = units ? ' ' + units : ''
    const key = (params) => JSON.stringify(params)
    /* The sub-metrics are keyed the same way, so a row can be completed from
     * them. */
    const lookup = (list, params) => {
        const e = (list || []).find(e => key(e.params) === key(params))
        return e ? e.value : null
    }
    const last = (fl) => fl ? fl.last : null
    /* [key] identifies a row across refreshes: which parameters it is for. */
    const rows = []
    const push = (row) => rows.push(Object.assign(row, { key: key(row.params) }))
    switch (m.kind) {
        case 'atomic':
            /* The figure counts events, so the unit is what those events are:
               "12 queries" rather than "12 times". */
            for (const e of m.counts)
                push({ params: e.params, figure: num(e.value),
                       detail: units || 'times' })
            return { rows, last: last(m.first_last) }

        case 'counter': {
            for (const e of m.values) {
                const times = lookup(m.fired.counts, e.params)
                push({ params: e.params,
                            figure: num(e.value) + suffix,
                            /* How many times it was added to is worth saying
                             * only when it is not the total itself, which it
                             * is for anything counted one at a time. */
                            detail: times === null || times === e.value ? ''
                                  : 'over ' + num(times) + ' times' })
            }
            return { rows, last: last(m.fired.first_last) }
        }

        case 'gauge':
            for (const e of m.values)
                push({ params: e.params,
                            figure: num(e.value.current) + suffix,
                            detail: 'between ' + num(e.value.min) +
                                    ' and ' + num(e.value.max) })
            return { rows, last: last(m.first_last) }

        case 'timed': {
            const seen = new Set()
            for (const e of m.durations) {
                const d = e.value
                const running = lookup(m.simult.values, e.params)
                seen.add(key(e.params))
                push({ params: e.params,
                            figure: dur(d.sum / d.count) + ' on average',
                            detail: num(d.count) + ' of them, ' + dur(d.min) +
                                    ' to ' + dur(d.max) +
                                    (running && running.current
                                        ? ', ' + running.current + ' still running' : '') })
            }
            /* Started and not finished: it has no duration yet, but saying
             * nothing about it would be worse than saying that much. */
            for (const e of (m.simult ? m.simult.values : []))
                if (!seen.has(key(e.params)) && e.value.current)
                    push({ params: e.params,
                                figure: e.value.current + ' running',
                                detail: 'none finished yet' })
            return { rows, last: m.stops ? last(m.stops.first_last) : null }
        }
    }
    return { rows: [], last: null }
}

/* Order the rows, and note which of them are showing something new: a figure
 * that just moved is worth pointing at, and a table of numbers refreshing in
 * place gives the reader no clue which one did. */
const metricRows = (m, units, previous) => {
    const view = metricView(m, units)
    view.rows.sort((a, b) => compareParams(a.params, b.params))
    const was = new Map()
    for (const row of (previous ? previous.rows : [])) was.set(row.key, row)
    for (const row of view.rows) {
        const before = was.get(row.key)
        row.changedAt =
            !before ? null :
            before.figure !== row.figure || before.detail !== row.detail
                ? Date.now() : before.changedAt
    }
    return view
}

/*
 * Charts
 *
 * uPlot instances, the elements they live in and the points they draw are kept
 * out of Alpine's reactive data: it deep-proxies whatever it holds, and a
 * proxy around something that keeps DOM references and compares them by
 * identity is asking for trouble. The reactive side holds the descriptions --
 * which metric is in which chart -- and these hold the pixels and the numbers.
 */
const plots = new Map()    /* chart id -> { u, el, signature } */
const history = new Map()  /* metric key -> { last, kind, units, rows } */
/* The button the chart menu is hanging from, for the same reason: which menu
 * is open is a name the page reacts to, but the element it is pinned to is
 * one of the pixels. */
let menuAnchor = null

const metricKey = (m) => `${m.sim}/${m.widget}/${m.property}`
const rowKey = (m, params) => metricKey(m) + '/' + JSON.stringify(params)

/* How much of a series is kept here. The simulator keeps a bounded history of
 * its own and this only ever holds what it was told, but a page left open for
 * a day would otherwise accumulate every point it ever saw. */
const maxPoints = 2000

/* Distinguishable at a glance and stable within a chart: a line keeps its
 * colour as others come and go, since it is picked by position among the
 * lines the chart was given, not among those it happens to show. */
const palette = [ '#1f77b4', '#d62728', '#2ca02c', '#ff7f0e', '#9467bd',
                  '#17becf', '#8c564b', '#e377c2' ]

/* Fold an answer from .../history into what is kept for that metric. Points
 * arrive oldest first and only ever after the ones we have, so appending is
 * all there is to it. */
const mergeHistory = (m, answer) => {
    const key = metricKey(m)
    let h = history.get(key)
    if (!h) { h = { last: null, rows: new Map() } ; history.set(key, h) }
    h.kind = answer.kind
    h.units = answer.units
    for (const s of answer.series) {
        const k = JSON.stringify(s.params)
        let row = h.rows.get(k)
        if (!row) { row = { params: s.params, pts: [] } ; h.rows.set(k, row) }
        for (const p of s.points) {
            row.pts.push(p)
            if (h.last === null || p.t > h.last) h.last = p.t
        }
        if (row.pts.length > maxPoints)
            row.pts.splice(0, row.pts.length - maxPoints)
    }
}

/* What is drawn for one row, from the points as the simulator wrote them down.
 *
 * A counter holds a running total, which as a line says only that time passes:
 * what is worth looking at is how fast it grows. A total that drops means
 * somebody reset it -- a break in the line, not a negative rate.
 *
 * A gauge is drawn as it stands, a duration as its average over the interval
 * ((sum - sum') / (count - count')), and both carry the extremes of that same
 * interval, which is what the band is drawn from. An interval in which nothing
 * was measured has no average and no extremes: a gap, honestly. */
const lineOf = (kind, pts) => {
    const xs = [], ys = [], los = [], his = []
    const banded = kind === 'gauge' || kind === 'timed'
    for (let i = 0; i < pts.length; i++) {
        const p = pts[i], prev = i > 0 ? pts[i - 1] : null
        xs.push(p.t)
        if (kind === 'counter' || kind === 'atomic') {
            const dt = prev ? p.t - prev.t : 0
            ys.push(prev && dt > 0 && p.value >= prev.value
                    ? (p.value - prev.value) / dt : null)
        } else if (kind === 'gauge') {
            ys.push(p.value.current)
            los.push(p.value.sample_min)
            his.push(p.value.sample_max)
        } else {
            const dn = prev ? p.value.count - prev.value.count : 0
            ys.push(dn > 0 ? (p.value.sum - prev.value.sum) / dn : null)
            los.push(p.value.sample_min)
            his.push(p.value.sample_max)
        }
    }
    return { xs, ys, los: banded ? los : null, his: banded ? his : null }
}

/* A rate is per second whatever it counts. An atomic counts events and can say
 * so; a counter without a unit cannot say what it counts, so it says only how
 * often. A duration is a duration. */
const lineUnits = (kind, units) =>
    kind === 'atomic' ? (units || 'events') + '/s' :
    kind === 'counter' ? (units || '') + '/s' :
    kind === 'timed' ? 'secs' : units

const lineText = (kind, y) =>
    y === null || y === undefined ? '--' :
    kind === 'timed' ? dur(y) :
    Math.abs(y) >= 100 ? num(Math.round(y)) : String(Number(y.toFixed(2)))

/* Every line of a chart shares one x, since they are all sampled by the same
 * simulation at the same instants -- but a row that appeared late has fewer
 * points than one that was always there, so the axis is the union of what they
 * hold, and a line says nothing where it has nothing. */
const alignedData = (lines) => {
    const all = new Set()
    for (const l of lines) for (const x of l.xs) all.add(x)
    const xs = [ ...all ].sort((a, b) => a - b)
    const at = new Map()
    xs.forEach((x, i) => at.set(x, i))
    const spread = (src, values) => {
        const out = new Array(xs.length).fill(null)
        src.forEach((x, i) => { out[at.get(x)] = values[i] })
        return out
    }
    const data = [ xs ]
    for (const l of lines) {
        data.push(spread(l.xs, l.ys))
        if (l.los) { data.push(spread(l.xs, l.los)) ; data.push(spread(l.xs, l.his)) }
    }
    return data
}

/* Build (or rebuild) the plot of a chart. The instance is thrown away and made
 * again only when the lines themselves change, which is rare; a poll just
 * hands it new numbers. */
const drawChart = (id, lines) => {
    const p = plots.get(id)
    if (!p || !p.el) return
    const signature = lines.map(l => l.key).join('|')
    const data = alignedData(lines)
    if (p.u && p.signature === signature) { p.u.setData(data) ; return }
    if (p.u) { p.u.destroy() ; p.u = null }
    if (!lines.length) return
    /* One scale per unit, two at most: a chart of bytes and one of seconds
     * share an axis only by accident. */
    const units = [ ...new Set(lines.map(l => l.units)) ]
    const series = [ {} ], bands = []
    for (const l of lines) {
        const scale = l.units || 'y'
        series.push({ label: l.label, stroke: l.color, width: 1.5,
                      scale, points: { show: false } })
        if (l.los) {
            const lo = series.length, hi = lo + 1
            series.push({ scale, stroke: 'transparent', points: { show: false } })
            series.push({ scale, stroke: 'transparent', points: { show: false } })
            bands.push({ series: [ hi, lo ], fill: l.color + '25' })
        }
    }
    const axes = [ { stroke: '#888', grid: { stroke: '#8884' } } ]
    units.forEach((u, i) => {
        if (i > 1) return
        axes.push({ scale: u || 'y', side: i === 0 ? 3 : 1, label: u || undefined,
                    stroke: '#888', grid: { stroke: i === 0 ? '#8884' : 'transparent' } })
    })
    p.signature = signature
    p.u = new uPlot({
        width: p.el.clientWidth || 600,
        height: p.el.clientHeight || 140,
        legend: { show: false },
        cursor: { y: false },
        scales: { x: { time: true } },
        series, bands, axes,
    }, data, p.el)
}

/*
 * Logs
 *
 * What the watched widgets have logged, merged into one chronology. Kept out
 * of the reactive data for the same reason the chart points are: it is a lot
 * of it, and none of it is edited.
 */
const logs = new Map()   /* "sim/widget" -> { last, level, lines } */

const widgetKey = (w) => `${w.sim}/${w.widget}`

/* Enough to be worth scrolling through, and no more: the simulator keeps a
 * bounded history of its own, and a window left open for an afternoon must not
 * turn into an unread heap of debug lines nobody will ever read. */
const maxLogLines = 2000

/* The levels, most serious first, as the API names them. A level is how deep
 * to go, not which one to show: picking "info" asks for everything down to it,
 * fatal included. */
const levels = [ 'fatal', 'critical', 'error', 'warning', 'info', 'debug' ]

/* Fold one answer into what is kept for that widget. A gap the simulator
 * reports -- messages it had to overwrite before we asked for them -- becomes
 * a line of its own, in the place where the missing ones would have been: a
 * log that goes quiet about what it dropped is a log that lies. */
const mergeLogs = (w, answer) => {
    const key = widgetKey(w)
    let l = logs.get(key)
    if (!l) { l = { last: null, lines: [] } ; logs.set(key, l) }
    const line = (m, lost) => ({
        t: m.t, level: lost ? 'lost' : m.level, text: m.text,
        who: w.name, color: w.color,
        /* Stable across polls, and unique: several messages share an instant
         * by design, since a whole dispatch is logged at one. */
        key: key + '/' + m.t + '/' + (l.lines.length + Math.random()) })
    if (answer.lost)
        l.lines.push(line({ t: answer.messages.length ? answer.messages[0].t
                                                      : answer.now,
                            text: 'some messages were overwritten before we ' +
                                  'asked for them -- slow the simulation down ' +
                                  'to follow this closely' }, true))
    for (const m of answer.messages) {
        l.lines.push(line(m, false))
        if (l.last === null || m.t > l.last) l.last = m.t
    }
    if (l.lines.length > maxLogLines)
        l.lines.splice(0, l.lines.length - maxLogLines)
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

/* How many whole values a slider may span before dragging it becomes a game
 * of chance and the number input is the only honest control. */
const sliderValues = 10000

/* A property the reader can type into: what a poll must never overwrite. */
const isEditable = (p) => !p.read_only && baseKind(p.kind).type !== 'metric'

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
        /* Why the last widget offered to the log window was not taken. */
        logError: null,

        /* Which simulation serves this page: the one that must never be
         * paused. It is the only one whose httpd widget we are talking to, so
         * we recognise it by that. */
        servingId: null,

        /* The charts, which outlive the selection: one is opened while looking
         * at a hub and watched while looking at something else. Only their
         * descriptions live here -- see [plots] and [history] for the rest. */
        charts: [],
        chartSeq: 1,
        /* Bumped when new points arrive, purely so that the legends, which
         * read from [history], are re-rendered. */
        chartTock: 0,
        /* The metric being dragged, and the chart the cursor is over. */
        dragging: null,
        dragOver: null,
        /* The metric whose chart menu is open, by property name, and the chart
         * that menu is pointing at as the pointer moves down it. Dragging is
         * the quicker way to put a metric on a chart, but not one to depend
         * on: a touch screen has no drag, and neither has a browser told not
         * to. */
        chartMenu: null,
        chartHint: null,

        /* The widgets whose logs are watched, each at its own level: some are
         * far more talkative than others, and the one being followed is
         * usually not the one that needs quietening. */
        logged: [],
        logTock: 0,
        /* Whether the window follows the newest line. It does until the reader
         * scrolls up, and again as soon as they come back to the bottom:
         * anything else fights whoever is trying to read. */
        logFollow: true,
        pollingLogs: false,

        /* Which panels of the dock are folded away. Remembered across
         * reloads: a reader who folds the graph away wants it folded away
         * tomorrow too. */
        collapsed: { charts: false, logs: false },

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
            this.restoreFolds()
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
            if (this.charts.length) await this.pollCharts()
            if (this.logged.length) await this.pollLogs()
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
            /* It was opened on a property of the widget being left. */
            this.chartMenu = null
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
                    p.enabled = p.value !== null
                    p.dirty = false
                    p.error = null
                    p.metric = p.kind.type === 'metric'
                        ? metricRows(p.value, p.units) : null
                    return p
                }
                /* A field one types in is not ours to touch unless asked. A
                 * metric is not one: it is read, and reset at most, so it
                 * refreshes like any other value even when it is writable. */
                if (!full && isEditable(old)) return old
                old.value = p.value
                old.text = asText(p.value)
                old.descr = p.descr
                old.units = p.units
                old.kind = p.kind
                old.read_only = p.read_only
                if (p.kind.type === 'metric') {
                    old.metric = metricRows(p.value, p.units, old.metric)
                    if (old.metric.rows.some(r => this.fresh(r.changedAt)))
                        this.unlightLater()
                /* A value that is only ever displayed: say when it moved. */
                } else if (old.text !== asText(p.value)) {
                    old.changedAt = Date.now()
                    this.unlightLater()
                }
                /* Something typed but not accepted yet outlives even an
                 * explicit refresh: it is the reader's, not ours to drop. */
                if (!old.dirty) {
                    old.draft = draftFor(old, old.text)
                    old.enabled = p.value !== null
                    old.error = null
                }
                return old
            })
            /* Reassigning the array re-runs the x-for; when the same objects
             * come back in the same order there is nothing to redraw. */
            const same = merged.length === this.props.length &&
                         merged.every((p, i) => p === this.props[i])
            if (!same) this.props = merged
        },

        /* A range is drawn as a slider beside the number input, but only when
         * the slider has something to offer: it needs both ends to draw a
         * track between, and, when only whole numbers will do, few enough of
         * them that a drag lands on the one that was aimed at. A lease time of
         * "zero to as long as you like" is left to the number input alone.
         * A missing end is one that means "no bound" -- the API sends null
         * rather than an infinity, which JSON cannot carry, or [max_int],
         * which no slider could span. */
        hasSlider(kind) {
            return kind.min !== null && kind.max !== null &&
                   (!kind.int || kind.max - kind.min <= sliderValues)
        },

        /* Whole ranges step by one, so that the slider can only ever produce a
         * value the setter accepts; a continuous one divides its track into a
         * thousand, which is finer than the track has pixels. */
        sliderStep(kind) {
            return kind.int ? 1 : (kind.max - kind.min) / 1000
        },

        /* Whatever is written to a metric resets it; the value does not
         * matter, so send the least meaningful one. */
        async resetMetric(p) {
            const { sim, id } = this.selected
            const r = await this.exchange(() => api(
                `/simulations/${sim}/widgets/${id}/properties/${encodeURIComponent(p.name)}`,
                { method: 'PUT', body: 'null' }))
            if (!r.ok) {
                p.error = r.error.kind === 'offline'
                    ? 'not reset: no answer from the simulator'
                    : r.error.message
                return
            }
            p.value = r.value.value
            p.metric = metricRows(p.value, p.units, p.metric)
            p.error = null
        },

        /* How long ago, on the clock of the simulation being looked at: a
         * metric of a simulation running as fast as it can is dated by that
         * simulation's clock, not by the wall clock the page runs on. */
        ago(t) {
            const s = this.selected && this.sims.find(s => s.id === this.selected.sim)
            if (!s || t === null || t === undefined) return ''
            const d = s.now - t
            return d <= 0 ? 'just now' : dur(d) + ' ago'
        },

        /* A simulated time as a clock reads it. Three decimals rather than
         * the two the simulator shows for the present: a whole dispatch is
         * logged at one instant, and the reader is looking for the boundaries
         * between them. */
        clock(t) {
            const d = new Date(t * 1000)
            return d.toTimeString().slice(0, 8) + '.' +
                   String(d.getMilliseconds()).padStart(3, '0')
        },

        fresh(t) {
            this.tock /* re-evaluate me as time passes */
            return t != null && Date.now() - t < highlightMs
        },

        /* [tock] only ticks once a second, far too slow to put a highlight
         * out on time: after marking something as changed, ask for one
         * re-evaluation at the moment it stops being true. */
        unlightLater() {
            clearTimeout(this.unlightTimer)
            this.unlightTimer = setTimeout(() => this.tock++, highlightMs + 30)
        },

        /* The kind whose input this property gets: see [baseKind]. */
        base(p) {
            return baseKind(p.kind)
        },

        /* Has this property a value to edit at all? Anything that cannot be
         * absent always has one. */
        set(p) {
            return p.kind.type !== 'optional' || p.enabled
        },

        paramsText(params) {
            return Object.entries(params).map(([k, v]) => k + '=' + v).join(', ')
        },

        /* The tick box in front of a value that may be absent. Unticking is
         * itself a value -- there is none -- so it saves at once; ticking
         * cannot save yet, since the field holds whatever was there before it
         * was unset and it is the reader's to confirm or change. */
        async toggleOptional(p, el) {
            if (!p.enabled) return await this.save(p)
            const input = el.closest('td')
                            .querySelector('input[type=number], input[type=text], select')
            if (input) this.$nextTick(() => input.focus())
        },

        async save(p) {
            /* Neither the value nor its presence has moved: nothing to say. */
            const unchanged =
                p.draft === p.text &&
                (p.kind.type !== 'optional' || p.enabled === (p.value !== null))
            if (p.read_only || unchanged) { p.dirty = false ; return }
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
            p.draft = draftFor(p, p.text)
            p.enabled = r.value.value !== null
            p.dirty = false
            p.error = null
        },

        /*
         * Charts
         */

        /* Every metric a chart wants, once: the same metric in two charts is
         * one request, and the answer feeds both. */
        wantedMetrics() {
            const wanted = new Map()
            for (const c of this.charts)
                for (const m of c.metrics)
                    wanted.set(metricKey(m), m)
            return [ ...wanted.values() ]
        },

        /* Ask each of them for what has been written down since the last point
         * we hold: the whole history the first time, a point or two after
         * that. */
        async pollCharts() {
            for (const m of this.wantedMetrics()) {
                const h = history.get(metricKey(m))
                const since = h && h.last !== null ? `?since=${h.last}` : ''
                const r = await this.exchange(() => api(
                    `/simulations/${m.sim}/widgets/${m.widget}` +
                    `/properties/${encodeURIComponent(m.property)}/history${since}`))
                /* A metric that has gone (its widget deleted, say) leaves the
                 * charts it was in rather than making every poll fail. */
                if (!r.ok) {
                    if (r.error.status === 404) this.forget(m)
                    continue
                }
                mergeHistory(m, r.value)
            }
            this.chartTock++
            for (const c of this.charts) drawChart(c.id, this.lines(c))
        },

        /* What a chart draws, and what its legend lists: one line per metric
         * and set of parameters, minus the ones struck off. */
        lines(chart) {
            this.chartTock /* re-read me when points arrive */
            const lines = []
            let colour = 0
            for (const m of chart.metrics) {
                const h = history.get(metricKey(m))
                if (!h) continue
                const rows = [ ...h.rows.values() ]
                    .sort((a, b) => compareParams(a.params, b.params))
                for (const row of rows) {
                    const key = rowKey(m, row.params)
                    const color = palette[colour++ % palette.length]
                    if (chart.hidden.includes(key)) continue
                    const l = lineOf(h.kind, row.pts)
                    const params = this.paramsText(row.params)
                    lines.push({ key, color, ...l,
                                 units: lineUnits(h.kind, h.units),
                                 label: `${m.widgetName} ${m.property}` +
                                        (params ? ` (${params})` : ''),
                                 text: lineText(h.kind, l.ys[l.ys.length - 1]) })
                }
            }
            return lines
        },

        /* The metric a property row stands for. */
        metricOf(p) {
            const w = this.get(this.selected.sim, this.selected.id)
            return { sim: this.selected.sim, widget: this.selected.id,
                     widgetName: w ? w.name : '#' + this.selected.id,
                     property: p.name }
        },

        addChart(p) {
            const chart = { id: this.chartSeq++, sim: this.selected.sim,
                            metrics: [ this.metricOf(p) ], hidden: [] }
            this.charts.push(chart)
            this.chartTock++
            this.pollCharts()
        },

        /* Where the plot of a chart lives. Mounted from the template, since
         * that is where the element comes into being. */
        mountChart(chart, el) {
            plots.set(chart.id, { u: null, el, signature: null })
            /* uPlot is told a size in pixels, so it has to be told again when
             * the page gives it a different one. */
            const watcher = new ResizeObserver(() => {
                const p = plots.get(chart.id)
                if (p && p.u && el.clientWidth)
                    p.u.setSize({ width: el.clientWidth, height: el.clientHeight })
            })
            watcher.observe(el)
            plots.get(chart.id).watcher = watcher
            drawChart(chart.id, this.lines(chart))
        },

        startDrag(p, event) {
            this.dragging = this.metricOf(p)
            /* Firefox starts no drag at all without something to carry. */
            event.dataTransfer.setData('text/plain', p.name)
            event.dataTransfer.effectAllowed = 'copy'
        },

        /* A chart is one simulation's: its lines share a clock, and two clocks
         * on one axis would say nothing. */
        canDrop(chart) {
            return this.dragging !== null && this.dragging.sim === chart.sim
        },

        dropOn(chart) {
            this.dragOver = null
            if (!this.canDrop(chart)) return
            const m = this.dragging
            this.dragging = null
            this.place(chart, m)
        },

        /* A metric onto a chart, however it was asked for -- dropped there, or
         * picked off the menu. */
        place(chart, m) {
            if (chart.metrics.some(x => metricKey(x) === metricKey(m))) return
            chart.metrics.push(m)
            /* Struck off in an earlier life, but asked for again now. */
            chart.hidden = chart.hidden.filter(k => !k.startsWith(metricKey(m) + '/'))
            this.pollCharts()
        },

        /*
         * The chart menu: the same choice as dragging, for the platforms and
         * the readers that have no drag.
         */

        /* The charts this metric could join. A chart is one simulation's: its
         * lines share a clock, and two clocks on one axis would say nothing. */
        chartsHere() {
            return this.selected
                 ? this.charts.filter(c => c.sim === this.selected.sim) : []
        },

        openChartMenu(p, button) {
            /* With no chart to choose between, the only answer the menu could
             * give is the one a click gives directly. */
            if (!this.chartsHere().length) { this.addChart(p) ; return }
            this.chartHint = null
            if (this.chartMenu === p.name) { this.chartMenu = null ; return }
            this.chartMenu = p.name
            menuAnchor = button
            /* Once it is on the page and has a height to measure. */
            this.$nextTick(() => this.placeMenu())
        },

        /* The menu hangs off the page rather than out of the properties. They
         * scroll within their own half of the window, and anything of ours
         * reaching past the bottom of that is cut off there -- the reader
         * would get a menu with its last entries missing, or none of it at
         * all, hidden behind the dock. Fixed to the window instead, it can go
         * where there is room: below the button, or above it when what is left
         * below is the dock, which is about other things. */
        placeMenu() {
            const menu = menuAnchor &&
                         menuAnchor.parentElement.querySelector('ul.menu')
            if (!menu) return
            const b = menuAnchor.getBoundingClientRect()
            const view = menuAnchor.closest('.widget-view')
            const floor = view ? view.getBoundingClientRect().bottom
                               : window.innerHeight
            const gap = 4
            const height = menu.offsetHeight
            menu.style.top = (b.bottom + gap + height <= floor
                              ? b.bottom + gap
                              : Math.max(gap, b.top - gap - height)) + 'px'
            menu.style.left = (b.right - menu.offsetWidth) + 'px'
        },

        /* Fixed to the window, the menu does not follow the properties as they
         * scroll: it is put back where its button now is, and dropped once
         * that button has been scrolled out of sight. */
        repositionMenu() {
            if (this.chartMenu === null) return
            const view = menuAnchor && menuAnchor.isConnected &&
                         menuAnchor.closest('.widget-view')
            if (!view) { this.chartMenu = null ; return }
            const b = menuAnchor.getBoundingClientRect()
            const v = view.getBoundingClientRect()
            if (b.bottom < v.top || b.top > v.bottom) this.chartMenu = null
            else this.placeMenu()
        },

        /* Charts are numbered by where they are on screen rather than by the
         * order they were opened in: the number is read off this menu and
         * matched against what is in front of the reader, and nothing else
         * ever refers to it. Hence also that they are named only while the
         * menu is open. */
        chartName(chart) {
            return 'Chart ' + (this.charts.indexOf(chart) + 1)
        },

        holds(chart, p) {
            const key = metricKey(this.metricOf(p))
            return chart.metrics.some(m => metricKey(m) === key)
        },

        newChart(p) {
            this.chartMenu = null
            this.chartHint = null
            this.addChart(p)
        },

        addTo(chart, p) {
            this.chartMenu = null
            this.chartHint = null
            this.place(chart, this.metricOf(p))
        },

        /* Striking off the last line of a metric drops the metric, and a chart
         * with nothing left in it is a chart nobody asked for. */
        removeLine(chart, key) {
            chart.hidden.push(key)
            chart.metrics = chart.metrics.filter(m =>
                this.lines(chart).some(l => l.key.startsWith(metricKey(m) + '/')))
            if (!chart.metrics.length) this.closeChart(chart)
            else drawChart(chart.id, this.lines(chart))
        },

        closeChart(chart) {
            const p = plots.get(chart.id)
            if (p && p.u) p.u.destroy()
            if (p && p.watcher) p.watcher.disconnect()
            plots.delete(chart.id)
            this.charts = this.charts.filter(c => c.id !== chart.id)
            if (this.chartHint === chart.id) this.chartHint = null
        },

        /* Drop a metric from every chart that holds it. */
        forget(m) {
            const key = metricKey(m)
            history.delete(key)
            for (const c of [ ...this.charts ]) {
                c.metrics = c.metrics.filter(x => metricKey(x) !== key)
                if (!c.metrics.length) this.closeChart(c)
            }
        },

        /*
         * Logs
         */

        /* Is the selected widget among those being watched? *(The button that
         * adds it says so, and takes it off again.) */
        isLogged(w) {
            return this.logged.some(x => x.sim === w.sim && x.widget === w.id)
        },

        toggleLogged() {
            const { sim, id } = this.selected
            if (this.isLogged({ sim, id })) {
                this.unwatch(this.logged.find(x =>
                    x.sim === sim && x.widget === id))
                return
            }
            /* One clock per window: lines from two simulations interleaved by
             * time would be in an order that means nothing. */
            if (this.logged.length && this.logged[0].sim !== sim) {
                this.logError =
                    'The log window follows one simulation at a time; take ' +
                    'the others off it first.'
                return
            }
            const w = this.get(sim, id)
            this.logged.push({ sim, widget: id, name: w ? w.name : '#' + id,
                               level: 'info',
                               color: palette[this.logged.length % palette.length] })
            this.logError = null
            this.pollLogs()
        },

        unwatch(w) {
            logs.delete(widgetKey(w))
            this.logged = this.logged.filter(x => x !== w)
            this.logError = null
            this.logTock++
        },

        /* Asking for more than was being asked for cannot be answered from
         * what we hold, so that widget starts again from the beginning of what
         * the simulator still has. Asking for less could be done by filtering,
         * but starting again is the same request and one rule instead of
         * two. */
        relevel(w) {
            logs.delete(widgetKey(w))
            this.logTock++
            this.pollLogs()
        },

        async pollLogs() {
            /* Changing a level asks for a poll of its own, which must not run
             * alongside the one the clock started: both would ask from the
             * same cursor and the window would show everything twice. */
            if (this.pollingLogs) return
            this.pollingLogs = true
            try { await this.fetchLogs() } finally { this.pollingLogs = false }
        },

        async fetchLogs() {
            for (const w of this.logged) {
                const l = logs.get(widgetKey(w))
                const since = l && l.last !== null ? `&since=${l.last}` : ''
                const r = await this.exchange(() => api(
                    `/simulations/${w.sim}/widgets/${w.widget}` +
                    `/logs?level=${w.level}${since}`))
                if (!r.ok) {
                    if (r.error.status === 404) this.unwatch(w)
                    continue
                }
                mergeLogs(w, r.value)
            }
            this.logTock++
            this.$nextTick(() => this.followTail())
        },

        /* Every watched widget's messages, in one chronology. */
        logLines() {
            this.logTock /* re-read me when messages arrive */
            const all = []
            for (const w of this.logged) {
                const l = logs.get(widgetKey(w))
                if (l) all.push(...l.lines)
            }
            /* Stable: messages sharing an instant keep the order they were
             * logged in, widget by widget. */
            all.sort((a, b) => a.t - b.t)
            return all.length > maxLogLines
                 ? all.slice(all.length - maxLogLines) : all
        },

        followTail() {
            const el = this.$refs.logBody
            if (el && this.logFollow) el.scrollTop = el.scrollHeight
        },

        /* Lines are rendered as the interface gets round to it, which is not
         * necessarily before the tick that asked for them is over. Watching
         * the list itself is the only way to stay at the bottom of something
         * that is still growing. */
        mountLog(el) {
            new MutationObserver(() => this.followTail()).observe(el, {
                childList: true, subtree: true })
        },

        /* Back to the newest line, and following it again. Unfolds the panel
         * on the way if it was folded away: being shown the newest line is the
         * whole of what was asked for. */
        jumpToBottom() {
            this.logFollow = true
            if (this.collapsed.logs) this.fold('logs')
            this.$nextTick(() => this.followTail())
        },

        onLogScroll() {
            const el = this.$refs.logBody
            if (!el) return
            this.logFollow =
                el.scrollTop + el.clientHeight >= el.scrollHeight - 4
        },

        /*
         * The dock
         */

        fold(what) {
            this.collapsed[what] = !this.collapsed[what]
            try {
                localStorage.setItem('robinet.collapsed',
                                     JSON.stringify(this.collapsed))
            } catch (e) { /* a browser that keeps nothing is not a failure */ }
            if (what === 'logs') this.$nextTick(() => this.followTail())
        },

        restoreFolds() {
            try {
                const kept = JSON.parse(localStorage.getItem('robinet.collapsed'))
                /* Only the panels there are today: what was kept was written
                 * by whatever version of this page the reader had then. */
                for (const what of Object.keys(this.collapsed))
                    if (kept && typeof kept[what] === 'boolean')
                        this.collapsed[what] = kept[what]
            } catch (e) { /* likewise */ }
        },

        /*
         * Speed
         */

        /* The rung below, or the fastest one when coming down from full
         * speed -- which is above the whole ladder. */
        slower(s) {
            if (s.speed_ratio === null) return speeds[speeds.length - 1]
            const below = speeds.filter(x => x < s.speed_ratio * 0.999999)
            return below.length ? below[below.length - 1] : speeds[0]
        },

        /* The rung above, or full speed once off the top. */
        faster(s) {
            if (s.speed_ratio === null) return null
            const above = speeds.find(x => x > s.speed_ratio * 1.000001)
            return above === undefined ? null : above
        },

        speedText(s) {
            if (s.paused) return 'paused'
            /* A simulation that follows the wall clock has no speed to set. */
            if (s.realtime) return 'real time'
            if (s.speed_ratio === null) return 'full speed'
            return ratioText(s.speed_ratio) + ' \u00d7 real time'
        },

        /* Only worth pointing at when it is more than the jitter of a poll. */
        isLate(s) { return !s.paused && s.late > 0.1 },

        lateText(s) {
            return 'Cannot keep up: ' + s.late.toFixed(1) +
                   's behind the speed asked for'
        },

        async setSpeed(sim, ratio) {
            await this.control(sim, 'speed?ratio=' +
                                    (ratio === null ? 'full' : ratio))
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

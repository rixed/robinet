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

/* An example of how the value is written, for the input to show while it is
 * empty -- a port range as "min-max", a network as "192.168.0.0/24". Read from
 * either side of an [optional], since a hint may be given for the value or for
 * the possibility of it and both mean the same thing here. */
const hintOf = (kind) => baseKind(kind).placeholder || kind.placeholder || ''

/* What the field must show for a value that came from the simulator. A value
 * that is not set keeps whatever was in the field: the input is only disabled,
 * so ticking the box back hands the reader what they had. */
const draftFor = (p, text) =>
    p.kind.type === 'optional' && p.value === null ? p.draft : text

/* Whether a kind takes more than one input to edit: a list and a record are
 * drawn as a table of cells, everything else as a single field. */
const isStructured = (kind) => {
    const t = baseKind(kind).type
    return t === 'list' || t === 'record'
}

/* What one input is worth, in the JSON a setter reads.
 *
 * A property of a plain kind, a field of a record and an element of a list are
 * all edited the same way and read back the same way: each is a [cell], which
 * is anything carrying the [kind] it holds, the [draft] of what is typed for
 * it, and whether it has a value at all. */
const cellValue = (c) => {
    /* Unticked is a value in itself: there is none. */
    if (c.kind.type === 'optional' && !c.enabled) return null
    switch (baseKind(c.kind).type) {
        case 'bool':
            return c.draft === true || c.draft === 'true'
        /* Which of the choices, by its place among them: that is what the
         * simulator keeps (see [Widget.Enum]), and the select holds it as the
         * string an option's value attribute always is. */
        case 'enum': {
            const n = Number(c.draft)
            return Number.isInteger(n) ? n : String(c.draft)
        }
        case 'int': case 'float': case 'range': {
            const n = Number(c.draft)
            /* Send what was typed rather than guessing, and let the setter say
             * what is wrong with it. */
            return Number.isNaN(n) || c.draft === '' ? String(c.draft) : n
        }
        default:
            return String(c.draft)
    }
}

/* Rows come and go under Alpine's feet, and it keeps the inputs of a row with
 * that row only if the row says which one it is: keyed by position, dropping
 * one would shift the contents of every row below it up by one. */
let rowSeq = 0

const cellOf = (name, kind, value) => ({
    name, kind,
    draft: asText(value),
    enabled: value !== null && value !== undefined
})

/* The cells one value of [kind] is edited through: one per field when it is a
 * record -- in the order the simulator named them, which is the order of the
 * columns -- and a single unnamed one otherwise. */
const cellsOf = (kind, value) =>
    kind.type === 'record'
        ? kind.fields.map(f => cellOf(f.name, f.kind,
                                      value == null ? null : value[f.name]))
        : [ cellOf(null, kind, value) ]

const rowOf = (kind, value) => ({ key: ++rowSeq, cells: cellsOf(kind, value) })

/* A cell nobody has put anything in: no value at all, or nothing but blanks.
 * A tick box that is off is one of those, whatever the field beside it still
 * shows -- that is what the box says. */
const cellIsBlank = (c) =>
    (c.kind.type === 'optional' && !c.enabled) || String(c.draft).trim() === ''

/* A row where every cell is blank is not an element of the list: it is the
 * empty row the reader was given to fill in, and it goes out of the value the
 * same way it came in -- unsaid. */
const rowIsBlank = (row) => row.cells.every(cellIsBlank)

const rowValue = (kind, row) =>
    kind.type === 'record'
        ? Object.fromEntries(row.cells.map(c => [ c.name, cellValue(c) ]))
        : cellValue(row.cells[0])

/* Where the reader's edits of a property live: a [draft] for a plain value, or
 * the [rows] of the table a list or a record is drawn as -- a record being a
 * table of one row, which is what makes the two the same thing to draw and the
 * same thing to read back. */
const rowsOf = (p) => {
    const k = baseKind(p.kind)
    return k.type === 'list' ? (p.value || []).map(v => rowOf(k.of, v))
                             : [ rowOf(k, p.value) ]
}

/* Put back into the inputs what the simulator last said this property is.
 *
 * A table is rebuilt only when there is something new to show, or when the
 * reader asks for it back ([force]): a read-only table rebuilt on every poll
 * would be redrawn from scratch once a second, taking the reader's selection
 * with it, to show exactly what was already there. */
const resetDraft = (p, force) => {
    p.enabled = p.value !== null
    if (isStructured(p.kind)) {
        const from = asText(p.value)
        if (!force && p.rows && p.rowsFrom === from) return
        p.rowsFrom = from
        p.rows = rowsOf(p)
    } else {
        /* A value that is not set keeps whatever was in the field: see
         * [draftFor]. */
        p.draft = draftFor(p, asText(p.value))
    }
}

const encode = (p) => {
    if (p.kind.type === 'optional' && !p.enabled) return 'null'
    const k = baseKind(p.kind)
    if (k.type === 'list')
        return JSON.stringify(p.rows.filter(r => !rowIsBlank(r))
                                    .map(r => rowValue(k.of, r)))
    if (k.type === 'record')
        return JSON.stringify(rowValue(k, p.rows[0]))
    return JSON.stringify(cellValue(p))
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

/*
 * The map, and the one rule that makes it work.
 *
 * Composition (parent and children) and connectivity (peers, through a cable)
 * are two different graphs: a strict tree and a general graph. Keeping them
 * apart is the whole trick -- composition is drawn as containment, so a host is
 * a box with its insides in it rather than a node with lines to its layers, and
 * only cables are ever lines.
 *
 * A box the reader has not opened hides its insides, and the ends of a cable do
 * not all sit at the same depth: simwan wires peers at interface level, at hub
 * level and at gateway level. So an edge cannot simply be drawn between its
 * ends -- it is drawn between the nearest *drawn* ancestor of each end, which
 * is what this calls promotion. Everything the map can do follows from it: a
 * hidden end becomes a port on the box that stands for it, and a cable whose
 * two ends are inside the same closed box disappears into that box instead of
 * being drawn from it back to itself.
 *
 * All of it is a pure function of the widget listing and of which boxes are
 * open, so none of it is in the component: it is worth being able to try
 * against a graph rather than against a screen.
 */

/* The widgets that are links rather than boxes: a widget is a cable exactly
 * when some peering goes through it. They are drawn as the edges they are, and
 * never as a box of their own -- which is also why a plane built from a
 * parent's children has to leave them out. */
const linkSet = (byId) => {
    const links = new Set()
    for (const w of Object.values(byId))
        for (const p of w.peers) if (p.via !== null) links.add(p.via)
    return links
}

/* What the map starts from: the children of [rootId], minus the cables between
 * them. The root itself is not drawn -- it is the simulation, not a thing
 * inside it. */
const planeOf = (byId, rootId, links = linkSet(byId)) =>
    (byId[rootId] ? byId[rootId].children : []).filter(id => !links.has(id))

/* Which widgets the map actually draws: the boxes of the plane, and the insides
 * of every box the reader has opened. */
const drawnSet = (byId, plane, open, links = linkSet(byId)) => {
    const drawn = new Set()
    const walk = (id) => {
        if (!byId[id] || links.has(id)) return
        drawn.add(id)
        if (open.has(id)) byId[id].children.forEach(walk)
    }
    plane.forEach(walk)
    return drawn
}

/* The box that stands for a widget: itself when it is drawn, otherwise the
 * closest of its ancestors that is -- and null when it is on no box at all,
 * which is what a widget outside the plane's subtrees comes back as. */
const anchorOf = (byId, drawn, id) => {
    for (let w = byId[id] ; w ; w = byId[w.parent])
        if (drawn.has(w.id)) return w.id
    return null
}

/* Every peering, once.
 *
 * The simulator records a peering on both of its ends, and the cable in the
 * middle also lists the two ends it joins (see [Widget.make_peers]), so one
 * link is stated four times. Keyed by its ends and its cable it is kept once,
 * and the cable's own two statements are dropped: they say nothing the link
 * does not already say. Parallel cables between the same pair stay distinct,
 * the cable being part of the key. */
const relations = (byId, links = linkSet(byId)) => {
    const out = new Map()
    for (const w of Object.values(byId))
        for (const p of w.peers) {
            const a = Math.min(w.id, p.widget), b = Math.max(w.id, p.widget)
            if (p.via === null && (links.has(a) || links.has(b))) continue
            out.set(`${a}-${b}-${p.via}`, { a, b, via: p.via })
        }
    return [ ...out.values() ]
}

/* The edges to draw, promoted onto the boxes that are on screen.
 *
 * An edge carries the widget each of its ends really is, beside the box it is
 * drawn from: that widget is the port it lands on, and what the port is
 * labelled with. A null port is an end that is the box itself, and the line
 * simply goes to the box.
 *
 * [inside] counts, per box, the links that vanished into it, so that a closed
 * box can say how much connectivity it is folding away rather than quietly
 * losing it. */
const mapEdges = (byId, drawn, links = linkSet(byId)) => {
    const edges = [], inside = new Map()
    for (const r of relations(byId, links)) {
        const from = anchorOf(byId, drawn, r.a)
        const to = anchorOf(byId, drawn, r.b)
        if (from === null || to === null) continue
        if (from === to) {
            inside.set(from, (inside.get(from) || 0) + 1)
            continue
        }
        edges.push({ key: `${r.a}-${r.b}-${r.via}`, via: r.via,
                     from, fromPort: from === r.a ? null : r.a,
                     to, toPort: to === r.b ? null : r.b })
    }
    return { edges, inside }
}

/* Web Mercator, in a unit square: the whole world is 0..1 both ways, and the
 * pane decides how many pixels that is worth. Ten lines rather than a map
 * library, because with nothing to fetch from outside there are no tiles, and
 * a map library without tiles is a projection and a wheel handler.
 *
 * Latitude is clamped to the square's own limit: Mercator sends the poles to
 * infinity, and a box at 89 degrees is not worth an infinite canvas. */
const mercatorLimit = 85.05112878

const mercator = (lat, lon) => {
    const f = Math.max(-mercatorLimit, Math.min(mercatorLimit, lat)) * Math.PI / 180
    return { x: (lon + 180) / 360,
             y: (1 - Math.log(Math.tan(f) + 1 / Math.cos(f)) / Math.PI) / 2 }
}

const unmercator = (x, y) => ({
    lat: Math.atan(Math.sinh(Math.PI * (1 - 2 * y))) * 180 / Math.PI,
    lon: x * 360 - 180,
})

/* The coastlines, projected once.
 *
 * [coastline] is what coast.js defines: lon/lat in degrees, which is how the
 * data is kept and not how anything is drawn. The projection of a shoreline
 * never changes, so it is done on first use and kept, while the view -- which
 * changes constantly -- is applied per frame. Missing, the map draws no coast
 * and everything else about it still works. */
let coastCache = null
const coastWorld = () => {
    if (coastCache === null)
        coastCache = (typeof coastline === 'undefined' ? [] : coastline)
            .map(l => {
                const out = new Float64Array(l.length)
                for (let i = 0 ; i < l.length ; i += 2) {
                    const p = mercator(l[i + 1], l[i])
                    out[i] = p.x ; out[i + 1] = p.y
                }
                return out
            })
    return coastCache
}

/* The part of a segment that falls within the pane, or null (Liang-Barsky).
 *
 * Drawing has to be clipped rather than left to the renderer: zoomed in on a
 * network a kilometre across, the line along the Pacific is tens of millions
 * of pixels long, and handing that to the browser every frame is how a map
 * stops being a map. The margin keeps a stroke that runs along the edge from
 * being cut in half by its own clip. */
const clipMargin = 4
const clipSeg = (x0, y0, x1, y1, w, h) => {
    const dx = x1 - x0, dy = y1 - y0
    let t0 = 0, t1 = 1
    const edge = (p, q) => {
        if (p === 0) return q >= 0
        const r = q / p
        if (p < 0) { if (r > t1) return false ; if (r > t0) t0 = r }
        else { if (r < t0) return false ; if (r < t1) t1 = r }
        return true
    }
    const m = clipMargin
    if (!(edge(-dx, x0 + m) && edge(dx, w + m - x0) &&
          edge(-dy, y0 + m) && edge(dy, h + m - y0))) return null
    return [ x0 + t0 * dx, y0 + t0 * dy, x0 + t1 * dx, y0 + t1 * dy ]
}

/* Kept for the same reason as [sceneMemo]: the binding asks for the path on
 * every render, and it only changes when the view does. */
let coastMemo = { sig: null, value: '' }

/* The page's own unit, as the stylesheet set it: everything laid out here is
 * a multiple of it, so that the one number that sets the density of the page
 * sets the size of the map's boxes too, rather than leaving them the size they
 * were around text that has shrunk. Read once -- the stylesheet is in the
 * document head and this script is deferred, so it is applied by now. */
const rem = parseFloat(getComputedStyle(document.documentElement).fontSize) || 16

/* A box is a fixed size on screen, not in world units: zooming out must bring
 * more of the network into view, not shrink its labels until they cannot be
 * read. Only positions are projected. */
const boxW = 7.4 * rem, boxH = 2.1 * rem  /* a box with nothing shown inside it */
const boxPad = .55 * rem       /* between a box's border and its contents */
const boxGap = .7 * rem        /* between two boxes side by side */
const boxHead = 1.2 * rem      /* the name of a box that is showing its insides */

/* Watching the pane rather than the window: it also changes size when the
 * divider is dragged and when the dock is folded away. One at a time. */
let mapObserver = null

/* How far a pointer may wander between pressing a divider and letting it go
 * and still count as having clicked it rather than dragged it. */
const dragSlack = 4

/* The two dividers are one thing along two axes. Each names the field holding
 * its share, where to go back to when it is brought out of being shut, where
 * that is kept, and how far along the row a pointer is -- which is measured
 * towards the pane whose share it is: rightwards for the column divider, whose
 * share is the left column's, and upwards for the dock's. */
const dividers = {
    split: { share: 'split', last: 'splitLast', kept: 'robinet.split',
             rows: false,
             at: (r, e) => r.width > 0 ? (e.clientX - r.left) / r.width : null },
    dock: { share: 'dockShare', last: 'dockLast', kept: 'robinet.dock',
            rows: true,
            at: (r, e) => r.height > 0 ? (r.bottom - e.clientY) / r.height : null },
}

/* The world, in metres, for the two numbers below. */
const earth = 40075000

/* How far in and out the map goes. A simulated network may be a continent
 * apart or a rack apart and both have to be lookable at, but there have to be
 * ends to it, or the arithmetic runs off to a zoom no wheel could ever undo.
 *
 * In, to about ten metres across the pane. Out, to the whole world exactly
 * filling it: there is nothing beyond the world to see, and a map showing the
 * globe adrift in a larger window says the reader has gone somewhere they
 * cannot have gone. Both directions, since the pane is usually taller than it
 * is wide and the world has to cover it either way. */
const zoomTo = (paneW, paneH, k) =>
    Math.min(paneW * earth / 10, Math.max(paneW, paneH, k))

/* What is framed when there is nothing to frame: a single placed box spans
 * nothing at all, and neither does a network small enough to sit inside one.
 * Thirty metres, so that the box is seen with a little room around it rather
 * than at whatever the ceiling above happens to be. */
const minSpan = 30 / earth

/* How big a box is, and where everything inside it sits, from the leaves up. A
 * closed box is one rectangle; an open one is as big as what it holds.
 *
 * The insides are laid out in a square-ish block rather than in a row: a host
 * with eight layers in a row would be a box wider than the network. */
const boxTree = (byId, id, open, links) => {
    const w = byId[id]
    const kids = !w || !open.has(id) ? [] :
        w.children.filter(c => byId[c] && !links.has(c))
    if (!kids.length) return { id, w: boxW, h: boxH, open: false, kids: [] }
    const inner = kids.map(k => boxTree(byId, k, open, links))
    const perRow = Math.ceil(Math.sqrt(inner.length))
    let x = boxPad, y = boxHead + boxPad, rowH = 0, width = 0
    inner.forEach((t, i) => {
        if (i && i % perRow === 0) {
            width = Math.max(width, x - boxGap)
            x = boxPad ; y += rowH + boxGap ; rowH = 0
        }
        t.dx = x ; t.dy = y
        x += t.w + boxGap ; rowH = Math.max(rowH, t.h)
    })
    width = Math.max(width, x - boxGap)
    return { id, open: true, kids: inner,
             w: Math.max(boxW, width + boxPad - boxGap + boxPad),
             h: y + rowH + boxPad }
}

/* Turn a sized tree into one rectangle per drawn widget, in pane pixels. The
 * depth comes along so that a nested box can be drawn as being inside another
 * one rather than merely on top of it. */
const placeTree = (tree, x, y, into, depth = 0) => {
    into.set(tree.id, { id: tree.id, x, y, w: tree.w, h: tree.h,
                        open: tree.open, depth })
    for (const k of tree.kids) placeTree(k, x + k.dx, y + k.dy, into, depth + 1)
    return into
}

/* Which side of a box a point on its border is on. */
const borderSide = (r, p) => {
    const d = [ [ 'top', Math.abs(p.y - r.y) ],
                [ 'bottom', Math.abs(p.y - (r.y + r.h)) ],
                [ 'left', Math.abs(p.x - r.x) ],
                [ 'right', Math.abs(p.x - (r.x + r.w)) ] ]
    return d.reduce((a, b) => (b[1] < a[1] ? b : a))[0]
}

/* Ends that land on the same side of the same box, spread evenly along it.
 *
 * Two cables coming from nearly the same direction otherwise cross the border
 * at nearly the same spot, and the ports naming them are drawn one on top of
 * the other -- which is the one thing a port is there to avoid. Evenly rather
 * than merely nudged apart, so that a box with the same cables on it always
 * looks the same, however far away the other ends happen to be; the order along
 * the side is the order they arrive in, so that spreading them crosses no line
 * that was not crossed already. */
const spreadEnds = (ends, rects) => {
    const groups = new Map()
    for (const e of ends) {
        const r = rects.get(e.box)
        if (!r) continue
        const key = e.box + ':' + borderSide(r, e.pt)
        if (!groups.has(key)) groups.set(key, [])
        groups.get(key).push(e)
    }
    for (const [ key, g ] of groups) {
        if (g.length < 2) continue
        const r = rects.get(g[0].box)
        const horiz = /:(top|bottom)$/.test(key)
        g.sort((a, b) => horiz ? a.pt.x - b.pt.x : a.pt.y - b.pt.y)
        g.forEach((e, i) => {
            const t = (i + 1) / (g.length + 1)
            if (horiz) e.pt.x = r.x + r.w * t
            else e.pt.y = r.y + r.h * t
        })
    }
}

/* Where a line leaving a box crosses its border, heading for a point outside:
 * the port sits there, so that no line is ever drawn across the box it comes
 * from. */
const borderPoint = (r, tx, ty) => {
    const cx = r.x + r.w / 2, cy = r.y + r.h / 2
    const dx = tx - cx, dy = ty - cy
    if (!dx && !dy) return { x: cx, y: cy }
    const s = Math.min(dx ? (r.w / 2) / Math.abs(dx) : Infinity,
                       dy ? (r.h / 2) / Math.abs(dy) : Infinity)
    return { x: cx + dx * s, y: cy + dy * s }
}

/* The scene is rebuilt from scratch whenever anything it is drawn from moves,
 * and the bindings ask for it several times per frame; this is what keeps that
 * from being several layouts per frame. Kept out of the component, being
 * pixels rather than anything the page reacts to. */
let sceneMemo = { sig: null, value: null }

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
        /* simulation id -> the reason its last command was refused */
        simError: {},
        /* Why the last widget offered to the log window was not taken. */
        logError: null,

        /* The simulations folded away in the left column, and the ones that
         * have been seen at all. One is usually being worked on and the rest
         * are in the way -- most of all the one serving this page, which is
         * never the subject. So a simulation seen for the first time is folded
         * unless it is the one wanted, and what the reader folds or unfolds
         * afterwards is left exactly as they left it, across reloads and across
         * the simulator going away and coming back. */
        simFolded: [],
        simSeen: [],

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
        /* The key of the row a drag is carrying, when one is: see [grabRow]. */
        dragRow: null,
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

        /* How much of the top half the schematic gets, the map taking the
         * rest. Dragging the divider all the way to either side collapses that
         * side, which is what a toggle between the two views would have been,
         * without a second control to find. Remembered, like the folds. */
        split: 0.45,
        /* The share to go back to when a side that was shut is brought out
         * again: what it was before it was shut. */
        splitLast: 0.45,

        /* And how much of the height under it goes to the dock. Dragged rather
         * than fixed, because how much room the charts and the logs are worth
         * against the network above them is a question about the screen and
         * about what is being watched, neither of which this page knows. */
        dockShare: 0.4,
        dockLast: 0.4,

        /* The boxes the reader has opened, which is not a function of the
         * zoom: one wants a single host opened while the whole network stays
         * collapsed around it, and that is unsayable if detail follows scale.
         * Zooming brings more of the network into view and nothing else. */
        mapOpen: [],
        /* And the boxes the selection is holding open, so that the widget
         * being looked at is drawn rather than hidden inside something. Kept
         * apart from the ones the reader opened, because these shut again on
         * their own: see [openToSelection]. */
        mapAuto: [],
        /* What the middle of the pane is looking at, in world units, and how
         * many pixels a world unit is worth. [k] of zero means the map has not
         * been fitted to its contents yet. */
        mapView: { cx: 0.5, cy: 0.5, k: 0 },
        mapSize: { w: 0, h: 0 },
        /* The box being dragged, at the pane pixels it has been dragged to. */
        mapDrag: null,
        /* Bumped whenever the shape of the network, or where something in it
         * sits, has changed: what the scene is rebuilt on. */
        topoTock: 0,
        mapError: null,

        /* The catalogue of what can be built, as /api/device-types gives it.
         * Fetched the first time it is asked for: it is the same for every
         * simulation and does not change while the program runs. */
        deviceTypes: [],
        typeMenu: false,
        /* The device being built, or null. It stands where the schematic
         * stands, there being no widget yet to draw a schematic of. */
        adding: null,
        /* While the ends of a cable are being clicked on the map. A cable is
         * the one device whose parameters are two other devices, and it cannot
         * be built without them: nothing here or in the simulator has any use
         * for a cable with one end loose. */
        picking: null,
        /* Set by the first click on Delete and cleared by the second, or by
         * looking at something else. Taking a device out cannot be undone. */
        confirmDelete: false,

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
            const wasOffline = this.offline
            await this.poll()
            if (wasOffline && this.online)
                /* The topology may have changed while we could not see it, so
                 * come back with a full reload rather than a refresh. */
                await this.reload()
            else if (this.offline)
                this.backoff = Math.min(this.backoff * 2, this.maxBackoff)
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
            this.foldNewSims(sims)
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
                /* The tree may have changed shape under it. */
                this.openToSelection()
                await this.loadProps({ full: true })
            }
        },

        /*
         * Navigation
         */

        foldSim(id) {
            const i = this.simFolded.indexOf(id)
            if (i < 0) this.simFolded.push(id) ; else this.simFolded.splice(i, 1)
        },

        /* The one worth having open: the first that is not serving this page.
         * Applied to each simulation once, the first time it is seen. */
        foldNewSims(sims) {
            const wanted = sims.find(s => s.id !== this.servingId) || sims[0]
            for (const s of sims) {
                if (this.simSeen.includes(s.id)) continue
                this.simSeen.push(s.id)
                if (!wanted || s.id !== wanted.id) this.simFolded.push(s.id)
            }
        },

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
            /* Armed on the widget being left, and meaningless on this one. */
            this.confirmDelete = false
            this.openToSelection()
            this.showSelection()
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
                    p.dirty = false
                    p.error = null
                    resetDraft(p)
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
                old.only_when_set = p.only_when_set
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
                    resetDraft(old)
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

        /* The properties worth a row of the panel.
         *
         * Absence is usually itself the answer -- a DHCP server serving no
         * gateway says so -- so a property that reads as nothing stays, and
         * the panel writes "unset". The exceptions say so themselves: see
         * [only_when_set] in widget.ml. */
        shownProps() {
            return this.props.filter(p => p.value !== null || !p.only_when_set)
        },

        /* The kind whose input this property gets: see [baseKind]. */
        base(p) {
            return baseKind(p.kind)
        },

        /* Has this property (or one cell of it) a value to edit at all?
         * Anything that cannot be absent always has one. */
        set(p) {
            return p.kind.type !== 'optional' || p.enabled
        },

        /* Several inputs rather than one: see [isStructured]. */
        structured(p) {
            return isStructured(p.kind)
        },

        /* The columns of the table a list or a record is drawn as: the fields
         * of the record, or none when what is repeated is a bare value and
         * there is nothing to head the single column with. */
        cols(p) {
            const k = baseKind(p.kind)
            const el = k.type === 'list' ? k.of : k
            return el.type === 'record' ? el.fields : null
        },

        /* Rows are added and dropped from a list; a record has the one row it
         * has, and always will. */
        growable(p) {
            return !p.read_only && baseKind(p.kind).type === 'list'
        },

        /* Is there a row waiting to be filled in? It is not sent (see
         * [rowIsBlank]), and handing out a second one while the first is still
         * empty only grows a table of nothing. */
        hasBlank(p) {
            return (p.rows || []).some(rowIsBlank)
        },

        /* Which input a cell gets. Anything else is typed, which is what a
         * string is -- and what a widget id is until this offers them by
         * name, as the map already does. */
        cellInput(c) {
            const t = baseKind(c.kind).type
            if (t === 'bool' || t === 'enum') return t
            if (t === 'int' || t === 'float' || t === 'range') return 'number'
            return 'text'
        },

        /* An example of how to write it, shown in the empty input: see
         * [hintOf]. */
        hint(x) {
            return hintOf(x.kind)
        },

        /* Where the bytes of a file property are: the property, and "/file"
         * (see [get_property_file]). The path is not sent -- the widget
         * answers with its own -- so there is nothing here but the name of the
         * property to ask about. */
        fileUrl(p) {
            const { sim, id } = this.selected
            return `/api/simulations/${sim}/widgets/${id}` +
                   `/properties/${encodeURIComponent(p.name)}/file`
        },

        /* The choice an enum's value stands for. Falls back to the number
         * when there is no such choice, which is the interface and the
         * simulator disagreeing about how many there are -- worth showing as
         * it is rather than as a blank. */
        choice(kind, i) {
            const cs = baseKind(kind).choices
            return cs && cs[i] !== undefined ? cs[i] : String(i)
        },

        /* What a property reads as when it is only read. An enum travels as
         * the index of its choice, a number that means nothing on its own, so
         * it reads as the choice. */
        shown(p) {
            if (p.value === null) return 'unset'
            return baseKind(p.kind).type === 'enum' ? this.choice(p.kind, p.value)
                                                    : p.text
        },

        /* What one cell of a read-only table says. */
        cellText(c) {
            if (!this.set(c)) return 'unset'
            if (baseKind(c.kind).type !== 'enum') return c.draft
            /* A cell of a row nobody has filled in yet has no choice, and no
               index either: [choice] would answer for the first one. */
            return c.draft === '' ? '' : this.choice(c.kind, Number(c.draft))
        },

        /* A table means something only once every cell of it has been filled:
         * a half-typed row would be refused, and refusing it at every
         * keystroke says nothing anyone can act on. So it is sent when the
         * reader says so, not on the way out of a field -- and until then this
         * is what says there is something to send. */
        touch(p) {
            p.dirty = true
            p.error = null
        },

        /* Touching the input of a value that is not set is asking for it to
         * be: the box in front of it ticks itself. Nobody wants the detour of
         * ticking a box before they may type, and nothing is lost -- untick it
         * again and the value goes back to being absent.
         *
         * Bound to what the reader does to the value (typing, picking,
         * dragging), never to the field merely gaining focus: clicking into a
         * field to read it must leave it exactly as it was found. */
        enable(x) {
            if (x.kind.type === 'optional' && !x.enabled) x.enabled = true
        },

        /* Move a row [by] places, up when that is negative. The order of a
         * list is part of its value -- the first route that matches is the one
         * taken -- so this is an edit like any other, and waits for Apply like
         * any other.
         *
         * The row keeps its key, which is what carries its inputs with it
         * rather than leaving them at the position they were at. */
        moveRow(p, row, by) {
            const i = p.rows.findIndex(r => r.key === row.key)
            const j = i + by
            if (i < 0 || j < 0 || j >= p.rows.length) return
            const rows = p.rows.slice()
            rows.splice(j, 0, rows.splice(i, 1)[0])
            p.rows = rows
            this.touch(p)
        },

        /* Carry a row up or down the table by its handle.
         *
         * Pointer events rather than HTML5 drag and drop, as the divider and
         * the map already do: nothing is being handed to anywhere else -- the
         * row never leaves the table it is in -- and this works with a finger.
         *
         * The rows are laid out in order, so where the pointer is says which
         * one it is over; the row moves there as it is passed, so what is on
         * screen during the drag is what letting go will leave. */
        grabRow(p, row, ev) {
            if (!this.online || p.read_only) return
            if (ev.pointerType === 'mouse' && ev.button !== 0) return
            const tbody = ev.currentTarget.closest('tbody')
            if (!tbody) return
            this.dragRow = row.key
            const move = (e) => {
                const at = p.rows.findIndex(r => r.key === this.dragRow)
                if (at < 0) return
                const rows = [ ...tbody.querySelectorAll(':scope > tr') ]
                const over = rows.findIndex(el => {
                    const b = el.getBoundingClientRect()
                    return e.clientY >= b.top && e.clientY < b.bottom
                })
                if (over >= 0 && over !== at) this.moveRow(p, p.rows[at], over - at)
            }
            const done = () => {
                this.dragRow = null
                document.body.classList.remove('carrying')
                window.removeEventListener('pointermove', move)
                window.removeEventListener('pointerup', done)
                window.removeEventListener('pointercancel', done)
            }
            /* Said on the whole page rather than on the handle: the pointer
               spends the drag over the rows, not over what it took hold of. */
            document.body.classList.add('carrying')
            window.addEventListener('pointermove', move)
            window.addEventListener('pointerup', done)
            /* A drag the browser takes away from us -- a call coming in, a
               touch turned into a scroll -- ends it too, or the page would be
               left holding a row nobody is carrying. */
            window.addEventListener('pointercancel', done)
            ev.preventDefault()
        },

        addRow(p) {
            p.rows.push(rowOf(baseKind(p.kind).of, null))
            this.touch(p)
        },

        dropRow(p, row) {
            p.rows = p.rows.filter(r => r.key !== row.key)
            this.touch(p)
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
            /* Neither the value nor its presence has moved: nothing to say.
             * A table is not compared cell by cell: rows come and go as well,
             * so what says it has been touched is [dirty], which every one of
             * its inputs sets. */
            const unchanged =
                isStructured(p.kind) ? !p.dirty :
                /* Not set, and still not set. What is in the field is only
                 * what was there before it was unset, and means nothing until
                 * the box is ticked again -- so a field one merely clicked in
                 * and left has nothing to say. */
                (p.kind.type === 'optional' && !p.enabled) ? p.value === null :
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
            /* From the answer rather than from what was typed: a setter may
             * well hold something other than what it was handed -- an address
             * written another way, rows in another order -- and what it holds
             * is what the reader must be looking at. */
            resetDraft(p, true)
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
            const view = menuAnchor.closest('.pane.detail')
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
                         menuAnchor.closest('.pane.detail')
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
            /* And the panel itself changes size -- the divider above it moves,
             * the other panel folds away, the window is resized -- which slides
             * the newest line out from under a reader who was following it,
             * with no new line coming to put it back.
             *
             * Only when it gets shorter, which is the only direction that can:
             * growing, the browser has already brought the bottom back into
             * view by clamping how far down it is scrolled. Following the tail
             * when there is nothing to follow it to would only be another
             * chance to land between a reader scrolling away and the event
             * that says so. */
            if (typeof ResizeObserver !== 'undefined') {
                let was = el.clientHeight
                new ResizeObserver(() => {
                    const shorter = el.clientHeight < was
                    was = el.clientHeight
                    if (shorter) this.followTail()
                }).observe(el)
            }
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

        /* Every panel the dock holds is folded away. There is then nothing to
         * give its room to, so it gives it back to what is above: folding is
         * for making room elsewhere, and the dock is somewhere else too. */
        allFolded() {
            return (!this.charts.length || this.collapsed.charts) &&
                   (!this.logged.length || this.collapsed.logs)
        },

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
                for (const name of Object.keys(dividers)) {
                    const d = dividers[name]
                    /* Nothing kept is not a share of zero: [Number(null)] is 0,
                     * which would come back as "that side is shut". */
                    const raw = localStorage.getItem(d.kept)
                    const f = raw === null ? NaN : Number(raw)
                    if (!Number.isFinite(f) || f < 0 || f > 1) continue
                    this[d.share] = f
                    /* A share that was kept shut says nothing about how wide
                     * that side should come back: the default does. */
                    if (f > 0 && f < 1) this[d.last] = f
                }
            } catch (e) { /* likewise */ }
        },

        /*
         * The divider between the schematic and the map
         */

        shut(name) {
            const share = this[dividers[name].share]
            return share === 0 || share === 1
        },
        get splitShut() { return this.shut('split') },
        get dockShut() { return this.shut('dock') },

        saveDivider(name) {
            const d = dividers[name]
            try {
                localStorage.setItem(d.kept, String(this[d.share]))
            } catch (e) { /* a browser that keeps nothing is not a failure */ }
        },

        /* Dragged to either end a divider collapses that side, so it is also
         * the switch between the two things it separates: there is no third
         * control saying which one is showing.
         *
         * And pushed all the way over it is the only part of the shut side
         * still on screen, so it is the way back as well: pressed and released
         * without going anywhere, it brings that side out again at the share it
         * had before. Without that, a pane shut once is shut for good -- the
         * share being remembered, that would outlast the browser.
         *
         * The click is recognised here rather than from a click event, because
         * a drag that ends well away from the divider has its click delivered
         * somewhere else entirely, and a flag set to swallow it would still be
         * set when the reader went on to click the divider for real. */
        grabDivider(ev, name) {
            const d = dividers[name]
            const row = ev.currentTarget.parentElement
            /* What to come back to if this drag ends up shutting a side. Taken
             * before rather than as it goes: the last share a drag passes
             * through on its way out is the sliver next to the edge, which is
             * no share to come back to. */
            const was = this.shut(name) ? this[d.last] : this[d.share]
            const from = { x: ev.clientX, y: ev.clientY }
            let moved = false
            const move = (e) => {
                if (!moved && Math.abs(e.clientX - from.x) +
                              Math.abs(e.clientY - from.y) < dragSlack) return
                moved = true
                let f = d.at(row.getBoundingClientRect(), e)
                if (f === null) return
                /* A sliver of a pane is no use to anyone: near either end,
                 * shut that side rather than leaving a stripe. */
                if (f < 0.08) f = 0
                else if (f > 0.92) f = 1
                this[d.share] = f
            }
            const done = () => {
                window.removeEventListener('pointermove', move)
                window.removeEventListener('pointerup', done)
                document.body.classList.remove('splitting', 'rows')
                if (!moved && this.shut(name)) this[d.share] = this[d.last]
                this[d.last] = was
                this.saveDivider(name)
                this.$nextTick(() => this.measureMap())
            }
            document.body.classList.add('splitting')
            if (d.rows) document.body.classList.add('rows')
            window.addEventListener('pointermove', move)
            window.addEventListener('pointerup', done)
            ev.preventDefault()
        },

        /*
         * The map
         */

        /* The pane's size in pixels, which the layout is done in. Watched
         * rather than read on every frame: it changes when the divider moves,
         * when the dock folds, and when the window is resized. */
        measureMap() {
            const el = this.$refs.mapPane
            if (!el) return
            const r = el.getBoundingClientRect()
            if (r.width === this.mapSize.w && r.height === this.mapSize.h) return
            this.mapSize = { w: r.width, h: r.height }
            if (!this.mapView.k) this.fitMap()
        },

        watchMap() {
            const el = this.$refs.mapPane
            if (!el) return
            if (typeof ResizeObserver !== 'undefined') {
                if (mapObserver) mapObserver.disconnect()
                mapObserver = new ResizeObserver(() => this.measureMap())
                mapObserver.observe(el)
            }
            this.measureMap()
        },

        /* Every box that has a place in the world, as world points.
         *
         * Only the boxes of the plane: a location on anything else is never
         * drawn -- what is inside a box is at that box's place, and a cable is
         * a line between its ends -- and framing around a point that is never
         * shown leaves the reader looking at nothing. */
        placedPoints() {
            if (!this.selected) return []
            const sim = this.selected.sim
            const byId = this.widgetsOf(sim)
            const out = []
            for (const id of planeOf(byId, this.roots[sim])) {
                const w = byId[id]
                if (w && w.location)
                    out.push(mercator(w.location.lat, w.location.lon))
            }
            return out
        },

        /* Frame what is placed, with room around it. With nothing placed there
         * is nothing to frame, and the whole world is as good a view as any. */
        fitMap() {
            const pts = this.placedPoints()
            const { w, h } = this.mapSize
            if (!w || !h) return
            if (!pts.length) {
                this.mapView = { cx: 0.5, cy: 0.5, k: zoomTo(w, h, 0) }
                return
            }
            const xs = pts.map(p => p.x), ys = pts.map(p => p.y)
            const x0 = Math.min(...xs), x1 = Math.max(...xs)
            const y0 = Math.min(...ys), y1 = Math.max(...ys)
            /* A margin in world units, and a floor under it: see [minSpan]. */
            const span = Math.max(x1 - x0, y1 - y0, minSpan) * 1.6
            this.mapView = { cx: (x0 + x1) / 2, cy: (y0 + y1) / 2,
                             k: zoomTo(w, h, Math.min(w, h) / span) }
            this.topoTock++
        },

        toWorld(px, py) {
            const { cx, cy, k } = this.mapView
            const { w, h } = this.mapSize
            return { x: cx + (px - w / 2) / k, y: cy + (py - h / 2) / k }
        },

        toPane(wx, wy) {
            const { cx, cy, k } = this.mapView
            const { w, h } = this.mapSize
            return { x: (wx - cx) * k + w / 2, y: (wy - cy) * k + h / 2 }
        },

        /* Zoom about the pointer, so that what is under it stays under it --
         * which is the only way to zoom towards something rather than towards
         * the middle and then pan back. */
        zoomMap(ev) {
            if (!this.mapView.k) return
            ev.preventDefault()
            const el = this.$refs.mapPane.getBoundingClientRect()
            const px = ev.clientX - el.left, py = ev.clientY - el.top
            const at = this.toWorld(px, py)
            const k = zoomTo(this.mapSize.w, this.mapSize.h,
                             this.mapView.k * Math.exp(-ev.deltaY * 0.0015))
            this.mapView = { k,
                cx: at.x - (px - this.mapSize.w / 2) / k,
                cy: at.y - (py - this.mapSize.h / 2) / k }
        },

        /* Dragging the background moves the view under it. */
        panMap(ev) {
            if (ev.button !== 0 || !this.mapView.k) return
            const start = { x: ev.clientX, y: ev.clientY,
                            cx: this.mapView.cx, cy: this.mapView.cy }
            const move = (e) => {
                this.mapView = { k: this.mapView.k,
                    cx: start.cx - (e.clientX - start.x) / this.mapView.k,
                    cy: start.cy - (e.clientY - start.y) / this.mapView.k }
            }
            const done = () => {
                window.removeEventListener('pointermove', move)
                window.removeEventListener('pointerup', done)
            }
            window.addEventListener('pointermove', move)
            window.addEventListener('pointerup', done)
        },

        /* Show what a box holds, or stop showing it. */
        toggleBox(id) {
            if (this.isOpen(id)) {
                /* Shutting one the selection was holding open shuts it: asked
                 * plainly, the reader wins over what the selection wanted. It
                 * comes back open when the selection next moves into it, which
                 * is the only thing that could make it worth seeing again. */
                this.mapOpen = this.mapOpen.filter(x => x !== id)
                this.mapAuto = this.mapAuto.filter(x => x !== id)
            } else {
                this.mapOpen.push(id)
            }
            this.topoTock++
        },

        isOpen(id) {
            return this.mapOpen.includes(id) || this.mapAuto.includes(id)
        },

        /* What has to be open for the selected widget to be drawn at all:
         * every box between it and the plane.
         *
         * Held open by the selection rather than by the reader, so it is worked
         * out afresh whenever the selection moves and shuts again on its own as
         * soon as it moves elsewhere -- unlike a box the reader opened, which
         * stays open until they shut it. Selecting the eth layer of a host
         * therefore opens that host and nothing else, and moving on to another
         * host puts it back as it was. */
        openToSelection() {
            const auto = []
            if (this.selected) {
                const byId = this.widgetsOf(this.selected.sim)
                const root = this.roots[this.selected.sim]
                let w = byId[this.selected.id]
                for (w = w && byId[w.parent] ; w && w.id !== root ;
                     w = byId[w.parent])
                    auto.push(w.id)
            }
            this.mapAuto = auto
            this.topoTock++
        },

        /* Drag a box: on the map it is placed where it was dropped, in the
         * strip below it is taken off the map again. Both are the same one
         * request, since a location that is not is null. */
        dragBox(id, ev) {
            if (ev.button !== 0 || !this.mapView.k) return
            ev.stopPropagation()
            /* A box is an end to be picked, not a box to be moved, while a
             * cable is waiting for its two ends. */
            if (this.picking) { this.pickEnd(id) ; return }
            const pane = this.$refs.mapPane.getBoundingClientRect()
            const scene = this.mapScene()
            const r = scene.rects.get(id)
            if (!r) return
            /* Only a box on the plane has a place of its own. What is inside
             * one is drawn where its box says, so there is nowhere for it to be
             * dragged to; clicking it still selects it. */
            if (r.depth > 0) { this.select(this.selected.sim, id) ; return }
            const grab = { dx: ev.clientX - pane.left - r.x,
                           dy: ev.clientY - pane.top - r.y }
            let moved = false
            const move = (e) => {
                moved = true
                this.mapDrag = { id, x: e.clientX - pane.left - grab.dx,
                                     y: e.clientY - pane.top - grab.dy }
            }
            const done = async (e) => {
                window.removeEventListener('pointermove', move)
                window.removeEventListener('pointerup', done)
                const drag = this.mapDrag
                this.mapDrag = null
                /* A click, not a drag: that is a selection. */
                if (!moved || !drag) { this.select(this.selected.sim, id) ; return }
                const centre = { x: drag.x + r.w / 2, y: drag.y + r.h / 2 }
                if (centre.y > this.mapScene().trayTop) {
                    await this.placeBox(id, null)
                } else {
                    const p = this.toWorld(centre.x, centre.y)
                    await this.placeBox(id, unmercator(p.x, p.y))
                }
            }
            window.addEventListener('pointermove', move)
            window.addEventListener('pointerup', done)
        },

        async placeBox(id, location) {
            const sim = this.selected.sim
            const r = await this.exchange(() =>
                api(`/simulations/${sim}/widgets/${id}/location`,
                    { method: 'PUT', body: JSON.stringify(location) }))
            if (!r.ok) { this.mapError = r.error ; return }
            this.mapError = null
            /* Keep the listing we hold in step rather than reloading the whole
             * topology: nothing else about it has changed. */
            const w = this.get(sim, id)
            if (w) w.location = r.value.location
            this.topoTock++
        },

        /*
         * Building, and unbuilding
         */

        /* What a cable can be plugged into: a device with a port left. The
         * widget listing counts them, since that is all this asks. */
        canTakeCable(w) {
            return !!w && w.free_ports > 0
        },

        async toggleTypeMenu() {
            if (this.typeMenu) { this.typeMenu = false ; return }
            if (!this.deviceTypes.length) {
                const r = await this.exchange(() => api('/device-types'))
                if (!r.ok) { this.mapError = r.error.message ; return }
                this.deviceTypes = r.value
            }
            this.mapError = null
            this.typeMenu = true
        },

        /* The parameters of a kind of device that are other devices, and are
         * therefore clicked on the map rather than typed. */
        endsOf(t) {
            return t.params.filter(p => baseKind(p.kind).type === 'widget')
        },

        startAdd(t) {
            this.typeMenu = false
            const sim = this.selected.sim
            if (this.endsOf(t).length) this.picking = { sim, type: t, ends: [] }
            else this.adding = this.formFor(sim, t, [])
        },

        /* One field per parameter, holding what will be sent. The catalogue
         * says what each one may be worth, in the same words a property's kind
         * does, so the inputs are the same inputs. */
        formFor(sim, t, picked) {
            const ends = this.endsOf(t)
            const fields = t.params.map(p => {
                const i = ends.indexOf(p)
                return {
                    name: p.name, descr: p.descr, units: p.units, kind: p.kind,
                    /* What the input says while it is empty: an example, or
                     * what will happen if it is left that way. */
                    placeholder: p.placeholder,
                    /* An end picked on the map is shown, not typed into. */
                    picked: i >= 0 ? picked[i] : null,
                    /* Something that may be left out starts left out, unless
                     * the catalogue has something to offer for it. */
                    enabled: p.kind.type !== 'optional' || p.default !== null,
                    draft: p.default === null ? '' : String(p.default)
                }
            })
            return { sim, type: t.type, descr: t.descr, name: '', fields,
                     /* The ends already clicked, kept as they were picked: the
                      * map goes on marking them for as long as this form is
                      * open, since where the cable will land is the one thing
                      * the form cannot show. */
                     ends: picked,
                     /* What it will be called if the name is left alone,
                      * shown in the box rather than filled into it: the name
                      * is not sent when it is empty, and the server picks it
                      * then, which is the only moment it can be sure the name
                      * is free. */
                     nameHint: this.nextName(sim, t, picked),
                     error: null, busy: false }
        },

        /* The name the server would pick, worked out the same way it does, so
         * that the hint is what happens. Being one number behind -- something
         * else built in between, a cable that is the second between the same
         * pair -- costs nothing, since this is never sent. */
        nextName(sim, t, picked) {
            const byId = this.widgetsOf(sim)
            const root = byId[this.roots[sim]]
            const siblings = (root ? root.children : [])
                .map(id => byId[id]).filter(w => w)
            if (t.type === 'cable' && picked.length === 2) {
                const ends = picked.map(id => byId[id])
                if (ends.every(w => w)) return ends.map(w => w.name).join('-')
            }
            for (let i = 1 ;; i++) {
                const n = `${t.type}-${i}`
                if (!siblings.some(w => w.name === n)) return n
            }
        },

        /* The ends of what is being built, while they are being clicked and then
         * while the form that finishes it is open. Empty once it is built, or
         * given up on. */
        pickedEnds() {
            const b = this.picking || this.adding
            return b && b.ends ? b.ends : []
        },

        /* What is being built, named as the catalogue names it. [picking] holds
         * the catalogue entry itself, the form only its name. */
        buildingType() {
            return this.picking ? this.picking.type.type
                 : this.adding ? this.adding.type : ''
        },

        pickEnd(id) {
            const p = this.picking
            if (!p || p.sim !== this.selected.sim) return
            const w = this.get(p.sim, id)
            if (!this.canTakeCable(w)) {
                this.mapError = `${w ? w.name : 'that'} has no port left`
                return
            }
            if (p.ends.includes(id)) {
                this.mapError = 'a cable joins two devices, not one to itself'
                return
            }
            this.mapError = null
            p.ends.push(id)
            if (p.ends.length === this.endsOf(p.type).length) {
                this.adding = this.formFor(p.sim, p.type, p.ends)
                this.picking = null
            }
        },

        cancelAdd() {
            this.picking = null
            this.adding = null
            this.typeMenu = false
            this.mapError = null
        },

        /* What one field is worth, in the JSON the API expects. */
        fieldValue(f) {
            if (f.picked !== null) return f.picked
            /* A field of the form is read exactly as a property's input is:
             * see [cellValue]. No parameter of any device is a list or a
             * record so far; the day one is, this form has a table to grow
             * as the property panel did. */
            return cellValue(f)
        },

        async submitAdd() {
            const a = this.adding
            if (!a || a.busy) return
            const params = {}
            for (const f of a.fields) params[f.name] = this.fieldValue(f)
            a.busy = true
            const r = await this.exchange(() =>
                api(`/simulations/${a.sim}/widgets`,
                    { method: 'POST',
                      body: JSON.stringify({ type: a.type, name: a.name,
                                             params }) }))
            a.busy = false
            /* Whatever it refused, said beside the form it was refused for:
             * the fields are still there to be corrected. */
            if (!r.ok) { a.error = r.error.message ; return }
            const id = r.value.id
            this.adding = null
            /* The tree has a new branch and the map a new box in the strip
             * below it, since nothing built here is placed. The reader is left
             * on what they built, which is where its properties are. */
            await this.reload()
            await this.select(a.sim, id)
        },

        async deleteSelected() {
            if (!this.selected || !this.selected.deletable) return
            if (!this.confirmDelete) { this.confirmDelete = true ; return }
            this.confirmDelete = false
            const r = await this.exchange(() =>
                api(`/simulations/${this.selected.sim}/widgets/${this.selected.id}`,
                    { method: 'DELETE' }))
            if (!r.ok) { this.mapError = r.error.message ; return }
            this.mapError = null
            /* What was being looked at is gone, and [reload] settles on
             * something that is not. */
            await this.reload()
        },

        /* Bring the selection into view, if it is not already there.
         *
         * Only if: the whole promise of this map is that things stay where they
         * were left, and sliding it about whenever the reader clicks something
         * they can already see is exactly what breaks that. So this is for the
         * case it cannot help with -- picking something out of the tree that is
         * off the edge of the map, or behind where it has been panned to. */
        showSelection() {
            if (!this.selected || !this.mapView.k) return
            const scene = this.mapScene()
            let box = scene.rects.get(this.selected.id)
            if (!box) {
                /* Not drawn as a box. A cable is a line, and the point of it
                 * is where its name is written; anything else is shown by the
                 * box standing for it. */
                const line = scene.edges.find(e => e.via === this.selected.id)
                if (line) {
                    box = { x: line.mx, y: line.my, w: 0, h: 0 }
                } else {
                    const byId = this.widgetsOf(this.selected.sim)
                    let w = byId[this.selected.id]
                    for (w = w && byId[w.parent] ; w ; w = byId[w.parent])
                        if (scene.rects.has(w.id)) {
                            box = scene.rects.get(w.id) ; break
                        }
                }
            }
            if (!box) return
            const at = { x: box.x + box.w / 2, y: box.y + box.h / 2 }
            /* In the strip below the map, which is pinned to the pane rather
             * than laid over the world: it is in view already, and panning
             * could not bring it into view if it were not. */
            if (at.y > scene.trayTop) return
            const m = 8
            if (box.x >= m && box.y >= m &&
                box.x + box.w <= this.mapSize.w - m &&
                box.y + box.h <= scene.trayTop - m) return
            const w = this.toWorld(at.x, at.y)
            this.mapView = { k: this.mapView.k, cx: w.x, cy: w.y }
        },

        /* Everything the map draws, in pane pixels.
         *
         * Rebuilt whenever anything it is drawn from moves, and returned as it
         * was otherwise: the bindings ask for it several times per render, and
         * laying the network out several times per render for the same answer
         * would be a waste that grows with the size of the network. */
        mapScene() {
            const sim = this.selected ? this.selected.sim : null
            const drag = this.mapDrag
            const sig = [ sim, this.selected && this.selected.id, this.topoTock,
                          this.mapOpen.join(), this.mapAuto.join(),
                          this.mapView.cx, this.mapView.cy,
                          this.mapView.k, this.mapSize.w, this.mapSize.h,
                          drag && `${drag.id}@${Math.round(drag.x)},${Math.round(drag.y)}`
                        ].join('|')
            if (sceneMemo.sig === sig) return sceneMemo.value
            const value = this.buildScene(sim, drag)
            sceneMemo = { sig, value }
            return value
        },

        buildScene(sim, drag) {
            const { w: paneW, h: paneH } = this.mapSize
            const empty = { boxes: [], edges: [], ports: [], rects: new Map(),
                            trayTop: paneH, trayCount: 0 }
            if (sim === null || !paneW || !paneH) return empty
            const byId = this.widgetsOf(sim)
            const root = this.roots[sim]
            if (byId[root] === undefined) return empty
            const links = linkSet(byId)
            const plane = planeOf(byId, root, links)
            const open = new Set([ ...this.mapOpen, ...this.mapAuto ])
            const drawn = drawnSet(byId, plane, open, links)
            const { edges, inside } = mapEdges(byId, drawn, links)

            /* Size every box on the plane, then place it: where it belongs if
             * it has a place, in the strip below if it has none. A widget with
             * no location is not at 0,0 -- it is nowhere, and saying so is the
             * point of the strip. */
            const rects = new Map()
            const placed = [], unplaced = []
            for (const id of plane) {
                const tree = boxTree(byId, id, open, links)
                if (byId[id].location) placed.push({ id, tree })
                else unplaced.push({ id, tree })
            }
            /* The strip is as tall as what it holds, and never shorter than one
             * box: it is also where a box is dropped to take it off the map,
             * so it has to be there even when it is empty. */
            const rows = [ [] ]
            let rowW = boxPad
            for (const u of unplaced) {
                if (rowW + u.tree.w > paneW - boxPad &&
                    rows[rows.length - 1].length) {
                    rows.push([]) ; rowW = boxPad
                }
                rows[rows.length - 1].push(u) ; rowW += u.tree.w + boxGap
            }
            const rowHeight = (r) =>
                r.reduce((m, u) => Math.max(m, u.tree.h), boxH)
            const trayH = rows.reduce((h, r) => h + rowHeight(r) + boxGap, 0)
            const trayTop = paneH - trayH - boxPad

            let y = trayTop + boxGap
            for (const row of rows) {
                let x = boxPad
                for (const u of row) {
                    placeTree(u.tree, x, y, rects)
                    x += u.tree.w + boxGap
                }
                y += rowHeight(row) + boxGap
            }
            for (const p of placed) {
                const l = byId[p.id].location
                const m = mercator(l.lat, l.lon)
                const c = this.toPane(m.x, m.y)
                placeTree(p.tree, c.x - p.tree.w / 2, c.y - p.tree.h / 2, rects)
            }
            /* The box under the pointer follows it, and everything hanging off
             * it follows too, because the edges are drawn from these rects. */
            if (drag && rects.has(drag.id)) {
                const r = rects.get(drag.id)
                const dx = drag.x - r.x, dy = drag.y - r.y
                const shift = (id) => {
                    const q = rects.get(id)
                    if (!q) return
                    q.x += dx ; q.y += dy
                    ;(byId[id] ? byId[id].children : []).forEach(shift)
                }
                shift(drag.id)
            }

            /* Now the edges, between the rectangles that are actually on
             * screen, and the ports where they land. Where each end crosses
             * its box first, then spread out, and only then are the lines and
             * the ports read off them: a port and the line reaching it must
             * arrive at the same spot. */
            const ends = []
            for (const e of edges) {
                const a = rects.get(e.from), b = rects.get(e.to)
                if (!a || !b) continue
                const ac = { x: a.x + a.w / 2, y: a.y + a.h / 2 }
                const bc = { x: b.x + b.w / 2, y: b.y + b.h / 2 }
                ends.push({ edge: e, box: e.from, port: e.fromPort,
                            pt: borderPoint(a, bc.x, bc.y), first: true },
                          { edge: e, box: e.to, port: e.toPort,
                            pt: borderPoint(b, ac.x, ac.y), first: false })
            }
            spreadEnds(ends, rects)

            const lines = [], ports = []
            for (let i = 0 ; i < ends.length ; i += 2) {
                const e = ends[i].edge
                const p1 = ends[i].pt, p2 = ends[i + 1].pt
                lines.push({ key: e.key, via: e.via,
                             name: e.via === null ? '' : this.nameOf(e.via),
                             /* A cable is a widget one can be looking at, and
                              * it is a line here rather than a box, so this is
                              * the only thing there is to mark. */
                             on: this.selected !== null &&
                                 e.via === this.selected.id,
                             /* Named only where there is room to read it. Two
                              * boxes side by side leave a few pixels of cable
                              * between them, and a name written across both of
                              * them says less than no name at all -- which is
                              * the state everything is in before anything has
                              * been placed. */
                             room: Math.hypot(p2.x - p1.x, p2.y - p1.y) > 48,
                             x1: p1.x, y1: p1.y, x2: p2.x, y2: p2.y,
                             mx: (p1.x + p2.x) / 2, my: (p1.y + p2.y) / 2 })
            }
            /* A port is an end that is not the box it is drawn from: the widget
             * the cable really reaches, standing on the perimeter of whatever is
             * hiding it. An end that is the box itself has no port -- the line
             * simply goes to the box. */
            for (const e of ends) {
                if (e.port === null) continue
                ports.push({ key: `${e.edge.key}:${e.first ? 'a' : 'b'}`,
                             id: e.port, name: this.nameOf(e.port),
                             x: e.pt.x, y: e.pt.y })
            }

            /* The boxes the selected widget is inside. There is always one of
             * these to see even when the widget itself is not drawn -- because
             * the reader shut the box holding it, or because it is a cable and
             * so is no box at all. */
            const held = new Set()
            if (this.selected) {
                let w = byId[this.selected.id]
                for (w = w && byId[w.parent] ; w ; w = byId[w.parent])
                    if (drawn.has(w.id)) held.add(w.id)
            }

            const boxes = [ ...rects.values() ].map(r => Object.assign({}, r, {
                name: this.nameOf(r.id),
                holds: held.has(r.id),
                /* What a shut box is folding away, so that connectivity does
                 * not silently vanish into it. */
                inside: inside.get(r.id) || 0,
                hasKids: byId[r.id].children.some(c => byId[c] && !links.has(c)),
                placed: !!byId[r.id].location,
                /* Drawn as having no place of its own only where having one
                 * would mean something. What is inside a box is drawn where
                 * that box says, and never has a place of its own: marking it
                 * would mark every nested box on the map, always. */
                nowhere: r.depth === 0 && !byId[r.id].location,
            })).sort((a, b) => a.depth - b.depth)

            return { boxes, edges: lines, ports, rects, trayTop,
                     trayCount: unplaced.length }
        },

        /* The lines, as one lump of SVG: a <template> inside an <svg> is parsed
         * as an SVG element with no content, so x-for cannot be used there.
         * Only the lines go in -- everything one can click is HTML above
         * them, which is also what lets them be styled like the rest of the
         * page. */
        edgeSvg() {
            return this.mapScene().edges.map(e =>
                `<line class="${e.on ? 'on' : ''}" x1="${e.x1}" y1="${e.y1}" ` +
                `x2="${e.x2}" y2="${e.y2}"/>`
            ).join('')
        },

        /* The coast under it all, as a single path: a shoreline is a thousand
         * segments, and a thousand elements to move on every pan is a thousand
         * too many.
         *
         * It stops at the strip along the bottom. What is down there has no
         * place in the world, and drawing a coast behind it would say it has
         * one. */
        coastPath() {
            const { w, h } = this.mapSize
            const { cx, cy, k } = this.mapView
            if (!w || !h || !k) return ''
            const bottom = this.mapScene().trayTop
            const sig = [ cx, cy, k, w, bottom ].join('|')
            if (coastMemo.sig === sig) return coastMemo.value
            /* The projection, written out: [toPane] for a thousand points, a
             * dozen times a second. */
            const ox = w / 2 - cx * k, oy = h / 2 - cy * k
            const at = (v) => Math.round(v * 10) / 10
            let d = '', wasX = null, wasY = null
            for (const l of coastWorld()) {
                let px = l[0] * k + ox, py = l[1] * k + oy
                for (let i = 2 ; i < l.length ; i += 2) {
                    const qx = l[i] * k + ox, qy = l[i + 1] * k + oy
                    const s = clipSeg(px, py, qx, qy, w, bottom)
                    if (s !== null) {
                        /* Carried on from where the last piece ended, or begun
                         * afresh. Two pieces of one shoreline that meet are a
                         * single stroke; two that do not must not be joined by
                         * a coast that is not there. */
                        if (s[0] !== wasX || s[1] !== wasY)
                            d += `M${at(s[0])} ${at(s[1])}`
                        d += `L${at(s[2])} ${at(s[3])}`
                        wasX = s[2] ; wasY = s[3]
                    }
                    px = qx ; py = qy
                }
            }
            coastMemo = { sig, value: d }
            return d
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

        /* What a speed button leads to, for its tooltip: null is off the top
         * of the ladder. */
        speedTip(ratio) {
            return ratio === null ? 'as fast as it can go'
                                  : ratioText(ratio) + ' \u00d7 real time'
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

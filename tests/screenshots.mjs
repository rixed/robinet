/* Drives the administration interface in a real browser and writes a
 * screenshot of each state worth looking at, including the ones that are
 * awkward to reach by hand: a value the setter refused, and the simulator
 * going away and coming back.
 *
 * Deliberately not part of [make check]: it wants a browser and a node
 * package, neither of which the library depends on. To run it:
 *
 *   cd /tmp && npm install playwright-core
 *   cd <robinet>
 *   PLAYWRIGHT=/tmp/node_modules/playwright-core \
 *   CHROME=$HOME/.cache/ms-playwright/chromium_headless_shell-*}/chrome-headless-shell-linux64/chrome-headless-shell \
 *     node tests/screenshots.mjs /tmp/shots
 *
 * CHROME may be left unset if a chromium is on the PATH.
 */
import { createRequire } from 'module'
import { spawn } from 'child_process'

const require = createRequire(import.meta.url)
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright-core')

const PORT = 18093, BASE = `http://127.0.0.1:${PORT}`
const OUT = process.argv[2] || '/tmp/shots'
const sleep = ms => new Promise(r => setTimeout(r, ms))

let srv = null
process.on('exit', () => { if (srv) srv.kill('SIGKILL') })

const start = async () => {
    /* A server left over from an earlier run would answer in place of ours,
     * and then stopping "the" server would stop nothing -- which looks exactly
     * like the interface failing to notice that it went away. */
    let inUse = false
    try { await fetch(BASE + '/api/simulations') ; inUse = true } catch (e) {}
    if (inUse) throw new Error(`something is already listening on ${PORT}`)

    srv = spawn('./examples/admin_demo.opt', [String(PORT)], { stdio: 'ignore' })
    for (let i = 0; i < 100; i++) {
        try { await fetch(BASE + '/api/simulations') ; return } catch (e) {}
        await sleep(100)
    }
    throw new Error('the demo would not start')
}

const stop = async () => {
    if (!srv) return
    srv.kill('SIGKILL') ; srv = null
    for (let i = 0; i < 100; i++) {
        try { await fetch(BASE + '/api/simulations') } catch (e) { return }
        await sleep(100)
    }
    throw new Error('the demo would not stop')
}

await start()
const browser = await chromium.launch({
    executablePath: process.env.CHROME,
    args: [ '--no-sandbox', '--disable-dev-shm-usage' ],
})
const page = await browser.newPage({ viewport: { width: 1400, height: 950 } })
const problems = []
page.on('pageerror', e => problems.push('uncaught: ' + e.message))

await page.goto(BASE + '/', { waitUntil: 'networkidle' })
await page.waitForSelector('nav.tree a')

/* A cable: its two ends either side, and its properties below. */
await page.getByRole('link', { name: 'cable1', exact: true }).first().click()
await page.waitForSelector('input[type=range]')
await page.screenshot({ path: `${OUT}/a-cable.png` })

/* A range, drawn from what the API said about it: a slider between the two
 * ends, and a number input beside it for the value the slider cannot land on
 * exactly. */
const rate = page.locator('article.properties tr').filter({ hasText: 'error rate' })
const attrs = async (sel) => {
    const e = rate.locator(sel)
    return { n: await e.count(), min: await e.getAttribute('min'),
             max: await e.getAttribute('max'), step: await e.getAttribute('step') }
}
const slider = await attrs('input[type=range]')
const typed_ = await attrs('input[type=number]')
if (slider.n !== 1 || slider.min !== '0' || slider.max !== '1' ||
    slider.step !== '0.001')
    problems.push('the slider of a 0..1 range: ' + JSON.stringify(slider))
if (typed_.step !== 'any')
    problems.push('a continuous range must accept any value: ' + typed_.step)

/* And the two decisions it makes, on the ranges the demo has not got: a
 * slider is drawn only when it has both ends to draw a track between and,
 * when only whole numbers will do, few enough of them that a drag lands
 * where it was aimed. */
const drawn = await page.evaluate(() => {
    const d = Alpine.$data(document.body)
    const k = (int, min, max) => ({ type: 'range', int, min, max })
    return { smallInt: d.hasSlider(k(true, 0, 100)),
             smallStep: d.sliderStep(k(true, 0, 100)),
             hugeInt: d.hasSlider(k(true, 0, 1e6)),
             unbounded: d.hasSlider(k(true, 0, null)),
             floatStep: d.sliderStep(k(false, -5, 5)) }
})
if (!drawn.smallInt || drawn.smallStep !== 1)
    problems.push('a short whole range wants a slider stepping by one: ' +
                  JSON.stringify(drawn))
if (drawn.hugeInt || drawn.unbounded)
    problems.push('a slider was drawn where dragging it means nothing: ' +
                  JSON.stringify(drawn))
if (drawn.floatStep !== 0.01)
    problems.push('a continuous slider steps by a thousandth of its span: ' +
                  drawn.floatStep)

/* The switch: three peers, each joined by the cable that reaches it. */
await page.getByRole('link', { name: 'switch', exact: true }).first().click()
await page.waitForTimeout(300)
await page.screenshot({ path: `${OUT}/b-switch.png` })

/* The speed controls, driven as a reader would: what the buttons do, what the
 * simulation says it is doing, and that unpausing goes back to the speed that
 * was in use rather than to full speed. */
const wan = page.locator('article.sim').first()
const says = async () => (await wan.locator('p.speed span').first().innerText()).trim()
const shouldSay = async (want, what) => {
    for (let i = 0; i < 40; i++) {
        if (await says() === want) return
        await page.waitForTimeout(100)
    }
    problems.push(`${what}: expected "${want}", the page said "${await says()}"`)
}
await shouldSay('full speed', 'a closed simulation starts at full speed')
await wan.getByTitle('Real time').click()
await shouldSay('1 \u00d7 real time', 'matching real time')
await wan.getByTitle('Faster').click()
await shouldSay('2 \u00d7 real time', 'speeding up')
await wan.getByTitle('Slower').click()
await wan.getByTitle('Slower').click()
await shouldSay('1/2 \u00d7 real time', 'slowing down, in halves')
await wan.getByRole('button', { name: 'Pause' }).click()
await shouldSay('paused', 'pausing')
if (!await wan.getByRole('button', { name: 'Step 10' }).isVisible())
    problems.push('stepping is not offered while paused')
await page.screenshot({ path: `${OUT}/i-speed.png` })
await wan.getByRole('button', { name: 'Resume' }).click()
await shouldSay('1/2 \u00d7 real time', 'unpausing goes back to the speed in use')

/* Asked for more than the machine can do: it must say so rather than quietly
 * run slower than asked. Through the API, since the buttons deliberately do
 * not offer a speed that absurd. */
await fetch(`${BASE}/api/simulations/0/speed?ratio=1e9`, { method: 'POST' })
await page.waitForTimeout(1500)
const warned = wan.locator('p.speed .late')
if (!await warned.isVisible())
    problems.push('a simulation that cannot keep up does not say so')
else {
    const tip = await warned.getAttribute('title')
    if (!/behind/.test(tip || '')) problems.push(`unhelpful warning: ${tip}`)
}
await fetch(`${BASE}/api/simulations/0/speed?ratio=full`, { method: 'POST' })
await shouldSay('full speed', 'back to full speed')
if (await warned.isVisible())
    problems.push('the warning outlived the speed that caused it')

/* How a refused value looks against its field. The inputs are type=number, so
 * the browser blocks non-numeric text before any setter sees it, and no
 * property currently refuses a number -- so put the component in that state
 * and check it renders. That it gets there on its own is covered elsewhere. */
await page.getByRole('link', { name: 'cable1', exact: true }).first().click()
await page.waitForSelector('input[type=range]')
await page.evaluate(() => {
    const p = Alpine.$data(document.body).props.find(p => p.name === 'length')
    p.error = 'Cannot set property "length" to -3: length must be positive'
    p.dirty = true
})
await page.waitForTimeout(300)
await page.screenshot({ path: `${OUT}/c-refused.png` })

/* The simulator goes away: everything on screen becomes last-known. */
await stop()
await page.waitForSelector('.banner', { state: 'visible', timeout: 15000 })
await page.waitForTimeout(1500)
await page.screenshot({ path: `${OUT}/d-offline.png` })
const banner = (await page.locator('.banner').innerText()).replace(/\s+/g, ' ')
/* Nothing that needs the simulator may still look pressable. */
const live = await page.evaluate(() =>
    [...document.querySelectorAll('.controls button, article.properties button, ' +
                                  'article.properties input, article.properties select')]
        .filter(e => e.offsetParent !== null && !e.disabled)
        .map(e => e.textContent.trim() || e.type))
if (live.length) problems.push('still offered while offline: ' + live.join(', '))

/* And comes back, with no help from the reader. */
await start()
await page.waitForSelector('.banner', { state: 'hidden', timeout: 30000 })
await page.waitForTimeout(500)
await page.screenshot({ path: `${OUT}/e-recovered.png` })

/* The live refresh must not fight whoever is typing: what was typed stays,
 * and keeps the focus, across several polls -- while the read-only counters
 * beside it carry on moving. */
await page.getByRole('link', { name: 'cable1', exact: true }).first().click()
await page.waitForSelector('input[type=range]')
const length = page.locator('article.properties input[type=number]').first()
await length.click()
await length.fill('42.5')
/* Named rather than positional: the rows carry hidden spans for the shapes
 * they are not. */
const counter = page.locator('article.properties tr')
                    .filter({ hasText: 'total bits' })
                    .locator('.metric .figure')
const countedBefore = await counter.innerText()
await page.waitForTimeout(3500)   /* three polls or so */
const typed = await length.inputValue()
const stillFocused = await length.evaluate(e => e === document.activeElement)
const countedAfter = await counter.innerText()
if (typed !== '42.5') problems.push(`the poll overwrote the field being edited: "${typed}"`)
if (!stillFocused) problems.push('the poll took the focus away from the field being edited')
if (countedBefore === countedAfter) problems.push('the read-only values stopped refreshing')
await page.screenshot({ path: `${OUT}/f-editing.png` })

/* And leaving the field saves it. */
await page.locator('article.properties strong').first().click()
await page.waitForTimeout(1500)
const saved = await length.inputValue()
if (saved !== '42.5') problems.push(`the edited value did not stick: "${saved}"`)

/* What just changed is pointed at, and stops being pointed at once it stops
 * changing. */
await page.getByRole('link', { name: 'cable1', exact: true }).first().click()
await page.waitForSelector('.metric .figure')
const counterRow = page.locator('article.properties tr').filter({ hasText: 'total bits' })
/* The highlight lasts a fraction of a second and the poll a whole one, so
 * looking once would mostly look between two pulses: watch for one. */
const lit = counterRow.locator('.metric .figure.changed')
let sawLit = false
for (let i = 0; i < 40 && !sawLit; i++) {
    if (await lit.count()) sawLit = true
    else await page.waitForTimeout(100)
}
if (!sawLit) problems.push('a counter that is moving is never highlighted')
/* For the picture only: the pulse is over before a screenshot can be taken,
 * so light it by hand. That it lights on its own is what the loop above
 * establishes; this only records what it looks like. */
await page.evaluate(() => {
    for (const p of Alpine.$data(document.body).props)
        if (p.metric) for (const row of p.metric.rows) row.changedAt = Date.now()
})
await page.screenshot({ path: `${OUT}/h-changed.png` })
/* Stop the simulation from underneath it: nothing moves, so nothing stays
 * lit. This also exercises the highlight going out on its own. */
await page.getByRole('button', { name: 'Pause' }).first().click()
await page.waitForTimeout(2000)
const stuck = await page.locator('article.properties .changed').count()
if (stuck) problems.push(`${stuck} value(s) stayed highlighted after the simulation was paused`)
await page.getByRole('button', { name: 'Resume' }).first().click()
await page.waitForTimeout(1500)

/* Columns must not shift while the values refresh. The hub is the one to
 * watch: its counters have a row per port, and they gain digits as they run. */
await page.getByRole('link', { name: 'hub', exact: true }).first().click()
await page.waitForSelector('.metric .figure')
const widths = new Set()
for (let i = 0; i < 25; i++) {
    widths.add(await page.evaluate(() =>
        [...document.querySelectorAll('article.properties thead th')]
            .map(e => Math.round(e.getBoundingClientRect().width)).join('/')))
    await page.waitForTimeout(120)
}
if (widths.size !== 1)
    problems.push('the property columns move as the values refresh: ' +
                  [...widths].join(' then '))

/* The cable only has counters, so the other three kinds of metric would go
 * unseen. Feed the renderer the shapes metric.ml produces for them -- with the
 * poll off, since it would replace them with what the server really has. */
await page.evaluate(() => {
    const d = Alpine.$data(document.body)
    d.live = false
    const now = d.sims[0].now
    const fired = (n, counts, at) => ({
        name: n, counts, first_last: { first: at, last: at } })
    const once = (params, value) => ({ params, value })
    const mk = (name, descr, value, read_only) => ({
        name, descr, read_only, kind: { type: 'metric' },
        value, metric: metricRows(value), error: null })
    d.props = [
        mk('mac table', 'MACs the switch remembers.', {
            kind: 'gauge', name: 'macs',
            values: [ { params: {}, value: { min: 0, current: 12, max: 25 } } ],
            first_last: { first: now - 60, last: now - 2.5 } }, true),
        /* Out of order, and with a two-digit port: the simulator's hash
         * table has no order, and 9 must not sort after 10. */
        mk('lookups', 'Table misses, per port.', {
            kind: 'atomic', name: 'misses',
            counts: [ { params: { port: 10 }, value: 3 },
                      { params: { port: 2 }, value: 17 },
                      { params: { port: 9 }, value: 5 } ],
            first_last: { first: now - 60, last: now - 0.5 } }, true),
        mk('resolutions', 'How long a name took to resolve.', {
            kind: 'timed', name: 'queries',
            durations: [ { params: {},
                           value: { min: 0.25, max: 0.9, sum: 2.3, count: 4 } } ],
            starts: fired('queries/start', [ once({}, 6) ], now - 30),
            stops: fired('queries/stop', [ once({}, 4) ], now - 4),
            simult: { name: 'queries/simult',
                      values: [ { params: {}, value: { min: 0, current: 2, max: 3 } } ],
                      first_last: { first: now - 60, last: now - 4 } } }, true),
        /* Writable: the only thing a write does is reset it. */
        mk('queries', 'Every request served.', {
            kind: 'counter', name: 'queries', units: 'requests',
            values: [ { params: { status: 200 }, value: 1204 },
                      { params: { status: 404 }, value: 3 } ],
            /* Counted one at a time, as Counter.add does with the same
             * params it was given. */
            fired: fired('queries/fired',
                         [ once({ status: 200 }, 1204), once({ status: 404 }, 3) ],
                         now - 0.2) }, false),
        mk('errors', 'Nothing has gone wrong yet.',
           { kind: 'atomic', name: 'errors', counts: [], first_last: null }, true),
    ]
})
await page.waitForTimeout(300)
await page.screenshot({ path: `${OUT}/g-metrics.png` })

const shown = await page.evaluate(() =>
    [...document.querySelectorAll('article.properties tbody tr')].map(tr =>
        tr.innerText.replace(/\s+/g, ' ').trim()))
const wants = [
    [ 'gauge', /12 between 0 and 25/ ],
    [ 'params of an atomic, in order',
      /port=2 17 times port=9 5 times port=10 3 times/ ],
    [ 'timed', /575ms on average 4 of them, 250ms to 900ms, 2 still running/ ],
    [ 'counter rows', /status=200 1,204 requests status=404 3 requests/ ],
    [ 'a metric with nothing in it', /nothing yet/ ],
]
for (const [what, re] of wants)
    if (!shown.some(t => re.test(t)))
        problems.push(`${what} not rendered as expected; rows were: ${JSON.stringify(shown)}`)
/* Only the writable one offers a reset. */
const resets = await page.locator('button.metric-reset:visible').count()
if (resets !== 1) problems.push(`expected 1 reset button, found ${resets}`)

/* And it must not move as the text beside it is refreshed: "last just now"
 * and "last 3h 20min ago" are not the same width, and a button that shifts
 * under the pointer is a button one misses. */
const spots = new Set()
for (const age of [ 0, 0.5, 2.5, 45.7, 3600 * 3 + 1200, 86400 ]) {
    await page.evaluate((age) => {
        const d = Alpine.$data(document.body)
        const now = d.sims.find(s => s.id === d.selected.sim).now
        for (const p of d.props)
            if (p.metric && p.metric.last !== null) p.metric.last = now - age
    }, age)
    await page.waitForTimeout(120)
    spots.add(await page.locator('button.metric-reset:visible').evaluate(e => {
        const b = e.getBoundingClientRect()
        return Math.round(b.x) + ',' + Math.round(b.y)
    }))
}
if (spots.size !== 1)
    problems.push('the reset button moves as its metric refreshes: ' +
                  [...spots].join(' then '))

console.log('banner said:', banner)
console.log(problems.length ? 'UNCAUGHT ERRORS:\n  ' + problems.join('\n  ')
                            : 'no uncaught exceptions')
await browser.close()
await stop()
process.exit(problems.length ? 1 : 0)

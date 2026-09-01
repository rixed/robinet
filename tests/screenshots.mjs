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

/* Everything the page needs is served by the simulator itself: a robinet
 * program is one binary, and its interface has to work on a machine with no
 * network. Anything reaching elsewhere is cut off here and reported, so that a
 * script or a style sheet fetched from a CDN cannot pass unnoticed. */
const outside = []
await page.route('**', route => {
    const url = route.request().url()
    if (url.startsWith(BASE + '/')) return route.continue()
    outside.push(url)
    return route.abort()
})

await page.goto(BASE + '/', { waitUntil: 'networkidle' })
await page.waitForSelector('nav.tree a')

/* The title is the one link out of the page. It leaves for somewhere this
 * simulator cannot serve, so it has to say so and take the reader there
 * without taking this page with it -- and without handing the new tab a
 * handle on this one. */
const brand = page.locator('.brand h1 a')
const away = await brand.evaluate(a => ({
    href: a.getAttribute('href'), target: a.getAttribute('target'),
    rel: a.getAttribute('rel'), text: a.innerText.trim(),
    icons: a.querySelectorAll('svg.ext').length }))
if (away.href !== 'https://happyleptic.org/robinet.html' ||
    away.target !== '_blank' || !/\bnoopener\b/.test(away.rel || '') ||
    away.text !== 'RobiNet' || away.icons !== 1)
    problems.push('the title must link out, marked as leaving: ' +
                  JSON.stringify(away))

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

/* What a value is counted in is shown beside it and nowhere else: what is
 * typed, and what is sent, stays the bare number. */
const lengthRow = page.locator('article.properties tr').filter({ hasText: 'length' })
const unit = await lengthRow.locator('small.units').innerText()
const inInput = await lengthRow.locator('input[type=number]').inputValue()
if (unit !== 'meters') problems.push('a length in metres said: ' + unit)
if (!/^[0-9.]+$/.test(inInput))
    problems.push('the unit leaked into the field: ' + inInput)
if (await rate.locator('small.units').isVisible())
    problems.push('a property with no units still showed one')

/* And within a metric it goes on the figure -- except where the figure
 * already knows what it is: an atomic counts events, so the unit says what
 * they are, and a duration is written as one whatever the property says. */
const counted = await page.evaluate(() => {
    const atomic = (units) => metricView(
        { kind: 'atomic', counts: [ { params: {}, value: 3 } ], first_last: null },
        units).rows[0]
    const timed = metricView(
        { kind: 'timed', simult: { values: [] }, stops: { first_last: null },
          durations: [ { params: {}, value: { count: 2, sum: 4, min: 1, max: 3 } } ] },
        'seconds').rows[0]
    const counter = metricView(
        { kind: 'counter', values: [ { params: {}, value: 1024 } ],
          fired: { counts: [], first_last: null } }, 'bytes').rows[0]
    return { units: atomic('queries').detail, none: atomic('').detail,
             timed: timed.figure, counter: counter.figure }
})
if (counted.units !== 'queries' || counted.none !== 'times')
    problems.push('what an atomic counts: ' + JSON.stringify(counted))
if (counted.counter !== '1,024 bytes')
    problems.push('a counter of bytes reads: ' + counted.counter)
if (/seconds/.test(counted.timed))
    problems.push('a duration took a unit it had no use for: ' + counted.timed)

/* A DHCP server: values that may be absent. The box in front says whether
 * there is one; the input beside it keeps the last, disabled, so that ticking
 * the box back offers it again rather than an empty field. */
await page.getByRole('link', { name: 'dhcpd', exact: true }).first().click()
await page.waitForSelector('input.enabler')
const dhcpdId = (await (await fetch(`${BASE}/api/simulations/0/widgets`)).json())
                .find(w => w.name === 'dhcpd').id
const mtuValue = async () =>
    (await (await fetch(
        `${BASE}/api/simulations/0/widgets/${dhcpdId}/properties/MTU`)).json()).value
const mtu = page.locator('article.properties tbody tr').filter({ hasText: 'MTU' })
const box = mtu.locator('input.enabler')
const num = mtu.locator('input[type=number]')
const unset = page.locator('article.properties tbody tr').filter({ hasText: 'gateway' })
if ((await unset.locator('span.ro').innerText()).trim() !== 'unset')
    problems.push('an unset read-only value must say so, not show an empty cell')
if (await unset.locator('input.enabler').count())
    problems.push('a read-only value got a box that cannot do anything')
await page.screenshot({ path: `${OUT}/b-optional.png` })

if (!await box.isChecked()) problems.push('a value that is there must be ticked')
await box.uncheck()
await page.waitForTimeout(500)
if (await mtuValue() !== null) problems.push('unticking must unset the value')
if (!await num.isDisabled() || await num.inputValue() !== '1500')
    problems.push('the input must stay, disabled, holding what it had: ' +
                  await num.inputValue())
/* Three polls: the box is part of what the reader is editing. */
await page.waitForTimeout(3200)
if (await box.isChecked() || await num.inputValue() !== '1500')
    problems.push('a poll undid the unticking')
await box.check()
await page.waitForTimeout(400)
if (await mtuValue() !== null) problems.push('ticking the box alone must save nothing')
if (!await num.evaluate(e => e === document.activeElement))
    problems.push('ticking the box must hand the reader the field')
await num.press('Enter')
await page.waitForTimeout(400)
if (await mtuValue() !== 1500)
    problems.push('confirming must save what was remembered, got ' + await mtuValue())

/* Where a widget is, read like anything else it has to say about itself --
 * but only once it is somewhere. Every widget carries the pair, and a server
 * that is nowhere of its own has nothing to say through it: the row would be
 * two lines of "unset" on every widget in the tree. Unlike the gateway just
 * above, which is unset because that is how the server is configured, and
 * says so. */
const propRow = (name) =>
    page.locator('article.properties tbody tr')
        .filter({ has: page.locator(`td span:text-is("${name}")`) })
const listed = async (id) =>
    (await (await fetch(`${BASE}/api/simulations/0/widgets/${id}/properties`))
        .json()).find(p => p.name === 'latitude')

const nowhere = await listed(dhcpdId)
if (!nowhere || nowhere.value !== null || nowhere.only_when_set !== true)
    problems.push('an unplaced widget must still offer its latitude, marked: ' +
                  JSON.stringify(nowhere))
if (await propRow('latitude').count())
    problems.push('a widget that is nowhere showed a row saying so')

/* The switch: three peers, each joined by the cable that reaches it. */
await page.getByRole('link', { name: 'switch', exact: true }).first().click()
await page.waitForTimeout(300)

/* And the same pair, on something that is somewhere. */
const switchId = (await (await fetch(`${BASE}/api/simulations/0/widgets`)).json())
                 .find(w => w.name === 'switch').id
const somewhere = await listed(switchId)
const shownLat = (await propRow('latitude').locator('span.ro').innerText()).trim()
if (somewhere.value === null || Math.abs(somewhere.value - 48.8566) > 1e-6)
    problems.push('a placed widget reads its latitude back: ' +
                  JSON.stringify(somewhere))
if (!shownLat.startsWith('48.8566'))
    problems.push('the panel must show a place it has: ' + shownLat)
await page.screenshot({ path: `${OUT}/b-switch.png` })

/* One simulation is what is being worked on; the rest are in the way, and the
 * one serving this page never is the subject. So it opens with that one folded
 * away and the other not. */
const simCard = (name) => page.locator('article.sim')
    .filter({ has: page.locator(`header strong:text-is("${name}")`) })
const folded = async (name) =>
    !await simCard(name).locator('.body').isVisible()

if (await folded('wan'))
    problems.push('the simulation under study should open unfolded')
if (!await folded('admin'))
    problems.push('the simulation serving the page should open folded away')
/* Folded, its header is all there is of it, so it has to say what its clock is
 * doing: folding one is not ceasing to care whether it is running. */
const adminBadge = await simCard('admin').locator('.badge:visible').innerText()
if (adminBadge !== 'real time')
    problems.push('a folded simulation must still say what it is doing, and ' +
                  `it said "${adminBadge}"`)

await simCard('admin').locator('header button.twisty').click()
await page.waitForTimeout(200)
await simCard('wan').locator('header button.twisty').click()
await page.waitForTimeout(200)
if (await folded('admin') || !await folded('wan'))
    problems.push('the twisty must fold and unfold a simulation')

/* And what the reader chose survives the topology being read afresh -- which
 * happens on its own whenever the simulator goes away and comes back. */
await page.evaluate(() => Alpine.$data(document.body).reload())
await page.waitForTimeout(500)
if (await folded('admin') || !await folded('wan'))
    problems.push('a reload must not undo what the reader folded')

/* Back to the way it opened, for the sections below. */
await simCard('admin').locator('header button.twisty').click()
await simCard('wan').locator('header button.twisty').click()
await page.waitForTimeout(300)

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
const speedButton = (name) =>
    wan.getByRole('button', { name, exact: true })
await speedButton('Real time').click()
await shouldSay('1 \u00d7 real time', 'matching real time')
await speedButton('Faster').click()
await shouldSay('2 \u00d7 real time', 'speeding up')
await speedButton('Slower').click()
await speedButton('Slower').click()
await shouldSay('1/2 \u00d7 real time', 'slowing down, in halves')
await wan.getByRole('button', { name: 'Pause' }).click()
await shouldSay('paused', 'pausing')
if (!await wan.getByRole('button', { name: 'Step 10' }).isVisible())
    problems.push('stepping is not offered while paused')
/* And a speed is not, while there is no clock running for it to be the speed
 * of: three buttons that set one without starting it are three ways of
 * appearing to resume without resuming. */
for (const which of [ 'Slower', 'Real time', 'Faster', 'Full speed' ])
    if (await speedButton(which).isVisible())
        problems.push(`${which} is offered while the simulation is paused`)
await page.screenshot({ path: `${OUT}/i-speed.png` })
await wan.getByRole('button', { name: 'Resume' }).click()
await shouldSay('1/2 \u00d7 real time', 'unpausing goes back to the speed in use')
/* The speed it was set to is what it comes back at, so the buttons come back
 * having lost nothing by being away. */
for (const which of [ 'Slower', 'Real time', 'Faster', 'Full speed' ])
    if (!await speedButton(which).isVisible())
        problems.push(`${which} did not come back once it was resumed`)

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

/* Charts. Driven at real time: a chart of a simulation running as fast as it
 * can scrolls a simulated hour every second, which is hard to assert about. */
await fetch(`${BASE}/api/simulations/0/speed?ratio=1`, { method: 'POST' })
const plotIcon = async (widget, metric) => {
    await page.getByRole('link', { name: widget, exact: true }).first().click()
    await page.waitForSelector('button.metric-plot')
    return page.locator('article.properties tr').filter({ hasText: metric })
               .locator('button.metric-plot')
}
const legendText = async () =>
    (await page.locator('.chart-legend').first().innerText()).replace(/\s+/g, ' ')
const entries = () => page.locator('.chart-legend .entry:not(.empty)').count()

await (await plotIcon('cable0', 'total bits')).click()
await page.waitForSelector('article.chart canvas')
await page.waitForTimeout(2000)
if (await page.locator('article.chart').count() !== 1)
    problems.push('clicking the plot icon must open one chart')
if (!/total bits/.test(await legendText()))
    problems.push('the legend must name the metric: ' + await legendText())
/* A counter holds a running total; what is drawn is how fast it grows. */
const asRate = await page.evaluate(() => {
    const d = Alpine.$data(document.body)
    const l = d.lines(d.charts[0])[0]
    return { above: l.ys.filter(y => y > 0).length, units: l.units }
})
if (!asRate.above) problems.push('a counter must be drawn as a rate, and this one is flat')
if (asRate.units !== '/s') problems.push('a rate is per second: ' + asRate.units)

/* Charts outlive the selection: this one came from a cable, and is still
 * there -- and still droppable onto -- while the switch is being looked at. */
const gaugeIcon = await plotIcon('switch', 'macs')
if (await page.locator('article.chart').count() !== 1)
    problems.push('a chart must outlive the widget it was opened from')
await gaugeIcon.dragTo(page.locator('article.chart').first())
await page.waitForTimeout(2000)
const both = await legendText()
if (!/total bits/.test(both) || !/macs/.test(both))
    problems.push('dragging a metric onto a chart must add it there: ' + both)
if (await page.locator('article.chart').count() !== 1)
    problems.push('and must not open a second chart')
/* Two units, so two axes: one metric per side. */
const sides = await page.evaluate(() =>
    [...document.querySelectorAll('article.chart .u-axis')].length)
if (sides < 3) problems.push(`two units want an axis each, found ${sides} axes in all`)
await page.screenshot({ path: `${OUT}/f-charts.png` })

/* Drag is not to be depended on, so a click offers the same choice on a menu:
   which chart, or a new one. The charts are named only while it is open, the
   names being there to be matched against it. */
const menu = page.locator('.plot-menu ul.menu:visible')
await (await plotIcon('cable0', 'total bits')).click()
await page.waitForTimeout(300)
if (!await menu.isVisible())
    problems.push('the plot button must offer the open charts to choose from')
if (!await page.locator('.chart-name').first().isVisible())
    problems.push('and they must be named while it is open')
const choices = (await menu.innerText()).replace(/\s+/g, ' ')
if (!/New chart/.test(choices) || !/Chart 1/.test(choices))
    problems.push('a new chart, or one of those open: ' + choices)
if (!/already there/.test(choices))
    problems.push('and it must say where this metric already is: ' + choices)
await menu.getByText('New chart').click()
await page.waitForTimeout(1500)
if (await page.locator('article.chart').count() !== 2)
    problems.push('"New chart" must open one')
if (await page.locator('.chart-name').first().isVisible())
    problems.push('and the names go with the menu')

/* Onto a chart that is already open, picked by the name it is showing. */
await (await plotIcon('switch', 'macs')).click()
await page.waitForTimeout(300)
await page.screenshot({ path: `${OUT}/f-chart-menu.png` })
await menu.locator('a', { hasText: 'Chart 2' }).click()
await page.waitForTimeout(1500)
if (await page.locator('article.chart').count() !== 2)
    problems.push('choosing a chart from the menu must not open another')
const second = (await page.locator('article.chart').nth(1).innerText()).replace(/\s+/g, ' ')
if (!/macs/.test(second))
    problems.push('the metric must land on the chart that was chosen: ' + second)

/* Escape closes it, as a menu should. */
await (await plotIcon('switch', 'macs')).click()
await page.waitForTimeout(300)
await page.keyboard.press('Escape')
await page.waitForTimeout(300)
if (await menu.count()) problems.push('escape must close the menu')

/* A short window, and a metric near the bottom of the room the properties are
   left: the menu must still be readable whole rather than cut off where they
   stop scrolling, or hidden behind the dock. */
await page.setViewportSize({ width: 1400, height: 620 })
await page.waitForTimeout(600)
await (await plotIcon('switch', 'cache misses')).click()
await page.waitForTimeout(400)
if (!await menu.isVisible())
    problems.push('the menu must open in a short window too')
const menuBox = await menu.boundingBox()
const room2 = await page.evaluate(() => ({
    page: window.innerHeight,
    dock: Math.round(document.querySelector('.dock').getBoundingClientRect().top) }))
if (!menuBox || menuBox.y < 0 || menuBox.y + menuBox.height > room2.page)
    problems.push('the menu must fit on the page: ' +
                  JSON.stringify({ menuBox, ...room2 }))
else if (menuBox.y + menuBox.height > room2.dock)
    problems.push('and keep off the dock: ' +
                  JSON.stringify({ menuBox, ...room2 }))
await page.screenshot({ path: `${OUT}/f-chart-menu-short.png` })
await page.keyboard.press('Escape')
await page.setViewportSize({ width: 1400, height: 950 })
await page.waitForTimeout(600)

const before = await entries()
await page.locator('.chart-legend .entry button').first().click()
await page.waitForTimeout(400)
if (await entries() !== before - 1)
    problems.push(`the cross must take one line off (${before} -> ${await entries()})`)
while (await entries() && await page.locator('article.chart').count()) {
    await page.locator('.chart-legend .entry button').first().click()
    await page.waitForTimeout(300)
}
if (await page.locator('article.chart').count())
    problems.push('a chart with no lines left must go')

/* Logs. Two widgets at once, merged into one chronology, each followed as
 * deeply as one asks. Still at real time: debug logs are only readable when
 * the clock is. */
const watch = async (widget) => {
    await page.getByRole('link', { name: widget, exact: true }).first().click()
    await page.waitForSelector('button.watch-logs')
    await page.locator('button.watch-logs').click()
    await page.waitForTimeout(800)
}
await watch('host0')
await watch('eth')
if (!await page.locator('section.panel.logs').isVisible())
    problems.push('watching a widget must open the log panel')
if (await page.locator('.log-legend .entry').count() !== 2)
    problems.push('one legend entry per watched widget')
for (const sel of await page.locator('.log-legend .entry select').all())
    await sel.selectOption('debug')
await page.waitForTimeout(2500)
const logged = await page.evaluate(() => {
    const ls = Alpine.$data(document.body).logLines()
    return { n: ls.length, debug: ls.filter(l => l.level === 'debug').length,
             who: [ ...new Set(ls.map(l => l.who)) ],
             ordered: ls.every((l, i) => i === 0 || ls[i - 1].t <= l.t) }
})
if (!logged.debug) problems.push('asking for debug must bring debug lines')
if (logged.who.length !== 2)
    problems.push('both widgets belong in the one chronology: ' + logged.who)
if (!logged.ordered) problems.push('and it must be in order')
await page.screenshot({ path: `${OUT}/g-logs.png` })

/* Following the newest line, until the reader looks away. Waited for rather
 * than timed: how fast the lines come is the simulation's business. */
const waitFor = async (cond, secs = 6) => {
    for (let i = 0; i < secs * 10; i++) {
        if (await cond()) return true
        await page.waitForTimeout(100)
    }
    return false
}
const atBottom = () => page.locator('.body.log').evaluate(e =>
    e.scrollTop + e.clientHeight >= e.scrollHeight - 4)
const following = () => page.evaluate(() => Alpine.$data(document.body).logFollow)
/* There has to be more than fits, or there is nothing to scroll away from. */
if (!await waitFor(() => page.locator('.body.log').evaluate(e =>
        e.scrollHeight > e.clientHeight + 50)))
    problems.push('the log window filled up with nothing to scroll')
if (!await atBottom()) problems.push('the log window must follow the newest line')
await page.locator('.body.log').evaluate(e => { e.scrollTop = 0 })
if (!await waitFor(async () => !await following()))
    problems.push('it must stop following once the reader scrolls up')
await page.waitForTimeout(1500)   /* a poll or two of staying put */
if (await page.locator('.body.log').evaluate(e => e.scrollTop) > 40)
    problems.push('and leave what they are reading where it was')
await page.locator('.body.log').evaluate(e => { e.scrollTop = e.scrollHeight })
if (!await waitFor(following))
    problems.push('and follow again once they come back to it')
if (!await waitFor(atBottom)) problems.push('staying at the newest line')

/* Let it rip: the queues then overwrite themselves between two polls, and a
 * log that went quiet about what it dropped would be lying. */
await fetch(`${BASE}/api/simulations/0/speed?ratio=full`, { method: 'POST' })
await page.waitForTimeout(3000)
if (!await page.locator('.body.log .line.lost').count())
    problems.push('a gap in the log must say so')
const kept = await page.evaluate(() => Alpine.$data(document.body).logLines().length)
if (kept > 2000) problems.push('the window must keep a bounded number of lines: ' + kept)

/* A chart as well as the logs, so that both panels are docked at once -- the
 * charts were all closed again by the section above. */
await (await plotIcon('cable0', 'total bits')).click()
await page.waitForSelector('article.chart canvas')
await page.waitForTimeout(1000)

/* With both panels docked, nothing above them scrolls: the widget being
 * looked at scrolls within its own bounds, and the panels within theirs. A
 * scrollbar inside a scrolling page loses whatever one was reading. */
const room = await page.evaluate(() => ({
    doc: document.documentElement.scrollHeight - document.documentElement.clientHeight,
    body: document.body.scrollHeight - document.body.clientHeight,
    main: document.querySelector('main').scrollHeight -
          document.querySelector('main').clientHeight,
    view: document.querySelector('.widget-view').clientHeight,
    charts: document.querySelector('.body.charts').clientHeight,
    logs: document.querySelector('.body.log').clientHeight,
}))
if (room.doc > 0 || room.body > 0 || room.main > 0)
    problems.push('the page itself must not scroll: ' + JSON.stringify(room))
/* And the two panels share the dock rather than one crowding the other out. */
if (Math.min(room.charts, room.logs) < Math.max(room.charts, room.logs) / 3)
    problems.push('the docked panels must share the room: ' + JSON.stringify(room))
if (room.view < 100)
    problems.push('and leave the widget above something to be seen in: ' + room.view)

/* The way back to the newest line, for a reader who scrolled away from it. */
if (await page.locator('button.follow-tail').isVisible())
    problems.push('nothing to jump to while already following')
await page.locator('.body.log').evaluate(e => { e.scrollTop = 0 })
await page.waitForTimeout(1500)
if (!await page.locator('button.follow-tail').isVisible())
    problems.push('a way back must appear once the reader scrolls up')
await page.locator('button.follow-tail').click()
await page.waitForTimeout(800)
if (!await atBottom()) problems.push('and it must go back to the newest line')

/* Folded away, the panel still says what it is watching -- and stays folded. */
await page.locator('section.panel.logs .twisty').click()
await page.waitForTimeout(300)
if (await page.locator('.body.log').isVisible())
    problems.push('folding must hide the lines')
if (!await page.locator('.log-legend').isVisible())
    problems.push('but not what is being watched')
await page.reload({ waitUntil: 'networkidle' })
await page.waitForTimeout(600)
if (!await page.evaluate(() => Alpine.$data(document.body).collapsed.logs))
    problems.push('a folded panel must still be folded after a reload')
await page.evaluate(() => { Alpine.$data(document.body).fold('logs') })

/* The simulator goes away: everything on screen becomes last-known. */
await stop()
await page.waitForSelector('.banner', { state: 'visible', timeout: 15000 })
await page.waitForTimeout(1500)
await page.screenshot({ path: `${OUT}/d-offline.png` })
const banner = (await page.locator('.banner').innerText()).replace(/\s+/g, ' ')
/* Nothing that needs the simulator may still look pressable. */
/* Folding a panel away is the reader's own business and works offline, so the
   twisty is not one of the things that must go grey. */
const live = await page.evaluate(() =>
    [...document.querySelectorAll('.controls button, article.properties button, ' +
                                  'article.properties input, article.properties select')]
        .filter(e => e.offsetParent !== null && !e.disabled &&
                     !e.classList.contains('twisty'))
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
 * poll off, since it would replace them with what the server really has. The
 * poll reschedules itself from its own callback, so dropping the pending timer
 * stops it for good. */
await page.evaluate(() => {
    const d = Alpine.$data(document.body)
    clearTimeout(d.timer)
    const now = d.sims[0].now
    const fired = (counts, at) => ({ counts, first_last: { first: at, last: at } })
    const once = (params, value) => ({ params, value })
    /* [units] belongs to the property, not to the metric: what a figure is
     * counted in is the same question for a counter and for a length. */
    const mk = (name, descr, value, read_only, units = '') => ({
        name, descr, units, read_only, kind: { type: 'metric' },
        value, metric: metricRows(value, units), error: null })
    d.props = [
        mk('mac table', 'MACs the switch remembers.', {
            kind: 'gauge',
            values: [ { params: {}, value: { min: 0, current: 12, max: 25 } } ],
            first_last: { first: now - 60, last: now - 2.5 } }, true),
        /* Out of order, and with a two-digit port: the simulator's hash
         * table has no order, and 9 must not sort after 10. */
        mk('lookups', 'Table misses, per port.', {
            kind: 'atomic',
            counts: [ { params: { port: 10 }, value: 3 },
                      { params: { port: 2 }, value: 17 },
                      { params: { port: 9 }, value: 5 } ],
            first_last: { first: now - 60, last: now - 0.5 } }, true),
        mk('resolutions', 'How long a name took to resolve.', {
            kind: 'timed',
            durations: [ { params: {},
                           value: { min: 0.25, max: 0.9, sum: 2.3, count: 4 } } ],
            starts: fired([ once({}, 6) ], now - 30),
            stops: fired([ once({}, 4) ], now - 4),
            simult: { values: [ { params: {}, value: { min: 0, current: 2, max: 3 } } ],
                      first_last: { first: now - 60, last: now - 4 } } }, true,
            /* A duration says what it is on its own: this must not show. */
            'seconds'),
        /* Writable: the only thing a write does is reset it. */
        mk('queries', 'Every request served.', {
            kind: 'counter',
            values: [ { params: { status: 200 }, value: 1204 },
                      { params: { status: 404 }, value: 3 } ],
            /* Counted one at a time, as Counter.add does with the same
             * params it was given. */
            fired: fired([ once({ status: 200 }, 1204), once({ status: 404 }, 3) ],
                         now - 0.2) }, false, 'requests'),
        mk('errors', 'Nothing has gone wrong yet.',
           { kind: 'atomic', counts: [], first_last: null }, true),
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
    [ 'a duration ignoring the property\'s unit', /^(?!.*seconds).*575ms on average/ ],
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

/* The map's promotion rule, which is a pure function of the widget listing and
 * of which boxes are open, so it is tried here against graphs rather than
 * against a screen -- including the shapes the demo does not have. */
const mapSay = (what, got, want) => {
    const a = JSON.stringify(got), b = JSON.stringify(want)
    if (a !== b) problems.push(`${what}: got ${a}, wanted ${b}`)
}

/* Two hosts on a switch, and inside the first one a second interface cabled to
 * the first: an edge with both ends in the same box, which is the case the
 * Inspector cannot draw at all. */
const graph = {}
for (const [ id, name, parent, children ] of [
        [ 0, 'net', null, [ 1, 2, 3, 4, 5 ] ],
        [ 1, 'hostA', 0, [ 6, 7, 11, 12 ] ],
        [ 2, 'hostB', 0, [ 8 ] ],
        [ 3, 'switch', 0, [ 9, 10 ] ],
        [ 4, 'cable1', 0, [] ], [ 5, 'cable2', 0, [] ],
        [ 6, 'eth0', 1, [] ], [ 7, 'tcp', 1, [] ], [ 11, 'eth1', 1, [] ],
        [ 12, 'loopback cable', 1, [] ],
        [ 8, 'eth0', 2, [] ], [ 9, 'port0', 3, [] ], [ 10, 'port1', 3, [] ] ])
    graph[id] = { id, name, parent, children, peers: [], properties: [],
                  location: null, sim: 0,
                  full_name: (parent === null ? '' : '/net') + '/' + name }
const peer = (a, b, via) => {
    graph[a].peers.push({ widget: b, via })
    graph[b].peers.push({ widget: a, via })
    /* The cable lists its own two ends, exactly as Widget.make_peers leaves
     * them: the listing really does state one link four times. */
    graph[via].peers.push({ widget: a, via: null },
                          { widget: b, via: null })
}
peer(6, 9, 4)
peer(8, 10, 5)
peer(6, 11, 12)

const map = await page.evaluate((byId) => {
    const links = [ ...linkSet(byId) ].sort((a, b) => a - b)
    const plane = planeOf(byId, 0)
    const view = (open) => {
        const drawn = drawnSet(byId, plane, new Set(open))
        const { edges, inside } = mapEdges(byId, drawn)
        return { drawn: [ ...drawn ].sort((a, b) => a - b),
                 edges: edges.map(e => [ e.from, e.fromPort, e.to, e.toPort,
                                         e.via ]),
                 inside: [ ...inside.entries() ],
                 /* A box's ports are the ends of its edges that are not the box
                  * itself, which is how the drawing reads them too. */
                 ports: plane.map(id => [ id, edges.flatMap(e =>
                     [ e.from === id ? e.fromPort : null,
                       e.to === id ? e.toPort : null ]).filter(p => p !== null) ]) }
    }
    return { links, plane, relations: relations(byId).length,
             closed: view([]), openA: view([ 1 ]),
             elsewhere: anchorOf(byId, drawnSet(byId, plane, new Set()), 999) }
}, graph)

/* A cable is whatever a peering goes through, and is never a box: the plane is
 * the root's children without them. */
mapSay('the cables of the graph', map.links, [ 4, 5, 12 ])
mapSay('the boxes on the plane', map.plane, [ 1, 2, 3 ])
/* Four statements, one link. */
mapSay('the number of distinct links', map.relations, 3)

/* Nothing opened: every end is promoted to the box that hides it, and the
 * link inside hostA is folded into hostA rather than drawn from it to itself.
 *
 * The edges are pinned down in order, not as a set: the listing is enumerated
 * in widget order, so the same graph gives the same edges in the same order,
 * and the map can hand them straight to the drawing without sorting. */
mapSay('the boxes drawn with nothing opened', map.closed.drawn, [ 1, 2, 3 ])
mapSay('the promoted edges', map.closed.edges,
       [ [ 1, 6, 3, 9, 4 ], [ 2, 8, 3, 10, 5 ] ])
mapSay('what the boxes swallowed', map.closed.inside, [ [ 1, 1 ] ])
/* The switch is on the plane and both cables land inside it, so it has the two
 * ports; the hosts have one each. */
mapSay('the ports of each box', map.closed.ports,
       [ [ 1, [ 6 ] ], [ 2, [ 8 ] ], [ 3, [ 9, 10 ] ] ])

/* hostA opened: its interfaces are drawn, so the edges land on them directly
 * and the link it was hiding comes out. Its cable stays a line, never a box,
 * and the TCP layer -- which no peering mentions -- is drawn but is no port. */
mapSay('the boxes drawn with hostA opened', map.openA.drawn, [ 1, 2, 3, 6, 7, 11 ])
mapSay('the edges with hostA opened', map.openA.edges,
       [ [ 6, null, 3, 9, 4 ], [ 6, null, 11, null, 12 ], [ 2, 8, 3, 10, 5 ] ])
mapSay('what is left swallowed', map.openA.inside, [])
mapSay('hostA has no port of its own once opened', map.openA.ports[0], [ 1, [] ])

/* A widget the plane does not reach is on no box at all, rather than on some
 * arbitrary one. */
mapSay('a widget outside the map', map.elsewhere, null)

/* And against the graph the demo actually has: three cables, three edges,
 * nothing hidden. Each lands on the switch itself -- whose ports are not
 * widgets -- and on the adapter within the host it reaches, which is drawn as
 * a port on the host's box. */
const demoMap = await page.evaluate(() => {
    const d = Alpine.$data(document.body)
    const sim = d.sims.find(s => s.id !== d.servingId)
    const byId = d.widgetsOf(sim.id)
    const plane = planeOf(byId, sim.root)
    const { edges, inside } = mapEdges(byId, drawnSet(byId, plane, new Set()))
    return { plane: plane.map(id => byId[id].name),
             edges: edges.map(e => [ byId[e.from].name,
                                     e.fromPort && byId[e.fromPort].name,
                                     byId[e.to].name,
                                     e.toPort && byId[e.toPort].name ]),
             inside: inside.size }
})
mapSay('the demo boxes', demoMap.plane, [ 'switch', 'host0', 'host1', 'host2' ])
mapSay('the demo edges', demoMap.edges,
       [ [ 'switch', null, 'host2', 'eth' ], [ 'switch', null, 'host1', 'eth' ],
         [ 'switch', null, 'host0', 'eth' ] ])
mapSay('nothing hidden in the demo', demoMap.inside, 0)

/* ---------------------------------------------------------- the two panes */

/* Both views at once, and the divider between them is the switch: pushed all
 * the way over, it shuts one side. */
const paneWidth = (which) =>
    page.locator(`.pane.${which}`).evaluate(e => e.getBoundingClientRect().width)
        .catch(() => 0)
const widths0 = { detail: await paneWidth('detail'), map: await paneWidth('map') }
if (widths0.detail < 100 || widths0.map < 100)
    problems.push('both panes must be showing to start with, and they were ' +
                  JSON.stringify(widths0))

const splitter = await page.locator('.splitter.cols').boundingBox()
const panes = await page.locator('.panes').boundingBox()
await page.mouse.move(splitter.x + splitter.width / 2, splitter.y + splitter.height / 2)
await page.mouse.down()
await page.mouse.move(panes.x + panes.width * 0.7, splitter.y + 10, { steps: 6 })
await page.mouse.up()
await page.waitForTimeout(200)
const widths1 = { detail: await paneWidth('detail'), map: await paneWidth('map') }
if (!(widths1.detail > widths0.detail + 40))
    problems.push('dragging the divider right must widen the left column: ' +
                  JSON.stringify(widths0) + ' then ' + JSON.stringify(widths1))
/* And it is remembered, or folding it away would have to be done again on
 * every visit. */
const keptSplit = await page.evaluate(() => localStorage.getItem('robinet.split'))
if (!(Number(keptSplit) > 0.6))
    problems.push(`the split must be remembered, and was kept as ${keptSplit}`)

/* Measured again: it has just moved, and pressing where it used to be is
 * pressing on the pane beside it. */
const splitter2 = await page.locator('.splitter.cols').boundingBox()
await page.mouse.move(splitter2.x + splitter2.width / 2, splitter2.y + 10)
await page.mouse.down()
await page.mouse.move(panes.x + panes.width - 4, splitter2.y + 10, { steps: 6 })
await page.mouse.up()
await page.waitForTimeout(200)
if (await page.locator('.pane.map').isVisible())
    problems.push('the divider pushed all the way over must shut the map')
/* And it must still be reachable, or a pane shut once is shut for good --
 * the share being remembered, that would outlast the browser. */
/* Off the divider first: it has just been dragged, and a photograph of it
 * under the pointer is a photograph of the hover state. */
await page.mouse.move(panes.x + panes.width / 2, panes.y + panes.height / 2)
await page.waitForTimeout(150)
await page.screenshot({ path: `${OUT}/h-split-shut.png` })
const handle = await page.locator('.splitter.cols').boundingBox()
const view = await page.locator('.widget-view').boundingBox()
if (!handle || handle.x + handle.width > view.x + view.width + 1 || handle.width < 4)
    problems.push('the divider must stay on screen with a side shut: ' +
                  JSON.stringify(handle) + ' in ' + JSON.stringify(view))
await page.locator('.splitter.cols').click()
await page.waitForTimeout(300)
if (!await page.locator('.pane.map').isVisible())
    problems.push('clicking the shut divider must bring that side back')
const backTo = await page.evaluate(() => Alpine.$data(document.body).split)
if (!(backTo > 0.6 && backTo < 1))
    problems.push('and at the share it had before it was shut, not ' + backTo)
/* Back to something to look at. */
await page.evaluate(() => { Alpine.$data(document.body).split = 0.45 })
await page.waitForTimeout(200)

/* The same divider along the other axis, between the dock and everything above
 * it: how much of the window the charts and the logs are worth is a question
 * about the screen, so it is asked of the reader rather than answered here. */
const dockSizes = () => page.evaluate(() => {
    const h = (s) => { const e = document.querySelector(s)
        if (!e) return 0
        return Math.round(e.getBoundingClientRect().height) }
    return { share: Alpine.$data(document.body).dockShare,
             view: h('.widget-view'), dock: h('.dock'),
             plot: h('.chart .plot'), canvas: h('.chart .plot canvas'),
             panels: [ ...document.querySelectorAll('.dock .panel') ]
                 .map(e => Math.round(e.getBoundingClientRect().height)) }
})
/* Something in the dock to share the room with, whatever the sections above
 * left behind. */
await page.locator('nav.tree a', { hasText: 'cable0' }).click()
await page.waitForTimeout(400)
if (await page.evaluate(() => !Alpine.$data(document.body).charts.length))
    await page.locator('button.metric-plot').first().click()
if (await page.evaluate(() => !Alpine.$data(document.body).logged.length))
    await page.locator('button.watch-logs').click()
await page.waitForTimeout(800)

const dockWas = await dockSizes()
if (!(dockWas.dock > 60) || !dockWas.panels.every(p => p > 40))
    problems.push('the dock and its panels must have room to start with: ' +
                  JSON.stringify(dockWas))

const bar = await page.locator('.splitter.rows').boundingBox()
const mainBox = await page.locator('main').boundingBox()
await page.mouse.move(bar.x + bar.width / 2, bar.y + bar.height / 2)
await page.mouse.down()
await page.mouse.move(bar.x + bar.width / 2, mainBox.y + mainBox.height * 0.35,
                      { steps: 8 })
await page.mouse.up()
await page.waitForTimeout(400)
const dockTall = await dockSizes()
if (!(dockTall.dock > dockWas.dock + 100) || !(dockTall.view < dockWas.view - 100))
    problems.push('dragging the dock divider up must give the dock the room ' +
                  'the view above it loses: ' + JSON.stringify(dockWas) +
                  ' then ' + JSON.stringify(dockTall))
/* The panels take the room with it, rather than the dock growing around them,
 * and so does the plot inside: a chart at a fixed height in a taller panel is
 * a chart with a gap under it. */
if (!dockTall.panels.every((p, i) => p > dockWas.panels[i] + 40))
    problems.push('and the panels in it must grow too: ' +
                  JSON.stringify(dockTall.panels))
if (!(dockTall.plot > dockWas.plot + 40) ||
    !(dockTall.canvas > dockWas.canvas + 40))
    problems.push('and the plot must be redrawn at the size it is given: ' +
                  JSON.stringify([ dockWas.plot, dockWas.canvas ]) + ' then ' +
                  JSON.stringify([ dockTall.plot, dockTall.canvas ]))
await page.screenshot({ path: `${OUT}/h-dock-tall.png` })

/* All the way down shuts it, and the handle left behind is the way back -- at
 * the share it had dockWas, not at the sliver the drag went out through. */
const bar2 = await page.locator('.splitter.rows').boundingBox()
await page.mouse.move(bar2.x + bar2.width / 2, bar2.y + bar2.height / 2)
await page.mouse.down()
await page.mouse.move(bar2.x + bar2.width / 2, mainBox.y + mainBox.height - 2,
                      { steps: 8 })
await page.mouse.up()
await page.waitForTimeout(400)
if (await page.locator('.dock').isVisible())
    problems.push('the dock divider pushed all the way down must shut it')
const shutBar = await page.locator('.splitter.rows').boundingBox()
if (!shutBar || shutBar.y + shutBar.height > mainBox.y + mainBox.height + 1)
    problems.push('and must stay on screen: ' + JSON.stringify(shutBar))
await page.locator('.splitter.rows').click()
await page.waitForTimeout(400)
const back = await dockSizes()
if (Math.abs(back.share - dockTall.share) > 0.01)
    problems.push('clicking it must bring the dock back at the share it had, ' +
                  `${dockTall.share}, and it came back at ${back.share}`)
/* Back to what the shots below are taken with. */
await page.evaluate(() => { Alpine.$data(document.body).dockShare = 0.4 })
await page.waitForTimeout(300)

/* -------------------------------------------------------------- the map */

const mapBox = () => page.locator('.pane.map').boundingBox()
const boxOf = (name) =>
    page.locator('.pane.map .box', { has: page.locator(`.name:text-is("${name}")`) })
const scene = () => page.evaluate(() => {
    const d = Alpine.$data(document.body)
    const s = d.mapScene()
    return { trayCount: s.trayCount, k: d.mapView.k,
             boxes: s.boxes.map(b => ({ name: b.name, placed: b.placed,
                                        depth: b.depth, open: b.open,
                                        inside: b.inside })),
             ports: s.ports.map(p => p.name),
             edges: s.edges.map(e => e.name) }
})

/* From a known starting point: whatever was being looked at above may be
 * inside a box, and the selection holds the boxes it is inside open. A box on
 * the plane holds nothing open. */
await page.locator('nav.tree a', { hasText: 'host2' }).click()
await page.waitForTimeout(400)

let sc = await scene()
/* The demo places its switch and its hosts, and derives its cable lengths from
 * the distances between them, so the map has something on it from the start.
 * Only the boxes on the plane: what is inside one is drawn where that box says
 * and never has a place of its own. */
if (sc.trayCount !== 0 || !sc.boxes.filter(b => !b.depth).every(b => b.placed))
    problems.push('every box of the demo should start placed, and the scene ' +
                  'was ' + JSON.stringify(sc))
if (await page.locator('.pane.map svg.cables line').count() !== 3)
    problems.push('the three cables of the demo should be drawn as three lines')
mapSay('the cables are named on the map', [ ...sc.edges ].sort(),
       [ 'cable0', 'cable1', 'cable2' ])

/* Dragging a box about is for real, both ways: the simulator is told, and says
 * so when asked again. Into the strip is a location that is not -- one request
 * with a null -- and back out of it is a location again. */
const grab = async (loc, at) => {
    const b = await loc.boundingBox()
    await page.mouse.move(b.x + (at === 'header' ? 20 : b.width / 2),
                          b.y + (at === 'header' ? 6 : b.height / 2))
    await page.mouse.down()
}
const locationOf = async (id) =>
    (await (await fetch(`${BASE}/api/simulations/0/widgets/${id}`)).json()).location
const pane = await mapBox()

await grab(boxOf('switch'))
await page.mouse.move(pane.x + 120, pane.y + pane.height - 12, { steps: 8 })
await page.mouse.up()
await page.waitForTimeout(400)
if (await locationOf(1) !== null)
    problems.push('dragging a box into the strip must take it off the map, ' +
                  'and it is still at ' + JSON.stringify(await locationOf(1)))
sc = await scene()
if (sc.trayCount !== 1)
    problems.push(`one box should be left unplaced, not ${sc.trayCount}`)

await grab(boxOf('switch'))
await page.mouse.move(pane.x + pane.width * 0.4, pane.y + 80, { steps: 8 })
await page.mouse.up()
await page.waitForTimeout(400)
const placedAt = await locationOf(1)
if (!placedAt ||
    !Number.isFinite(placedAt.lat) || !Number.isFinite(placedAt.lon))
    problems.push('dragging it back onto the map must place it: the simulator ' +
                  'has it at ' + JSON.stringify(placedAt))
sc = await scene()
if (sc.trayCount !== 0)
    problems.push(`nothing should be left unplaced, not ${sc.trayCount}`)

/* Opening a box shows what is in it. Which is not a matter of zoom: one wants
 * a single box open with the rest of the network shut around it. */
await boxOf('switch').locator('.twisty').click()
await page.waitForTimeout(300)
sc = await scene()
if (!sc.boxes.some(b => b.name === 'hub') ||
    !sc.boxes.some(b => b.name === 'switch' && b.open))
    problems.push('opening the switch must show the hub inside it: ' +
                  JSON.stringify(sc.boxes))
const zoomed = await scene()
await page.mouse.move(pane.x + pane.width / 2, pane.y + pane.height / 2)
await page.mouse.wheel(0, -400)
await page.waitForTimeout(200)
if (!((await scene()).k > zoomed.k * 1.2))
    problems.push('the wheel must zoom the map in')
if (!(await scene()).boxes.some(b => b.name === 'hub'))
    problems.push('zooming must not close what was opened: detail is not scale')

/* A cable is a widget with properties of its own, so its name on the line is
 * the way to it. */
await page.locator('.pane.map .cable-label').first().click()
await page.waitForTimeout(400)
const onCable = await page.evaluate(() => Alpine.$data(document.body).selected.name)
if (!/^cable/.test(onCable))
    problems.push(`clicking a cable's name must select it, and selected ${onCable}`)

/* Framed again: the zoom above moved everything. */
await page.locator('.map-tools button').click()
await page.waitForTimeout(300)
await page.screenshot({ path: `${OUT}/h-map.png` })

/* Framing the demo must show it, rather than a scale at which its four boxes
 * are one heap: it is 900m across, and a map that only went down to a few
 * kilometres would have nothing to say about a network of that size. */
const spread = await page.evaluate(() => {
    const bs = Alpine.$data(document.body).mapScene().boxes
    const xs = bs.map(b => b.x), ys = bs.map(b => b.y)
    return { x: Math.max(...xs) - Math.min(...xs),
             y: Math.max(...ys) - Math.min(...ys) }
})
if (spread.x < 120 || spread.y < 60)
    problems.push('fitting a network 900m across must spread it over the ' +
                  'pane, and it spans ' + JSON.stringify(spread))

/* And it frames what the map draws and nothing else. Anything with a widget
 * can be placed -- by [Widget.place], or through the API the map's own drags
 * go through -- including something inside a box, which is drawn at that box's
 * place: framing around it would leave the reader looking at empty world
 * halfway to it. */
const framed = await page.evaluate(() => {
    const d = Alpine.$data(document.body)
    const before = Object.assign({}, d.mapView)
    const inner = Object.values(d.widgetsOf(d.selected.sim))
                        .find(w => w.name === 'eth')
    inner.location = { lat: -33.87, lon: 151.21 }   /* the other hemisphere */
    d.fitMap()
    const after = Object.assign({}, d.mapView)
    inner.location = null
    d.fitMap()
    return { before, after }
})
if (framed.before.k !== framed.after.k ||
    framed.before.cx !== framed.after.cx || framed.before.cy !== framed.after.cy)
    problems.push('a location on something the map never draws must not move ' +
                  'the framing: ' + JSON.stringify(framed))

/* The coast behind it all. Nothing about the network depends on it, so what is
 * asked of it is that it is there, and that what reaches the renderer is
 * bounded by the pane: the demo sits in a city, and at that zoom the shoreline
 * of the Atlantic is tens of millions of pixels away. */
const clipped = await page.evaluate(() => {
    const seg = (...a) => clipSeg(...a, 100, 100)
    return { inside: seg(10, 10, 20, 20),
             past: seg(50, 50, 500, 50),
             across: seg(-500, 50, 500, 50),
             gone: seg(-500, -500, -400, -400) }
})
mapSay('a segment within the pane is drawn whole', clipped.inside, [10, 10, 20, 20])
mapSay('one running out of it is cut at the edge', clipped.past, [50, 50, 104, 50])
mapSay('one crossing it is cut at both', clipped.across, [-4, 50, 104, 50])
mapSay('and one that never enters it is not drawn', clipped.gone, null)

const coastNow = () => page.evaluate(() => {
    const d = Alpine.$data(document.body)
    const path = document.querySelector('.pane.map svg.coast path')
                         .getAttribute('d') || ''
    const nums = (path.match(/-?[0-9.]+/g) || []).map(Number)
    const m = 8   /* the clip's own margin, and room for rounding */
    return { points: nums.length / 2,
             outside: nums.some((v, i) => i % 2 === 0
                 ? v < -m || v > d.mapSize.w + m
                 : v < -m || v > d.mapScene().trayTop + m) }
})

/* Framed on the demo, in Paris: every coastline there is is off the edge, and
 * an unclipped path would say so in millions of pixels. */
const near = await coastNow()
if (near.outside)
    problems.push('the coast must be clipped to the pane, and at the scale of ' +
                  'the demo it reached ' + JSON.stringify(near))

await page.evaluate(() => {
    const d = Alpine.$data(document.body)
    d.mapView = { cx: 0.5, cy: 0.5,
                  k: Math.max(d.mapSize.w, d.mapSize.h) }
})
await page.waitForTimeout(300)
const world = await coastNow()
if (world.points < 300)
    problems.push('the whole world should show a coastline, and it drew ' +
                  world.points + ' points')
if (world.outside)
    problems.push('the coast must be clipped to the pane: ' +
                  JSON.stringify(world))
await page.screenshot({ path: `${OUT}/h-map-world.png` })

/* And that view is as far out as the wheel goes. There is nothing beyond the
 * world to look at, and a globe adrift in a larger window says the reader has
 * gone somewhere they cannot have gone. Whichever way round the pane is: it is
 * usually taller than it is wide, and the world has to cover it either way. */
const paneNow = await mapBox()
await page.mouse.move(paneNow.x + paneNow.width / 2,
                      paneNow.y + paneNow.height / 2)
for (let i = 0 ; i < 30 ; i++) await page.mouse.wheel(0, 600)
await page.waitForTimeout(300)
const out = await page.evaluate(() => {
    const d = Alpine.$data(document.body)
    return { k: d.mapView.k, w: d.mapSize.w, h: d.mapSize.h }
})
if (out.k < Math.max(out.w, out.h) - 0.5)
    problems.push('zooming out must stop with the world filling the pane: ' +
                  JSON.stringify(out))

/* Framed again, for the sections below. */
await page.locator('.map-tools button').click()
await page.waitForTimeout(300)

/* Selecting something the map is not showing must still show something. The
 * boxes between it and the plane are held open by the selection itself, so
 * that the widget being looked at is drawn rather than hidden inside a box --
 * and every box it is inside is marked, so that there is a way back up. */
const marks = () => page.evaluate(() => {
    const d = Alpine.$data(document.body)
    const s = d.mapScene()
    return { open: [ ...d.mapOpen ], auto: [ ...d.mapAuto ],
             names: s.boxes.map(b => b.name),
             selected: s.boxes.filter(b => b.id === d.selected.id)
                              .map(b => b.name),
             holds: s.boxes.filter(b => b.holds).map(b => b.name),
             cable: s.edges.filter(e => e.on).map(e => e.name) }
})
await page.locator('nav.tree a', { hasText: 'eth' }).first().click()
await page.waitForTimeout(500)
let mk = await marks()
mapSay('the host holding the selected layer is opened', mk.auto, [ 3 ])
mapSay('so the layer itself is drawn, and marked', mk.selected, [ 'eth' ])
mapSay('and the box it is in says so', mk.holds, [ 'host0' ])
/* A box the reader opened is not one the selection may shut. */
if (!mk.open.length || !mk.names.includes('hub'))
    problems.push('a box the reader opened must stay open: ' + JSON.stringify(mk))

/* A cable is a line, not a box, so that is what is marked. */
await page.locator('nav.tree a', { hasText: 'cable1' }).click()
await page.waitForTimeout(500)
mk = await marks()
mapSay('the selected cable is the line', mk.cable, [ 'cable1' ])

/* And moving on lets go of what was held open, without touching what the
 * reader opened. */
await page.locator('nav.tree a', { hasText: 'host2' }).click()
await page.waitForTimeout(500)
mk = await marks()
mapSay('nothing is held open any more', mk.auto, [])
mapSay('the selection is the box itself', mk.selected, [ 'host2' ])
if (mk.names.includes('eth'))
    problems.push('the host opened by the selection must shut when it moves ' +
                  'on: ' + JSON.stringify(mk.names))
if (!mk.names.includes('hub'))
    problems.push('but the box the reader opened must still be open: ' +
                  JSON.stringify(mk.names))
await page.screenshot({ path: `${OUT}/h-map-selection.png` })

/* And picking something out of the tree that is off the edge of the map brings
 * it into view. Only then: the map's promise is that things stay where they
 * were left, and sliding it about whenever the reader clicks something already
 * on screen is exactly what breaks that. */
const inView = () => page.evaluate(() => {
    const d = Alpine.$data(document.body)
    const s = d.mapScene()
    const ok = (b) => b.x >= 0 && b.y >= 0 &&
                      b.x + b.w <= d.mapSize.w && b.y + b.h <= s.trayTop
    const line = s.edges.find(e => e.via === d.selected.id)
    return { cx: d.mapView.cx, cy: d.mapView.cy,
             on: s.boxes.filter(ok).map(b => b.name),
             off: s.boxes.filter(b => !ok(b)).map(b => b.name),
             cable: line === undefined ? null
                    : line.mx >= 0 && line.mx <= d.mapSize.w &&
                      line.my >= 0 && line.my <= s.trayTop }
})
/* Somewhere else entirely. */
const panAway = () => page.evaluate(() => {
    const d = Alpine.$data(document.body)
    d.mapView = { k: d.mapView.k, cx: d.mapView.cx + 0.0002,
                                  cy: d.mapView.cy + 0.0002 }
})
await panAway()
await page.waitForTimeout(300)
if ((await inView()).on.length)
    problems.push('the map should be looking at nothing at this point')
await page.locator('nav.tree a', { hasText: 'host1' }).click()
await page.waitForTimeout(500)
const found = await inView()
if (!found.on.includes('host1'))
    problems.push('selecting a widget off the edge of the map must bring it ' +
                  'into view: ' + JSON.stringify(found))

/* Something already on screen leaves the view exactly where it was. Whichever
 * box that turns out to be: the pan just above chose the framing, so which of
 * them lands clear of the edges is not something this test may assume, and a
 * box straddling the edge is one the map is right to bring in. Clear by a
 * wider margin than the map itself asks for, so that the box picked here is in
 * view by any reading. By its header, since an open box has its contents drawn
 * across its middle. */
const settled = await page.evaluate(() => {
    const d = Alpine.$data(document.body), s = d.mapScene(), m = 16
    const b = s.boxes.find(b => b.depth === 0 && b.id !== d.selected.id &&
                                b.x >= m && b.y >= m &&
                                b.x + b.w <= d.mapSize.w - m &&
                                b.y + b.h <= s.trayTop - m)
    return b ? b.name : null
})
if (settled === null) {
    problems.push('framing the map should leave a box clear of its edges')
} else {
    await boxOf(settled).click({ position: { x: 20, y: 6 } })
    await page.waitForTimeout(500)
    const still = await inView()
    if (still.cx !== found.cx || still.cy !== found.cy)
        problems.push(`picking ${settled}, already in view, must not move the ` +
                      `map: ${found.cx},${found.cy} then ${still.cx},${still.cy}`)
}

/* A cable is a line and not a box, so what is brought into view is the line --
 * at the point its name is written. */
await panAway()
await page.waitForTimeout(300)
await page.locator('nav.tree a', { hasText: 'cable2' }).click()
await page.waitForTimeout(500)
const onCable2 = await inView()
if (onCable2.cable !== true)
    problems.push('selecting a cable off the edge must bring its line into ' +
                  'view: ' + JSON.stringify(onCable2))

/* Ports, which the demo has none of: every cable in it joins two boxes that
 * are on the plane already. The graph from the promotion checks above does
 * have them, so the drawing is tried against that -- a shape a real network
 * has as soon as its cables are wired at interface level, as simwan's are. */
await page.evaluate((byId) => {
    const d = Alpine.$data(document.body)
    const sim = d.selected.sim
    /* Somewhere, so that the boxes are spread over a map rather than heaped in
     * the strip: this is the view the ports exist for. */
    byId[1].location = { lat: 51.51, lon: -0.13 }   /* hostA */
    byId[2].location = { lat: 52.37, lon: 4.90 }    /* hostB */
    byId[3].location = { lat: 48.85, lon: 2.35 }    /* the switch */
    d.widgets[sim] = byId
    d.roots[sim] = 0
    d.mapOpen = []
    d.mapAuto = []
    d.selected = Object.assign({ sim }, byId[1])
    d.topoTock++
    d.fitMap()
}, graph)
await page.waitForTimeout(300)
sc = await scene()
mapSay('the ports of a shut box, drawn on it', [ ...sc.ports ].sort(),
       [ 'eth0', 'eth0', 'port0', 'port1' ])
mapSay('and what the shut box is folding away',
       sc.boxes.filter(b => b.inside).map(b => [ b.name, b.inside ]),
       [ [ 'hostA', 1 ] ])
if (await page.locator('.pane.map .port').count() !== 4)
    problems.push('the four ports must be drawn')
await page.screenshot({ path: `${OUT}/h-map-ports.png` })

/* ------------------------------------------------------------------
 * Building a device, cabling it, and taking it out again.
 *
 * The whole point of the Add button: what is built has no place of its own, so
 * it arrives in the strip under the map for the reader to drag out. A cable is
 * the exception, its two ends being other devices, so it asks for them first.
 * ------------------------------------------------------------------ */

/* Both panes on screen: the form stands in the detail pane and the ends are
 * clicked on the map, so this needs the two of them at once. */
await page.evaluate(() => {
    const d = Alpine.$data(document.body)
    d.split = 0.45
    d.mapOpen = []
    d.fitMap()
})
await page.waitForTimeout(300)

const names = () => page.evaluate(() =>
    Alpine.$data(document.body).mapScene().boxes.map(b => b.name))
const trayNames = () => page.evaluate(() => {
    const d = Alpine.$data(document.body)
    const s = d.mapScene()
    return s.boxes.filter(b => b.y > s.trayTop).map(b => b.name)
})

await page.locator('.pane.map .tray-line .adder button.add').click()
await page.waitForTimeout(300)
const offered = await page.locator('.pane.map .type-menu button').allTextContents()
for (const t of [ 'host', 'switch', 'hub', 'router', 'gateway', 'cable' ])
    if (!offered.includes(t))
        problems.push(`the Add menu must offer a ${t}: ` + JSON.stringify(offered))
await page.screenshot({ path: `${OUT}/j-add-menu.png` })

/* A hub: no end to pick, so the form comes straight up, in the schematic's
 * place rather than over the map. */
await page.locator('.pane.map .type-menu button', { hasText: 'hub' }).click()
await page.waitForTimeout(300)
if (await page.locator('.schematic').isVisible())
    problems.push('the schematic must give way to the form')
if (await page.locator('article.properties').isVisible())
    problems.push('and so must the properties of whatever was selected')
/* The catalogue's default, offered before anything is typed. */
const portsField = page.locator('.creator .field', { hasText: 'ports' })
                       .locator('input[type=number]')
if (await portsField.inputValue() !== '8')
    problems.push('a field must open on the default the catalogue gives: ' +
                  await portsField.inputValue())
await page.locator('.creator input[type=text]').first().fill('built-hub')
await portsField.fill('3')
await page.screenshot({ path: `${OUT}/j-add-form.png` })
await page.locator('.creator button[type=submit]').click()
await page.waitForTimeout(800)

if (await page.locator('.creator').isVisible())
    problems.push('the form must close once the device is built')
const built = await page.evaluate(() => Alpine.$data(document.body).selected.name)
if (built !== 'built-hub')
    problems.push('what was built is what one is left looking at: ' + built)
if (!(await trayNames()).includes('built-hub'))
    problems.push('a device is built with no place of its own, so it belongs ' +
                  'in the strip below the map: ' + JSON.stringify(await trayNames()))
await page.screenshot({ path: `${OUT}/j-built.png` })

/* A cable, which asks for its two ends on the map before it offers a form. */
await page.locator('.pane.map .tray-line .adder button.add').click()
await page.waitForTimeout(200)
await page.locator('.pane.map .type-menu button', { hasText: 'cable' }).click()
await page.waitForTimeout(200)
if (!await page.locator('.pane.map .tray-line .picking').isVisible())
    problems.push('a cable must say it is waiting for its ends')
/* A host is full -- one adapter, one cable already on it -- and says so by
 * being drawn out of the way. */
const dim = await page.evaluate(() =>
    [ ...document.querySelectorAll('.pane.map .box.unpluggable .name') ]
        .map(e => e.textContent))
if (!dim.includes('host0'))
    problems.push('a device with no port left must be shown as no target: ' +
                  JSON.stringify(dim))
if (dim.includes('built-hub'))
    problems.push('a device with ports left must stay a target: ' +
                  JSON.stringify(dim))
await page.screenshot({ path: `${OUT}/j-picking.png` })

/* Dispatched rather than clicked: two devices a few hundred metres apart
 * overlap at this zoom, so which box a click at a point lands on is the map's
 * business and not this test's. What is being tried here is that a pointer on
 * a box is an end being picked rather than a box being dragged. */
const pickBox = async (n) => {
    await page.locator('.pane.map .box')
              .filter({ has: page.locator(`.name:text-is("${n}")`) })
              .dispatchEvent('pointerdown', { button: 0 })
    await page.waitForTimeout(300)
}
await pickBox('built-hub')
await pickBox('switch')
if (!await page.locator('.creator').isVisible())
    problems.push('the form must open once both ends are picked')
const picked = await page.locator('.creator .picked').allTextContents()
mapSay('the two ends the form was opened with', picked, [ 'built-hub', 'switch' ])
/* A parameter the catalogue has no default for says in the empty box itself
 * what leaving it that way will do, rather than in a line of help under it. */
const portHint = await page.locator('.creator .field', { hasText: 'from port' })
                           .locator('input[type=number]')
                           .getAttribute('placeholder')
if (portHint !== 'the first free one')
    problems.push('an empty field must show the catalogue\'s placeholder: ' +
                  JSON.stringify(portHint))
await page.locator('.creator input[type=text]').first().fill('built-cable')
await page.screenshot({ path: `${OUT}/j-cable-form.png` })
await page.locator('.creator button[type=submit]').click()
await page.waitForTimeout(800)

const cabled = await page.evaluate(() => {
    const d = Alpine.$data(document.body)
    const byId = d.widgetsOf(d.selected.sim)
    const hub = Object.values(byId).find(w => w.name === 'built-hub')
    return { selected: d.selected.name,
             /* Peered through the new cable, and so drawn as an edge. */
             edges: d.mapScene().edges.filter(e => e.name === 'built-cable').length,
             taken: hub ? hub.ports.filter(t => t).length : -1 }
})
if (cabled.selected !== 'built-cable')
    problems.push('one is left on the cable that was built: ' + cabled.selected)
if (cabled.edges !== 1)
    problems.push('a cable that was built must be drawn: ' + cabled.edges)
if (cabled.taken !== 1)
    problems.push('and the port it took must say it is taken: ' + cabled.taken)
await page.screenshot({ path: `${OUT}/j-cabled.png` })

/* Taking the hub out takes the cable with it: a cable is the link, and a link
 * with one end missing is nothing. Asked twice, since it cannot be undone. */
await page.locator('nav.tree a', { hasText: 'built-hub' }).click()
await page.waitForTimeout(400)
const del = page.locator('nav.breadcrumb button.delete')
if (!await del.isVisible())
    problems.push('a device this interface built must be one it will remove')
await del.click()
await page.waitForTimeout(200)
if (await del.textContent() !== 'really?')
    problems.push('deleting must ask before it does it')
await page.screenshot({ path: `${OUT}/j-delete.png` })
await del.click()
await page.waitForTimeout(800)

const after = await page.evaluate(() => {
    const d = Alpine.$data(document.body)
    const byId = d.widgetsOf(d.selected.sim)
    const named = (n) => Object.values(byId).filter(w => w.name === n).length
    const sw = Object.values(byId).find(w => w.name === 'switch')
    return { hub: named('built-hub'), cable: named('built-cable'),
             free: sw ? sw.ports.filter(t => !t).length : -1 }
})
if (after.hub || after.cable)
    problems.push('the device and the cable that reached it must both be ' +
                  'gone: ' + JSON.stringify(after))
if (after.free !== 1)
    problems.push('and the port that cable was on must be free again: ' +
                  after.free)
if (!(await names()).includes('switch'))
    problems.push('while what was at the other end stays')
await page.screenshot({ path: `${OUT}/j-deleted.png` })

/* Only a device: a part of one is not offered. */
await page.locator('nav.tree a', { hasText: 'host1' }).click()
await page.waitForTimeout(400)
if (!await page.locator('nav.breadcrumb button.delete').isVisible())
    problems.push('a host is a device and may be removed')
/* Down into it through the schematic, which lists what it is made of. */
await page.locator('.children a.child', { hasText: 'eth' }).first().click()
await page.waitForTimeout(400)
if (await page.locator('nav.breadcrumb button.delete').isVisible())
    problems.push('a part of a device is not one, and must not offer to go')

if (outside.length)
    problems.push('the page went looking outside the simulator for ' +
                  [ ...new Set(outside) ].join(', '))

console.log('banner said:', banner)
console.log(problems.length ? 'UNCAUGHT ERRORS:\n  ' + problems.join('\n  ')
                            : 'no uncaught exceptions')
await browser.close()
await stop()
process.exit(problems.length ? 1 : 0)

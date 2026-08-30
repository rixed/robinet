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
 * poll off, since it would replace them with what the server really has. */
await page.evaluate(() => {
    const d = Alpine.$data(document.body)
    d.live = false
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
    graph[id] = { id, name, parent, children, peers: [] }
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
                 ports: plane.map(id => [ id, portsOf(byId, edges, id) ]) }
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

/* And against the graph the demo actually has, where both ends of every cable
 * are already boxes on the plane: three cables, three edges, no port and
 * nothing hidden. */
const demoMap = await page.evaluate(() => {
    const d = Alpine.$data(document.body)
    const sim = d.sims.find(s => s.id !== d.servingId)
    const byId = d.widgetsOf(sim.id)
    const plane = planeOf(byId, sim.root)
    const { edges, inside } = mapEdges(byId, drawnSet(byId, plane, new Set()))
    return { plane: plane.map(id => byId[id].name),
             edges: edges.map(e => [ byId[e.from].name, e.fromPort,
                                     byId[e.to].name, e.toPort ]),
             inside: inside.size }
})
mapSay('the demo boxes', demoMap.plane, [ 'switch', 'host0', 'host1', 'host2' ])
mapSay('the demo edges', demoMap.edges,
       [ [ 'switch', null, 'host2', null ], [ 'switch', null, 'host1', null ],
         [ 'switch', null, 'host0', null ] ])
mapSay('nothing hidden in the demo', demoMap.inside, 0)

if (outside.length)
    problems.push('the page went looking outside the simulator for ' +
                  [ ...new Set(outside) ].join(', '))

console.log('banner said:', banner)
console.log(problems.length ? 'UNCAUGHT ERRORS:\n  ' + problems.join('\n  ')
                            : 'no uncaught exceptions')
await browser.close()
await stop()
process.exit(problems.length ? 1 : 0)

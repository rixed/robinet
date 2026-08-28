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

/* The switch: three peers, each joined by the cable that reaches it. */
await page.getByRole('link', { name: 'switch', exact: true }).first().click()
await page.waitForTimeout(300)
await page.screenshot({ path: `${OUT}/b-switch.png` })

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
/* Named rather than positional: every row has a read-only span, the editable
 * ones simply keep theirs hidden. */
const counter = page.locator('article.properties tr').filter({ hasText: 'tot bits' })
                    .locator('.ro')
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

console.log('banner said:', banner)
console.log(problems.length ? 'UNCAUGHT ERRORS:\n  ' + problems.join('\n  ')
                            : 'no uncaught exceptions')
await browser.close()
await stop()
process.exit(problems.length ? 1 : 0)

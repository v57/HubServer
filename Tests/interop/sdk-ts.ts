// End-to-end: the TS SDK (HubService/hub-service) against hub-server-swift. Run: bun Tests/interop/sdk-ts.ts
import { Channel } from '../../../../Channel/channel/client'
import { createPrivateKey, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const root = new URL('../..', import.meta.url).pathname
const HUB = process.env.HUB_SERVER_SWIFT ?? `${root}.build/debug/hub-server-swift`
const SDK = new URL('../../../../HubService/hub-service/index.ts', import.meta.url).pathname
const port = 25000 + Math.floor(Math.random() * 5000)
const dir = mkdtempSync(join(tmpdir(), 'hub-sdk-e2e-'))
const svcDir = mkdtempSync(join(tmpdir(), 'hub-sdk-svc-'))
process.env.HUB_DEVICE_KEY = join(dir, 'device.key')
process.env.HUB = `ws://127.0.0.1:${port}`
process.chdir(svcDir) // the SDK keeps its `auth` key file and hubs.json in the working directory

const k = generateKeyPairSync('ed25519', { privateKeyEncoding: { format: 'der', type: 'pkcs8' }, publicKeyEncoding: { format: 'der', type: 'spki' } })
const owner = { pub: k.publicKey.toString('base64'), priv: createPrivateKey({ key: k.privateKey, format: 'der', type: 'pkcs8' }) }
const hub = Bun.spawn([HUB, '--port', String(port), '--owner', owner.pub], { cwd: dir, stdout: 'ignore', stderr: 'pipe' })
const wait = (ms: number) => new Promise(r => setTimeout(r, ms))
await wait(1200)

const results: [string, boolean, string?][] = []
const check = async (n: string, f: () => Promise<unknown>) => { try { await f(); results.push([n, true]) } catch (e: any) { results.push([n, false, String(e?.message ?? e)]) } }
const assert = (c: unknown, m: string) => { if (!c) throw new Error(m) }
async function first<T>(it: AsyncIterable<T>, pred: (v: T) => boolean, ms = 5000): Promise<T> {
  return Promise.race([(async () => { for await (const v of it) if (pred(v)) return v; throw new Error('ended') })(), wait(ms).then(() => { throw new Error('timeout') })]) as Promise<T>
}

try {
  const anon = new Channel<any>().connect(`ws://127.0.0.1:${port}`, { headers: () => ({}) })
  const info = await anon.send('hub/info')
  const exp = () => Math.floor(Date.now() / 1000) + 60
  const ownerC = new Channel<any>().connect(`ws://127.0.0.1:${port}`, {
    headers: () => { const e = exp(); return { v: '1', auth: `key.${owner.pub}.${sign(null, Buffer.from(`hub1:${info.key}:${e}`), owner.priv).toString('base64')}.${e}` } },
  })

  const { Service } = await import(SDK)
  let seen: any
  const svc = new Service({ name: 'E2E Echo', instance: 'e2e/sdk', reporter: true })
    .post('e2e/sdk', (_body: any, request: any) => { seen = request; return request?.caller ?? null })
    .start()
  await wait(2500) // first connect v0 + hub/info pin + reconnect v1

  await check('SDK service appears as a pending device', async () => {
    const list: any[] = await first(ownerC.values('hub/devices/pending'), (l: any) => Array.isArray(l) && l.length > 0)
    assert(list[0].safetyCode, 'no safety code')
    await ownerC.send('hub/device/approve', { id: list[0].id })
  })
  await check('hub-key pin written', async () => {
    const pins = await Bun.file(join(svcDir, 'hubs.json')).json().catch(() => null)
    assert(pins && Object.values(pins).includes(info.key), `hubs.json ${JSON.stringify(pins)}`)
  })
  await check('owner allows hosting', async () => {
    const pending: Record<string, string[]> = await first(ownerC.values('hub/host/pending'), (p: any) => Object.values(p ?? {}).some((paths: any) => paths.includes('e2e/sdk')))
    for (const [key, paths] of Object.entries(pending)) if (paths.includes('e2e/sdk')) await ownerC.send('hub/host/update', { key, allow: ['e2e/sdk'] })
  })
  await wait(1000)
  await check('device lists SDK instance', async () => {
    const list: any[] = await first(ownerC.values('hub/devices'), (l: any) => Array.isArray(l) && l.some((d: any) => d.services?.some((s: any) => s.instance === 'e2e/sdk')))
    assert(list.length, 'missing')
  })
  await check('SDK handler receives caller', async () => {
    const caller = await ownerC.send('e2e/sdk')
    assert(caller?.owner === true && caller.key === owner.pub, `caller ${JSON.stringify(caller)}; request ${JSON.stringify(seen)}`)
  })
} finally {
  hub.kill()
  for (const [n, ok, e] of results) console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${e ? ` — ${e}` : ''}`)
  console.log(`\n${results.filter(r => r[1]).length}/${results.length} passed`)
  process.exit(results.every(r => r[1]) ? 0 : 1)
}

// The channel TS QUIC client (Channel/channel/quic.ts, the protocol reference) against ChannelServer's QUICServer,
// through the Swift fixture that serves the routes of Channel/channel/tests/server.ts (Sources/channel-fixture).
// Run from the package root: swift build --product channel-fixture && bun test Tests/interop
import { afterAll, beforeAll, expect, test } from 'bun:test'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { SocketAddress } from 'node:net'
import { join } from 'node:path'
import { QuicEndpoint, connect } from 'node:quic'
import { Channel, ChannelError, FrameReader, encodeFrame } from '../../../../Channel/channel/quic'

const root = new URL('../..', import.meta.url).pathname
const binary = process.env.CHANNEL_FIXTURE ?? `${root}.build/debug/channel-fixture`
const port = 25000 + Math.floor(Math.random() * 4000)
const address = `quic://127.0.0.1:${port}`
const directory = mkdtempSync(join(tmpdir(), 'channel-quic-'))
let fixture: ReturnType<typeof Bun.spawn>
let cert: Buffer
let fingerprint: string

const sleep = (seconds = 0.001) => new Promise(resolve => setTimeout(resolve, seconds * 1000))
async function failure(promise: Promise<any>): Promise<ChannelError> {
  try {
    await promise
  } catch (error) {
    expect(error).toBeInstanceOf(ChannelError)
    return error as ChannelError
  }
  throw new Error('expected a rejection')
}
async function until(predicate: () => boolean | Promise<boolean>, seconds = 2) {
  const end = Date.now() + seconds * 1000
  while (!(await predicate())) {
    if (Date.now() > end) throw new Error('timed out')
    await sleep(0.005)
  }
}
const client = (options: any = {}) => new Channel().connect(address, { quic: { ca: cert }, ...options })

function openssl(...args: string[]) {
  const result = Bun.spawnSync(['/usr/bin/openssl', ...args], { stderr: 'pipe' })
  if (result.exitCode !== 0) throw new Error(`openssl ${args[0]}: ${result.stderr}`)
  return result.stdout.toString()
}

beforeAll(async () => {
  const key = join(directory, 'key.pem')
  const certPath = join(directory, 'cert.pem')
  const p12 = join(directory, 'server.p12')
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', '/CN=localhost',
    '-keyout', key, '-out', certPath, '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1')
  openssl('pkcs12', '-export', '-inkey', key, '-in', certPath, '-out', p12, '-passout', 'pass:channel')
  cert = readFileSync(certPath)
  fingerprint = openssl('x509', '-in', certPath, '-noout', '-fingerprint', '-sha256').split('=')[1].trim()

  fixture = Bun.spawn([binary, String(port)], {
    stdout: 'pipe',
    stderr: 'inherit',
    env: { ...process.env, CHANNEL_QUIC_P12: p12, CHANNEL_QUIC_PASSWORD: 'channel' },
  })
  const reader = fixture.stdout.getReader()
  let output = ''
  while (!output.includes('quic listening') && !output.includes('failed')) {
    const { value, done } = await reader.read()
    if (done) break
    output += new TextDecoder().decode(value)
  }
  expect(output).toContain('quic listening')
})
afterAll(() => {
  fixture?.kill()
  rmSync(directory, { recursive: true, force: true })
})

test('posts: values, objects, void, unicode and large bodies', async () => {
  const c = client()
  expect(await c.send('hello')).toBe('world')
  const body = { a: [1, 2.5, -3e-7, true, null], s: 'кириллица 🚀 "quoted" \\ \n tab\t', nested: { x: {} } }
  expect(await c.send('echo', body)).toEqual(body)
  expect(await c.send('empty')).toBeUndefined()
  const large = 'x'.repeat(3 * 1024 * 1024)
  expect(await c.send('echo', large)).toBe(large)
  const medium = 'y'.repeat(70000)
  expect(await c.send('echo', medium)).toBe(medium)
  const results = await Promise.all(Array.from({ length: 500 }, (_, i) => c.send('echo', i)))
  expect(results).toEqual(Array.from({ length: 500 }, (_, i) => i))
  c.stop()
})

test('structured errors and library codes', async () => {
  const c = client()
  const banned = await failure(c.send('v2/error'))
  expect(banned.message).toBe('banned')
  expect(banned.code).toBe(403)
  expect(banned.info).toEqual({ remaining: 5 })
  const missing = await failure(c.send('nothing/here'))
  expect(missing.code).toBe('not_found')
  c.stop()
})

test('connection state is per connection', async () => {
  const a = client()
  const b = client()
  expect(await a.send('auth', { name: 'alice' })).toBe('alice')
  expect(await a.send('auth/name')).toBe('alice')
  await failure(b.send('auth/name'))
  a.stop()
  b.stop()
})

test('streams and the server calling the client back', async () => {
  const c = new Channel()
    .post('hello', () => 'from client')
    .stream('stream/values', async function* () {
      yield 'a'
      yield 'b'
    })
    .connect(address, { quic: { ca: cert } })
  const values: any[] = []
  for await (const value of c.values('stream/values')) values.push(value)
  expect(values).toEqual([0, 1, 2])
  const mirrored: any[] = []
  for await (const value of c.values('mirror/stream')) mirrored.push(value)
  expect(mirrored).toEqual(['a', 'b'])
  expect(await c.send('mirror')).toBe('from client')
  c.stop()
})

test('room subscription: snapshot, events, unsubscribe', async () => {
  const c = client()
  const events: any[] = []
  const sub = await c.subscribe('v2/room', { room: 'a' }, (body: any) => events.push(body))
  expect(events).toEqual(['joined'])
  await c.send('v2/publish', { room: 'a', body: 'hi' })
  await c.send('v2/publish', { room: 'b', body: 'other room' })
  await until(() => events.length === 2)
  sub.cancel()
  await sleep(0.02)
  await c.send('v2/publish', { room: 'a', body: 'after' })
  await sleep(0.05)
  expect(events).toEqual(['joined', 'hi'])
  c.stop()
})

test('hello headers reach the server lowercased, with the remote address', async () => {
  const c = client({ headers: async () => ({ Token: 't1' }) })
  const headers = await c.send('v2/headers')
  expect(headers.token).toBe('t1')
  expect(headers['x-hub-remote-ip']).toBe('127.0.0.1')
  c.stop()
})

test('replay false fails with disconnected when the server drops the connection, then it reconnects', async () => {
  const c = client()
  await c.send('v2/drops/reset')
  const error = await failure(c.send('v2/drop', undefined, { replay: false }))
  expect(error.code).toBe('disconnected')
  expect(await c.send('v2/drops')).toBe(1)
  c.stop()
})

test('a pinned fingerprint replaces verification; an unknown certificate is refused', async () => {
  const pinned = new Channel().connect(address, { quic: { fingerprint } })
  expect(await pinned.send('hello')).toBe('world')
  pinned.stop()
  const untrusted = new Channel().connect(address, { quic: { fingerprint: '00'.repeat(32) } })
  const result = await Promise.race([untrusted.send('hello').then(() => 'answered'), sleep(0.5).then(() => 'refused')])
  expect(result).toBe('refused')
  untrusted.stop()
})

/** Opens a raw QUIC stream to the fixture, to check the wire rules. Each on its own UDP socket: Network.framework
 * takes one connection per client address and port. */
async function raw() {
  const session = await connect(new SocketAddress({ address: '127.0.0.1', port, family: 'ipv4' }), {
    endpoint: new QuicEndpoint(),
    alpn: 'channel/1',
    servername: 'localhost',
    ca: cert,
    enableEarlyData: false,
  } as any)
  await session.opened
  const stream = await session.createBidirectionalStream()
  return { session, stream }
}

test('raw frames: hello, keepalive, a batch; a first frame that is not a hello closes', async () => {
  const { session, stream } = await raw()
  stream.writer.writevSync([...encodeFrame(JSON.stringify({ hello: { Token: 'raw' } })), Uint8Array.of(0)])
  stream.writer.writevSync(encodeFrame(JSON.stringify([{ id: 1, path: 'v2/headers' }, { id: 2, path: 'hello' }])))
  const reader = new FrameReader()
  const replies: any[] = []
  for await (const chunks of stream) {
    for (const chunk of chunks) for (const text of reader.push(chunk)) replies.push(JSON.parse(text))
    if (replies.length >= 2) break
  }
  expect(replies.find(r => r.id === 1).body.token).toBe('raw')
  expect(replies.find(r => r.id === 2).body).toBe('world')
  session.destroy()

  const second = await raw()
  second.stream.writer.writevSync(encodeFrame(JSON.stringify({ id: 1, path: 'hello' })))
  const closed = await Promise.race([second.session.closed.then(() => true, () => true), sleep(2).then(() => false)])
  expect(closed).toBe(true)
})

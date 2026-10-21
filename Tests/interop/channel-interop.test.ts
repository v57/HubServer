// The channel TS client (Channel/channel, the protocol reference) against ChannelServer, through the Swift fixture
// that serves the routes of Channel/channel/tests/server.ts (Sources/channel-fixture).
// Run from the package root: swift build --product channel-fixture && bun test Tests/interop
import { afterAll, beforeAll, expect, test } from 'bun:test'
import { Channel, ChannelError } from '../../../../Channel/channel/client'

const root = new URL('../..', import.meta.url).pathname
const binary = process.env.CHANNEL_FIXTURE ?? `${root}.build/debug/channel-fixture`
const port = 21000 + Math.floor(Math.random() * 4000)
const address = `ws://127.0.0.1:${port}`
let fixture: ReturnType<typeof Bun.spawn>

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
const stats = async (): Promise<Record<string, number>> => {
  const client = new Channel().connect(address)
  const result = await client.send('fixture/stats')
  client.stop()
  return result
}

beforeAll(async () => {
  fixture = Bun.spawn([binary, String(port)], { stdout: 'pipe', stderr: 'inherit' })
  const reader = fixture.stdout.getReader()
  const { value } = await reader.read()
  expect(new TextDecoder().decode(value)).toContain('listening')
})
afterAll(() => fixture?.kill())

test('posts: values, objects, void, unicode and large bodies', async () => {
  const client = new Channel().connect(address)
  expect(await client.send('hello')).toBe('world')
  const body = { a: [1, 2.5, -3e-7, true, null], s: 'кириллица 🚀 "quoted" \\ \n tab\t', nested: { x: {} } }
  expect(await client.send('echo', body)).toEqual(body)
  expect(await client.send('empty')).toBeUndefined()
  expect(await client.send('echo', 0)).toBe(0)
  expect(await client.send('echo', '')).toBe('')
  expect(await client.send('echo', 9007199254740991)).toBe(9007199254740991)
  const large = 'x'.repeat(3 * 1024 * 1024)
  expect(await client.send('echo', large)).toBe(large)
  const medium = 'y'.repeat(70000)
  expect(await client.send('echo', medium)).toBe(medium)
  client.stop()
})

test('batched requests in one frame', async () => {
  const client = new Channel().connect(address)
  await client.send('hello')
  const results = await Promise.all(Array.from({ length: 200 }, (_, i) => client.send('echo', i)))
  expect(results).toEqual(Array.from({ length: 200 }, (_, i) => i))
  client.stop()
})

test('1. structured errors carry message, code and info', async () => {
  const client = new Channel().connect(address)
  const banned = await failure(client.send('v2/error'))
  expect(banned.message).toBe('banned')
  expect(banned.code).toBe(403)
  expect(banned.info).toEqual({ remaining: 5 })
  const slow = await failure(client.send('v2/error/code'))
  expect(slow.message).toBe('slow down')
  expect(slow.code).toBe('rate_limited')
  expect(slow.info).toEqual({ retryAfter: 1 })
  client.stop()
})

test('2. v1 string errors and library codes', async () => {
  const client = new Channel().connect(address)
  const unauthorized = await failure(client.send('auth/name'))
  expect(String(unauthorized)).toBe('unauthorized')
  expect(unauthorized.code).toBeUndefined()
  const notFound = await failure(client.send('v2/missing'))
  expect(notFound.message).toBe('api not found')
  expect(notFound.code).toBe('not_found')
  const streamNotFound = await failure((async () => {
    for await (const _ of client.values('v2/missing')) {
    }
  })())
  expect(streamNotFound.code).toBe('not_found')
  client.stop()
})

test('connection state is per connection', async () => {
  const a = new Channel().connect(address)
  const b = new Channel().connect(address)
  expect(await a.send('auth', { name: 'alice' })).toBe('alice')
  expect(await a.send('auth/name')).toBe('alice')
  await failure(b.send('auth/name'))
  a.stop()
  b.stop()
})

test('streams: values, cancel and mirrored streams', async () => {
  const client = new Channel()
    .stream('stream/values', async function* () {
      yield 'a'
      yield 'b'
    })
    .connect(address)
  const values: any[] = []
  for await (const value of client.values('stream/values')) values.push(value)
  expect(values).toEqual([0, 1, 2])

  const mirrored: any[] = []
  for await (const value of client.values('mirror/stream')) mirrored.push(value)
  expect(mirrored).toEqual(['a', 'b'])

  const before = (await stats()).streamCancel
  for await (const value of client.values('stream/cancel')) if (value === 1) break
  await sleep(0.05)
  const after = (await stats()).streamCancel
  await sleep(0.05)
  expect((await stats()).streamCancel).toBe(after)
  expect(after - before).toBeLessThan(5)
  client.stop()
})

test('the server calls the client back', async () => {
  const client = new Channel().post('hello', () => 'from client').connect(address)
  expect(await client.send('mirror')).toBe('from client')
  client.stop()
})

test('4. room subscription: snapshot, events, falsy events, unsubscribe', async () => {
  const client = new Channel().connect(address)
  const events: any[] = []
  const sub = await client.subscribe('v2/room', { room: 'a' }, (body: any) => events.push(body))
  expect(events).toEqual(['joined'])
  await client.send('v2/publish', { room: 'a', body: 'hi' })
  await client.send('v2/publish', { room: 'a', body: 0 })
  await client.send('v2/publish', { room: 'b', body: 'other room' })
  await until(() => events.length === 3)
  expect(events).toEqual(['joined', 'hi', 0])
  sub.cancel()
  await sleep(0.02)
  await client.send('v2/publish', { room: 'a', body: 'after' })
  await sleep(0.05)
  expect(events).toEqual(['joined', 'hi', 0])
  client.stop()
})

test('3. one-shot subscription and refused subscriptions', async () => {
  const client = new Channel().connect(address)
  const events: any[] = []
  await client.subscribe('v2/once', undefined, (body: any) => events.push(body))
  expect(events).toEqual(['once'])
  const refused = await failure(client.subscribe('v2/private', undefined, () => {}))
  expect(refused.code).toBe(401)
  await client.send('auth', { name: 'bob' })
  const names: any[] = []
  await client.subscribe('v2/private', undefined, (body: any) => names.push(body))
  expect(names).toEqual(['bob'])
  const missing = await failure(client.subscribe('v2/nothing', undefined, () => {}))
  expect(missing.message).toBe('subscription not found')
  client.stop()
})

test('6. timeout cancels the request on the server', async () => {
  const client = new Channel().connect(address)
  await client.send('hello')
  const before = (await stats()).cancels
  const error = await failure(client.send('v2/never', undefined, { timeout: 0.05 }))
  expect(error.code).toBe('timeout')
  await until(async () => (await stats()).cancels === before + 1)
  client.stop()
})

test('7. replay false fails with disconnected when the server drops the connection', async () => {
  const client = new Channel().connect(address)
  await client.send('v2/drops/reset')
  const error = await failure(client.send('v2/drop', undefined, { replay: false }))
  expect(error.code).toBe('disconnected')
  expect(await client.send('v2/drops')).toBe(1)
  client.stop()
})

test('9. headers reach the server, with the remote address', async () => {
  let n = 0
  const client = new Channel().connect(address, { headers: async () => ({ token: `t${++n}` }) })
  const headers = await client.send('v2/headers')
  expect(headers.token).toBe('t1')
  expect(headers['x-hub-remote-ip']).toBe('127.0.0.1')
  client.stop()
})

test('query parameters count as headers', async () => {
  const ws = new WebSocket(`${address}/?auth=abc&v=1`)
  const result = await new Promise<any>((resolve, reject) => {
    ws.onopen = () => ws.send(JSON.stringify({ id: 1, path: 'v2/headers' }))
    ws.onmessage = event => resolve(JSON.parse(String(event.data)))
    ws.onerror = reject
  })
  expect(result.body.auth).toBe('abc')
  expect(result.body.v).toBe('1')
  ws.close()
})

test('text that is not JSON closes the connection, binary is ignored', async () => {
  const ws = new WebSocket(address)
  await new Promise(resolve => (ws.onopen = resolve))
  const answers: any[] = []
  ws.onmessage = event => answers.push(JSON.parse(String(event.data)))
  ws.send(new Uint8Array([1, 2, 3]))
  ws.send(JSON.stringify({ id: 7, path: 'hello' }))
  await until(() => answers.length === 1)
  expect(answers[0]).toEqual({ id: 7, body: 'world' })
  const closed = new Promise(resolve => (ws.onclose = resolve))
  ws.send('not json')
  await closed
})

// hub-server-swift: the Swift HubServer as a command, with hub-server's options, for testing and headless machines
import Foundation
import HubServer

setvbuf(stdout, nil, _IOLBF, 0)

let help = """
  Usage: hub-server-swift [options]

  Options:
    -p, --port <port>      listen on a port or address (default 1997, env HUBLISTEN)
    --data <directory>     where the hub keeps its key and stores (default ./data)
    --owner <key>          trust this key as an owner (env HUBOWNER)
    --launcher <key>       let this key host launcher/* (env HUBLAUNCHER)
    --local                local mode: 127.0.0.1 only, default-allow, the launcher key is an owner, no pairing
                           (env HUB_MODE=local)
    --pair                 write a new pairing code to the data directory, print it and exit; a running hub on that
                           directory takes it at once (a hub without owners makes one at start anyway)
    -h, --help             print this help

  The hub's device key is HUB_DEVICE_KEY, else ~/.hub/device.key (created if missing).
  """

let environment = ProcessInfo.processInfo.environment
func nonEmpty(_ value: String?) -> String? { value?.isEmpty == false ? value : nil }

var listen = nonEmpty(environment["HUBLISTEN"]) ?? "1997"
var data = "data"
var owners = [nonEmpty(environment["HUBOWNER"])].compactMap { $0 }
var launcher = nonEmpty(environment["HUBLAUNCHER"])
var local = environment["HUB_MODE"] == "local"
var pair = false

var arguments = Array(CommandLine.arguments.dropFirst())
while !arguments.isEmpty {
  let argument = arguments.removeFirst()
  func value() -> String {
    guard !arguments.isEmpty else {
      FileHandle.standardError.write(Data("\(argument) needs a value\n".utf8))
      exit(2)
    }
    return arguments.removeFirst()
  }
  switch argument {
  case "-p", "--port": listen = value()
  case "--data": data = value()
  case "--owner": owners.append(value())
  case "--launcher": launcher = value()
  case "--local": local = true
  case "--pair": pair = true
  case "--merge", "--proxy":
    print("\(argument) isn't supported by the Swift HubServer, ignored \(value())")
  case "-h", "--help":
    print(help)
    exit(0)
  default:
    print("Unknown option \(argument)")
  }
}

let dataDirectory = URL(fileURLWithPath: data, relativeTo: URL(fileURLWithPath: FileManager.default.currentDirectoryPath)).standardizedFileURL

if pair {
  do {
    let code = try HubServer.writePairingCode(dataDirectory: dataDirectory)
    print("Pairing code: \(code.code) (valid until \(ISO8601DateFormatter().string(from: code.expires)))")
    exit(0)
  } catch {
    print("Pairing code unavailable: \(error)")
    exit(1)
  }
}

guard let address = ListenAddress(listen) else {
  print("Invalid listen address \(listen)")
  exit(2)
}

/// This machine's device key: HUB_DEVICE_KEY, `/var/lib/hub/device.key` for root on Linux, else `~/.hub/device.key`
func deviceKeyURL() -> URL {
  if let path = nonEmpty(environment["HUB_DEVICE_KEY"]) { return URL(fileURLWithPath: path) }
  #if os(Linux)
  if getuid() == 0 { return URL(fileURLWithPath: "/var/lib/hub/device.key") }
  #endif
  return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".hub/device.key")
}

var configuration = HubServer.Configuration(dataDirectory: dataDirectory)
configuration.listen = address
configuration.local = local
configuration.owners = owners
configuration.launcherKey = launcher
do {
  configuration.devicePublicKey = try HubKeyPair.loadOrCreate(deviceKeyURL()).publicKey
} catch {
  print("Hub device key unavailable, the hub has no device: \(error)")
}

let server = HubServer(configuration)
var sources: [DispatchSourceSignal] = []
for signal in [SIGINT, SIGTERM] {
  Foundation.signal(signal, SIG_IGN)
  let source = DispatchSource.makeSignalSource(signal: signal, queue: .main)
  source.setEventHandler {
    Task {
      await server.stop()
      exit(0)
    }
  }
  source.resume()
  sources.append(source)
}

Task {
  do {
    try await server.start()
  } catch {
    print("Hub failed to start: \(error)")
    exit(1)
  }
}
dispatchMain()

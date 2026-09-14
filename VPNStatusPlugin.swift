import Darwin
import Foundation

private let schemaVersion = 1
private let pluginName = "VPN Status"
private let activityID = "vpn-status"
private let socketEnvironmentKey = "DYNAMICLAKE_JSON_SOCKET"
private let settingsPathEnvironmentKey = "DYNAMICLAKE_PLUGIN_SETTINGS_PATH"
private let maxFrameSize = 64 * 1024

private final class JSONSocketClient {
    let socketPath: String
    private var fileDescriptor: Int32 = -1
    private var readBuffer = Data()

    init(socketPath: String) {
        self.socketPath = socketPath
    }

    deinit { close() }

    func connect() throws {
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw PluginError.socket("socket failed") }
        fileDescriptor = fd

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let maxPathLength = MemoryLayout.size(ofValue: address.sun_path)
        guard socketPath.utf8.count < maxPathLength else { throw PluginError.socket("socket path too long") }

        socketPath.withCString { source in
            withUnsafeMutablePointer(to: &address.sun_path) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: maxPathLength) { dest in
                    memset(dest, 0, maxPathLength)
                    strncpy(dest, source, maxPathLength - 1)
                }
            }
        }

        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sp in
                Darwin.connect(fd, sp, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else { throw PluginError.socket("connect failed") }

        let flags = Darwin.fcntl(fd, F_GETFL, 0)
        if flags >= 0 { _ = Darwin.fcntl(fd, F_SETFL, flags | O_NONBLOCK) }
    }

    func close() {
        guard fileDescriptor >= 0 else { return }
        Darwin.close(fileDescriptor)
        fileDescriptor = -1
    }

    func send(_ payload: [String: Any]) throws {
        let data = try JSONSerialization.data(withJSONObject: payload, options: [])
        guard data.count <= maxFrameSize else { throw PluginError.frameTooLarge(data.count) }
        var frame = Data()
        var length = UInt32(data.count).bigEndian
        withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }
        frame.append(data)
        try sendAll(frame)
    }

    func receiveAvailable() -> [[String: Any]] {
        guard fileDescriptor >= 0 else { return [] }
        var tmp = [UInt8](repeating: 0, count: 4096)
        while true {
            let cap = tmp.count
            let count = tmp.withUnsafeMutableBytes { p in
                Darwin.recv(fileDescriptor, p.baseAddress!, cap, 0)
            }
            if count > 0 { readBuffer.append(tmp, count: count); continue }
            if count == 0 { break }
            if errno == EAGAIN || errno == EWOULDBLOCK { break }
            break
        }
        var messages: [[String: Any]] = []
        while readBuffer.count >= 4 {
            let lenData = readBuffer.prefix(4)
            let length = lenData.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            if length > maxFrameSize { readBuffer.removeAll(); break }
            let total = Int(length) + 4
            guard readBuffer.count >= total else { break }
            let body = readBuffer.subdata(in: 4..<total)
            readBuffer.removeSubrange(0..<total)
            if let obj = try? JSONSerialization.jsonObject(with: body, options: []),
               let dict = obj as? [String: Any] {
                messages.append(dict)
            }
        }
        return messages
    }

    private func sendAll(_ data: Data) throws {
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var sent = 0
            while sent < data.count {
                let r = Darwin.send(fileDescriptor, base.advanced(by: sent), data.count - sent, 0)
                if r > 0 { sent += r; continue }
                if r < 0 && errno == EINTR { continue }
                if r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { usleep(10_000); continue }
                throw PluginError.socket("send failed")
            }
        }
    }
}

private enum PluginError: Error, CustomStringConvertible {
    case socketPathMissing
    case socket(String)
    case frameTooLarge(Int)
    var description: String {
        switch self {
        case .socketPathMissing: return "\(socketEnvironmentKey) is missing"
        case .socket(let m): return m
        case .frameTooLarge(let s): return "frame too large: \(s)"
        }
    }
}

private struct VPNStatus {
    var connected: Bool
    var provider: String?
    var protocol_: String?
    var fullName: String?
}

private func getVPNStatus() -> VPNStatus {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
    proc.arguments = ["--nc", "list"]
    proc.standardOutput = Pipe()
    proc.standardError = Pipe()
    try? proc.run()
    proc.waitUntilExit()
    let out = (proc.standardOutput as! Pipe).fileHandleForReading.readDataToEndOfFile()
    if let str = String(data: out, encoding: .utf8) {
        for line in str.components(separatedBy: "\n") {
            if line.contains("(Connected)") {
                var inQuote = false
                var serviceName = ""
                for char in line {
                    if char == "\"" {
                        if inQuote { break }
                        inQuote = true
                        continue
                    }
                    if inQuote { serviceName.append(char) }
                }
                guard !serviceName.isEmpty else { continue }
                let parts = serviceName.split(separator: " ", maxSplits: 1)
                if parts.count == 2 {
                    let status = VPNStatus(connected: true, provider: String(parts[0]), protocol_: String(parts[1]), fullName: serviceName)
                    debugLog("vpn: connected=true provider=\(status.provider ?? "nil") proto=\(status.protocol_ ?? "nil")")
                    return status
                }
                let status = VPNStatus(connected: true, provider: serviceName, protocol_: serviceName, fullName: serviceName)
                debugLog("vpn: connected=true provider=\(status.provider ?? "nil") proto=\(status.protocol_ ?? "nil")")
                return status
            }
        }
    }
    debugLog("vpn: connected=false (no scutil match)")

    // Fallback: detect WireGuard-based VPNs (ProtonVPN) via active utun interface
    let ifconfig = Process()
    ifconfig.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
    ifconfig.arguments = ["-a"]
    ifconfig.standardOutput = Pipe()
    ifconfig.standardError = Pipe()
    guard let ifData = try? runWithTimeout(ifconfig, timeout: 3) else {
        return VPNStatus(connected: false, provider: nil, protocol_: nil, fullName: nil)
    }
    let ifStr = String(data: ifData, encoding: .utf8) ?? ""

    // Find utun interfaces with an IPv4 address (not 127.x)
    var hasUtunIPv4 = false
    var currentIface = ""
    for line in ifStr.components(separatedBy: "\n") {
        if line.hasPrefix("utun") && line.contains(":") {
            currentIface = String(line.split(separator: ":").first ?? "")
        }
        if line.contains("inet ") && !line.contains("inet 127.") && currentIface.hasPrefix("utun") {
            hasUtunIPv4 = true
            break
        }
    }

    if hasUtunIPv4 {
        debugLog("vpn: detected VPN via utun+\(currentIface)")
        return VPNStatus(connected: true, provider: "ProtonVPN", protocol_: "WireGuard", fullName: "ProtonVPN")
    }

    return VPNStatus(connected: false, provider: nil, protocol_: nil, fullName: nil)
}

private func runWithTimeout(_ process: Process, timeout: TimeInterval) throws -> Data {
    process.standardError = FileHandle.nullDevice
    try process.run()
    let deadline = Date().addingTimeInterval(timeout)
    while process.isRunning && Date() < deadline {
        usleep(50_000)
    }
    if process.isRunning {
        process.terminate()
    }
    let pipe = process.standardOutput as! Pipe
    return pipe.fileHandleForReading.readDataToEndOfFile()
}

private func disconnectVPN(_ serviceName: String) {
    if serviceName.contains("Nord") {
        disableOnDemandAndStop(serviceName, provider: "nordvpn")
    } else if serviceName.contains("Proton") {
        // ProtonVPN: stop via scutil + disable network service (no sudo needed)
        for attempt in 1...5 {
            let stop = Process()
            stop.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
            stop.arguments = ["--nc", "stop", "ProtonVPN"]
            stop.standardOutput = Pipe()
            stop.standardError = Pipe()
            try? stop.run()
            stop.waitUntilExit()

            let disable = Process()
            disable.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
            disable.arguments = ["-setnetworkserviceenabled", "ProtonVPN", "off"]
            disable.standardOutput = Pipe()
            disable.standardError = Pipe()
            try? disable.run()
            disable.waitUntilExit()

            Thread.sleep(forTimeInterval: 2)

            let check = Process()
            check.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
            check.arguments = ["--nc", "status", "ProtonVPN"]
            check.standardOutput = Pipe()
            check.standardError = Pipe()
            try? check.run()
            check.waitUntilExit()
            let out = String(data: (check.standardOutput as! Pipe).fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            if !out.contains("Connected") {
                debugLog("ProtonVPN disconnected after \(attempt) attempt(s)")
                return
            }
            debugLog("ProtonVPN reconnected after attempt \(attempt), retrying...")
        }
        debugLog("ProtonVPN still connected after 5 attempts")
    } else {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
        proc.arguments = ["--nc", "stop", serviceName]
        proc.standardOutput = Pipe()
        proc.standardError = Pipe()
        try? proc.run()
        proc.waitUntilExit()
        debugLog("scutil stop \(serviceName): exitCode=\(proc.terminationStatus)")
    }
}

private func openVPNApp() {
    // Try common VPN app URL schemes
    let schemes = ["nordvpn://", "expressvpn://", "surfshark://", "protonvpn://", "mullvad://", "wireguard://", "tailscale://"]
    for scheme in schemes {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        proc.arguments = [scheme]
        proc.standardOutput = Pipe()
        proc.standardError = Pipe()
        try? proc.run()
        proc.waitUntilExit()
        if proc.terminationStatus == 0 {
            debugLog("opened \(scheme)")
            return
        }
    }
    debugLog("no VPN app found to open")
}

private func disableOnDemandAndStop(_ service: String, provider: String) {
    let pythonCode: String
    if provider == "nordvpn" {
        pythonCode = """
import plistlib, subprocess, time

def disable_ondemand():
    path = '/Library/Preferences/SystemConfiguration/preferences.plist'
    with open(path, 'rb') as f:
        plist = plistlib.load(f)
    changed = False
    for key, svc in plist.get('NetworkServices', {}).items():
        vpn = svc.get('VPN', {})
        if 'nordvpn' in svc.get('Interface', {}).get('SubType', '').lower():
            if vpn.get('OnDemandEnabled', False):
                vpn['OnDemandEnabled'] = False
                vpn['OnDemandRules'] = [{'Action': 'NeverConnect'}]
                changed = True
    if changed:
        with open(path, 'wb') as f:
            plistlib.dump(plist, f)
        print('OnDemand disabled')
    return changed

def is_connected():
    for svc in ['NordVPN NordWhisper', 'NordVPN NordLynx']:
        r = subprocess.run(['/usr/sbin/scutil', '--nc', 'status', svc], capture_output=True, text=True)
        if 'Connected' in r.stdout:
            return True
    return False

def stop_vpn():
    subprocess.run(['/usr/sbin/scutil', '--nc', 'stop', 'NordVPN NordWhisper'], capture_output=True)
    subprocess.run(['/usr/sbin/scutil', '--nc', 'stop', 'NordVPN NordLynx'], capture_output=True)

for attempt in range(5):
    disable_ondemand()
    time.sleep(0.3)
    stop_vpn()
    time.sleep(2)
    if not is_connected():
        print(f'VPN disconnected after {attempt+1} attempt(s)')
        break
    print(f'Reconnected after attempt {attempt+1}, retrying...')
else:
    print('VPN still connected after 5 attempts')
"""
    } else {
        pythonCode = """
import subprocess, time

def is_connected():
    r = subprocess.run(['/usr/sbin/scutil', '--nc', 'status', 'ProtonVPN'], capture_output=True, text=True)
    return 'Connected' in r.stdout

def stop_vpn():
    subprocess.run(['/usr/sbin/scutil', '--nc', 'stop', 'ProtonVPN'], capture_output=True)
    subprocess.run(['/usr/sbin/networksetup', '-setnetworkserviceenabled', 'ProtonVPN', 'off'], capture_output=True)

for attempt in range(5):
    stop_vpn()
    time.sleep(2)
    if not is_connected():
        print(f'VPN disconnected after {attempt+1} attempt(s)')
        break
    print(f'Reconnected after attempt {attempt+1}, retrying...')
else:
    print('VPN still connected after 5 attempts')
"""
    }
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
    proc.arguments = ["/usr/bin/python3", "-c", pythonCode]
    proc.standardOutput = Pipe()
    proc.standardError = Pipe()
    try? proc.run()
    proc.waitUntilExit()
    let out = (proc.standardOutput as! Pipe).fileHandleForReading.readDataToEndOfFile()
    let outStr = String(data: out, encoding: .utf8) ?? ""
    debugLog("disableOnDemandAndStop: exitCode=\(proc.terminationStatus) output=\(outStr.trimmingCharacters(in: .whitespacesAndNewlines))")
}

private func createPayload(showOpenButton: Bool = true) -> [String: Any] {
    var sneakPeek: [String: Any] = [
        "center": ["type": "text", "id": "vpn-detail", "text": "Connected", "style": "compact"] as [String: Any],
        "rightSlot": ["type": "button", "id": "vpn-toggle-btn", "actionID": "toggle-vpn", "systemImage": "xmark", "tint": "red"] as [String: Any]
    ]
    if showOpenButton {
        sneakPeek["leftSlot"] = ["type": "button", "id": "vpn-open-btn", "actionID": "open-vpn-app", "systemImage": "arrow.up.forward.app", "tint": "gray"] as [String: Any]
    }
    return [
        "schemaVersion": schemaVersion,
        "requestID": "create-vpn",
        "type": "create",
        "activityID": activityID,
        "title": pluginName,
        "priority": "low",
        "size": "small",
        "surfaces": [
            "compactLiveActivity": [
                "leftSlot": ["type": "image", "id": "vpn-icon", "source": "sfSymbol", "systemImage": "network.badge.shield.half.filled", "tint": "blue"] as [String: Any]
            ],
            "extraLiveActivity": [
                "leftSlot": ["type": "image", "id": "vpn-icon", "source": "sfSymbol", "systemImage": "network.badge.shield.half.filled", "tint": "blue"] as [String: Any]
            ],
            "sneakPeek": sneakPeek
        ] as [String: Any]
    ]
}

private func updatePayload(_ vpn: VPNStatus, showOpenButton: Bool = true) -> [String: Any]? {
    guard vpn.connected else { return nil }
    var sneakPeek: [String: Any] = [
        "center": ["type": "text", "id": "vpn-detail", "text": vpn.protocol_ ?? "Connected", "style": "compact"] as [String: Any],
        "rightSlot": ["type": "button", "id": "vpn-toggle-btn", "actionID": "toggle-vpn", "systemImage": "xmark", "tint": "red"] as [String: Any]
    ]
    if showOpenButton {
        sneakPeek["leftSlot"] = ["type": "button", "id": "vpn-open-btn", "actionID": "open-vpn-app", "systemImage": "arrow.up.forward.app", "tint": "gray"] as [String: Any]
    }
    return [
        "schemaVersion": schemaVersion,
        "requestID": "update-\(Int(Date().timeIntervalSince1970))",
        "type": "update",
        "activityID": activityID,
        "surfaces": [
            "compactLiveActivity": [
                "leftSlot": ["type": "image", "id": "vpn-icon", "source": "sfSymbol", "systemImage": "network.badge.shield.half.filled", "tint": "blue"] as [String: Any]
            ],
            "extraLiveActivity": [
                "leftSlot": ["type": "image", "id": "vpn-icon", "source": "sfSymbol", "systemImage": "network.badge.shield.half.filled", "tint": "blue"] as [String: Any]
            ],
            "sneakPeek": sneakPeek
        ] as [String: Any]
    ]
}

private func dismissPayload() -> [String: Any] {
    [
        "schemaVersion": schemaVersion,
        "requestID": "dismiss-vpn",
        "type": "dismiss",
        "activityID": activityID
    ]
}

private var running = true

private func handleSignal(_ sig: Int32) {
    running = false
}

private func debugLog(_ message: String) {
    let formatter = ISO8601DateFormatter()
    let line = "\(formatter.string(from: Date())) \(message)\n"
    let fm = FileManager.default
    let dir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("DynamicLake", isDirectory: true)
        .appendingPathComponent("PluginLogs", isDirectory: true)
    try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
    let url = dir.appendingPathComponent("vpn-status-debug.log")
    if fm.fileExists(atPath: url.path),
       let handle = try? FileHandle(forWritingTo: url) {
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        try? handle.write(contentsOf: Data(line.utf8))
    } else {
        try? line.write(to: url, atomically: true, encoding: .utf8)
    }
}

@main
private enum Main {
    static func main() {
        signal(SIGINT, handleSignal)
        signal(SIGTERM, handleSignal)

        guard let socketPath = ProcessInfo.processInfo.environment[socketEnvironmentKey],
              !socketPath.isEmpty else {
            fputs("VPN Status: \(PluginError.socketPathMissing)\n", stderr)
            exit(64)
        }

        let client = JSONSocketClient(socketPath: socketPath)
        do {
            try client.connect()
            debugLog("connected socket=\(socketPath)")
        } catch {
            fputs("VPN Status: \(error)\n", stderr)
            debugLog("ERROR \(error)")
            exit(65)
        }

        var published = false
        var lastSig = ""
        var togglePending = false
        var openAppPending = false
        var currentFullName = ""

        while running {
            for msg in client.receiveAvailable() {
                if msg["type"] as? String == "action" {
                    let actionID = msg["actionID"] as? String
                    if actionID == "toggle-vpn" {
                        togglePending = true
                    } else if actionID == "open-vpn-app" {
                        openAppPending = true
                    }
                }
            }

            if togglePending {
                togglePending = false
                disconnectVPN(currentFullName)
                Thread.sleep(forTimeInterval: 2)
            }

            if openAppPending {
                openAppPending = false
                openVPNApp()
            }

            // Read settings
            var showOpenButton = true
            if let settingsPath = ProcessInfo.processInfo.environment[settingsPathEnvironmentKey],
               let data = try? Data(contentsOf: URL(fileURLWithPath: settingsPath)),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let values = obj["values"] as? [String: Any] {
                showOpenButton = values["showOpenButton"] as? Bool ?? true
            }

            let vpn = getVPNStatus()
            let sig = "\(vpn.connected)|\(vpn.provider ?? "")|\(vpn.protocol_ ?? "")"

            if vpn.connected {
                if sig != lastSig {
                    currentFullName = vpn.fullName ?? ""
                    if !published {
                        let payload = createPayload(showOpenButton: showOpenButton)
                        debugLog("sending create")
                        try? client.send(payload)
                        published = true
                    }
                    if let upd = updatePayload(vpn, showOpenButton: showOpenButton) {
                        debugLog("sending update: \(upd)")
                        try? client.send(upd)
                    }
                    lastSig = sig
                }
            } else if published {
                try? client.send(dismissPayload())
                published = false
                lastSig = ""
            }

            Thread.sleep(forTimeInterval: 5)
        }

        if published {
            try? client.send(dismissPayload())
        }
    }
}

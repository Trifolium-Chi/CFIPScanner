//
//  NetworkCore.swift
//  CFIPScanner
//
//  底层网络：TCP 连接计时、TLS 握手计时（自定义 SNI、忽略证书验证）、
//  下载 / 上传测速（通过 speed.cloudflare.com）
//  使用 POSIX socket + Security framework，与 Python 版行为一致
//

import Foundation
import Security
import Darwin

// MARK: - SSL 读写回调（C 函数）

private func sslReadFunc(_ connection: SSLConnectionRef,
                         _ data: UnsafeMutableRawPointer,
                         _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
    let fd = connection.load(as: Int32.self)
    let n = read(fd, data, dataLength.pointee)
    if n < 0 {
        dataLength.pointee = 0
        return OSStatus(errno)
    }
    dataLength.pointee = n
    return n == 0 ? OSStatus(errSSLClosedGraceful) : noErr
}

private func sslWriteFunc(_ connection: SSLConnectionRef,
                          _ data: UnsafeRawPointer,
                          _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
    let fd = connection.load(as: Int32.self)
    let n = write(fd, data, dataLength.pointee)
    if n < 0 {
        dataLength.pointee = 0
        return OSStatus(errno)
    }
    dataLength.pointee = n
    return noErr
}

// MARK: - TLS 连接封装（持有 fd 与 SSLContext，保证 fd 指针生命周期）

final class TLSSocket {
    let ctx: SSLContext
    let fd: Int32
    private let fdPtr: UnsafeMutablePointer<Int32>

    init?(fd: Int32, sni: String) {
        guard let ctx = SSLCreateContext(nil, .clientSide, .streamType) else { return nil }
        self.ctx = ctx
        self.fd = fd

        // 将 fd 放入堆内存，作为 SSLConnectionRef 传给 Security framework，
        // 避免局部变量指针失效
        let ptr = UnsafeMutablePointer<Int32>.allocate(capacity: 1)
        ptr.pointee = fd
        self.fdPtr = ptr

        guard SSLSetConnection(ctx, ptr) == noErr else {
            ptr.deallocate()
            return nil
        }
        SSLSetIOFuncs(ctx, sslReadFunc, sslWriteFunc)

        // 自定义 SNI
        _ = sni.withCString { cstr in
            SSLSetPeerDomainName(ctx, cstr, strlen(cstr))
        }

        // 忽略证书验证
        _ = SSLSetSessionOption(ctx, .breakOnServerAuth, true)
    }

    /// 执行握手，返回是否成功
    func handshake() -> Bool {
        // errSSLServerAuthCompleted = -9841（SecureTransport 常量，Swift 中未直接暴露为符号）
        let errServerAuthCompleted: OSStatus = -9841
        var status = SSLHandshake(ctx)
        // .breakOnServerAuth 会让握手在服务器证书认证阶段暂停并返回
        // errSSLServerAuthCompleted；此时继续握手即等效于跳过证书验证，
        // 与原版 Python 的 ssl.CERT_NONE 行为一致。
        if status == errServerAuthCompleted {
            status = SSLHandshake(ctx)
        }
        return status == noErr
    }

    /// 写入数据，返回是否全部写出
    func write(_ data: Data) -> Bool {
        var written = 0
        let status = data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> OSStatus in
            SSLWrite(ctx, raw.baseAddress!, data.count, &written)
        }
        return status == noErr && written > 0
    }

    /// 读入最多 maxLen 字节，返回实际读到的数据（空表示连接关闭/出错）
    func read(maxLen: Int) -> Data {
        var buf = [UInt8](repeating: 0, count: maxLen)
        var processed = 0
        let status = buf.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) -> OSStatus in
            SSLRead(ctx, raw.baseAddress!, maxLen, &processed)
        }
        if status != noErr && status != OSStatus(errSSLClosedGraceful) && status != OSStatus(errSSLClosedAbort) {
            return Data()
        }
        guard processed > 0 else { return Data() }
        return Data(buf[0..<processed])
    }

    func close() {
        _ = SSLClose(ctx)
        Darwin.close(fd)
    }

    deinit {
        fdPtr.deallocate()
    }
}

// MARK: - TCP 连接（返回 socket fd 与 TCP 延迟毫秒）

func tcpConnect(ip: String, port: Int, timeout: TimeInterval) -> (fd: Int32, ms: Double)? {
    let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    guard fd >= 0 else { return nil }

    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = in_port_t(port).bigEndian
    var inAddr = in_addr()
    _ = ip.withCString { cstr in
        inet_pton(AF_INET, cstr, &inAddr)
    }
    addr.sin_addr = inAddr

    // 设置收发超时
    let secs = Int(timeout)
    let usecs = Int((timeout - Double(secs)) * 1_000_000)
    var tv = timeval(tv_sec: secs, tv_usec: Int32(usecs))
    _ = withUnsafePointer(to: &tv) { p in
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, p, socklen_t(MemoryLayout<timeval>.size))
    }
    _ = withUnsafePointer(to: &tv) { p in
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, p, socklen_t(MemoryLayout<timeval>.size))
    }

    let t0 = DispatchTime.now().uptimeNanoseconds
    let ret = withUnsafePointer(to: &addr) { p in
        p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    let t1 = DispatchTime.now().uptimeNanoseconds
    let ms = Double(t1 - t0) / 1_000_000.0
    guard ret == 0 else {
        Darwin.close(fd)
        return nil
    }
    return (fd, ms)
}

// MARK: - 连通性测试

/// 返回 (tcpMs, tlsMs?)，tlsMs 在非严格模式下为 nil；失败返回 nil
func testOne(ip: String, port: Int, timeout: TimeInterval, strictTLS: Bool, sni: String) -> (tcp: Double, tls: Double?)? {
    guard let (fd, tcpMs) = tcpConnect(ip: ip, port: port, timeout: timeout) else { return nil }
    if !strictTLS {
        Darwin.close(fd)
        return (tcpMs, nil)
    }
    guard let tls = TLSSocket(fd: fd, sni: sni) else {
        Darwin.close(fd)
        return nil
    }
    let t0 = DispatchTime.now().uptimeNanoseconds
    let ok = tls.handshake()
    let t1 = DispatchTime.now().uptimeNanoseconds
    let tlsMs = Double(t1 - t0) / 1_000_000.0
    tls.close()
    return ok ? (tcpMs, tlsMs) : nil
}

// MARK: - 下载测速

/// 通过 ip:port 下载约 10MB，返回平均下载速度(Mbps)，失败返回 nil
func downloadSpeed(ip: String,
                   port: Int,
                   maxBytes: Int = 10_000_000,
                   timeout: TimeInterval = 15,
                   sni: String = "speed.cloudflare.com",
                   progress: ((Int, Double) -> Void)? = nil) -> Double? {
    guard let (fd, _) = tcpConnect(ip: ip, port: port, timeout: timeout) else { return nil }
    guard let tls = TLSSocket(fd: fd, sni: sni) else {
        Darwin.close(fd)
        return nil
    }
    defer { tls.close() }
    guard tls.handshake() else { return nil }

    let req = "GET /__down?bytes=\(maxBytes) HTTP/1.1\r\n" +
              "Host: speed.cloudflare.com\r\n" +
              "User-Agent: Mozilla/5.0\r\n" +
              "Accept: */*\r\n" +
              "Connection: close\r\n\r\n"
    guard let reqData = req.data(using: .utf8), tls.write(reqData) else { return nil }

    var total = 0
    var headerDone = false
    var headerBuf = Data()
    var t0 = DispatchTime.now().uptimeNanoseconds
    var lastCb = 0.0

    while true {
        let data = tls.read(maxLen: 65536)
        if data.isEmpty { break }

        if !headerDone {
            headerBuf.append(data)
            let marker = Data([0x0D, 0x0A, 0x0D, 0x0A])
            if let range = headerBuf.range(of: marker) {
                let body = headerBuf.subdata(in: range.upperBound..<headerBuf.count)
                headerBuf = Data()
                headerDone = true
                t0 = DispatchTime.now().uptimeNanoseconds
                total += body.count
            }
        } else {
            total += data.count
        }

        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - t0) / 1_000_000_000.0
        if let progress = progress, elapsed - lastCb >= 0.5 {
            lastCb = elapsed
            progress(total, elapsed)
        }
        if total >= maxBytes { break }
        if elapsed > 20 { break }
    }

    let elapsed = Double(DispatchTime.now().uptimeNanoseconds - t0) / 1_000_000_000.0
    if elapsed <= 0 || total <= 0 { return nil }
    let mbps = (Double(total) * 8.0 / 1000.0 / 1000.0) / elapsed
    return (mbps * 10).rounded() / 10
}

// MARK: - 上传测速

/// 通过 ip:port 向 Cloudflare 上传约 20MB，返回平均上传速度(Mbps)，失败返回 nil
func uploadSpeed(ip: String,
                 port: Int,
                 maxBytes: Int = 20_000_000,
                 timeout: TimeInterval = 15,
                 sni: String = "speed.cloudflare.com",
                 progress: ((Int, Double) -> Void)? = nil) -> Double? {
    guard let (fd, _) = tcpConnect(ip: ip, port: port, timeout: timeout) else { return nil }
    guard let tls = TLSSocket(fd: fd, sni: sni) else {
        Darwin.close(fd)
        return nil
    }
    defer { tls.close() }
    guard tls.handshake() else { return nil }

    let req = "POST /__up HTTP/1.1\r\n" +
              "Host: speed.cloudflare.com\r\n" +
              "Content-Type: application/octet-stream\r\n" +
              "Content-Length: \(maxBytes)\r\n" +
              "User-Agent: Mozilla/5.0\r\n" +
              "Connection: close\r\n\r\n"
    guard let reqData = req.data(using: .utf8), tls.write(reqData) else { return nil }

    let chunk = [UInt8](repeating: 48, count: 65536) // 字符 "0"
    var total = 0
    let t0 = DispatchTime.now().uptimeNanoseconds
    var lastCb = 0.0

    while total < maxBytes {
        let sent = chunk.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Int in
            var n = 0
            let status = SSLWrite(tls.ctx, raw.baseAddress!, chunk.count, &n)
            return status == noErr ? n : 0
        }
        if sent <= 0 { break }
        total += sent

        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - t0) / 1_000_000_000.0
        if let progress = progress, elapsed - lastCb >= 0.5 {
            lastCb = elapsed
            progress(total, elapsed)
        }
        if elapsed > 12 { break }
    }

    let elapsed = Double(DispatchTime.now().uptimeNanoseconds - t0) / 1_000_000_000.0
    if elapsed <= 0 || total <= 0 { return nil }
    let mbps = (Double(total) * 8.0 / 1000.0 / 1000.0) / elapsed
    return (mbps * 10).rounded() / 10
}

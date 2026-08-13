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

// SecureTransport 中未在 Swift 里暴露为符号的状态码（数值取自 Apple SecureTransport.h）
private let kErrSSLWouldBlock: OSStatus = -9803
private let kErrSSLServerAuthCompleted: OSStatus = -9841

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
    private let ioTimeoutMs: Int32

    init?(fd: Int32, sni: String, timeout: TimeInterval) {
        guard let ctx = SSLCreateContext(nil, .clientSide, .streamType) else { return nil }
        self.ctx = ctx
        self.fd = fd
        self.ioTimeoutMs = max(1000, Int32(timeout * 1000))

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

        // 忽略证书验证（等效于 Python 版 ssl.CERT_NONE）
        _ = SSLSetSessionOption(ctx, .breakOnServerAuth, true)
    }

    /// 等待 fd 可读/可写，超时或出错返回 false
    private func waitFd(events: Int16, timeoutMs: Int32) -> Bool {
        var pfd = pollfd(fd: fd, events: events, revents: 0)
        var remaining = timeoutMs
        while remaining > 0 {
            pfd.revents = 0
            let start = DispatchTime.now().uptimeNanoseconds
            let r = poll(&pfd, 1, remaining)
            if r > 0 { return true }
            if r == 0 { return false }                    // 超时
            if errno == EINTR {                            // 被信号打断，继续等
                let elapsed = Int32((DispatchTime.now().uptimeNanoseconds - start) / 1_000_000)
                remaining -= max(elapsed, 1)
                continue
            }
            return false
        }
        return false
    }

    /// 执行握手，返回是否成功
    func handshake() -> Bool {
        var status = SSLHandshake(ctx)
        // .breakOnServerAuth 会让握手在服务器证书认证阶段暂停并返回
        // errSSLServerAuthCompleted；此时继续握手即等效于跳过证书验证，
        // 与原版 Python 的 ssl.CERT_NONE 行为一致。
        // 底层 socket 短暂非阻塞或网络抖动时 SSLHandshake 会返回 errSSLWouldBlock，
        // 需等待 socket 就绪后重试，避免“一点击就立即失败”。
        while status == kErrSSLWouldBlock || status == kErrSSLServerAuthCompleted {
            if status == kErrSSLWouldBlock {
                guard waitFd(events: Int16(POLLIN | POLLOUT), timeoutMs: ioTimeoutMs) else { return false }
            }
            status = SSLHandshake(ctx)
        }
        return status == noErr
    }

    /// 写入数据，返回是否全部写出（自动处理部分写入与 WouldBlock）
    func write(_ data: Data) -> Bool {
        guard !data.isEmpty else { return true }
        var total = 0
        let count = data.count
        while total < count {
            var written = 0
            let status = data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> OSStatus in
                SSLWrite(ctx, raw.baseAddress! + total, count - total, &written)
            }
            if status == noErr {
                if written <= 0 { return false }
                total += written
                continue
            }
            if status == kErrSSLWouldBlock {
                guard waitFd(events: Int16(POLLOUT), timeoutMs: ioTimeoutMs) else { return false }
                continue
            }
            return false
        }
        return true
    }

    /// 读入最多 maxLen 字节，返回实际读到的数据（空表示连接关闭/出错）
    func read(maxLen: Int) -> Data {
        var buf = [UInt8](repeating: 0, count: maxLen)
        while true {
            var processed = 0
            let status = buf.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) -> OSStatus in
                SSLRead(ctx, raw.baseAddress!, maxLen, &processed)
            }
            if status == noErr {
                return processed > 0 ? Data(buf[0..<processed]) : Data()
            }
            if status == kErrSSLWouldBlock {
                guard waitFd(events: Int16(POLLIN), timeoutMs: ioTimeoutMs) else { return Data() }
                continue
            }
            // 连接关闭（errSSLClosedGraceful / errSSLClosedAbort 等）：若本次已读到数据则返回
            if processed > 0 { return Data(buf[0..<processed]) }
            return Data()
        }
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

    // 设置收发超时（对后续阻塞式 SSLRead/SSLWrite 生效）
    let secs = Int(timeout)
    let usecs = Int((timeout - Double(secs)) * 1_000_000)
    var tv = timeval(tv_sec: secs, tv_usec: Int32(usecs))
    _ = withUnsafePointer(to: &tv) { p in
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, p, socklen_t(MemoryLayout<timeval>.size))
    }
    _ = withUnsafePointer(to: &tv) { p in
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, p, socklen_t(MemoryLayout<timeval>.size))
    }

    // 非阻塞 connect：先设为非阻塞，connect 立即返回，再用 poll 等待，
    // 实现真正的「超时」控制。阻塞 connect 不受 SO_RCVTIMEO/SO_SNDTIMEO 影响，
    // 目标不可达（如关闭 VPN 后大量 IP 不通）会长时间卡住 worker 线程。
    let origFlags = fcntl(fd, F_GETFL, 0)
    _ = fcntl(fd, F_SETFL, origFlags | O_NONBLOCK)

    var connectErrno: Int32 = 0
    let t0 = DispatchTime.now().uptimeNanoseconds
    let ret = withUnsafePointer(to: &addr) { p -> Int32 in
        let r = p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
        connectErrno = errno
        return r
    }

    var connectOK = (ret == 0)
    if ret < 0 && connectErrno == EINPROGRESS {
        // 连接进行中：poll 等待可写，再读 SO_ERROR 判断最终结果
        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        let pr = poll(&pfd, 1, Int32(timeout * 1000))
        if pr > 0 {
            var sockErr: Int32 = 0
            var optLen = socklen_t(MemoryLayout<Int32>.size)
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockErr, &optLen)
            connectOK = (sockErr == 0)
        } else {
            connectOK = false
        }
    }
    let t1 = DispatchTime.now().uptimeNanoseconds
    let ms = Double(t1 - t0) / 1_000_000.0

    // 恢复阻塞模式，供后续 SSL 读写正常使用
    _ = fcntl(fd, F_SETFL, origFlags)

    guard connectOK else {
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
    guard let tls = TLSSocket(fd: fd, sni: sni, timeout: timeout) else {
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
    guard let tls = TLSSocket(fd: fd, sni: sni, timeout: timeout) else {
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
    guard let tls = TLSSocket(fd: fd, sni: sni, timeout: timeout) else {
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
    let chunkData = Data(chunk)
    var total = 0
    let t0 = DispatchTime.now().uptimeNanoseconds
    var lastCb = 0.0

    while total < maxBytes {
        if !tls.write(chunkData) { break }
        total += chunk.count

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

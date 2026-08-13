//
//  Scanner.swift
//  CFIPScanner
//
//  扫描状态管理与异步扫描引擎
//  对应 Python 版 Scanner 类 + start_speed_job
//
//  线程模型：后台并发 worker 执行 testOne，结果先写入线程安全的 pending 缓冲，
//  主线程定时器每 0.2 秒合并到 @Published 属性，保证 UI 更新都在主线程。
//

import Foundation

final class Scanner: ObservableObject {
    // 导入数据
    @Published private(set) var items: [IpItem] = []
    @Published private(set) var filename = ""
    // 扫描状态
    @Published private(set) var running = false
    @Published private(set) var results: [ScanResult] = []
    @Published private(set) var total = 0
    @Published private(set) var done = 0
    @Published private(set) var statusText = "就绪"
    @Published var isp = "" {
        didSet { refreshOutputText() }
    }

    // 显示过滤（勾选 = 显示）
    @Published var hiddenRegions: Set<String> = []
    @Published var hiddenPorts: Set<String> = []
    // 排序：null | ip | tcp | tls（默认 tcp 升序）
    @Published var sortKey: String = "tcp"
    @Published var sortDir: Int = 1

    // 输出文本（自动生成）
    @Published var outputText = ""

    // 测速任务
    @Published var speedJobs: [String: SpeedJob] = [:]
    private var speedJobCounter = 0

    // 扫描内部状态
    private let lock = NSLock()
    private var cancelFlag = false
    private var pendingResults: [ScanResult] = []
    private var pendingDone = 0
    private var mergeTimer: Timer?

    var countImported: Int { items.count }

    // MARK: - 导入

    func importContent(_ text: String, filename: String) {
        items = parseText(text)
        self.filename = filename
        results = []
        total = 0
        done = 0
        statusText = "已导入 \(items.count) 条 IP（去重后）"
        cancelFlag = false
    }

    // MARK: - 地区统计（扫描设置用）

    func regionOptions() -> [RegionOption] {
        var counts: [String: Int] = [:]
        var order: [String] = []
        for item in items {
            let key = item.cc
            if counts[key] == nil {
                counts[key] = 0
                order.append(key)
            }
            counts[key]! += 1
        }
        let opts = order.map { key -> RegionOption in
            RegionOption(cc: key,
                         region: key.isEmpty ? "未知地区" : regionName(key),
                         count: counts[key] ?? 0)
        }
        return sortRegionOpts(opts)
    }

    // MARK: - 扫描

    func startScan(count: String,
                   ports: String,
                   regions: [String],
                   threads: Int,
                   timeout: Double,
                   sni: String,
                   strict: Bool) -> String? {
        if running { return "正在扫描中" }
        if items.isEmpty { return "请先导入 IP 文件" }

        // 端口筛选
        var portSet: Set<Int>? = nil
        let portsTrimmed = ports.trimmingCharacters(in: .whitespacesAndNewlines)
        if !portsTrimmed.isEmpty {
            var s = Set<Int>()
            let tokens = portsTrimmed.components(separatedBy: CharacterSet(charactersIn: ",，;；\t "))
            for token in tokens {
                if token.isEmpty { continue }
                guard let p = Int(token) else { return "端口格式不正确：\(token)" }
                if p > 0 && p <= 65535 { s.insert(p) }
            }
            portSet = s
        }

        var filtered = items
        if let portSet = portSet {
            filtered = filtered.filter { portSet.contains($0.port) }
        }

        // 地区筛选（空 = 不限）
        let regionSet = Set(regions)
        if !regionSet.isEmpty {
            filtered = filtered.filter { regionSet.contains($0.cc) }
        }

        // 数量
        let numRaw = count.trimmingCharacters(in: .whitespacesAndNewlines)
        if !numRaw.isEmpty {
            guard let n = Int(numRaw), n > 0 else { return "扫描数量需为正整数" }
            filtered = Array(filtered.prefix(n))
        }

        if filtered.isEmpty { return "没有符合筛选条件的 IP" }

        let workerCount = max(1, threads)
        let timeoutVal = max(0.5, timeout)
        let sniVal = sni.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? "speed.cloudflare.com" : sni

        // 初始化状态
        cancelFlag = false
        running = true
        results = []
        total = filtered.count
        done = 0
        statusText = "正在扫描 0/\(filtered.count)"
        lock.lock()
        pendingResults = []
        pendingDone = 0
        lock.unlock()

        // 主线程定时器合并 pending
        let timer = Timer(timeInterval: 0.2, repeats: true) { [weak self] _ in
            self?.mergePending()
        }
        RunLoop.main.add(timer, forMode: .common)
        mergeTimer = timer

        // 并发 worker
        let queue = DispatchQueue(label: "cfipscan.workers", qos: .userInitiated,
                                  attributes: .concurrent)
        let group = DispatchGroup()
        let idxQueue = DispatchQueue(label: "cfipscan.idx")
        let itemsCopy = filtered
        let itemCount = itemsCopy.count
        let shared = UnsafeMutablePointer<Int>.allocate(capacity: 1)
        shared.initialize(to: 0)

        for _ in 0..<min(workerCount, itemCount) {
            group.enter()
            queue.async { [weak self] in
                defer { group.leave() }
                guard let self = self else { return }
                while true {
                    var idx = -1
                    idxQueue.sync {
                        idx = shared.pointee
                        shared.pointee += 1
                    }
                    if idx >= itemCount { break }
                    // 检查停止标志
                    var stopped = false
                    self.lock.lock(); stopped = self.cancelFlag; self.lock.unlock()
                    if stopped { break }

                    let item = itemsCopy[idx]
                    if let r = testOne(ip: item.ip, port: item.port,
                                       timeout: timeoutVal, strictTLS: strict, sni: sniVal) {
                        let res = ScanResult(ip: item.ip, port: item.port,
                                             cc: item.cc, region: regionName(item.cc),
                                             tcp: (r.tcp * 10).rounded() / 10,
                                             tls: r.tls.map { ($0 * 10).rounded() / 10 })
                        self.lock.lock()
                        self.pendingResults.append(res)
                        self.pendingDone += 1
                        self.lock.unlock()
                    } else {
                        self.lock.lock()
                        self.pendingDone += 1
                        self.lock.unlock()
                    }
                }
            }
        }

        group.notify(queue: .main) { [weak self] in
            guard let self = self else { return }
            shared.deinitialize(count: 1)
            shared.deallocate()
            self.finishScan()
        }

        refreshOutputText()
        return nil
    }

    func stopScan() {
        lock.lock(); cancelFlag = true; lock.unlock()
        running = false
        refreshOutputText()
    }

    private func mergePending() {
        var newResults: [ScanResult] = []
        var deltaDone = 0
        lock.lock()
        newResults = pendingResults
        pendingResults = []
        deltaDone = pendingDone
        pendingDone = 0
        lock.unlock()
        if deltaDone > 0 { done += deltaDone }
        if !newResults.isEmpty { results.append(contentsOf: newResults) }
        statusText = "正在扫描 \(done)/\(total)"
        refreshOutputText()
    }

    private func finishScan() {
        mergePending()
        mergeTimer?.invalidate()
        mergeTimer = nil
        running = false
        statusText = "扫描完成，共找到 \(results.count) 个可用 IP"
        refreshOutputText()
    }

    // MARK: - 测速

    func startSpeedJob(ip: String, port: Int) -> String {
        speedJobCounter += 1
        let jobId = "sp\(speedJobCounter)"
        let job = SpeedJob(id: jobId, ip: ip, port: port)
        DispatchQueue.main.async { [weak self] in
            self?.speedJobs[jobId] = job
        }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let dl = downloadSpeed(ip: ip, port: port) { total, elapsed in
                let speed = elapsed > 0 ? (Double(total) * 8.0 / 1000.0 / 1000.0) / elapsed : 0.0
                let rounded = (speed * 10).rounded() / 10
                DispatchQueue.main.async { self?.speedJobs[jobId]?.dlSpeed = rounded }
            }
            DispatchQueue.main.async {
                self?.speedJobs[jobId]?.resultDl = dl
                if let dl = dl { self?.speedJobs[jobId]?.dlSpeed = dl }
            }

            let ul = uploadSpeed(ip: ip, port: port) { total, elapsed in
                let speed = elapsed > 0 ? (Double(total) * 8.0 / 1000.0 / 1000.0) / elapsed : 0.0
                let rounded = (speed * 10).rounded() / 10
                DispatchQueue.main.async { self?.speedJobs[jobId]?.ulSpeed = rounded }
            }
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.speedJobs[jobId]?.resultUl = ul
                if let ul = ul { self.speedJobs[jobId]?.ulSpeed = ul }
                self.speedJobs[jobId]?.done = true
            }
        }
        return jobId
    }

    // MARK: - 展示数据（过滤 + 排序）

    func displayResults() -> [ScanResult] {
        var arr = results.filter { r in
            !hiddenRegions.contains(r.cc) && !hiddenPorts.contains(String(r.port))
        }
        switch sortKey {
        case "ip":
            arr.sort { a, b in
                let pa = ipParts(a.ip), pb = ipParts(b.ip)
                for i in 0..<4 where pa[i] != pb[i] {
                    return sortDir > 0 ? pa[i] < pb[i] : pa[i] > pb[i]
                }
                return false
            }
        case "tcp":
            arr.sort { sortDir > 0 ? $0.tcp < $1.tcp : $0.tcp > $1.tcp }
        case "tls":
            arr.sort { a, b in
                if a.tls == nil && b.tls == nil { return false }
                if a.tls == nil { return false }   // null 排最后
                if b.tls == nil { return true }
                return sortDir > 0 ? a.tls! < b.tls! : a.tls! > b.tls!
            }
        default:
            break
        }
        return arr
    }

    private func ipParts(_ ip: String) -> [Int] {
        return ip.split(separator: ".").map { Int($0) ?? 0 }
    }

    // MARK: - 结果地区选项

    func resultRegionOptions() -> [RegionOption] {
        var seen: [String: Int] = [:]
        for r in results {
            seen[r.cc, default: 0] += 1
        }
        let opts = seen.map { (key, count) -> RegionOption in
            RegionOption(cc: key,
                         region: key.isEmpty ? "未知地区" : regionName(key),
                         count: count)
        }
        return sortRegionOpts(opts)
    }

    // MARK: - 结果端口选项（升序）

    func resultPortOptions() -> [String] {
        let ports = Set(results.map { String($0.port) })
        return ports.sorted { (Int($0) ?? 0) < (Int($1) ?? 0) }
    }

    // MARK: - 输出文本

    func refreshOutputText() {
        let arr = displayResults()
        let lines = arr.map { exportLine($0, isp: isp) }
        outputText = lines.joined(separator: "\n")
    }
}

// MARK: - 测速任务模型

struct SpeedJob: Identifiable {
    let id: String
    let ip: String
    let port: Int
    var dlSpeed: Double = 0
    var ulSpeed: Double = 0
    var resultDl: Double?
    var resultUl: Double?
    var done = false
}

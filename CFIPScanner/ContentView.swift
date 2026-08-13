//
//  ContentView.swift
//  CFIPScanner
//
//  主界面：导入 -> 扫描设置 -> 结果列表 -> 输出文本
//

import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject var scanner: Scanner

    // 扫描设置
    @State private var count = ""
    @State private var ports = ""
    @State private var threads = "200"
    @State private var timeout = "3"
    @State private var sni = "speed.cloudflare.com"
    @State private var strict = true

    // 扫描地区选择（cc 列表，空 = 全部）
    @State private var scanRegions: [String] = []
    @State private var showRegionPicker = false

    // 结果地区 / 端口过滤
    @State private var showResultRegionPicker = false
    @State private var showResultPortPicker = false

    // 文件导入
    @State private var showFileImporter = false
    @State private var alertMessage: AlertMessage?

    // 导出
    @State private var showShareSheet = false
    @State private var exportURL: URL?

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    importCard
                    settingsCard
                    resultsCard
                    outputCard
                }
                .padding()
            }
            .navigationBarTitle("优选 IP 筛选工具", displayMode: .inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        export()
                    } label: {
                        Image(systemName: "square.and.arrow.up")
                    }
                    .disabled(scanner.displayResults().isEmpty)
                }
            }
        }
        .navigationViewStyle(StackNavigationViewStyle())
        .onAppear {
            detectISP { isp in
                DispatchQueue.main.async {
                    if scanner.isp.isEmpty && !isp.isEmpty {
                        scanner.isp = isp
                    }
                }
            }
        }
        .fileImporter(isPresented: $showFileImporter,
                      allowedContentTypes: [.plainText],
                      allowsMultipleSelection: false) { result in
            handleImport(result)
        }
        .alert(item: $alertMessage) { msg in
            Alert(title: Text("提示"), message: Text(msg.message),
                  dismissButton: .default(Text("好")))
        }
        .sheet(isPresented: $showShareSheet) {
            if let url = exportURL {
                ShareSheet(items: [url])
            }
        }
        .sheet(isPresented: $showRegionPicker) {
            let options = scanner.regionOptions()
            MultiSelectSheet(
                title: "只扫描指定地区",
                options: options,
                selected: $scanRegions,
                valueKey: { $0.cc },
                label: { $0.cc.isEmpty ? "未知地区(\($0.count))" : "\($0.region)(\($0.cc))(\($0.count))" }
            )
        }
        .sheet(isPresented: $showResultRegionPicker) {
            let options = scanner.resultRegionOptions()
            MultiSelectSheet(
                title: "地区筛选（勾选 = 显示）",
                options: options,
                selected: Binding(
                    get: { options.map(\.cc).filter { !scanner.hiddenRegions.contains($0) } },
                    set: { visible in
                        scanner.hiddenRegions = Set(options.map(\.cc)).subtracting(visible)
                        scanner.refreshOutputText()
                    }
                ),
                valueKey: { $0.cc },
                label: { $0.cc.isEmpty ? "未知地区(\($0.count))" : "\($0.region)(\($0.cc))(\($0.count))" }
            )
        }
        .sheet(isPresented: $showResultPortPicker) {
            let options = scanner.resultPortOptions()
            MultiSelectSheet(
                title: "端口筛选（勾选 = 显示）",
                options: options,
                selected: Binding(
                    get: { options.filter { !scanner.hiddenPorts.contains($0) } },
                    set: { visible in
                        scanner.hiddenPorts = Set(options).subtracting(visible)
                        scanner.refreshOutputText()
                    }
                ),
                valueKey: { $0 },
                label: { $0 }
            )
        }
    }

    // MARK: - 导入

    private var importCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("1. 导入 IP 文件").font(.headline)
            HStack {
                Button("选择文件") { showFileImporter = true }
                Text(scanner.filename.isEmpty
                     ? "尚未导入文件"
                     : "已导入 \(scanner.countImported) 条 IP（去重后）")
                    .font(.footnote)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    // MARK: - 扫描设置

    private var settingsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("2. 扫描设置").font(.headline)

            HStack(spacing: 12) {
                field("扫描数量", text: $count, placeholder: "留空=全部", keyboard: .numberPad)
                field("端口筛选", text: $ports, placeholder: "443,2053,8443", keyboard: .numbersAndPunctuation)
            }
            HStack(spacing: 12) {
                field("线程数", text: $threads, placeholder: "200", keyboard: .numberPad)
                field("超时(秒)", text: $timeout, placeholder: "3", keyboard: .decimalPad)
            }
            HStack(spacing: 12) {
                field("SNI域名", text: $sni, placeholder: "speed.cloudflare.com", keyboard: .default)
                field("运营商", text: $scanner.isp, placeholder: "自动检测", keyboard: .default)
            }

            Toggle("严格模式(TLS握手)", isOn: $strict)

            VStack(alignment: .leading, spacing: 4) {
                Text("只扫描指定地区：").font(.subheadline)
                Button(scanRegions.isEmpty ? "全部地区 ▾" : "已选 \(scanRegions.count) 个地区 ▾") {
                    showRegionPicker = true
                }
                .font(.footnote)
                Text("不勾选任何地区 = 扫描全部地区")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            HStack {
                Button(scanner.running ? "扫描中…" : "开始扫描") {
                    startScan()
                }
                .buttonStyle(BorderlessButtonStyle())
                .disabled(scanner.running)

                Button("停止") { scanner.stopScan() }
                    .buttonStyle(BorderlessButtonStyle())
                    .disabled(!scanner.running)
            }

            ProgressView(value: scanner.total > 0
                         ? Double(scanner.done) / Double(scanner.total)
                         : 0)
            Text(scanner.statusText)
                .font(.footnote)
                .foregroundColor(.secondary)
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    private func field(_ title: String,
                       text: Binding<String>,
                       placeholder: String,
                       keyboard: UIKeyboardType) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption)
            TextField(placeholder, text: text)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .keyboardType(keyboard)
                .autocapitalization(.none)
                .disableAutocorrection(true)
        }
    }

    // MARK: - 结果列表

    private var resultsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("3. 可用 IP（仅显示可连接的 IP）").font(.headline)

            HStack {
                Button("地区筛选") { showResultRegionPicker = true }
                Button("端口筛选") { showResultPortPicker = true }
                Spacer()
            }
            .font(.caption)

            if scanner.displayResults().isEmpty {
                Text("暂无数据")
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 120)
            } else {
                ScrollView(.horizontal) {
                    VStack(spacing: 0) {
                        headerRow
                        ForEach(Array(scanner.displayResults().enumerated()), id: \.element.id) { idx, r in
                            resultRow(idx: idx, r: r)
                        }
                    }
                }
            }
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    private var headerRow: some View {
        HStack(spacing: 8) {
            cellText("#", width: 30)
            cellText("IP 地址", width: 105)
            cellText("端口", width: 50)
            cellText("地区", width: 95)
            sortableHeader("TCP(ms)", key: "tcp", width: 76)
            sortableHeader("TLS(ms)", key: "tls", width: 76)
            cellText("测速", width: 200)
        }
        .font(.caption.bold())
        .padding(.vertical, 6)
        .background(Color(.systemGray5))
    }

    private func sortableHeader(_ title: String, key: String, width: CGFloat) -> some View {
        Button {
            if scanner.sortKey == key {
                scanner.sortDir = -scanner.sortDir
            } else {
                scanner.sortKey = key
                scanner.sortDir = 1
            }
            scanner.refreshOutputText()
        } label: {
            HStack(spacing: 2) {
                Text(title)
                if scanner.sortKey == key {
                    Text(scanner.sortDir > 0 ? "▲" : "▼").font(.caption2)
                }
            }
            .frame(width: width, alignment: .leading)
        }
        .buttonStyle(PlainButtonStyle())
    }

    private func resultRow(idx: Int, r: ScanResult) -> some View {
        HStack(spacing: 8) {
            cellText("\(idx + 1)", width: 30)
            cellText(r.ip, width: 105)
            cellText("\(r.port)", width: 50)
            cellText(r.cc.isEmpty ? "-" : "\(r.cc)\(r.region)", width: 95)
            cellText(String(format: "%.1f", r.tcp), width: 76)
            cellText(r.tls.map { String(format: "%.1f", $0) } ?? "-", width: 76)
            SpeedCell(r: r)
        }
        .font(.caption)
        .padding(.vertical, 4)
    }

    private func cellText(_ text: String, width: CGFloat) -> some View {
        Text(text)
            .lineLimit(1)
            .frame(width: width, alignment: .leading)
    }

    // MARK: - 输出

    private var outputCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("4. 输出文本（可复制）").font(.headline)
            TextEditor(text: .constant(scanner.outputText))
                .font(.system(.caption, design: .monospaced))
                .frame(minHeight: 140)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color(.systemGray4)))
            Button("复制") {
                UIPasteboard.general.string = scanner.outputText
            }
            .disabled(scanner.outputText.isEmpty)
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    // MARK: - Actions

    private func handleImport(_ result: Result<[URL], Error>) {
        do {
            let urls = try result.get()
            guard let url = urls.first else { return }
            let access = url.startAccessingSecurityScopedResource()
            defer { if access { url.stopAccessingSecurityScopedResource() } }
            let text = try String(contentsOf: url, encoding: .utf8)
            scanner.importContent(text, filename: url.lastPathComponent)
        } catch {
            alertMessage = AlertMessage(message: "读取文件失败：\(error.localizedDescription)")
        }
    }

    private func startScan() {
        let threadsVal = Int(threads) ?? 200
        let timeoutVal = Double(timeout) ?? 3.0
        if let err = scanner.startScan(count: count, ports: ports, regions: scanRegions,
                                       threads: threadsVal, timeout: timeoutVal,
                                       sni: sni, strict: strict) {
            alertMessage = AlertMessage(message: err)
        }
    }

    private func export() {
        let arr = scanner.displayResults()
        guard !arr.isEmpty else { return }
        let lines = arr.map { exportLine($0, isp: scanner.isp) }
        let text = lines.joined(separator: "\r\n") + "\r\n"
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("可用IP.txt")
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            exportURL = url
            showShareSheet = true
        } catch {
            alertMessage = AlertMessage(message: "导出失败：\(error.localizedDescription)")
        }
    }
}

// MARK: - 测速单元格

struct SpeedCell: View {
    @EnvironmentObject var scanner: Scanner
    let r: ScanResult
    @State private var jobId: String?

    private var job: SpeedJob? {
        jobId.flatMap { scanner.speedJobs[$0] }
    }

    var body: some View {
        HStack(spacing: 6) {
            Text(dlText)
                .foregroundColor(.blue)
                .frame(minWidth: 80, alignment: .trailing)
            Button(job == nil ? "测速" : (job!.done ? "重测" : "测速中")) {
                start()
            }
            .font(.caption2)
            .disabled(job != nil && !job!.done)
            Text(ulText)
                .foregroundColor(.orange)
                .frame(minWidth: 80, alignment: .leading)
        }
        .font(.caption)
        .frame(width: 200, alignment: .center)
    }

    private var dlText: String {
        guard let job = job else { return "" }
        if job.done {
            if let d = job.resultDl { return "↓ \(d) Mbps" }
            return "↓ 失败"
        }
        return "↓ \(job.dlSpeed) Mbps"
    }

    private var ulText: String {
        guard let job = job else { return "" }
        if job.done {
            if let u = job.resultUl { return "↑ \(u) Mbps" }
            return "↑ 失败"
        }
        return "↑ \(job.ulSpeed) Mbps"
    }

    private func start() {
        jobId = scanner.startSpeedJob(ip: r.ip, port: r.port)
    }
}

// MARK: - 通用多选弹窗

struct MultiSelectSheet<T: Hashable, ID: Hashable>: View {
    let title: String
    let options: [T]
    @Binding var selected: [ID]
    let valueKey: (T) -> ID
    let label: (T) -> String

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            List {
                ForEach(options, id: \.self) { option in
                    Button {
                        toggle(option)
                    } label: {
                        HStack {
                            Text(label(option))
                            Spacer()
                            if selected.contains(valueKey(option)) {
                                Image(systemName: "checkmark")
                                    .foregroundColor(.accentColor)
                            }
                        }
                    }
                    .foregroundColor(.primary)
                }
            }
            .navigationBarTitle(title, displayMode: .inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("清空") { selected = [] }
                }
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("全选") { selected = options.map(valueKey) }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("完成") { dismiss() }
                }
            }
        }
    }

    private func toggle(_ option: T) {
        let v = valueKey(option)
        if selected.contains(v) {
            selected.removeAll { $0 == v }
        } else {
            selected.append(v)
        }
    }
}

// MARK: - 分享面板

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

// MARK: - 告警消息

struct AlertMessage: Identifiable {
    let id = UUID()
    let message: String
}

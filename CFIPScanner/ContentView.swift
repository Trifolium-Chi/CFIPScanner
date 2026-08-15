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
    @State private var showPasteSheet = false
    @State private var showFolderSheet = false
    @State private var alertMessage: AlertMessage?

    // 输出文本（可编辑）
    @State private var outputEditableText = ""

    // 键盘避让
    @State private var keyboardHeight: CGFloat = 0
    @State private var keyboardObservers: [NSObjectProtocol] = []

    // 输出文本编辑焦点（仅在该文本框聚焦且键盘弹出时，才自动滚动到输出框）
    @FocusState private var isEditingOutput: Bool

    // 导出（系统分享面板：可存储到文件 / 分享到其他 App）
    @State private var showShareSheet = false
    @State private var exportURL: URL?

    // 关于工具翻页（无手势滑动，仅按钮切换）
    @State private var showAbout = false

    var body: some View {
        ZStack {
            if showAbout {
                AboutView(onBack: { showAbout = false })
                    .transition(.move(edge: .trailing))
            } else {
                toolPage
                    .transition(.move(edge: .leading))
            }
        }
        .animation(.easeInOut(duration: 0.25), value: showAbout)
        .onAppear {
            detectISP { isp in
                DispatchQueue.main.async {
                    if scanner.isp.isEmpty && !isp.isEmpty {
                        scanner.isp = isp
                    }
                }
            }
            addKeyboardObservers()
        }
        .onDisappear {
            removeKeyboardObservers()
        }
        .fileImporter(isPresented: $showFileImporter,
                      allowedContentTypes: [.item],
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
        .sheet(isPresented: $showPasteSheet) {
            PasteImportSheet { text in
                scanner.importContent(text, filename: "手动粘贴")
            }
        }
        .sheet(isPresented: $showFolderSheet) {
            FolderImportSheet { url in
                importFromFolder(url)
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

    private var toolPage: some View {
        NavigationView {
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        importCard
                        settingsCard
                        resultsCard
                        outputCard
                    }
                    .padding()
                }
                .onChange(of: keyboardHeight) { h in
                    if h > 0 && isEditingOutput {
                        scrollToOutputButtons(proxy)
                    }
                }
                .onChange(of: isEditingOutput) { editing in
                    if editing && keyboardHeight > 0 {
                        scrollToOutputButtons(proxy)
                    }
                }
            }
            .navigationBarTitle("优选 IP 筛选工具", displayMode: .inline)
        }
        .navigationViewStyle(StackNavigationViewStyle())
    }

    // MARK: - 导入

    private var importCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("1. 导入 IP 文件").font(.headline)
            HStack(spacing: 8) {
                Button("选择文件") { showFileImporter = true }
                    .buttonStyle(FilledButtonStyle(color: .cfBlue))
                Button("App文件夹导入") { showFolderSheet = true }
                    .buttonStyle(FilledButtonStyle(color: .cfGreen))
                Button("粘贴导入") { showPasteSheet = true }
                    .buttonStyle(FilledButtonStyle(color: .cfOrange))
            }
            Text(scanner.filename.isEmpty
                 ? "尚未导入文件"
                 : "已导入 \(scanner.countImported) 条 IP（去重后）")
                .font(.footnote)
                .foregroundColor(.secondary)
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
                .buttonStyle(FilledButtonStyle(color: .cfOrange, vertical: 5, horizontal: 12))
                Text("不勾选任何地区 = 扫描全部地区")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            HStack {
                Button(scanner.running ? "扫描中…" : "开始扫描") {
                    startScan()
                }
                .buttonStyle(FilledButtonStyle(color: .cfBlue))
                .disabled(scanner.running)

                Button("停止") { scanner.stopScan() }
                    .buttonStyle(FilledButtonStyle(color: .cfRed))
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
                    .buttonStyle(FilledButtonStyle(color: .cfOrange, vertical: 5, horizontal: 12))
                Button("端口筛选") { showResultPortPicker = true }
                    .buttonStyle(FilledButtonStyle(color: .cfOrange, vertical: 5, horizontal: 12))
                Spacer()
            }

            if scanner.displayResults().isEmpty {
                Text("暂无数据")
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 120)
            } else {
                ScrollView(.horizontal, showsIndicators: true) {
                    VStack(alignment: .leading, spacing: 0) {
                        headerRow
                        ScrollView(.vertical, showsIndicators: true) {
                            LazyVStack(alignment: .leading, spacing: 0) {
                                ForEach(Array(scanner.displayResults().enumerated()), id: \.element.id) { idx, r in
                                    resultRow(idx: idx, r: r)
                                        .frame(height: 26)
                                }
                            }
                            .fixedSize(horizontal: true, vertical: false)
                        }
                        .frame(height: 260)
                    }
                    .fixedSize(horizontal: true, vertical: false)
                }
            }
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    private var headerRow: some View {
        HStack(spacing: 8) {
            cellText("#", width: 36)
            sortableHeader("IP 地址", key: "ip", width: 120)
            cellText("端口", width: 64)
            cellText("地区", width: 110)
            sortableHeader("TCP延迟(ms)", key: "tcp", width: 92)
            sortableHeader("TLS延迟(ms)", key: "tls", width: 92)
            cellText("测速", width: 260)
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
            cellText("\(idx + 1)", width: 36)
            cellText(r.ip, width: 120)
            cellText("\(r.port)", width: 64)
            cellText(r.cc.isEmpty ? "-" : "\(r.cc)\(r.region)", width: 110)
            cellText(String(format: "%.1f", r.tcp), width: 92)
            cellText(r.tls.map { String(format: "%.1f", $0) } ?? "-", width: 92)
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
            Text("4. 输出文本（可编辑 / 可复制）").font(.headline)
            TextEditor(text: $outputEditableText)
                .font(.system(size: 11, design: .monospaced))
                .autocapitalization(.none)
                .disableAutocorrection(true)
                .focused($isEditingOutput)
                .frame(height: 140)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.systemBackground))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color(.systemGray4)))
                .onAppear { syncOutputText() }
                .onChange(of: scanner.outputText) { _ in syncOutputText() }

            HStack {
                Button("复制") {
                    UIPasteboard.general.string = outputEditableText
                    alertMessage = AlertMessage(message: "已复制至粘贴板")
                }
                .buttonStyle(FilledButtonStyle(color: .cfBlue))
                .disabled(outputEditableText.isEmpty)

                Button("导出可用IP") { export() }
                    .buttonStyle(FilledButtonStyle(color: .cfGreen))
                    .disabled(scanner.displayResults().isEmpty)

                Button("关于工具") { showAbout = true }
                    .buttonStyle(FilledButtonStyle(color: .cfGray))
            }
            .id("outputButtons")
        }
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(10)
    }

    private func syncOutputText() {
        if !scanner.outputText.isEmpty && outputEditableText != scanner.outputText {
            outputEditableText = scanner.outputText
        }
    }

    // MARK: - Actions

    private func handleImport(_ result: Result<[URL], Error>) {
        do {
            let urls = try result.get()
            guard let url = urls.first else { return }
            let access = url.startAccessingSecurityScopedResource()
            defer { if access { url.stopAccessingSecurityScopedResource() } }

            let data = try Data(contentsOf: url)
            guard !data.isEmpty else {
                throw NSError(domain: "import", code: 2,
                              userInfo: [NSLocalizedDescriptionKey: "文件为空，无法导入"])
            }
            // 先按 utf-8，失败再按 gbk 解析，兼容 Windows 记事本/微信等常见编码
            let text: String
            if let t = String(data: data, encoding: .utf8) {
                text = t
            } else {
                let gbk = CFStringConvertEncodingToNSStringEncoding(
                    CFStringEncoding(CFStringEncodings.GB_18030_2000.rawValue))
                if let t = String(data: data, encoding: String.Encoding(rawValue: gbk)) {
                    text = t
                } else {
                    throw NSError(domain: "import", code: 1,
                                  userInfo: [NSLocalizedDescriptionKey: "文件编码无法识别（仅支持 UTF-8 / GBK）"])
                }
            }
            scanner.importContent(text, filename: url.lastPathComponent)
        } catch {
            alertMessage = AlertMessage(message: "读取文件失败：\(error.localizedDescription)")
        }
    }

    private func importFromFolder(_ url: URL) {
        do {
            let data = try Data(contentsOf: url)
            guard let text = decodeImportText(data) else {
                alertMessage = AlertMessage(message: "文件编码无法识别（仅支持 UTF-8 / GBK）")
                return
            }
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

    private func scrollToOutputButtons(_ proxy: ScrollViewProxy) {
        // 延后一帧，等键盘弹出/焦点切换引发的布局完成后，再滚动到按钮行
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            withAnimation {
                proxy.scrollTo("outputButtons", anchor: .bottom)
            }
        }
    }

    // MARK: - 键盘避让（点击输出框时自动上移，保证复制/导出按钮可见）

    private func addKeyboardObservers() {
        let show = NotificationCenter.default.addObserver(
            forName: UIResponder.keyboardWillShowNotification,
            object: nil, queue: .main) { note in
                guard let frame = note.userInfo?[UIResponder.keyboardFrameEndUserInfoKey] as? CGRect else { return }
                keyboardHeight = frame.height
            }
        let hide = NotificationCenter.default.addObserver(
            forName: UIResponder.keyboardWillHideNotification,
            object: nil, queue: .main) { _ in
                keyboardHeight = 0
            }
        keyboardObservers = [show, hide]
    }

    private func removeKeyboardObservers() {
        keyboardObservers.forEach { NotificationCenter.default.removeObserver($0) }
        keyboardObservers = []
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
        HStack(spacing: 4) {
            Text(dlText)
                .foregroundColor(.blue)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
                .frame(minWidth: 84, alignment: .trailing)
            Button(job == nil ? "测速" : (job!.done ? "重测" : "测速中")) {
                start()
            }
            .font(.caption)
            .lineLimit(1)
            .fixedSize()
            .buttonStyle(FilledButtonStyle(color: .cfGray, vertical: 4, horizontal: 8))
            .disabled(job != nil && !job!.done)
            Text(ulText)
                .foregroundColor(.orange)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
                .frame(minWidth: 84, alignment: .leading)
        }
        .font(.caption)
        .frame(width: 260, alignment: .center)
    }

    private var dlText: String {
        guard let job = job else { return "" }
        if job.done {
            if let d = job.resultDl { return "↓ \(fmtSpeed(d))" }
            return "↓ 失败"
        }
        return "↓ \(fmtSpeed(job.dlSpeed))"
    }

    private var ulText: String {
        guard let job = job else { return "" }
        if job.done {
            if let u = job.resultUl { return "↑ \(fmtSpeed(u))" }
            return "↑ 失败"
        }
        return "↑ \(fmtSpeed(job.ulSpeed))"
    }

    /// 速度显示：小于 1MB/s 时用 KB/s 展示，避免“0.0 MB/s”掩盖真实的低速
    private func fmtSpeed(_ mb: Double) -> String {
        if mb <= 0 { return "0.0 KB/s" }
        if mb < 1.0 { return String(format: "%.0f", mb * 1000) + " KB/s" }
        return String(format: "%.1f", mb) + " MB/s"
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

// MARK: - 配色与按钮样式（对齐原版 Web 界面）

extension Color {
    static let cfBlue = Color(red: 0.25, green: 0.62, blue: 1.0)      // #409eff
    static let cfRed = Color(red: 0.96, green: 0.42, blue: 0.42)       // #f56c6c
    static let cfGreen = Color(red: 0.40, green: 0.76, blue: 0.23)     // #67c23a
    static let cfOrange = Color(red: 0.90, green: 0.63, blue: 0.24)    // #e6a23c
    static let cfGray = Color(red: 0.56, green: 0.58, blue: 0.60)      // #909399
}

// MARK: - 文本解码（UTF-8 / GBK，供文件导入与文件夹导入共用）

private func decodeImportText(_ data: Data) -> String? {
    if let t = String(data: data, encoding: .utf8) { return t }
    let gbk = CFStringConvertEncodingToNSStringEncoding(
        CFStringEncoding(CFStringEncodings.GB_18030_2000.rawValue))
    if let t = String(data: data, encoding: String.Encoding(rawValue: gbk)) { return t }
    return nil
}

// MARK: - App 文件夹导入面板（绕开系统文件选择器）

struct FolderImportSheet: View {
    @Environment(\.dismiss) private var dismiss
    let onImport: (URL) -> Void
    @State private var files: [URL] = []
    @State private var errorText: String?

    var body: some View {
        NavigationView {
            Group {
                if let err = errorText {
                    VStack(spacing: 12) {
                        Text("读取 App 文件夹失败").font(.headline)
                        Text(err).font(.footnote).foregroundColor(.secondary)
                    }
                    .padding()
                } else if files.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("App 文件夹里还没有文件").font(.headline)
                        Text("""
请先把 TXT 文件放进本 App 的文件夹：

方法一（手机）：打开「文件」App →「我的 iPhone」→「优选IP筛选」文件夹，长按 TXT 文件 → 点「移动」→ 选择该文件夹。

方法二（电脑）：用数据线连接电脑，在 iTunes / 访达 / 爱思助手 的「文件共享」里把 TXT 拖进本 App。

放好后点右上角「刷新」即可看到文件。
""")
                            .font(.footnote)
                            .foregroundColor(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding()
                } else {
                    List(files, id: \.self) { url in
                        Button {
                            onImport(url)
                            dismiss()
                        } label: {
                            HStack {
                                Image(systemName: "doc.text")
                                    .foregroundColor(.cfBlue)
                                Text(url.lastPathComponent)
                                Spacer()
                            }
                        }
                    }
                    .listStyle(InsetGroupedListStyle())
                }
            }
            .navigationBarTitle("App 文件夹导入", displayMode: .inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("刷新") { loadFiles() }
                }
            }
            .onAppear { loadFiles() }
        }
    }

    private func loadFiles() {
        errorText = nil
        guard let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            errorText = "无法定位 App 文件夹"
            return
        }
        do {
            let all = try FileManager.default.contentsOfDirectory(at: docs, includingPropertiesForKeys: nil)
            files = all
                .filter { !$0.lastPathComponent.hasPrefix(".") && !$0.hasDirectoryPath }
                .sorted { $0.lastPathComponent.localizedCaseInsensitiveCompare($1.lastPathComponent) == .orderedAscending }
        } catch {
            errorText = error.localizedDescription
        }
    }
}

// MARK: - 粘贴导入面板（文件选择器无法点选文件时的兜底方案）

struct PasteImportSheet: View {
    @Environment(\.dismiss) private var dismiss
    let onImport: (String) -> Void
    @State private var text = ""

    var body: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 12) {
                Text("把 IP 内容（每行一个 ip:port，或 Cloudflare 测速地址）粘贴到下方文本框，再点右上角“导入”")
                    .font(.footnote)
                    .foregroundColor(.secondary)
                TextEditor(text: $text)
                    .font(.system(.footnote, design: .monospaced))
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                    .padding(6)
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(8)
                    .frame(minHeight: 220)
            }
            .padding()
            .navigationBarTitle("粘贴导入", displayMode: .inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("导入") {
                        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !t.isEmpty else { return }
                        onImport(t)
                        dismiss()
                    }
                    .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }
}

struct FilledButtonStyle: ButtonStyle {
    let color: Color
    var vertical: CGFloat = 7
    var horizontal: CGFloat = 14

    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundColor(.white)
            .padding(.vertical, vertical)
            .padding(.horizontal, horizontal)
            .background(configuration.isPressed
                        ? color.opacity(0.8)
                        : (isEnabled ? color : Color(.systemGray3)))
            .cornerRadius(6)
    }
}

// MARK: - 关于工具页

struct AboutView: View {
    let onBack: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Button {
                    onBack()
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "chevron.left")
                        Text("返回工具页面")
                    }
                    .font(.subheadline)
                    .foregroundColor(.cfBlue)
                }
                Spacer()
            }
            .padding(.horizontal)
            .padding(.top, 8)
            .padding(.bottom, 12)

            VStack(alignment: .leading, spacing: 14) {
                Text("关于工具")
                    .font(.title2.bold())

                Text("本工具仅用于学习、研究和技术交流，严禁用于任何违法违规用途。")
                    .fixedSize(horizontal: false, vertical: true)

                Text("· 本工具用于学习与测试网络技术，请遵守当地法律法规及相关网络服务条款。")
                    .fixedSize(horizontal: false, vertical: true)
                Text("· 本工具不提供任何翻墙、代理或其他规避网络审查的服务。")
                    .fixedSize(horizontal: false, vertical: true)
                Text("· 请勿将本工具用于商业用途、网络攻击或任何损害他人利益的行为。")
                    .fixedSize(horizontal: false, vertical: true)
                Text("· 使用本工具扫描、测速等产生的任何后果，均由使用者自行承担，作者不承担任何责任。")
                    .fixedSize(horizontal: false, vertical: true)

                Spacer()

                HStack {
                    Spacer()
                    Text("作者：Trifolium_Chi")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }
            }
            .padding()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color(.systemBackground))
    }
}

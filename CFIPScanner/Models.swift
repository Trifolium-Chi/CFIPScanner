//
//  Models.swift
//  CFIPScanner
//
//  数据模型、国家代码映射、地区拼音排序、解析、导出格式
//  与 Python 版 cf_ip_scanner_web.py 完全对应
//

import Foundation

// MARK: - 数据模型

/// 导入的 IP 条目
struct IpItem: Hashable {
    let ip: String
    let port: Int
    let cc: String
}

/// 扫描结果（可用 IP）
struct ScanResult: Identifiable {
    let id = UUID()
    let ip: String
    let port: Int
    var cc: String        // 真实地区检测后会更新
    var region: String    // 真实地区检测后会更新
    let tcp: Double
    let tls: Double?
}

/// 地区选项（含 IP 数量）
struct RegionOption: Identifiable, Hashable {
    let id = UUID()
    let cc: String        // "" 表示未知地区
    let region: String
    let count: Int
}

// MARK: - 两位国家代码 -> 中文地区名
let CC_CN: [String: String] = [
    "US": "美国", "DE": "德国", "JP": "日本", "SG": "新加坡",
    "HK": "中国香港", "NL": "荷兰", "GB": "英国", "FI": "芬兰",
    "FR": "法国", "KR": "韩国", "TW": "中国台湾", "CN": "中国",
    "RU": "俄罗斯", "CA": "加拿大", "AU": "澳大利亚", "IN": "印度",
    "SE": "瑞典", "TR": "土耳其", "PL": "波兰", "IT": "意大利",
    "ES": "西班牙", "CZ": "捷克", "AT": "奥地利", "CH": "瑞士",
    "BE": "比利时", "BG": "保加利亚", "LV": "拉脱维亚", "EE": "爱沙尼亚",
    "LT": "立陶宛", "RO": "罗马尼亚", "RS": "塞尔维亚", "KZ": "哈萨克斯坦",
    "MX": "墨西哥", "MY": "马来西亚", "TH": "泰国", "VN": "越南",
    "ID": "印度尼西亚", "BR": "巴西", "AR": "阿根廷", "IL": "以色列",
    "AE": "阿联酋", "SA": "沙特阿拉伯", "IE": "爱尔兰", "IS": "冰岛",
    "CY": "塞浦路斯", "NG": "尼日利亚", "EG": "埃及", "ZA": "南非",
    "CO": "哥伦比亚", "CL": "智利", "PE": "秘鲁", "PT": "葡萄牙",
    "HU": "匈牙利", "SK": "斯洛伐克", "SI": "斯洛文尼亚", "HR": "克罗地亚",
    "GR": "希腊", "UA": "乌克兰", "NO": "挪威", "DK": "丹麦",
    "LU": "卢森堡", "NZ": "新西兰", "QA": "卡塔尔", "KW": "科威特",
    "JO": "约旦", "GE": "格鲁吉亚", "AM": "亚美尼亚", "AZ": "阿塞拜疆",
    "MD": "摩尔多瓦", "BY": "白俄罗斯", "PH": "菲律宾", "BD": "孟加拉国",
    "PK": "巴基斯坦", "IR": "伊朗", "IQ": "伊拉克", "OM": "阿曼",
    "BH": "巴林", "MM": "缅甸", "KH": "柬埔寨", "LA": "老挝",
    "MO": "中国澳门", "KP": "朝鲜", "MN": "蒙古", "NP": "尼泊尔",
    "LK": "斯里兰卡", "UZ": "乌兹别克斯坦", "AF": "阿富汗",
]

/// 地区中文名 -> 拼音（用于排序，固定前四位后按拼音 A-Z）
let REGION_PINYIN: [String: String] = [
    "美国": "meiguo", "德国": "deguo", "日本": "riben", "新加坡": "xinjiapo",
    "中国香港": "zhongguoxianggang", "荷兰": "helan", "英国": "yingguo",
    "芬兰": "fenlan", "法国": "faguo", "韩国": "hanguo", "中国台湾": "zhongguotaiwan",
    "中国": "zhongguo", "俄罗斯": "eluosi", "加拿大": "jianada", "澳大利亚": "aodaliya",
    "印度": "yindu", "瑞典": "ruidian", "土耳其": "tuerqi", "波兰": "bolan",
    "意大利": "yidali", "西班牙": "xibanya", "捷克": "jieke", "奥地利": "aodili",
    "瑞士": "ruishi", "比利时": "bilishi", "保加利亚": "baojialiya",
    "拉脱维亚": "latuoweiya", "爱沙尼亚": "aishaniya", "立陶宛": "litaowan",
    "罗马尼亚": "luomaniya", "塞尔维亚": "saierweiya", "哈萨克斯坦": "hasakesitan",
    "墨西哥": "moxige", "马来西亚": "malaixiya", "泰国": "taiguo", "越南": "yuenan",
    "印度尼西亚": "yindunixiya", "巴西": "baxi", "阿根廷": "agenting", "以色列": "yiselie",
    "阿联酋": "alianqiu", "沙特阿拉伯": "shatealabo", "爱尔兰": "aierlan", "冰岛": "bingdao",
    "塞浦路斯": "saipulusi", "尼日利亚": "niriliya", "埃及": "aiji", "南非": "nanfei",
    "哥伦比亚": "gelunbiya", "智利": "zhili", "秘鲁": "bilu", "葡萄牙": "putaoya",
    "匈牙利": "xiongyali", "斯洛伐克": "siluofake", "斯洛文尼亚": "siluowenniya",
    "克罗地亚": "keluodiya", "希腊": "xila", "乌克兰": "wukelan", "挪威": "nuowei",
    "丹麦": "danmai", "卢森堡": "lusenbao", "新西兰": "xinxilan", "卡塔尔": "kataer",
    "科威特": "keweite", "约旦": "yuedan", "格鲁吉亚": "gelujiya", "亚美尼亚": "yameiniya",
    "阿塞拜疆": "asaibaijiang", "摩尔多瓦": "moerduowa", "白俄罗斯": "baieluosi",
    "菲律宾": "feilvbin", "孟加拉国": "mengjialaguo", "巴基斯坦": "bajisitan",
    "伊朗": "yilang", "伊拉克": "yilake", "阿曼": "aman", "巴林": "balin",
    "缅甸": "miandian", "柬埔寨": "jianpuzhai", "老挝": "laowo", "中国澳门": "zhongguoaomen",
    "朝鲜": "chaoxian", "蒙古": "menggu", "尼泊尔": "niboer", "斯里兰卡": "sililanka",
    "乌兹别克斯坦": "wuzibiekesitan", "阿富汗": "afuhan", "未知地区": "weizhidiqu",
]

/// 固定排序的前四位
let REGION_FIXED_ORDER = ["中国", "中国香港", "中国澳门", "中国台湾"]

// MARK: - 地区名

func regionName(_ cc: String) -> String {
    if cc.isEmpty { return "" }
    return CC_CN[cc] ?? cc
}

func resultRegionFor(_ cc: String) -> String {
    if cc.isEmpty { return "未知地区" }
    return regionName(cc)
}

// MARK: - 地区排序（固定前四位 + 拼音）

func regionPinyin(_ name: String) -> String {
    return REGION_PINYIN[name] ?? name
}

func sortRegionOpts(_ opts: [RegionOption]) -> [RegionOption] {
    var fixedIndex: [String: Int] = [:]
    for (i, n) in REGION_FIXED_ORDER.enumerated() { fixedIndex[n] = i }
    return opts.sorted { a, b in
        let fa = fixedIndex[a.region]
        let fb = fixedIndex[b.region]
        let faOk = fa != nil
        let fbOk = fb != nil
        if faOk || fbOk {
            if faOk && fbOk { return fa! < fb! }
            return faOk
        }
        let pa = regionPinyin(a.region)
        let pb = regionPinyin(b.region)
        return pa < pb
    }
}

// MARK: - 解析

/// 中文地区简称别名（CC_CN 中只存了“中国香港/中国澳门/中国台湾”，
/// 但导入文件里常直接写“香港/澳门/台湾”）
private let CN_ALIAS: [String: String] = [
    "香港": "HK", "澳门": "MO", "台湾": "TW",
]

/// 英文地区名 -> 国家代码（按“整词”精确匹配，避免误判）
private let CC_ENGLISH_TOKEN: [String: String] = [
    "HONGKONG": "HK", "MACAU": "MO", "MACAO": "MO",
    "USA": "US", "AMERICA": "US", "JAPAN": "JP",
    "SINGAPORE": "SG", "GERMANY": "DE", "NETHERLANDS": "NL",
    "ENGLAND": "GB", "UK": "GB", "TAIWAN": "TW", "CHINA": "CN",
    "RUSSIA": "RU", "CANADA": "CA", "AUSTRALIA": "AU", "INDIA": "IN",
    "KOREA": "KR", "FRANCE": "FR", "FINLAND": "FI", "SWEDEN": "SE",
    "TURKEY": "TR", "POLAND": "PL", "ITALY": "IT", "SPAIN": "ES",
]

/// 英文多词地区名（紧凑成无空格大写后 contains 匹配，仅长度较长者，
/// 避免短词误伤普通英文单词）
private let CC_ENGLISH_MULTI: [String: String] = [
    "HONGKONG": "HK", "UNITEDSTATES": "US", "UNITEDKINGDOM": "GB",
    "SOUTHKOREA": "KR",
]

/// 中文地区名按长度降序（提前算好，避免每条 IP 行都重新排序，减少导入卡顿）
private let CN_SORTED: [(code: String, name: String)] = CC_CN
    .sorted { $0.value.count > $1.value.count }
    .map { ($0.key, $0.value) }

/// 从注释中识别地区并返回国家代码；无法识别返回空字符串。
/// 与分隔符无关：无论注释用 #、-、,、:、|、/、空格、括号等分隔，
/// 只要出现“香港/HK/Hong Kong”等关键词即可命中。
/// 识别优先级：中文地区名 > 英文全称 > 独立两位国家代码。
func extractCC(from comment: String) -> String {
    guard !comment.isEmpty else { return "" }

    // 1) 中文地区名（长优先，避免“中国”误命中“中国香港”）
    for (code, name) in CN_SORTED {
        if comment.contains(name) { return code }
    }
    for (alias, code) in CN_ALIAS {
        if comment.contains(alias), CC_CN[code] != nil { return code }
    }

    // 2) 英文全称：分离连续字母片段（大小写不敏感）
    let letterRuns = comment.map { $0.isLetter ? String($0) : " " }.joined()
    let tokens = letterRuns.split(separator: " ").map { String($0).uppercased() }

    // 2a) 整词精确匹配
    for token in tokens {
        if let code = CC_ENGLISH_TOKEN[token], CC_CN[code] != nil { return code }
    }

    // 2b) 多词全称：紧凑后 contains（如 "Hong Kong" -> "HONGKONG"）
    let compact = comment.uppercased().filter { $0.isLetter }
    for (name, code) in CC_ENGLISH_MULTI {
        if name.count >= 6, compact.contains(name), CC_CN[code] != nil { return code }
    }

    // 3) 独立两位国家代码片段（如 "443-HK" -> "HK"、"443,US" -> "US"）
    for token in tokens {
        if CC_CN[token] != nil { return token }
    }

    return ""
}

/// 解析单行，返回 IpItem；无法解析返回 nil。
/// 支持 IP:端口 后带或不带注释，注释可用 #、-、,、:、|、/、空格、括号等分隔；
/// 地区从注释中识别（中文地区名 / 英文全称 / 独立两位国家代码），与分隔符无关。
func parseLine(_ rawLine: String) -> IpItem? {
    var line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
    if line.isEmpty || line.hasPrefix("#") { return nil }
    // 去除 scheme://
    if let r = line.range(of: "://") {
        line = String(line[r.upperBound...])
    }

    // 提取行首的 IP 部分：连续的数字与点（不支持 IPv6），
    // 手写字符扫描代替正则，避免大文件导入时逐行编译正则导致卡顿。
    let ipPrefix = line.prefix { $0.isNumber || $0 == "." }
    guard !ipPrefix.isEmpty else { return nil }
    let ipStr = String(ipPrefix)
    // 校验 IP：每段 0-255 且不超过 3 位数字
    let octets = ipStr.split(separator: ".")
    guard octets.count == 4 else { return nil }
    for o in octets {
        let s = String(o)
        guard s.count >= 1, s.count <= 3,
              s.allSatisfy({ $0 >= "0" && $0 <= "9" }),
              let v = Int(s), v <= 255 else { return nil }
    }
    let ip = ipStr

    // IP 之后的部分：可能以 :端口 开头，其余全部视为注释
    let rest = String(line.dropFirst(ipPrefix.count))
    var port = 443
    var comment = ""
    if rest.hasPrefix(":") {
        let afterColon = String(rest.dropFirst())
        var digitStr = ""
        for ch in afterColon {
            if ch.isNumber { digitStr.append(ch) } else { break }
        }
        if let p = Int(digitStr), p > 0, p <= 65535 {
            port = p
            comment = String(afterColon.dropFirst(digitStr.count))
        } else {
            // 冒号后无有效端口：整段视为注释（如 "91.110.174.202:香港"）
            comment = rest
        }
    } else {
        comment = rest
    }

    let cc = extractCC(from: comment)
    return IpItem(ip: ip, port: port, cc: cc)
}

/// 解析整段文本，按 (ip, port) 去重
func parseText(_ text: String) -> [IpItem] {
    var seen = Set<String>()
    var items: [IpItem] = []
    for line in text.components(separatedBy: .newlines) {
        guard let item = parseLine(line) else { continue }
        let key = item.ip + ":" + String(item.port)
        if seen.contains(key) { continue }
        seen.insert(key)
        items.append(item)
    }
    return items
}

// MARK: - 导出

/// 导出单行：IP:端口#中文地区名代码(运营商优选)[延迟ms]
func exportLine(_ r: ScanResult, isp: String) -> String {
    var line = "\(r.ip):\(r.port)"
    if !r.cc.isEmpty {
        line += "#" + regionName(r.cc) + r.cc
    }
    let tag = isp.isEmpty ? "优选" : (isp + "优选")
    line += "(\(tag))[\(Int(r.tcp.rounded()))ms]"
    return line
}

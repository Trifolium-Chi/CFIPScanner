//
//  ISPService.swift
//  CFIPScanner
//
//  运营商自动检测：调用 whois.pconline.com.cn 获取当前公网 IP 的归属运营商
//

import Foundation

/// 从归属地文本中提取运营商关键字
func extractISP(_ addr: String) -> String {
    for kw in ["电信", "联通", "移动", "铁通", "广电", "教育网"] {
        if addr.contains(kw) { return kw }
    }
    return ""
}

/// 自动检测运营商，失败返回空字符串（回调）
func detectISP(completion: @escaping (String) -> Void) {
    let urls = [
        "https://whois.pconline.com.cn/ipJson.jsp?json=true",
        "http://whois.pconline.com.cn/ipJson.jsp?json=true",
    ]
    detectISP(urls: urls, index: 0, completion: completion)
}

private func detectISP(urls: [String], index: Int, completion: @escaping (String) -> Void) {
    guard index < urls.count else {
        completion("")
        return
    }
    guard let url = URL(string: urls[index]) else {
        detectISP(urls: urls, index: index + 1, completion: completion)
        return
    }
    var request = URLRequest(url: url)
    request.timeoutInterval = 5
    request.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")

    URLSession.shared.dataTask(with: request) { data, _, _ in
        guard let data = data else {
            detectISP(urls: urls, index: index + 1, completion: completion)
            return
        }
        // 先按 utf-8，再按 gbk 解析 JSON
        let text: String?
        if let t = String(data: data, encoding: .utf8) {
            text = t
        } else {
            let gbk = CFStringConvertEncodingToNSStringEncoding(
                CFStringEncoding(CFStringEncodings.GB_18030_2000.rawValue))
            text = String(data: data, encoding: String.Encoding(rawValue: gbk))
        }
        var isp = ""
        if let text = text,
           let j = try? JSONSerialization.jsonObject(with: Data(text.utf8)) {
            if let dict = j as? [String: Any] {
                let addr = dict["addr"] as? String ?? ""
                isp = extractISP(addr)
            }
        }
        if !isp.isEmpty {
            completion(isp)
        } else {
            detectISP(urls: urls, index: index + 1, completion: completion)
        }
    }.resume()
}

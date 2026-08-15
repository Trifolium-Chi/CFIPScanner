//
//  GeoService.swift
//  CFIPScanner
//
//  IP 真实地区检测：调用公共 IP 归属地接口，返回两位国家代码。
//  用于修正导入文件里可能错误的地区代码，以及为无地区代码的 IP 自动补全。
//  优先 ipwho.is，失败回退 ip-api.com。
//

import Foundation

/// IP 归属地查询结果
struct GeoResult {
    let countryCode: String   // 两位国家代码，如 "US"；失败为空
    let countryName: String   // 英文国名，失败为空
}

/// 查询单个 IPv4 的真实归属地，失败返回空
func geoLookup(ip: String, completion: @escaping (GeoResult?) -> Void) {
    let urls = [
        "https://ipwho.is/\(ip)",
        "http://ip-api.com/json/\(ip)?fields=status,countryCode,country",
    ]
    geoLookup(urls: urls, index: 0, completion: completion)
}

private func geoLookup(urls: [String], index: Int, completion: @escaping (GeoResult?) -> Void) {
    guard index < urls.count else {
        completion(nil)
        return
    }
    guard let url = URL(string: urls[index]) else {
        geoLookup(urls: urls, index: index + 1, completion: completion)
        return
    }
    var request = URLRequest(url: url)
    request.timeoutInterval = 8
    request.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")

    URLSession.shared.dataTask(with: request) { data, _, _ in
        guard let data = data,
              let text = String(data: data, encoding: .utf8),
              let j = try? JSONSerialization.jsonObject(with: Data(text.utf8)),
              let dict = j as? [String: Any] else {
            geoLookup(urls: urls, index: index + 1, completion: completion)
            return
        }

        // ipwho.is 结构
        if let success = dict["success"] as? Bool, success == false {
            geoLookup(urls: urls, index: index + 1, completion: completion)
            return
        }
        if let cc = dict["country_code"] as? String, !cc.isEmpty {
            let name = dict["country"] as? String ?? ""
            completion(GeoResult(countryCode: cc.uppercased(), countryName: name))
            return
        }
        // ip-api.com 结构
        if let status = dict["status"] as? String, status == "fail" {
            geoLookup(urls: urls, index: index + 1, completion: completion)
            return
        }
        if let cc = dict["countryCode"] as? String, !cc.isEmpty {
            let name = dict["country"] as? String ?? ""
            completion(GeoResult(countryCode: cc.uppercased(), countryName: name))
            return
        }
        geoLookup(urls: urls, index: index + 1, completion: completion)
    }.resume()
}

/// 批量查询（串行限速，避免同时发起过多请求），每个 IP 处理完后回调
func geoLookupBatch(ips: [String], onItem: @escaping (String, GeoResult?) -> Void, onDone: @escaping () -> Void) {
    var queue = ips
    func next() {
        guard !queue.isEmpty else {
            onDone()
            return
        }
        let ip = queue.removeFirst()
        geoLookup(ip: ip) { result in
            onItem(ip, result)
            DispatchQueue.global(qos: .utility).async { next() }
        }
    }
    next()
}

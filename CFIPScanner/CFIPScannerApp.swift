//
//  CFIPScannerApp.swift
//  CFIPScanner
//
//  App 入口
//

import SwiftUI

@main
struct CFIPScannerApp: App {
    @StateObject private var scanner = Scanner()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(scanner)
        }
    }
}

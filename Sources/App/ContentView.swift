import SwiftUI
import UIKit
import WebKit

struct ContentView: View {
    @EnvironmentObject var state: AppState
    @AppStorage("verbose")  private var verbose: Bool = true
    @AppStorage("auto_run") private var auto_run: Bool = false

    @State private var show_settings: Bool = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Menu {
                        Button("ImageIO · malloc") { state.run86950(mode: 0, heap: true) }
                        Button("ImageIO · alloca") { state.run86950(mode: 0, heap: false) }
                        Button("CGPDF · malloc")   { state.run86950(mode: 1, heap: true) }
                        Button("CGFont · show-glyphs") { state.run86950(mode: 2, heap: true) }
                    } label: {
                        Label(state.t("CVE-2026-86950 (CG glyph OOB)", "CVE-2026-86950 (CG glyph OOB)"), systemImage: "textformat")
                    }
                    .disabled(state.running)

                    Text(state.cve86950Status)
                        .font(.system(.footnote, design: .monospaced))
                        .foregroundStyle(.secondary)

                    Button {
                        state.scalerProbe()
                    } label: {
                        Label(state.t("Scaler / Accelerator probe", "Проба Scaler / Accelerator"), systemImage: "scale.3d")
                    }
                    .disabled(state.running)

                    NavigationLink(destination: {
                        WebKitStageView()
                    }, label: {
                        Label(state.t("WebKit pivot (renderer AAR/AAW)", "WebKit пивот (AAR/AAW в рендере)"), systemImage: "safari")
                    })

                } header: {
                    Label(state.t("Actions", "Действия"), systemImage: "play.circle")
                } footer: {
                    Text(state.t("**86950** — live CoreGraphics glyph OOB, runs in-process or in the renderer. **WebKit pivot** — live renderer with arbitrary read/write (echo gate).",
                         "**86950** — живой CoreGraphics glyph OOB, работает в приложении или рендере. **WebKit пивот** — живой рендер с произвольным чтением/записью (echo gate)."))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section {
                    HStack {
                        Text(state.t("Slide", "Слайд"))
                        Spacer()
                        Text(state.slide == 0 ? "—" : String(format: "0x%llx", state.slide))
                            .font(.system(.body, design: .monospaced))
                            .foregroundColor(state.slide == 0 ? .secondary : .green)
                    }

                    HStack {
                        Text(state.t("Base", "База"))
                        Spacer()
                        Text(state.base == 0 ? "—" : String(format: "0x%llx", state.base))
                            .font(.system(.body, design: .monospaced))
                            .foregroundColor(state.base == 0 ? .secondary : .green)
                    }

                    HStack {
                        Text(state.t("Status", "Статус"))
                        Spacer()
                        HStack(spacing: 6) {
                            Circle()
                                .fill(state.status.color)
                                .frame(width: 7, height: 7)
                            Text(state.status.label)
                                .foregroundColor(state.status.color)
                        }
                    }

                    HStack {
                        Text(state.t("Device", "Устройство"))
                        Spacer()
                        Text(device_info())
                            .font(.system(.body, design: .monospaced))
                            .foregroundColor(.secondary)
                    }
                } header: {
                    Label(state.t("Runtime", "Состояние"), systemImage: "waveform.path.ecg")
                }

                Section {
                    LogView()
                        .environmentObject(state)
                        .modifier(TerminalPlatter())
                        .listRowInsets(EdgeInsets(top: 0, leading: 16, bottom: 0, trailing: 16))
                } header: {
                    Label(state.t("Logs", "Логи"), systemImage: "apple.terminal")
                }

                Section {
                    Toggle(state.t("Auto Run on Launch", "Автозапуск при открытии"), isOn: $auto_run)
                    Toggle(state.t("Verbose Output", "Подробный вывод"), isOn: $verbose)
                } header: {
                    Label(state.t("Options", "Опции"), systemImage: "gearshape")
                } footer: {
                    Text(state.t("Auto Run executes the exploit automatically when the app opens. Verbose shows detailed kernel logs.",
                                 "Автозапуск выполняет эксплойт сразу при открытии. Подробный вывод показывает детальные логи ядра."))
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("srk801")
            .navigationBarTitleDisplayMode(.large)
            .tint(.blue)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        show_settings = true
                    } label: {
                        Image(systemName: "gear")
                    }
                }
            }
            .sheet(isPresented: $show_settings) {
                SettingsView()
                    .environmentObject(state)
            }
        }
    }

    private func device_info() -> String {
        var sysinfo = utsname()
        uname(&sysinfo)
        let machine = Mirror(reflecting: sysinfo.machine).children.reduce("") { id, el in
            guard let v = el.value as? Int8, v != 0 else { return id }
            return id + String(UnicodeScalar(UInt8(v)))
        }
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "\(machine) · iOS \(v.majorVersion).\(v.minorVersion)"
    }
}

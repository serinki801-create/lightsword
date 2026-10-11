import SwiftUI
import UIKit

struct ContentView: View {
    @EnvironmentObject var state: AppState
    @AppStorage("verbose")  private var verbose: Bool = true
    @AppStorage("auto_run") private var auto_run: Bool = false

    @State private var show_settings: Bool = false
    @State private var show_webkit: Bool = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Button {
                        state.run()
                    } label: {
                        Label(state.t("Run Exploit", "Запустить эксплойт"), systemImage: "bolt.fill")
                    }
                    .disabled(state.running)

                    Button {
                        state.slideOnly()
                    } label: {
                        Label(state.t("Slide Only", "Только слайд"), systemImage: "scope")
                    }
                    .disabled(state.running)

                    Button {
                        state.aioB12()
                    } label: {
                                Label("AIO UAF B1/B2 (10x)", systemImage: "arrow.clockwise")
                    }
                    .disabled(state.running)

                    Button {
                        state.t0eSpike()
                    } label: {
                                Label("T0e Spike (SEP/DTrace)", systemImage: "antenna.radiowaves.left.and.right")
                    }
                    .disabled(state.running)

                    Button {
                        state.t2FrameProbe()
                    } label: {
                                Label("T2 Frame Probe (50x)", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .disabled(state.running)

                    Button {
                        state.t2Dummynet()
                    } label: {
                                Label("T2 Dummynet Probe", systemImage: "network")
                    }
                    .disabled(state.running)

                    Button {
                        state.guardTest()
                    } label: {
                                Label("Guard Test", systemImage: "cross.circle")
                    }
                    .disabled(state.running)

                    Button {
                        show_webkit = true
                    } label: {
                                Label("WebKit Stage", systemImage: "globe")
                    }
                    .sheet(isPresented: $show_webkit) {
                        NavigationStack {
                            WebKitStageView()
                                .environmentObject(AppState.shared)
                        }
                    }

                    Button {
                        state.resetProbes()
                    } label: {
                                Label("Reset Probe State", systemImage: "arrow.counterclockwise.circle")
                    }
                    .disabled(state.running)

                    Button {
                        state.pacSelfTest()
                    } label: {
                                Label("PAC Oracle A2", systemImage: "shield.fill")
                    }
                    .disabled(state.running)
                } header: {
                    Label(state.t("Actions", "Действия"), systemImage: "play.circle")
                } footer: {
                    Text(state.t("**Run Exploit** executes the full chain. **Slide Only** runs KASLR bypass in isolation.",
                                 "**Запустить эксплойт** выполняет всю цепочку. **Только слайд** запускает только обход KASLR."))
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
            .navigationTitle("natsuk1")
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

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
                        state.chain()
                    } label: {
                        Label(state.t("Chain", "Цепочка"), systemImage: "link")
                    }
                    .disabled(state.running)

                    VStack(spacing: 8) {
                        Button {
                            state.fuzz2()
                        } label: {
                            Label(state.t("Fuzz v2 map", "Фазз v2 карта"), systemImage: "square.grid.2x2")
                        }
                        .disabled(state.running)

                        Button {
                            state.iogpuOob64()
                        } label: {
                            Label(state.t("IOGPU sel64", "IOGPU sel64"), systemImage: "target")
                        }
                        .disabled(state.running)

                        Button {
                            state.oobHunt()
                        } label: {
                            Label(state.t("OOB Hunt", "OOB Hunt"), systemImage: "scope")
                        }
                        .disabled(state.running)
                    }

                    VStack(spacing: 8) {
                        Button {
                            state.groupOob(false)
                        } label: {
                            Label(state.t("Group OOB (read)", "Group OOB (проверка)"), systemImage: "eye")
                        }
                        .disabled(state.running)

                        Button {
                            state.groupOob(true)
                        } label: {
                            Label(state.t("Group OOB (trigger)", "Group OOB (триггер)"), systemImage: "bolt.trianglebadge.exclamationmark")
                        }
                        .disabled(state.running)
                    }

                    NavigationLink {
                        WebKitStageView()
                    } label: {
                        Label(state.t("WebKit pivot", "WebKit пивот"), systemImage: "safari")
                    }

                } header: {
                    Label(state.t("Actions", "Действия"), systemImage: "play.circle")
                } footer: {
                    Text(state.t("**Slide Only** — KASLR detection. **Fuzz batch** — registry/proc_info/IPC/mach-leak surface hunts.",
                                 "**Только слайд** — определение KASLR. **Фазз-прогон** — поверхности: registry / proc_info / IPC / mach-leak."))
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

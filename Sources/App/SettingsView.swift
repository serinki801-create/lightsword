import SwiftUI
import UIKit

struct SettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject var state: AppState

    @AppStorage("auto_run") private var auto_run: Bool = false
    @AppStorage("verbose")  private var verbose: Bool = true
    @AppStorage("full_recon") private var full_recon: Bool = false

    @AppStorage("unsafe_aks_oob") private var unsafe_aks_oob: Bool = false
    @AppStorage("unsafe_aks_oversize") private var unsafe_aks_oversize: Bool = false
    @AppStorage("unsafe_necp") private var unsafe_necp: Bool = false
    @AppStorage("unsafe_aio_uaf") private var unsafe_aio_uaf: Bool = false
    @AppStorage("unsafe_aio_kevent_probe") private var unsafe_aio_kevent_probe: Bool = false
    @AppStorage("unsafe_necp_dataonly") private var unsafe_necp_dataonly: Bool = false
    @AppStorage("unsafe_do_kwrite") private var unsafe_do_kwrite: Bool = false
    @AppStorage("unsafe_sandbox_escape") private var unsafe_sandbox_escape: Bool = false

    @State private var show_respring_confirm: Bool = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Picker(state.t("Language", "Язык"), selection: $state.lang) {
                        Text("English").tag("en")
                        Text("Русский").tag("ru")
                    }
                    .pickerStyle(.segmented)
                } header: {
                    Label(state.t("Interface", "Интерфейс"), systemImage: "globe")
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
                    Button { state.run() } label: {
                        Label(state.t("Run Exploit", "Запустить эксплойт"), systemImage: "bolt.fill")
                    }
                    .disabled(state.running)
                    Button { state.slideOnly() } label: {
                        Label(state.t("Slide Only", "Только слайд"), systemImage: "scope")
                    }
                    .disabled(state.running)
                } header: {
                    Label(state.t("Exploit", "Эксплойт"), systemImage: "wrench.and.screwdriver")
                } footer: {
                    Text(state.t("Default run is read-only mapping. Every kernel-touching stage is off and needs its own toggle.",
                                 "Дефолтный прогон — карта только на чтение. Каждая ядерная стадия выключена и требует свой тумблер."))
                }

                Section {
                    Toggle(state.t("Auto Run on Launch", "Автозапуск при открытии"), isOn: $auto_run)
                    Toggle(state.t("Verbose Output", "Подробный вывод"), isOn: $verbose)
                    Toggle(state.t("Full Recon (stages 0-0d)", "Полная разведка (стадии 0-0d)"), isOn: $full_recon)
                } header: {
                    Label(state.t("Options", "Опции"), systemImage: "gearshape")
                } footer: {
                    Text(state.t("Without full_recon the monitor, deep method maps and kernel pointer scan never run.",
                                 "Без full_recon монитор, глубокие карты методов и скан ядерных указателей не запускаются."))
                }

                Section {
                    Toggle(state.t("AKS selector map", "Карта селекторов AKS"), isOn: $unsafe_aks_oob)
                    Toggle(state.t("AKS oversize (PANIC RISK)", "AKS oversize (РИСК ПАНИКИ)"), isOn: $unsafe_aks_oversize)
                    Toggle(state.t("NECP UAF Dance", "NECP UAF танец"), isOn: $unsafe_necp)
                    Toggle(state.t("AIO kevent UAF", "AIO kevent UAF"), isOn: $unsafe_aio_uaf)
                    Toggle(state.t("AIO kevent PROBE (PANIC RISK)", "AIO kevent PROBE (РИСК ПАНИКИ)"), isOn: $unsafe_aio_kevent_probe)
                } header: {
                    Label(state.t("Dangerous Stages", "Опасные стадии"), systemImage: "exclamationmark.triangle.fill")
                } footer: {
                    Text(state.t("AIO kevent PROBE does one second kevent with a zero pattern. May panic.",
                                 "AIO kevent PROBE делает один второй kevent с нулевым паттерном. Может вызвать панику."))
                }

                Section {
                    Toggle(state.t("NECP Data-Only Chain", "NECP Data-Only цепочка"), isOn: $unsafe_necp_dataonly)
                    Toggle(state.t("Enable kwrite discovery", "Поиск записи"), isOn: $unsafe_do_kwrite)
                    Toggle(state.t("Sandbox escape (EXPERIMENTAL)", "Выход из песочницы (ЭКСПЕРИМЕНТАЛЬНО)"), isOn: $unsafe_sandbox_escape)
                } header: {
                    Label(state.t("Privilege Escalation", "Повышение привилегий"), systemImage: "key.fill")
                }

                Section {
                    Button { show_respring_confirm = true } label: {
                        Label(state.t("Respring", "Респринг"), systemImage: "arrow.clockwise")
                    }
                } header: {
                    Label(state.t("Tools", "Инструменты"), systemImage: "wrench.and.screwdriver")
                } footer: {
                    Text(state.t("Respring reboots userspace. KASLR slide is randomized on every boot — save a fresh panic log after respring.",
                                 "Респринг перезапускает userspace. KASLR слайд рандомится на каждый бут — после респринга сохрани свежий panic-лог."))
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle(state.t("Settings", "Настройки"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(state.t("Done", "Готово")) { dismiss() }
                }
            }
            .alert(state.t("Are you sure?", "Ты уверен?"), isPresented: $show_respring_confirm) {
                Button(state.t("Cancel", "Отмена"), role: .cancel) { }
                Button(state.t("Respring", "Респринг"), role: .destructive) {
                    state.respring()
                }
            } message: {
                Text(state.t("Confirm respring.", "Подтверди респринг."))
            }
        }
    }
}

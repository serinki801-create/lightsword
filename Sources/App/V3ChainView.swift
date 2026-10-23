import SwiftUI

struct V3ChainView: View {
    @EnvironmentObject var state: AppState

    private var st: nk_v3_stat_t { state.v3Stat }

    private var verdict: String {
        var s = state.v3Stat
        return withUnsafePointer(to: &s) { p in
            guard let c = nk_v3_verdict(p) else { return "—" }
            return String(cString: c)
        }
    }

    private var nodes: [(String, String, Bool, String)] {
        [
            ("64788 trigger", "bolt.fill", st.uaf_rc != 0,
             "IOSurface 1×65535 → XPC → create_resource_iosurface: overflow-ветка не освобождает объект"),
            ("reclaim 0x100", "square.stack.3d.up", st.bpf_spray > 0 || st.xattr_spray > 0,
             "BPF 0x100: \(st.bpf_spray)   xattr 0x100: \(st.xattr_spray)"),
            ("confirm stale id", "checkmark.seal",
             st.uaf_rc == 2,
             "повторный опрос id: 0xe00002be вместо 0xe00002c2"),
            ("relative write", "pencil.line", st.oob_called != 0,
             "remove из хеш-таблицы группы: 8 нулевых байт в соседний слот slab"),
        ]
    }

    var body: some View {
        List {
            Section {
                ForEach(Array(nodes.enumerated()), id: \.offset) { _, n in
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: n.1)
                            .frame(width: 24)
                            .foregroundStyle(n.2 ? Color.green : Color.secondary)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(n.0).font(.headline)
                            Text(n.3).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Label(state.t("Pipeline", "Пайплайн"), systemImage: "point.topleft.down.to.point.bottomright.curvepath")
            }

            Section {
                LabeledContent(state.t("Trigger rc", "Код триггера"), value: "\(st.uaf_rc)")
                LabeledContent("BPF 0x100", value: "\(st.bpf_spray)")
                LabeledContent("xattr 0x100", value: "\(st.xattr_spray)")
                LabeledContent(state.t("Elapsed", "Время"), value: "\(st.elapsed_ms) ms")
            } header: {
                Label(state.t("Metrics", "Метрики"), systemImage: "gauge")
            }

            Section {
                Text(verdict)
                    .font(.callout.monospaced())
            } header: {
                Label(state.t("Verdict", "Вердикт"), systemImage: "checkmark.circle")
            }

            Section {
                Button {
                    state.runV3()
                } label: {
                    Label(state.t("Run chain v3", "Прогнать цепочку v3"), systemImage: "play.fill")
                }
                .disabled(state.running)
            }
        }
        .navigationTitle(state.t("Chain v3", "Цепочка v3"))
    }
}

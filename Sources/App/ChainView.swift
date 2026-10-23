import SwiftUI

// language: Swift, file: ChainView.swift, target: iOS 15+ (Theos, arm64)
// Визуализация цепочки kernel R/W: AIO kevent UAF -> kernel read -> blind write.
// Каждый узел — измеримый факт из лога цепочки (Documents/aio_chain.log),
// а не «наверное»: цвет узла = состояние соответствующего этапа.

enum ChainStage: Int, CaseIterable {
    case trigger, reclaim, read, leak, write

    var title: String {
        switch self {
        case .trigger: return "1 · TRIGGER"
        case .reclaim: return "2 · FREE + RECLAIM"
        case .read:    return "3 · KERNEL READ"
        case .leak:    return "4 · KASLR LEAK"
        case .write:   return "5 · KERNEL WRITE"
        }
    }

    var subtitle: String {
        switch self {
        case .trigger: return "lio_listio(SIGEV_KEVENT) → knote без ref"
        case .reclaim: return "aio_return жертвы → слот забирает donor"
        case .read:    return "kevent64 читает поля освобождённой записи"
        case .leak:    return "kernel VA в ident/udata/ext[0..3]"
        case .write:   return "TAILQ_REMOVE: *tqe_prev = tqe_next"
        }
    }

    var icon: String {
        switch self {
        case .trigger: return "bolt.horizontal"
        case .reclaim: return "arrow.triangle.2.circlepath"
        case .read:    return "eye"
        case .leak:    return "key.viewfinder"
        case .write:   return "pencil.and.outline"
        }
    }

    var detail: String {
        switch self {
        case .trigger: return "kn_hook = &aio_workq_entry без aio_entry_ref — баг 26.2, в 26.3 пофиксили"
        case .reclaim: return "LIFO magazine того же CPU: первый aio_read после free забирает слот"
        case .read:    return "ext[0]=+0x28 errorval, ext[1]=+0x20 returnval, ident=+0x48, udata=+0x50"
        case .leak:    return "ext[2]/ext[3] — остатки буфера ядра; PAC маскируется"
        case .write:   return "цель и значение — kernel-указатели списка doneq (blind, без what/where)"
        }
    }
}

enum ChainNodeState {
    case pending, running, ok, fail

    var color: Color {
        switch self {
        case .pending: return .secondary
        case .running: return .blue
        case .ok:      return .green
        case .fail:    return .red
        }
    }

    var glyph: String {
        switch self {
        case .pending: return "circle"
        case .running: return "arrow.triangle.2.circlepath"
        case .ok:      return "checkmark.circle.fill"
        case .fail:    return "xmark.octagon.fill"
        }
    }

    var tag: String {
        switch self {
        case .pending: return "—"
        case .running: return "…"
        case .ok:      return "OK"
        case .fail:    return "FAIL"
        }
    }
}

private struct ChainNodeRow: View {
    let stage: ChainStage
    let nodeState: ChainNodeState
    let last: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(spacing: 0) {
                Image(systemName: nodeState.glyph)
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundColor(nodeState.color)
                if !last {
                    Rectangle()
                        .fill(nodeState == .ok ? Color.green : Color.secondary.opacity(0.3))
                        .frame(width: 2, height: 46)
                }
            }
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(stage.title)
                        .font(.subheadline.bold())
                    Spacer()
                    Text(nodeState.tag)
                        .font(.caption2.bold())
                        .foregroundColor(nodeState.color)
                }
                Text(stage.subtitle)
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text(stage.detail)
                    .font(.caption2)
                    .foregroundColor(.secondary.opacity(0.85))
            }
            .padding(.bottom, 10)
        }
    }
}

private struct ChainMetricRow: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        HStack {
            Text(title)
                .font(.footnote)
            Spacer()
            Text(value)
                .font(.system(.footnote, design: .monospaced))
                .foregroundColor(color)
        }
        .padding(.vertical, 7)
    }
}

struct ChainView: View {
    @EnvironmentObject var state: AppState
    @State private var attempts: Int = 200

    private func nodeState(_ stage: ChainStage) -> ChainNodeState {
        let st = state.chainStat
        switch stage {
        case .trigger:
            return st.trigger_ok > 0 ? .ok : (state.running ? .running : .pending)
        case .reclaim:
            return st.reclaim_ok > 0 ? .ok : (st.trigger_ok > 0 ? .running : .pending)
        case .read:
            return st.hits > 0 ? .ok : (st.read_ok > 0 ? .fail : (st.reclaim_ok > 0 ? .running : .pending))
        case .leak:
            return st.leak_ok > 0 ? .ok : (st.hits > 0 ? .fail : .pending)
        case .write:
            return st.write_ok > 0 ? .ok : (st.hits > 0 ? .running : .pending)
        }
    }

    private func metricItems() -> [(String, String, Color)] {
        let st = state.chainStat
        return [
            (state.t("Triggered", "Триггеров"), "\(st.trigger_ok)", .primary),
            (state.t("Reclaimed", "Переиспользовано"), "\(st.reclaim_ok)", .primary),
            (state.t("UAF hits", "UAF срабатываний"), "\(st.hits)", st.hits > 0 ? .green : .primary),
            (state.t("Silent", "Промахи"), "\(st.silent)", st.silent > 0 ? .orange : .primary),
            (state.t("Kernel VA found", "Найдено kernel VA"), "\(st.leak_ok)", st.leak_ok > 0 ? .green : .primary),
            (state.t("Blind writes", "Blind-записи"), "\(st.write_ok)", st.write_ok > 0 ? .green : .primary),
        ]
    }

    private func leakLine() -> String {
        var st = state.chainStat
        if st.leak_va == 0 { return "—" }
        return String(format: "0x%llx (%@)", st.leak_va, String(cString: nk_chain_leak_field(&st)))
    }

    private func verdictText() -> String {
        var st = state.chainStat
        return String(cString: nk_chain_verdict(&st))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                header
                pipeline
                controls
                metrics
                verdict
                LogView()
                    .environmentObject(state)
                    .modifier(TerminalPlatter())
            }
            .padding(16)
        }
        .navigationTitle(state.t("Kernel R/W chain", "Цепочка kernel R/W"))
        .navigationBarTitleDisplayMode(.inline)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("AIO kevent UAF → kernel read → blind write")
                .font(.headline)
            Text("23C55 · xnu-12377.62.10 · aio_workq_zonep 184 B · fixed in 26.3 "
                 + "(aio_entry_ref/unref + AIO_KEVENT_REGISTERED)")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color.secondary.opacity(0.08))
        .cornerRadius(10)
    }

    private var pipeline: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(ChainStage.allCases.enumerated()), id: \.element) { idx, stage in
                ChainNodeRow(stage: stage,
                             nodeState: nodeState(stage),
                             last: idx == ChainStage.allCases.count - 1)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color.secondary.opacity(0.06))
        .cornerRadius(10)
    }

    private var controls: some View {
        VStack(spacing: 10) {
            Stepper(value: $attempts, in: 1...300, step: 10) {
                HStack {
                    Text(state.t("Attempts", "Попыток"))
                    Spacer()
                    Text("\(attempts)")
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(.secondary)
                }
            }
            Button {
                state.runChain(attempts: attempts)
            } label: {
                HStack {
                    Image(systemName: "shield.lefthalf.filled")
                    Text(state.t("Run kernel R/W chain", "Прогнать цепочку kernel R/W"))
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
            }
            .buttonStyle(.borderedProminent)
            .disabled(state.running)

            HStack {
                Button {
                    state.runChain(attempts: 1)
                } label: {
                    Text(state.t("Single attempt", "Одна попытка"))
                }
                .buttonStyle(.bordered)
                .disabled(state.running)

                Button {
                    state.runChain(attempts: 300)
                } label: {
                    Text(state.t("Max", "Макс"))
                }
                .buttonStyle(.bordered)
                .disabled(state.running)
            }
        }
        .padding(12)
        .background(Color.secondary.opacity(0.06))
        .cornerRadius(10)
    }

    private var metrics: some View {
        VStack(spacing: 0) {
            ForEach(Array(metricItems().enumerated()), id: \.offset) { idx, item in
                ChainMetricRow(title: item.0, value: item.1, color: item.2)
                if idx < metricItems().count - 1 {
                    Divider()
                }
            }
            Divider()
            HStack {
                Text(state.t("Leak value", "Значение утечки"))
                    .font(.footnote)
                Spacer()
                Text(leakLine())
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundColor(state.chainStat.leak_va != 0 ? .green : .secondary)
            }
            .padding(.vertical, 7)
        }
        .padding(.horizontal, 12)
        .background(Color.secondary.opacity(0.06))
        .cornerRadius(10)
    }

    private var verdict: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(state.t("Verdict", "Вердикт"))
                .font(.subheadline.bold())
            Text(verdictText())
                .font(.caption)
                .foregroundColor(.secondary)
            Text(state.t("Durable log: Documents/aio_chain.log",
                         "Долговременный лог: Documents/aio_chain.log"))
                .font(.caption2)
                .foregroundColor(.secondary.opacity(0.8))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color.secondary.opacity(0.06))
        .cornerRadius(10)
    }
}

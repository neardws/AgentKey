// Placeholder SwiftUI multiplatform app (macOS / iOS / iPadOS). See App/README.md.
import SwiftUI
import AgentKeyCore

@main
struct AgentKeyApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}

struct ContentView: View {
    @State private var generated = PasswordGenerator.generate()
    var body: some View {
        NavigationStack {
            List {
                Section("AgentKey") {
                    Text("Agent-Native password & secrets manager for Apple devices")
                    Text("v0.1: vault UI coming in Phase 2").foregroundStyle(.secondary)
                }
                Section("Password generator") {
                    Text(generated).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    Button("Regenerate") { generated = PasswordGenerator.generate() }
                }
            }
            .navigationTitle("AgentKey")
        }
    }
}

import Testing

@testable import ShoesTunnel

/// The configuration is opaque on purpose: the consumer generates its YAML
/// elsewhere (KVN's is Kotlin) and the descriptor arrives as a parameter to
/// the engine, so nothing here parses or edits the document.
@Suite struct ShoesConfigurationTests {
    @Test func keepsTheDocumentVerbatim() {
        let yaml = "---\n- device_fd: 0\n  mtu: 9000\n"
        let config = ShoesConfiguration(yaml: yaml)
        #expect(config.yaml == yaml)
        #expect(config.logLevel == .info)
    }

    @Test func logLevelsSpellWhatShoesInitAccepts() {
        // shoes_init and shoes_set_log_level take exactly these strings.
        #expect(ShoesLogLevel.allCases.map(\.rawValue) == ["error", "warn", "info", "debug", "trace", "off"])
    }
}

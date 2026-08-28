/// Log verbosity, spelled the way `shoes_init` and `shoes_set_log_level`
/// accept it. Release builds of shoes compile with `release_max_level_info`,
/// so `debug` and `trace` behave as `info` unless the library was built with
/// those levels kept.
public enum ShoesLogLevel: String, Sendable, CaseIterable {
    case error, warn, info, debug, trace, off
}

/// What the engine is started with.
///
/// The YAML is carried verbatim. This type does not parse it, validate it or
/// inject the TUN descriptor -- the host that generated the document owns its
/// shape, and the descriptor goes to `ShoesEngine.start(_:deviceFD:)` as a
/// parameter, where `shoes_start_with_fd` sets it after parsing. A generator
/// may write `device_fd: 0` as a stand-in or omit the field.
public struct ShoesConfiguration: Sendable, Equatable {
    public let yaml: String
    public let logLevel: ShoesLogLevel

    public init(yaml: String, logLevel: ShoesLogLevel = .info) {
        self.yaml = yaml
        self.logLevel = logLevel
    }
}

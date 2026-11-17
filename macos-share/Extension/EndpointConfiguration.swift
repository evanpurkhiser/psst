import Foundation

enum EndpointConfiguration {
    static func load() throws -> URL {
        // A named lookup gets the account's home directory outside the sandbox container.
        guard let home = FileManager.default.homeDirectory(forUser: NSUserName()) else {
            throw ConfigurationError.homeUnavailable
        }

        let file = home.appendingPathComponent(".config/psst/helper.conf")
        let contents: String
        do {
            contents = try String(contentsOf: file, encoding: .utf8)
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            return URL(string: "https://psst.prk.network/sessions")!
        } catch {
            throw ConfigurationError.unreadable
        }

        let value = contents.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              let endpoint = URL(string: value),
              endpoint.scheme?.lowercased() == "https",
              let host = endpoint.host, !host.isEmpty,
              endpoint.fragment == nil else {
            throw ConfigurationError.invalidEndpoint
        }

        return endpoint
    }

    enum ConfigurationError: LocalizedError {
        case homeUnavailable
        case unreadable
        case invalidEndpoint

        var errorDescription: String? {
            switch self {
            case .homeUnavailable:
                return "Couldn’t locate your home directory."
            case .unreadable:
                return "Couldn’t read ~/.config/psst/helper.conf."
            case .invalidEndpoint:
                return "Put a single HTTPS endpoint URL in ~/.config/psst/helper.conf."
            }
        }
    }
}

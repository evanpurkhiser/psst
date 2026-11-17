import AppKit

final class ShareViewController: NSViewController {
    private let status = NSTextField(wrappingLabelWithString: "Sending to psst…")
    private lazy var closeButton = NSButton(title: "Close", target: self, action: #selector(close))

    override func loadView() {
        let size = NSSize(width: 320, height: 100)
        view = NSView(frame: NSRect(origin: .zero, size: size))
        preferredContentSize = size

        closeButton.isHidden = true
        let content = NSStackView(views: [status, closeButton])
        content.orientation = .vertical
        content.alignment = .leading
        content.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(content)

        NSLayoutConstraint.activate([
            content.topAnchor.constraint(equalTo: view.topAnchor, constant: 16),
            content.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            content.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
        ])
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        Task {
            await sendShare()
        }
    }

    private func sendShare() async {
        guard let context = extensionContext else {
            showFailure("The Share menu couldn’t pass the link to psst.")
            return
        }

        guard let share = await shareLink(in: context) else {
            showFailure("Share a 1Password item link to send it to psst.")
            return
        }

        do {
            var request = URLRequest(url: try EndpointConfiguration.load())
            request.httpMethod = "POST"
            request.timeoutInterval = 15
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONEncoder().encode(share)

            let session = URLSession(configuration: .ephemeral)
            defer { session.finishTasksAndInvalidate() }

            let (_, response) = try await session.data(for: request)
            guard let response = response as? HTTPURLResponse else {
                showFailure("psst returned an invalid response.")
                return
            }

            guard response.statusCode == 201 else {
                showFailure("psst couldn’t open the share link (HTTP \(response.statusCode)).")
                return
            }

            context.completeRequest(returningItems: nil, completionHandler: nil)
        } catch let error as EndpointConfiguration.ConfigurationError {
            showFailure(error.localizedDescription)
        } catch {
            showFailure("Couldn’t send the link to psst. Check your tailnet connection.")
        }
    }

    private func shareLink(in context: NSExtensionContext) async -> ShareLink? {
        let items = context.inputItems.compactMap { $0 as? NSExtensionItem }

        for provider in items.flatMap({ $0.attachments ?? [] }) {
            if let url = await load(NSURL.self, from: provider),
               let value = url.absoluteString,
               let share = ShareLink(value) {
                return share
            }

            if let text = await load(NSString.self, from: provider),
               let share = ShareLink(text as String) {
                return share
            }
        }

        return items.lazy.compactMap { item in
            item.attributedContentText.flatMap { ShareLink($0.string) }
        }.first
    }

    private func load<Item: NSItemProviderReading>(_ type: Item.Type, from provider: NSItemProvider) async -> Item? {
        guard provider.canLoadObject(ofClass: type) else {
            return nil
        }

        return await withCheckedContinuation { continuation in
            _ = provider.loadObject(ofClass: type) { item, _ in
                continuation.resume(returning: item as? Item)
            }
        }
    }

    private func showFailure(_ message: String) {
        status.stringValue = message
        closeButton.isHidden = false
    }

    @objc private func close() {
        extensionContext?.cancelRequest(withError: CocoaError(.userCancelled))
    }
}

private struct ShareLink: Encodable {
    let shareUrl: String

    init?(_ value: String) {
        let url = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let prefix = "https://share.1password.com/s#"
        guard url.hasPrefix(prefix), url.count > prefix.count else {
            return nil
        }

        shareUrl = url
    }
}

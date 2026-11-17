# Send to psst for macOS

Psst Share adds **Send to psst** to the macOS Share menu.
Selecting it sends the full 1Password share link to your psst server.

## Install

On a Mac with Xcode and XcodeGen, run these commands from this directory:

```sh
xcodegen generate
xcodebuild -project PsstShare.xcodeproj -scheme PsstShare -configuration Release \
  -derivedDataPath ~/Library/Developer/Xcode/DerivedData/PsstShare build
```

Copy
`~/Library/Developer/Xcode/DerivedData/PsstShare/Build/Products/Release/Psst Share.app`
to Applications and open it once.
Enable **Send to psst** in
**System Settings → General → Login Items & Extensions → Sharing**, then choose
it from 1Password’s **Share Link** menu.

Run `psst sessions` on the server to confirm the shared item is available.

## Configure the endpoint

By default, the extension posts to `https://psst.prk.network/sessions`.
To use a different server,
create `~/.config/psst/helper.conf` on your Mac with the complete HTTPS POST URL
on one line, including the path:

```text
https://psst.example.com/sessions
```

The extension reads the file each time you share a link.

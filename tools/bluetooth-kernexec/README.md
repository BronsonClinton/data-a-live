# Native Bluetooth exec hook

Applies an opt-in two-path exec redirection patch to the original open-source
XNU8796 source in the public yechenan buildtree. Replays that file's actual
Apple clang command without replacing any typed-allocator builtins. Publishes
only the open-source file's compiled object and build report. The fetched SDK
headers, firmware, images and Apple userland binaries are not uploaded.

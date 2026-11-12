# Bundled network engines

Fork Lite bundles separate command line programs in `vendor/bin` and in the `.app` so the downloaded app does not require Homebrew. They run as separate processes.

| Program | Version | Upstream source | License |
| --- | --- | --- | --- |
| sing-box | 1.14.3 | https://github.com/SagerNet/sing-box/tree/v1.14.3 | GPL-3.0-or-later |
| Xray-core | 26.3.27 | https://github.com/XTLS/Xray-core/tree/v26.3.27 | MPL-2.0 and CC-BY-SA-4.0 assets |
| amneziawg-go | 3.1.20260828 | https://github.com/amnezia-vpn/amneziawg-go/tree/v3.1.20260828 | MIT |
| amneziawg-tools (`awg`) | 3.1.20260812 | https://github.com/amnezia-vpn/amneziawg-tools/tree/v3.1.20260812 | GPL-2.0 |

The corresponding source archives and license texts are in this directory. `amneziawg-go` and `awg` were built for arm64 macOS from the exact upstream tags with `make` and `make -C src`. `sing-box` was built from the tagged source with `MACOSX_DEPLOYMENT_TARGET=14.0`, Go 1.26 and tags `with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api`. The Xray-core binary came from the matching Homebrew formula version, without local source changes. Their Go module dependencies are pinned in the source archives' `go.mod` and `go.sum` files.

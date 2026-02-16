# AirScap - AirScan bridge for legacy Wi-Fi ScanSnap scanner

ScanSnap iX500 の Wi-Fi プロトコル（VENS）を Go でネイティブ実装し、eSCL (AirScan) サーバーとして公開するブリッジ。

macOS Image Capture、sane-airscan (scanservjs)、Windows Scan など標準のスキャンクライアントから ScanSnap を利用可能にする。

## Architecture

```
eSCL Clients (macOS/Linux/Windows)
        │  HTTP (eSCL)
        ▼
┌──────────────────┐
│  mDNS (_uscan)   │  zeroconf
│  eSCL Server     │  go-mfp
│  ScanSnap Bridge │
│  VENS Protocol   │  native Go
└──────────────────┘
        │  Wi-Fi (UDP/TCP)
        ▼
   ScanSnap iX500
```

## Build

```bash
go build -o airscap ./cmd/airscap/
```

## Configuration

環境変数で設定。systemd の `EnvironmentFile=` と相性が良い。

| Variable | Required | Default | Description |
|---|---|---|---|
| `AIRSCAP_PASSWORD` | Yes* | - | スキャナのパスワード |
| `AIRSCAP_PASSWORD_FILE` | Yes* | - | パスワードファイルのパス |
| `AIRSCAP_SCANNER_IP` | No | auto-discover | スキャナの IP アドレス |
| `AIRSCAP_LISTEN_PORT` | No | `8080` | HTTP リッスンポート |
| `AIRSCAP_DEVICE_NAME` | No | `ScanSnap iX500` | mDNS 表示名 |

\* `AIRSCAP_PASSWORD` または `AIRSCAP_PASSWORD_FILE` のいずれかが必要。

## Usage

```bash
# Direct
AIRSCAP_PASSWORD=0700 ./airscap

# With specific scanner IP
AIRSCAP_PASSWORD=0700 AIRSCAP_SCANNER_IP=192.168.1.100 ./airscap
```

## Install (systemd)

```bash
# Build and install binary
go build -o /usr/local/bin/airscap ./cmd/airscap/

# Install service
sudo cp dist/airscap.service /etc/systemd/system/
sudo mkdir -p /etc/airscap
sudo cp dist/env.example /etc/airscap/env
sudo vi /etc/airscap/env  # Edit password and settings

sudo systemctl daemon-reload
sudo systemctl enable --now airscap
```

## Verify

```bash
# Check mDNS advertisement (macOS)
dns-sd -B _uscan._tcp

# Check eSCL capabilities
curl http://localhost:8080/eSCL/ScannerCapabilities

# Scan via sane-airscan
scanimage -L  # Should list the scanner
scanimage --device 'airscan:e0:ScanSnap iX500' --format=jpeg > scan.jpg
```

## License

MIT

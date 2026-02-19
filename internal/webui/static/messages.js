const MESSAGES = {
  // Card titles
  status:           { en: 'Status',           ja: 'ステータス' },
  deviceInfo:       { en: 'Device Info',      ja: 'デバイス情報' },
  capabilities:     { en: 'Capabilities',     ja: 'スキャン機能' },
  scanSettings:     { en: 'Scan Settings',    ja: 'スキャン設定' },
  saveDestination:  { en: 'Save Destination', ja: '保存先' },
  scan:             { en: 'Scan',             ja: 'スキャン' },
  esclEndpoint:     { en: 'eSCL Endpoint',    ja: 'eSCL エンドポイント' },

  // Status
  disconnectWarn:   { en: 'Scanner disconnected. Attempting to reconnect...', ja: 'スキャナーとの接続が切れています。再接続を試みています...' },
  connection:       { en: 'Connection',   ja: '接続' },
  paperLoaded:      { en: 'Paper loaded', ja: '用紙あり' },
  noPaper:          { en: 'No paper',     ja: '用紙なし' },
  lastUpdated:      { en: 'Last updated', ja: '最終更新' },

  // Device info
  name:             { en: 'Name',         ja: '名前' },
  serial:           { en: 'Serial',       ja: 'シリアル' },
  ipAddress:        { en: 'IP Address',   ja: 'IP アドレス' },
  manufacturer:     { en: 'Manufacturer', ja: 'メーカー' },
  fwRevision:       { en: 'F/W Revision', ja: 'F/W リビジョン' },

  // Capabilities
  resolution:       { en: 'Resolution',    ja: '解像度' },
  color:            { en: 'Color',         ja: 'カラー' },
  duplex:           { en: 'Duplex',        ja: '両面' },
  supported:        { en: 'Supported',     ja: '対応' },
  notSupported:     { en: 'Not supported', ja: '非対応' },
  outputFormat:     { en: 'Output Format', ja: '出力形式' },

  // Scan settings
  colorMode:        { en: 'Color Mode',    ja: 'カラーモード' },
  saved:            { en: 'Saved',         ja: '保存済み' },
  saveFailed:       { en: 'Save failed',   ja: '保存失敗' },
  singleSided:      { en: 'Single-sided',  ja: '片面スキャン' },
  doubleSided:      { en: 'Double-sided',  ja: '両面スキャン' },

  // Save destination
  disabled:         { en: 'Disabled',       ja: '保存しない' },
  localFolder:      { en: 'Local Folder',   ja: 'ローカルフォルダ' },
  saveDir:          { en: 'Save Directory', ja: '保存ディレクトリ' },
  saveDirHelp:      { en: 'Directory to save files when scanner button is pressed', ja: 'スキャナのボタンを押した時にファイルを保存するディレクトリ' },
  ftpAddress:       { en: 'FTP Address',    ja: 'FTP アドレス' },
  ftpHostHelp:      { en: 'hostname:port (default port 21)', ja: 'ホスト名:ポート（ポート省略時は 21）' },
  username:         { en: 'Username',       ja: 'ユーザー名' },
  password:         { en: 'Password',       ja: 'パスワード' },
  paperlessBaseUrl: { en: 'Paperless-ngx base URL', ja: 'Paperless-ngx のベース URL' },
  apiToken:         { en: 'API Token',      ja: 'API トークン' },
  apiTokenHelp:     { en: 'Get from Settings > API Token', ja: '設定 > API トークン から取得' },

  // Scan job
  scanning:         { en: 'Scanning...',   ja: 'スキャン中...' },
  pagesSaved:       { en: ' pages saved',  ja: ' ページ保存完了' },
  scanFailed:       { en: 'Scan failed',   ja: 'スキャン失敗' },

  // eSCL
  esclHelp:         { en: 'Available from Linux SANE / macOS Image Capture / Windows WSD', ja: 'Linux SANE / macOS Image Capture / Windows WSD から利用できます' },

  // Color modes
  modeAuto:         { en: 'Auto',        ja: '自動' },
  modeColor:        { en: 'Color',       ja: 'カラー' },
  modeGrayscale:    { en: 'Grayscale',   ja: 'グレースケール' },
  modeBW:           { en: 'B&W',         ja: '白黒' },
};

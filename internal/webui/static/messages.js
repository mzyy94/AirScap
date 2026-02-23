const MESSAGES = {
  // Card titles
  status:           { en: 'Status',           ja: 'ステータス' },
  deviceInfo:       { en: 'Device Info',      ja: 'デバイス情報' },
  capabilities:     { en: 'Capabilities',     ja: 'スキャン機能' },
  scanSettings:     { en: 'Button Scan Settings', ja: 'ボタンスキャン設定' },
  saveDestination:  { en: 'Save Destination', ja: '保存先' },
  scan:             { en: 'Scan',             ja: 'スキャン' },
  esclEndpoint:     { en: 'eSCL Endpoint',    ja: 'eSCL エンドポイント' },

  // Status
  disconnectWarn:   { en: 'Scanner disconnected. Attempting to reconnect...', ja: 'スキャナーとの接続が切れています。再接続を試みています...' },
  connection:       { en: 'Connection',   ja: '接続' },
  paperLoaded:      { en: 'Paper loaded', ja: '用紙あり' },
  noPaper:          { en: 'No paper',     ja: '用紙なし' },
  wifiSignal:       { en: 'Wi-Fi Signal', ja: 'Wi-Fi 強度' },
  lastUpdated:      { en: 'Last updated', ja: '最終更新' },
  adfErr_jam:       { en: 'Paper jam',    ja: '紙詰まり' },
  adfErr_hatchOpen: { en: 'Cover open',   ja: 'カバーオープン' },
  adfErr_multiFeed: { en: 'Multi-feed',   ja: '重送検知' },
  adfErr_error:     { en: 'Scanner error', ja: 'スキャナーエラー' },

  // Device info
  name:             { en: 'Name',         ja: '名前' },
  serial:           { en: 'Serial',       ja: 'シリアル' },
  ipAddress:        { en: 'IP Address',   ja: 'IP アドレス' },
  fwRevision:       { en: 'F/W Revision', ja: 'F/W リビジョン' },
  wifi_strong:      { en: 'Strong',       ja: '強い' },
  wifi_normal:      { en: 'Normal',       ja: '普通' },
  wifi_weak:        { en: 'Weak',         ja: '弱い' },
  wifi_disconnected:{ en: 'Disconnected', ja: '未接続' },
  wifi_unknown:     { en: 'Unknown',      ja: '不明' },

  // Capabilities
  resolution:       { en: 'Resolution',    ja: '解像度' },
  color:            { en: 'Color',         ja: 'カラー' },
  duplex:           { en: 'Duplex',        ja: '両面' },
  supported:        { en: 'Supported',     ja: '対応' },
  notSupported:     { en: 'Not supported', ja: '非対応' },
  outputFormat:     { en: 'Output Format', ja: '出力形式' },

  // Scan settings
  colorMode:        { en: 'Color Mode',              ja: 'カラーモード' },
  saved:            { en: 'Saved',                   ja: '保存済み' },
  saveFailed:       { en: 'Save failed',             ja: '保存失敗' },
  singleSided:      { en: 'Single-sided',            ja: '片面スキャン' },
  doubleSided:      { en: 'Double-sided',            ja: '両面スキャン' },
  blankPageRemoval: { en: 'Blank page removal',      ja: '白紙ページスキップ' },
  bleedThrough:     { en: 'Bleed-through reduction', ja: '裏写り軽減' },
  bwDensity:        { en: 'B&W Density',             ja: '白黒濃度' },
  compression:      { en: 'JPEG Quality',            ja: 'JPEG 画質' },
  compBest:         { en: 'Best',                   ja: '高画質' },
  compStandard:     { en: 'Standard',               ja: '標準' },
  compSmall:        { en: 'Small',                  ja: '小サイズ' },

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

  // Paper size
  paperSize:        { en: 'Paper Size',    ja: '用紙サイズ' },
  paper_auto:       { en: 'Auto',          ja: '自動' },
  paper_a4:         { en: 'A4',            ja: 'A4' },
  paper_a5:         { en: 'A5',            ja: 'A5' },
  paper_business_card: { en: 'Biz Card',   ja: '名刺' },
  paper_postcard:   { en: 'Postcard',      ja: 'はがき' },

  // AirScan settings
  airscanSettings:           { en: 'AirScan Settings',        ja: 'AirScan 設定' },
  airscanForcePaperAuto:     { en: 'Auto paper size detect',  ja: '用紙サイズ自動検出' },
  airscanForcePaperAutoHelp: { en: 'Ignore paper size specified by AirScan clients and always use auto-detect. Takes effect on the next scan.', ja: 'AirScan クライアントが指定した用紙サイズを無視し、常に自動検出を使用する。次回のスキャンから反映されます。' },
  airscanBleedThrough:       { en: 'Bleed-through reduction', ja: '裏写り軽減' },
  airscanBleedThroughHelp:   { en: 'Apply bleed-through reduction to AirScan scans.', ja: 'AirScan スキャンに裏写り軽減を適用する。' },
  airscanBwDensity:          { en: 'B&W Density',             ja: '白黒濃度' },
  airscanBwDensityHelp:      { en: 'Default B&W density for AirScan clients that don\'t specify threshold.', ja: 'Threshold を指定しない AirScan クライアント用の白黒濃度デフォルト値。' },

  // Browser scan
  scanNow:          { en: 'Scan & Preview',                 ja: 'スキャンしてプレビュー' },
  scanResult:       { en: 'Scan Result',                    ja: 'スキャン結果' },
  downloadPage:     { en: 'Download Page',                  ja: 'ページをダウンロード' },
  close:            { en: 'Close',                          ja: '閉じる' },
};

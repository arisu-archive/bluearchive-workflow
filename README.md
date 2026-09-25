# 🎮 Blue Archive Workflow

<div align="center">

<picture><img src="https://img.shields.io/badge/dynamic/yaml?url=https%3A%2F%2Fba.pokeguy.dev%2Fcom.nexon.bluearchive%2Fversion.txt&query=%24&prefix=v&style=for-the-badge&logo=nexon&label=Global&color=0099ff" alt="Nexon BlueArchive Latest Version" style="visibility:visible;max-width:100%;"></picture><picture><img src="https://img.shields.io/badge/dynamic/yaml?url=https%3A%2F%2Fba.pokeguy.dev%2Fcom.YostarJP.BlueArchive%2Fversion.txt&query=%24&prefix=v&style=for-the-badge&logo=googleplay&label=Yostar&color=7d3cc8" alt="Yostar BlueArchive Latest Version" style="visibility:visible;max-width:100%;"></picture>

<picture><img src="https://img.shields.io/badge/Made_with-Il2CppInspectorRedux-5cb85c?style=for-the-badge" alt="Made with Il2CppInspectorRedux" style="visibility:visible;max-width:100%;"></picture><picture><img src="https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go" style="visibility:visible;max-width:100%;"></picture><picture><img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" style="visibility:visible;max-width:100%;"></picture><picture><img src="https://img.shields.io/badge/Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white" alt="Bash" style="visibility:visible;max-width:100%;"></picture>

</div>

## 🚀 Overview

Automated pipeline that downloads, decompiles, and archives Blue Archive game APKs to S3 using AWS CLI in scheduled GitHub Actions. Keep track of game updates, analyze changes, and maintain a complete historical archive without manual intervention.

### ✨ Key Features

- **🔄 Automated Monitoring**: Track game updates with configurable schedules
- **📊 Version Control**: Maintain complete history of APK versions with detailed changelogs
- **🧩 Deep Decompilation**: Extract source code, assets, and resources automatically
- **☁️ Cloud Storage**: Securely archive all artifacts to S3 with intelligent retention policies
- **📱 Multi-Region Support**: Track both Global (Nexon) and Japan (Yostar) game versions

## 📋 Prerequisites

- GitHub account with Actions enabled
- S3-compatible `bluearchive` bucket configured
- IAM credentials with appropriate permissions
- APK source endpoints (configured for Blue Archive)

## ⚙️ Setup Instructions

### 1. Repository Configuration

```bash
# Clone this repository
git clone https://github.com/arisu-archive/blue-archive-workflow.git
cd blue-archive-workflow
```

### 2. GitHub Secrets Configuration

Configure the following secrets and variable in your GitHub repository:

| Secret Name    | Description            |
|----------------|------------------------|
| `S3_ACCESS_KEY` | S3 access key (secret) |
| `S3_SECRET_KEY` | S3 secret key (secret) |
| `S3_ENDPOINT`   | S3-compatible endpoint URL (variable) |

### 3. Workflow Configuration

Reference `.github/workflows/global.yml` and `.github/workflows/japan.yml` for the full workflow.

```yaml
schedule:
  # Check every 6 hours
  - cron: '0 */6 * * *'
```

## 🔍 How It Works

1. **Scheduling**: GitHub Actions triggers the workflow on a defined schedule
2. **Version Check**: System compares latest available APK with last archived version
3. **Download**: If new version is detected, APK is downloaded from official sources
4. **Metadata Extraction**: Version info, file hashes, and timestamps are recorded
5. **Decompilation**: Advanced tools extract code, assets, and configuration files
6. **Storage**: All artifacts are organized and uploaded to S3 with proper metadata

## 📁 Repository Structure

```
├── .github/
│   ├── actions/
│   │   ├── apk_inspector/
│   │   │   └── action.yml       # Action definition
│   ├── workflows/
│   │   ├── global.yml           # Global workflow
│   │   └── japan.yml            # Japan workflow
├── scripts/
│   ├── download.sh              # APK downloader
│   ├── extract-version.sh       # Version extractor
│   ├── decompile.sh             # Decompilation utilities
│   ├── upload.sh                # S3 upload handler
│   └── dump_config.py           # Config file analyzer
├── LICENSE                      # MIT License
└── README.md                    # This file
```

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for legitimate research, analysis, and monitoring purposes only. Always ensure you comply with the terms of service of any application you analyze and all relevant laws and regulations.

## 📬 Contact & Support

- Create an [Issue](https://github.com/arisu-archive/blue-archive-workflow/issues) for bug reports or feature requests
- Star ⭐ the repo if you find it useful
- Follow for updates on new features and improvements

---

<div align="center">
<strong>Built with ❤️ for the Blue Archive community</strong>
</div>

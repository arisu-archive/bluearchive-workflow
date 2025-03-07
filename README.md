# Blue Archive Workflow

Automated pipeline that downloads, decompiles, and archives game APKs to S3 using scheduled GitHub Actions.

## Overview

This repository contains a CI/CD pipeline that automatically tracks, analyzes, and archives game APK files. Using GitHub Actions with cron scheduling, the workflow regularly:

1. Fetches the latest version of target game APK files
2. Extracts version information and metadata
3. Decompiles APK contents for analysis
4. Uploads the original APK, version data, and decompiled files to S3 storage

Designed for monitoring game updates, performing security analysis, or tracking implementation changes over time.

## Features

- **Automated Monitoring**: Track game updates without manual intervention
- **Version History**: Maintain a complete history of APK versions
- **Decompilation**: Automatically extract source code and resources
- **Secure Storage**: Archive all artifacts to S3 for long-term storage
- **Configurable Schedule**: Adjust monitoring frequency as needed
- **Notification Support**: Optional alerts for new versions (via email, Slack, etc.)

## Prerequisites

- GitHub account with Actions enabled
- S3 bucket configured
- Target APK source (URL or API endpoint)

## Setup Instructions

### 1. Repository Configuration

1. Fork or clone this repository
2. Configure GitHub secrets:
   - `S3_ACCESS_KEY`: Your S3 access key
   - `S3_SECRET_KEY`: Your S3 secret key

### 2. Workflow Configuration

Edit `.github/workflows/apk-inspector.yml` to customize:

- Schedule frequency (cron expression)
- APK sources
- Decompilation options
- S3 storage paths

### 3. S3 Bucket Setup

Ensure your S3 bucket has:
- Appropriate lifecycle policies
- Versioning enabled (recommended)
- Correct IAM permissions

## How It Works

1. **Scheduling**: GitHub Actions triggers the workflow based on the defined cron schedule
2. **Download**: The workflow fetches the latest APK from the configured source
3. **Version Extraction**: APK is analyzed to extract version and metadata
4. **Decompilation**: Tools like JADX or APKTool are used to decompile the APK
5. **Storage**: Original APK, metadata, and decompiled files are organized and uploaded to S3
6. **Notification**: Optional alerts are sent if configured

## Workflow Structure

```
.github/
  workflows/
    apk-inspector.yml  # Main workflow definition
scripts/
  download.sh          # APK download script
  extract-version.sh   # Version extraction utilities
  decompile.sh         # Decompilation process
  upload.sh            # S3 upload handler
  dump_config.py       # Dump the GameMainConfig.bytes file
```

## Example Usage

### Custom Scheduling

```yaml
# .github/workflows/global.yml
on:
  schedule:
    # Check every day at 2 AM UTC
    - cron: '0 2 * * *'
  workflow_dispatch:  # Allow manual triggering
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for legitimate research, analysis, and monitoring purposes only. Always ensure you comply with the terms of service of any application you analyze and all relevant laws and regulations.

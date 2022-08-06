# Fennec v0.3.3
* Added support to SCP protocol in artifact package upload feature
* Fixes #8
# Fennec v0.3.2
* Added aarch64 build to CI workflow
* Miner modifications
* Dependencies pump up
# Fennec v0.3.1
* Reimplement S3 artifact package upload code to fix static compilation issue
* Remove SCP artifact package upload implementation to fix static compilation issue
# Fennec v0.3.0
* Added capability to upload artifact package to remote server. Supported protocols are s3, aws3 and scp
# Fennec v0.2.2
* Fixes issue #6
* Pump up dependencies
# Fennec v0.2.1
* Fixes issue #5
# Fennec v0.2.0
* Added support for `macos`
* Added support for `Linux aarch64` architecture
* Added `show-embedded` argument to show embedded files
* Support running Fennec without `query` artifacts. if osquery binary not specified a warning will be shown and `query` artifact will be ignored
# Fennec v0.1.0
Initial release
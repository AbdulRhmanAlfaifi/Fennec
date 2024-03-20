# Fennec v0.4.1
Added sginal handling (CTRL+C) and the capability to run Fennec as non root

* Added signal handling for SIGINT (CTRL+C), SIGTERM and SIGHUP. When any of these signals are sent, Fennec will stop collecting artifacts and start cleanup
* Added the option '--non-root' to add the capability of running Fennec with non root permissions (not recommended, but you have the option :D)
* Small changes to the help message
# Fennec v0.4.0
* Added feature to parse the output of the `command` artifact
* Replaced the artifact `file_list` from `query` type to `command`
* Added `to_int` modifier to parse string fields to `i64`
* Added `schema.json` which is a schema definition for the fennec configuration
* Changed the configuration file name from `config.yaml` to `fennec.yaml` so it works better with the schema file
* Small change to `push_to_es.py` script
# Fennec v0.3.5
Update MacOS configuration file, closes #7

* Remove `apt_sources` artifact (This is only for Debian based Linux systems)
* Remove `deb_packages` artifact (This is only for Debian based Linux systems)
* Added `apps` artifact to retrive installed applications
* Modified `file_list` artifact to replace the directory for users (/Users insted of /home)
* Remove `iptables` artifact
* Added `alf` artifact (Application Layer Firewall)
* Modifed `logged_in_users` artifact to add more data to the result
* Remove `rpm_packages` artifact (This is only for RedHat based Linux systems)
* Added `homebrew_packages` artifact to retrive packages installed using `homebrew`
* Removed `selinux_settings` artifact
* Removed `yum_sources` artifact (This is only for RedHat based Linux systems)
* Added `asl` artifact, retrive system logs
* Added `wifi_networks` artifact, list known/remembered Wi-Fi networks
* Added `time_machine` artifact, Retrive TimeMachine backup info
* Added `shared_folders` artifact, retrive configured shared folders on the system
* Added `keychain_acls` & `keychain_items` artifacts, contains information about the keychain
* Added `bad_logins` artifact, to retrive faild logins
* Added `nfs_shares` artifact, to retrive mounted shares
* Added `launchd` artifact, to retrive servies that run at startup
* Added the path `/private/var/log` to the artifact `logs`
* Added the following artifacts:
        * `loginwindow` : persistence artifacts
        * `alf_exceptions` : Firewall exceptions
        * `alf_services` : Fireqall services
        * `alf_explicit_auths`
        * `kextstat`
        * `ip_forwarding`
        * `recent_items`
        * `ramdisk`
        * `disk_encryption`
        * `app_schemes`
        * `sandboxes`
# Fennec v0.3.4
* Fixes #9
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
use core::result::Result;
use log::*;
use regex::Regex;
use remotefs::RemoteFs;
use remotefs_aws_s3::AwsS3Fs;
use remotefs_ssh::{ScpFs, SshOpts};
use std::fmt::Debug;
use std::fs::File;
use std::path::Path;

use crate::errors::FennecError;

/// Fennec supported proctocols to uploaded artifact packages
#[derive(Debug)]
pub enum UploadSupportedProtocols {
    S3(S3Config),
    AWS3(AWS3Config),
    SCP(SCPConfig),
}

/// Configuration for S3 bucket. This struct used to save self hosted S3 server (tested on MinIO) configurations.
pub struct S3Config {
    protocol: String,
    access_key: String,
    secret_access_key: String,
    hostname: String,
    port: u16,
    bucket_name: String,
    path: String,
}

impl Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "endpoint: '{}://{}:{}', bucket_name: '{}', path: '{}'",
            &self.protocol, &self.hostname, &self.port, &self.bucket_name, &self.path
        ))
    }
}

/// Configuration for AWS S3 bucket. This struct used to save Amazon Web Serive S3 buckets configurations.
pub struct AWS3Config {
    access_key: String,
    secret_access_key: String,
    regoin: String,
    bucket_name: String,
    path: String,
}

impl Debug for AWS3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "regoin: '{}', bucket_name: '{}', path: '{}'",
            &self.regoin, &self.bucket_name, &self.path
        ))
    }
}

/// Configuration for remote server SSH service.
pub struct SCPConfig {
    username: String,
    password: String,
    hostname: String,
    port: u16,
    path: String,
}

impl Debug for SCPConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "endpoint: '{}@{}:{}', path: '{}'",
            &self.username, &self.hostname, &self.port, &self.path
        ))
    }
}

/// This struct is responsable to parse upload configuration string & upload the artifact package to the remote server.
#[derive(Debug)]
pub struct UploadArtifacts {
    config: UploadSupportedProtocols,
}

impl UploadArtifacts {
    /// Take the upload configuration as string, parse it then return an instance of the struct `UploadArtifacts`, Supported protocols are:
    /// * `s3` : Upload artifact package to S3 bucket
    ///     * `Format` : s3://`<ACCESS_KEY>`:`<SECRET_ACCESS_KEY>`@`(http|https)`://`<HOSTNAME>`:`<PORT>`/`<BUCKET_NAME>`:`<PATH>`
    ///     * `Example`: s3://minioadmin:minioadmin@http://192.168.100.190:9000/fennec:/
    /// * `aws3` : Upload artifact package to AWS S3 bucket
    ///     * `Format` : aws3://`<ACCESS_KEY>`:`<SECRET_ACCESS_KEY>`@`<REGOIN>`.`<BUCKET_NAME>`:`<PATH>`
    ///     * `Example`: aws3://AKIAXXXXXXXXXXXXXXXXX:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX@us-east-1.fennecbucket:/
    /// * `scp` : Upload artifact package to a remote server using SCP protocol
    ///     * `Format` : scp://`<USERNAME>`:`<PASSWORD>`@`<HOSTNAME>`:`<PORT>`:`<PATH>`
    ///     * `Example`: scp://u0041:password@192.168.100.190:/fennec
    pub fn new(config: &str) -> Result<Self, FennecError> {
        let protocol = Regex::new("(?P<protocol>(aws3|s3|scp))")
            .unwrap()
            .captures(config)
            .unwrap()
            .name("protocol")
            .unwrap()
            .as_str();

        info!("Using '{}' protocol to upload the artifacts", protocol);

        let re = match protocol {
            "s3" => {
                let regex = "(?P<protocol>s3)://(\")?(?P<access_key>[^\":]+)(\")?:(\")?(?P<secret_access_key>[^\":]+)(\")?@(?P<proto>(http|https))://(?P<hostname>[a-zA-Z0-9\\-\\.]+):(?P<port>[0-9]+)/(?P<bucket_name>[a-zA-Z0-9\\-]+):(?P<path>[a-zA-Z0-9\\.\\-_/]+)";
                Regex::new(regex).unwrap()
            }
            "aws3" => {
                let regex = "(?P<protocol>aws3)://(\")?(?P<access_key>[^\":]+)(\")?:(\")?(?P<secret_access_key>[^\":]+)(\")?@(?P<regoin>[a-zA-Z0-9\\-]+)\\.(?P<bucket_name>[a-zA-Z0-9\\-]+):(?P<path>[a-zA-Z0-9\\.\\-_/]+)";
                Regex::new(regex).unwrap()
            }
            "scp" => {
                let regex = "(?P<protocol>scp)://(\")?(?P<username>[^\":]+)(\")?:(\")?(?P<password>[^\":]+)(\")?@(?P<hostname>[a-zA-Z0-9\\-\\.]+)(:)?(?P<port>[0-9]+)?:(?P<path>[a-zA-Z0-9\\.\\-_/~]+)";
                Regex::new(regex).unwrap()
            }
            _ => Regex::new("(?P<protocol>[^:])").unwrap(),
        };

        match re.captures(config) {
            Some(captures) => match captures.name("protocol") {
                Some(protocol) => match protocol.as_str() {
                    "s3" => {
                        let protocol = captures.name("proto").unwrap().as_str().to_string();
                        let access_key = captures.name("access_key").unwrap().as_str().to_string();
                        let secret_access_key = captures
                            .name("secret_access_key")
                            .unwrap()
                            .as_str()
                            .to_string();
                        let hostname = captures.name("hostname").unwrap().as_str().to_string();
                        let port = captures
                            .name("port")
                            .unwrap()
                            .as_str()
                            .to_string()
                            .parse::<u16>()
                            .unwrap();
                        let bucket_name =
                            captures.name("bucket_name").unwrap().as_str().to_string();
                        let path = captures.name("path").unwrap().as_str().to_string();

                        let config = UploadSupportedProtocols::S3(S3Config {
                            protocol,
                            access_key,
                            secret_access_key,
                            hostname,
                            port,
                            bucket_name,
                            path,
                        });

                        info!(
                            "Using the configuration '{:?}' to upload the artifacts",
                            config
                        );

                        return Ok(UploadArtifacts { config });
                    }
                    "aws3" => {
                        let access_key = captures.name("access_key").unwrap().as_str().to_string();
                        let secret_access_key = captures
                            .name("secret_access_key")
                            .unwrap()
                            .as_str()
                            .to_string();
                        let regoin = captures.name("regoin").unwrap().as_str().to_string();
                        let bucket_name =
                            captures.name("bucket_name").unwrap().as_str().to_string();
                        let path = captures.name("path").unwrap().as_str().to_string();

                        let config = UploadSupportedProtocols::AWS3(AWS3Config {
                            access_key,
                            secret_access_key,
                            regoin,
                            bucket_name,
                            path,
                        });

                        info!(
                            "Using the configuration '{:?}' to upload the artifacts",
                            config
                        );

                        return Ok(UploadArtifacts { config });
                    }
                    "scp" => {
                        let username = captures.name("username").unwrap().as_str().to_string();
                        let password = captures.name("password").unwrap().as_str().to_string();
                        let hostname = captures.name("hostname").unwrap().as_str().to_string();

                        let path = captures.name("path").unwrap().as_str().to_string();
                        let port = match captures.name("port") {
                            Some(port) => port.as_str().to_string().parse::<u16>().unwrap(),
                            None => 22,
                        };
                        let config = UploadSupportedProtocols::SCP(SCPConfig {
                            username,
                            password,
                            hostname,
                            port,
                            path,
                        });

                        info!(
                            "Using the configuration '{:?}' to upload the artifacts",
                            config
                        );

                        return Ok(UploadArtifacts { config });
                    }
                    _ => {
                        return Err(FennecError::upload_config_error("protocol not supported in upload artifacts. Supported protocol are s3, aws3 and scp.".to_string()));
                    }
                },
                None => {
                    return Err(FennecError::upload_config_error(
                        "upload artifacts configurations format issue".to_string(),
                    ));
                }
            },
            None => {
                return Err(FennecError::upload_config_error(
                    "upload artifacts configurations format issue".to_string(),
                ));
            }
        }
    }

    /// Upload the file specified in the argument `path` to the remote server specified in the `config` field.
    pub fn upload(&self, path: impl AsRef<Path>) -> Result<bool, FennecError> {
        match &self.config {
            UploadSupportedProtocols::S3(config) => {
                let mut client = AwsS3Fs::new(&config.bucket_name)
                    .access_key(&config.access_key)
                    .secret_access_key(&config.secret_access_key)
                    .endpoint(format!(
                        "{}://{}:{}",
                        &config.protocol, &config.hostname, &config.port
                    ))
                    .new_path_style(true);

                if let Err(e) = client.connect() {
                    return Err(FennecError::upload_error(format!(
                        "Unable to connect to the endpoints '{}://{}:{}', ERROR: {}",
                        config.protocol, config.hostname, config.port, e
                    )));
                }

                let mut file = match File::open(&path) {
                    Ok(file) => file,
                    Err(e) => {
                        return Err(FennecError::upload_error(format!(
                            "Unable to open the file '{}', ERROR: {}",
                            path.as_ref().to_str().unwrap(),
                            e
                        )));
                    }
                };

                info!(
                    "Uploading artifact package '{}' to the bucket '{}' with the path '{}'",
                    path.as_ref().to_str().unwrap(),
                    config.bucket_name,
                    config.path
                );

                match client.bucket().unwrap().put_object_stream(
                    &mut file,
                    format!(
                        "{}{}",
                        &config.path,
                        &path.as_ref().file_name().unwrap().to_str().unwrap()
                    ),
                ) {
                    Ok(status_code) => {
                        if status_code == 200 {
                            if let Err(e) = client.disconnect() {
                                return Err(FennecError::upload_error(format!(
                                    "Unable to disconnect from the endpoints '{}://{}:{}', ERROR: {}",
                                    config.protocol, config.hostname, config.port, e
                                )));
                            }
                            return Ok(true);
                        } else {
                            return Err(FennecError::upload_error(format!(
                                    "Unable to upload the object '{}' to the bucket '{}', ERROR: status code '{}'",
                                    &path.as_ref().file_name().unwrap().to_str().unwrap(),
                                    config.bucket_name,
                                    status_code
                                )));
                        }
                    }
                    Err(e) => {
                        return Err(FennecError::upload_error(format!(
                            "Unable to upload the object '{}' to the bucket '{}', ERROR: {}",
                            &path.as_ref().file_name().unwrap().to_str().unwrap(),
                            config.bucket_name,
                            e
                        )));
                    }
                }
            }
            UploadSupportedProtocols::AWS3(config) => {
                let mut client = AwsS3Fs::new(&config.bucket_name)
                    .access_key(&config.access_key)
                    .secret_access_key(&config.secret_access_key)
                    .region(&config.regoin)
                    .profile("default");

                if let Err(e) = client.connect() {
                    return Err(FennecError::upload_error(format!(
                        "Unable to connect to AWS S3 bucket '{}', ERROR: {}",
                        config.bucket_name, e
                    )));
                }

                let mut file = match File::open(&path) {
                    Ok(file) => file,
                    Err(e) => {
                        return Err(FennecError::upload_error(format!(
                            "Unable to open the file '{}', ERROR: {}",
                            path.as_ref().to_str().unwrap(),
                            e
                        )));
                    }
                };

                info!(
                    "Uploading artifact package '{}' to the bucket '{}' with the path '{}'",
                    path.as_ref().to_str().unwrap(),
                    config.bucket_name,
                    config.path
                );

                match client.bucket().unwrap().put_object_stream(
                    &mut file,
                    format!(
                        "{}{}",
                        &config.path,
                        &path.as_ref().file_name().unwrap().to_str().unwrap()
                    ),
                ) {
                    Ok(status_code) => {
                        if status_code == 200 {
                            if let Err(e) = client.disconnect() {
                                return Err(FennecError::upload_error(format!(
                                    "Unable to connect to AWS S3 bucket '{}', ERROR: {}",
                                    config.bucket_name, e
                                )));
                            }
                            return Ok(true);
                        } else {
                            return Err(FennecError::upload_error(format!(
                                        "Unable to upload the object '{}' to the bucket '{}', ERROR: status code '{}'",
                                        &path.as_ref().file_name().unwrap().to_str().unwrap(),
                                        config.bucket_name,
                                        status_code
                                    )));
                        }
                    }
                    Err(e) => {
                        return Err(FennecError::upload_error(format!(
                            "Unable to upload the object '{}' to the bucket '{}', ERROR: {}",
                            &path.as_ref().file_name().unwrap().to_str().unwrap(),
                            config.bucket_name,
                            e
                        )));
                    }
                }
            }
            UploadSupportedProtocols::SCP(config) => {
                let options = SshOpts::new(&config.hostname)
                    .username(&config.username)
                    .password(&config.password)
                    .port(config.port);

                let mut client = ScpFs::new(options);

                if let Err(e) = client.connect() {
                    return Err(FennecError::upload_error(format!(
                        "Unable to connect to '{}@{}:{}', ERROR: {}",
                        config.username, config.hostname, config.port, e
                    )));
                }

                let file = match File::open(&path) {
                    Ok(file) => file,
                    Err(e) => {
                        return Err(FennecError::upload_error(format!(
                            "Unable to open the file '{}', ERROR: {}",
                            path.as_ref().to_str().unwrap(),
                            e
                        )));
                    }
                };

                let metadata =
                    remotefs::fs::Metadata::default().size(file.metadata().unwrap().len());

                let remote_path = Path::new(&config.path);

                if let Err(e) = client.change_dir(remote_path) {
                    return Err(FennecError::upload_error(format!(
                        "Unable to change directory to '{}', ERROR: {}",
                        remote_path.to_str().unwrap(),
                        e
                    )));
                }

                info!(
                    "Uploading artifact package '{}' to '{}'",
                    path.as_ref().to_str().unwrap(),
                    config.path
                );

                let transfer_size = client
                    .create_file(
                        path.as_ref()
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .as_ref(),
                        &metadata,
                        Box::new(file),
                    )
                    .unwrap();

                info!(
                    "Successfully uploaded artifact package '{}' to '{}' with the file size '{}'",
                    path.as_ref().to_str().unwrap(),
                    config.path,
                    transfer_size
                );

                Ok(true)
            }
        }
    }
}

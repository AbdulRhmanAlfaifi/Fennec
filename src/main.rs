use clap::{App, Arg};
use colored::*;
use fennec::upload::UploadArtifacts;
use fennec::{Fennec, OutputFormat};
use log::*;
use log4rs::{
    append::{
        console::{ConsoleAppender, Target},
        file::FileAppender,
    },
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};
use nix::unistd::Uid;
use rust_embed::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Cursor, Read, Write},
    process::exit,
    time::Instant,
};
use zip::{write::FileOptions, CompressionMethod, ZipWriter};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(RustEmbed)]
#[folder = "deps/linux/"]
#[include = "config.yaml"]
#[include = "x86_64/osqueryd"]
#[prefix = ""]
struct Asset;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[derive(RustEmbed)]
#[folder = "deps/linux/"]
#[include = "config.yaml"]
#[include = "aarch64/osqueryd"]
#[prefix = ""]
struct Asset;
#[cfg(target_os = "freebsd")]
#[derive(RustEmbed)]
#[folder = "deps/freebsd"]
#[prefix = ""]
struct Asset;
#[cfg(target_os = "macos")]
#[derive(RustEmbed)]
#[folder = "deps/darwin"]
#[prefix = ""]
struct Asset;

fn init_logger(log_path: &str, level: log::LevelFilter, quiet: bool) -> log4rs::Handle {
    let log_format = "{d(%Y-%m-%d %H:%M:%S)(utc)} [{t}:{L:<3}] {h({l:<5})} {m}\n";

    let stderr = ConsoleAppender::builder()
        .target(Target::Stderr)
        .encoder(Box::new(PatternEncoder::new(log_format)))
        .build();

    // Logging to log file.
    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(log_format)))
        .build(log_path)
        .unwrap();

    // Log Trace level output to file where trace is the default level
    // and the programmatically specified level to stderr
    let mut config_builder =
        Config::builder().appender(Appender::builder().build("logfile", Box::new(logfile)));

    if !quiet {
        config_builder =
            config_builder.appender(Appender::builder().build("stderr", Box::new(stderr)));
    }

    let mut root_builder = Root::builder().appender("logfile");

    if !quiet {
        root_builder = root_builder.appender("stderr");
    }

    let config = config_builder.build(root_builder.build(level)).unwrap();
    log4rs::init_config(config).unwrap()
}

macro_rules! init_args {
    ($default_output_name:expr,$default_log_path:expr, $osquery_embedded:expr, $config_embedded:expr) => {
        App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("AbdulRhman Alfaifi <aalfaifi@u0041.co>")
        .about("Aritfact collection tool for *nix systems")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help(format!("Sets a custom config file (Embedded : {})", $config_embedded).as_ref())
                .takes_value(true),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .value_name("SEC")
                .help("Sets osquery queries timeout in seconds")
                .default_value("60")
                .takes_value(true),
        )
        .arg(
            Arg::new("show_config")
                .long("show-config")
                .help("Show the embedded configuration file"),
        )
        .arg(
            Arg::new("show_embedded")
                .long("show-embedded")
                .help("Show the embedded files metadata"),
        )
        .arg(
            Arg::new("log_path")
                .short('f')
                .long("log-file")
                .value_name("FILE")
                .help("Sets the log file name")
                .default_value($default_log_path)
                .takes_value(true),
        )
        .arg(
            Arg::new("log_level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Sets the log level")
                .takes_value(true)
                .default_value("info")
                .possible_values(["trace", "debug", "info", "error"]),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Sets output file name")
                .takes_value(true)
                .default_value($default_output_name),
        )
        .arg(
            Arg::new("output_format")
                .long("output-format")
                .value_name("FORMAT")
                .help("Sets output format")
                .takes_value(true)
                .possible_values(["jsonl", "csv", "kjson"])
                .default_value("jsonl"),
        )
        .arg(
            Arg::new("osquery_path")
                .long("osquery-path")
                .value_name("PATH")
                .help(format!("Sets osquery path, if osquery is embedded it will be writen to this path otherwise the path will be used to spawn osquery instance (Embedded : {})", $osquery_embedded).as_ref())
                .takes_value(true)
                .default_value("./osqueryd"),
        )
        .arg(
            Arg::new("upload_artifact")
                .short('u')
                .long("upload-artifact")
                .value_name("CONFIG")
                .help(r#"Upload configuration string. Supported Protocols: 
* s3 : Upload artifact package to S3 bucket (ex. minio)
    * Format : s3://<ACCESS_KEY>:<SECRET_ACCESS_KEY>@(http|https)://<HOSTNAME>:<PORT>/<BUCKET_NAME>:<PATH>
    * Example (minio): s3://minioadmin:minioadmin@http://192.168.100.190:9000/fennec:/
* aws3 : Upload artifact package to AWS S3 bucket
    * Format : aws3://<ACCESS_KEY>:<SECRET_ACCESS_KEY>@<AWS_REGOIN>.<BUCKET_NAME>:<PATH>
    * Example: aws3://AKIAXXX:XXX@us-east-1.fennecbucket:/
* scp : Upload artifact package to a server using SCP protocol
    * Format : scp://<USERNAME>:<PASSWORD>@<HOSTNAME>:<PORT>:<PATH>
    * Example: scp://testusername:testpassword@192.168.100.190:22:/dev/shm
                "#)
                .takes_value(true)
                .multiple_values(true)
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .help("Do not print logs to stdout"),
        )
    };
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmbeddedConfig {
    args: Option<Vec<String>>,
}

fn main() {
    let time_took = Instant::now();

    let mut to_cleanup: Vec<String> = vec![];

    let osquery_asset_name = match Asset::iter()
        .into_iter()
        .find(|asset_name| asset_name.contains("osqueryd"))
    {
        Some(asset_name) => asset_name.to_string().clone(),
        None => String::new(),
    };

    let config_asset_name = match Asset::iter()
        .into_iter()
        .find(|asset_name| asset_name.contains("config.yaml"))
    {
        Some(asset_name) => asset_name.to_string().clone(),
        None => String::new(),
    };

    let osquery_embedded = match Asset::get(&osquery_asset_name) {
        Some(_) => true,
        None => false,
    };

    let config_embedded = match Asset::get(&config_asset_name) {
        Some(_) => true,
        None => false,
    };

    let default_output_name = match hostname::get() {
        Ok(name) => format!("{}.zip", name.to_string_lossy().to_string()),
        Err(_) => {
            let hostname = match option_env!("HOSTNAME") {
                Some(name) => name.to_string(),
                None => String::from("HOSTNAME_NOT_FOUND"),
            };
            format!("{}.zip", hostname)
        }
    };

    let default_log_path = format!("{}.log", env!("CARGO_PKG_NAME"));

    let cli_matches = init_args!(
        &default_output_name,
        &default_log_path,
        osquery_embedded,
        config_embedded
    )
    .get_matches();

    let embedded_config = match Asset::get("config.yaml") {
        Some(embedded_config) => Some(embedded_config.data),
        None => None,
    };

    let conf_matches = match &embedded_config {
        Some(embedded_config) => {
            let reader = Cursor::new(embedded_config.clone());
            let embedded_conf_args: EmbeddedConfig =
                serde_yaml::from_reader(reader.clone()).unwrap();
            match embedded_conf_args.args {
                Some(mut conf_args) => {
                    let mut args = vec![String::from("")];
                    args.append(&mut conf_args);
                    init_args!(
                        &default_output_name,
                        &default_log_path,
                        osquery_embedded,
                        config_embedded
                    )
                    .get_matches_from(args)
                }
                None => {
                    let empty: Vec<String> = vec![];
                    init_args!(
                        &default_output_name,
                        &default_log_path,
                        osquery_embedded,
                        config_embedded
                    )
                    .get_matches_from(empty)
                }
            }
        }
        None => {
            let empty: Vec<String> = vec![];
            init_args!(
                &default_output_name,
                &default_log_path,
                osquery_embedded,
                config_embedded
            )
            .get_matches_from(empty)
        }
    };

    let quiet = match cli_matches.occurrences_of("quiet") {
        0 => match conf_matches.occurrences_of("quiet") {
            0 => false,
            _ => true,
        },
        _ => true,
    };

    let log_path = match cli_matches.occurrences_of("log_path") {
        0 => conf_matches.value_of("log_path").unwrap(),
        _ => cli_matches.value_of("log_path").unwrap(),
    };

    let timeout = match cli_matches.occurrences_of("timeout") {
        0 => conf_matches.value_of("timeout").unwrap().parse::<u64>(),
        _ => cli_matches.value_of("timeout").unwrap().parse::<u64>(),
    };

    let timeout = match timeout {
        Ok(t) => t,
        Err(e) => {
            panic!("The 'timeout' option should be a number, ERROR: {}", e);
        }
    };

    to_cleanup.push(log_path.to_string());

    let log_level = {
        let level = match cli_matches.occurrences_of("log_level") {
            0 => conf_matches.value_of("log_level").unwrap(),
            _ => cli_matches.value_of("log_level").unwrap(),
        };

        match level {
            "trace" => log::LevelFilter::Trace,
            "debug" => log::LevelFilter::Debug,
            "info" => log::LevelFilter::Info,
            "error" => log::LevelFilter::Error,
            _ => log::LevelFilter::Info,
        }
    };

    let upload = match cli_matches.occurrences_of("upload_artifact") {
        0 => conf_matches.values_of("upload_artifact"),
        _ => cli_matches.values_of("upload_artifact"),
    };

    init_logger(log_path, log_level, quiet);

    if cli_matches.occurrences_of("show_config") >= 1 {
        match embedded_config {
            Some(embedded_config) => {
                println!("{}", String::from_utf8_lossy(&embedded_config.clone()));
            }
            None => {
                println!("No embedded configuration");
            }
        }
        exit(0);
    }

    if cli_matches.occurrences_of("show_embedded") >= 1 {
        for asset_name in Asset::iter() {
            println!(
                "{} : {} (bytes)",
                asset_name,
                Asset::get(&asset_name).unwrap().data.len()
            );
        }
        exit(0);
    }

    if !Uid::effective().is_root() {
        error!("You must run this executable with root permissions");
        exit(1);
    }

    if !quiet {
        let ascii_art = format!(
            r#"
        ______                         
        |  ___|                        
        | |_ ___ _ __  _ __   ___  ___ 
        |  _/ _ \ '_ \| '_ \ / _ \/ __|
        | ||  __/ | | | | | |  __/ (__ 
        \_| \___|_| |_|_| |_|\___|\___|
        {}{}
    "#,
            "v".green().bold(),
            env!("CARGO_PKG_VERSION").green().bold()
        );

        println!("{}", ascii_art);
    }

    info!("Started '{}'", env!("CARGO_PKG_NAME"));

    let config = match cli_matches.value_of("config") {
        Some(config_path) => {
            let config_file = match File::open(config_path) {
                Ok(f) => f,
                Err(e) => panic!(
                    "Error reading configuration file '{}', ERROR: '{}'",
                    config_path, e
                ),
            };

            Box::new(config_file) as Box<dyn Read>
        }
        None => match embedded_config {
            Some(embedded_config) => {
                let reader = Cursor::new(embedded_config);
                Box::new(reader) as Box<dyn Read>
            }
            None => {
                error!("No embedded configuration and configuration path was not specified, recompile with configuration or specify configuration path with commandline argument '-c'");
                exit(1);
            }
        },
    };

    let output = match cli_matches.occurrences_of("output") {
        0 => conf_matches.value_of("output").unwrap(),
        _ => cli_matches.value_of("output").unwrap(),
    };

    let osquery_path = match cli_matches.occurrences_of("osquery_path") {
        0 => conf_matches.value_of("osquery_path").unwrap(),
        _ => cli_matches.value_of("osquery_path").unwrap(),
    };

    let output_format = {
        let format_str = match cli_matches.occurrences_of("output_format") {
            0 => conf_matches.value_of("output_format").unwrap(),
            _ => cli_matches.value_of("output_format").unwrap(),
        };

        match format_str {
            "jsonl" => OutputFormat::JSONL,
            "csv" => OutputFormat::CSV,
            "kjson" => OutputFormat::KJSON,
            _ => OutputFormat::JSONL,
        }
    };

    match Asset::get(&osquery_asset_name) {
        Some(embedded_osquery) => {
            match OpenOptions::new()
                .mode(0o700)
                .write(true)
                .create(true)
                .open(osquery_path)
            {
                Ok(mut file) => {
                    match file.metadata() {
                        Ok(metadata) => {
                            let mut perms = metadata.permissions();
                            perms.set_mode(0o700);
                        }
                        Err(e) => {
                            error!(
                                "Unable to set embedded osquery file permssions, ERROR: '{}'",
                                e
                            );
                        }
                    }
                    match file.write(embedded_osquery.data.as_ref()) {
                        Ok(n) => {
                            info!(
                                "Successfuly wrote '{}' bytes to osquery file '{}'",
                                n, osquery_path
                            );
                            to_cleanup.push(osquery_path.to_string());
                        }
                        Err(e) => {
                            error!(
                                "Unable to write osquery bytes to '{}', ERROR: '{}'",
                                osquery_path, e
                            );
                            exit(1);
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Unable to dump osquery file to '{}', ERROR: '{}'",
                        osquery_path, e
                    );
                }
            };
        }
        None => {
            warn!(
                "No osquery embedded, using osquery binary at '{}'",
                osquery_path
            )
        }
    }

    let mut zipfile = match File::create(output) {
        Ok(file) => ZipWriter::new(file),
        Err(e) => {
            error!("Unable to create output file '{}', ERROR: '{}'", output, e);
            exit(1);
        }
    };

    let foptions = FileOptions::default()
        .large_file(true)
        .compression_method(CompressionMethod::Deflated);

    let mut fennec = Fennec::from_reader(config, &mut zipfile)
        .unwrap()
        .set_output_format(output_format)
        .set_osquery_binary_path(osquery_path)
        .set_timeout(timeout)
        .set_options(&foptions);

    match fennec.triage() {
        Ok(_) => {
            let duration = time_took.elapsed();
            info!(
                "Successfully finished collecting artifacts!, took '{}' seconds",
                duration.as_secs_f64()
            );

            info!(
                "Adding '{}' to compressed file '{}' and running cleanup.",
                log_path, output
            );

            match zipfile.start_file(log_path, foptions) {
                Ok(_) => match File::open(log_path) {
                    Ok(in_file) => {
                        let mut reader = BufReader::with_capacity(1024 * 128, in_file);

                        loop {
                            let buf = reader.fill_buf().unwrap();
                            if buf.len() == 0 {
                                break;
                            }
                            let bytes = zipfile.write(&buf).unwrap();

                            reader.consume(bytes);
                        }
                        zipfile.flush().unwrap();
                        zipfile.finish().unwrap();
                    }
                    Err(e) => {
                        error!("Unable to open the log file '{}', ERROR: '{}'", log_path, e);
                    }
                },
                Err(e) => {
                    error!("Unable to write log file to '{}', ERROR: '{}'", log_path, e);
                }
            }
        }
        Err(e) => {
            error!("Unable to collect triage image, ERROR: '{}'", e.message);
        }
    };

    match upload {
        Some(config) => {
            for value in config {
                match UploadArtifacts::new(value) {
                    Ok(upload_artifact) => match upload_artifact.upload(output) {
                        Ok(_) => {
                            info!("Successfully uploaded the artifact package '{}'", output)
                        }
                        Err(e) => {
                            error!(
                                "Unable to upload the artifact package '{}', ERROR: {:?}",
                                output, e
                            );
                        }
                    },
                    Err(e) => {
                        error!("Error paring upload configuration, ERROR: {:?}", e)
                    }
                }
            }
        }
        None => {}
    }

    for path in to_cleanup {
        match fs::remove_file(&path) {
            Ok(_) => {
                info!("Successfuly deleted the file '{}'", path);
            }
            Err(e) => {
                error!(
                    "Unable to remove the files '{}', Please remove manually, ERROR: '{}'",
                    path, e
                );
            }
        }
    }

    info!("Done!");
}

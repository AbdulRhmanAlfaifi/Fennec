///! A library used to collect triage image from *nix machines
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use regex::{self, Regex};
use std::{
    fmt::Display,
    fs::File,
    io::{Read, Write},
    os::unix::prelude::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    result::Result,
    time::SystemTime,
};
use zip::{write::FileOptions, CompressionMethod, ZipWriter};
mod errors;
use errors::FennecError;
use glob;
use log::*;
use serde_json::{json, Value};
use std::io::{prelude::*, BufReader};
use std::process::Command;
mod modifiers;
use csv::Writer;
use modifiers::Modifier;

use osquery_rs::OSQuery;
use serde::{Deserialize, Serialize};

pub mod upload;

#[derive(Debug, Serialize, Deserialize)]
/// Contains the configuration for the all artifacts
pub struct FennecConfig {
    artifacts: Vec<Artifact>,
}

#[derive(Debug, Serialize, Deserialize)]
/// Represent field mapping and aply a specific modifer on the mapped field
pub struct Map {
    from: String,
    to: String,
    modifier: Option<Modifier>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Support artifact types:
/// * Query: the artifact of this type conrespond to osquery SQL query(s)
/// * Collection: this artifact type allows files and folders collection using (supports glob)
/// * Command: this artifact type allows system commands execution
/// * Parse: this artifact allows text files parsing using regex with named groups
pub enum ArtifactType {
    Query,
    Collection,
    Command,
    Parse,
}
#[derive(Debug, Serialize, Deserialize)]
/// Contains artifact configuration such as type, maps, description, etc
pub struct Artifact {
    name: String,
    #[serde(rename(deserialize = "type"))]
    #[serde(rename = "type")]
    artifact_type: ArtifactType,
    description: Option<String>,
    #[serde(alias = "queries", alias = "paths", alias = "commands")]
    artifacts: Vec<String>,
    maps: Option<Vec<Map>>,
    regex: Option<String>,
}

impl Artifact {
    pub fn map(&self, data: &Value) -> Option<Value> {
        match &self.artifact_type {
            ArtifactType::Query | ArtifactType::Command | ArtifactType::Parse => {
                match data.clone() {
                    Value::Object(data) => match &self.maps {
                        Some(maps) => {
                            let mut new_data = serde_json::Map::new();
                            maps.iter().for_each(|map| {
                                if data.contains_key(&map.from) {
                                    let mut value = data.get(&map.from).unwrap().clone();
                                    if let Some(modifier) = &map.modifier {
                                        value = modifier.run(value);
                                    }
                                    for (k, v) in data.iter() {
                                        if k == &map.from {
                                            new_data.insert(map.to.clone(), value.clone());
                                        } else {
                                            new_data.insert(k.to_string(), v.clone());
                                        }
                                    }
                                }
                            });
                            Some(Value::Object(new_data))
                        }
                        None => Some(Value::Object(data)),
                    },
                    _ => Some(data.clone()),
                }
            }
            _ => {
                warn!(
                    "Field mapping feature is not available for artifact type '{:?}'",
                    &self.artifact_type
                );
                None
            }
        }
    }
}

impl Default for Artifact {
    fn default() -> Self {
        Self {
            name: String::from("users"),
            artifact_type: ArtifactType::Query,
            description: Some(String::from("Collect users info")),
            artifacts: vec![String::from("select * from users")],
            maps: None,
            regex: None,
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
/// Supported output formates
pub enum OutputFormat {
    JSONL,
    CSV,
    KJSON,
}

impl Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::CSV => f.write_str("csv"),
            OutputFormat::JSONL => f.write_str("jsonl"),
            OutputFormat::KJSON => f.write_str("kjson"),
        }
    }
}

// #[derive(Serialize, Deserialize)]
/// Main struct responsable of parsing configuration, and running triage collection.
pub struct Fennec<'a> {
    _config: FennecConfig,
    _osquery_binary_path: String,
    _extension: OutputFormat,
    _output_file: &'a mut ZipWriter<File>,
    _foptions: FileOptions,
    _file_collect_buf_size: usize,
}

impl<'a> Fennec<'a> {
    /// Read configuration from YAML formated file and parses it then return an instance if this struct
    pub fn from_path(
        config_path: &str,
        output_path: &'a mut ZipWriter<File>,
    ) -> Result<Self, FennecError> {
        let config_file = match File::open(config_path) {
            Ok(f) => f,
            Err(e) => {
                return Err(FennecError::config_error(format!(
                    "Can not read configuration file '{}', ERROR: {}",
                    config_path, e
                )))
            }
        };

        Self::from_reader(config_file, output_path)
    }
    /// Same as `from_path` but it acceptes a reader insted of a file path
    pub fn from_reader<R: Read>(
        r: R,
        output_path: &'a mut ZipWriter<File>,
    ) -> Result<Self, FennecError> {
        let config: FennecConfig = match serde_yaml::from_reader(r) {
            Ok(c) => c,
            Err(e) => {
                return Err(FennecError::config_error(format!(
                    "Syntax error in the configuration, ERROR: {}",
                    e
                )))
            }
        };

        let foptions = FileOptions::default().compression_method(CompressionMethod::Deflated);

        Ok(Self {
            _config: config,
            _osquery_binary_path: String::from("/opt/osquery/bin/osqueryd"),
            _extension: OutputFormat::JSONL,
            _output_file: output_path,
            _foptions: foptions,
            _file_collect_buf_size: 1024 * 1024 * 5,
        })
    }

    /// This function is responsable of ouput formating specified in the configuration, for a list of supported output formats check `OutputFormat` enum.
    fn format(&self, data: &Value, artifact: &Artifact) -> String {
        match artifact.artifact_type {
            ArtifactType::Query
            | ArtifactType::Parse
            | ArtifactType::Command
            | ArtifactType::Collection => match self._extension {
                OutputFormat::CSV => {
                    let mut writer = Writer::from_writer(vec![]);
                    match data {
                        Value::Object(obj) => {
                            let values: Vec<String> = obj
                                .values()
                                .into_iter()
                                .map(|a| match a {
                                    Value::String(s) => s.clone(),
                                    Value::Number(n) => n.to_string(),
                                    Value::Bool(b) => b.to_string(),
                                    Value::Null => String::from(""),
                                    _ => format!("{}", a).to_string(),
                                })
                                .collect();
                            match writer.write_record(values) {
                                Ok(_) => {}
                                Err(e) => {
                                    debug!("Unable to write the data '{}' for the artifact '{}' to CSV writer, ERROR: '{}'", data, artifact.name, e);
                                }
                            };
                        }
                        _ => {}
                    }
                    let results = String::from_utf8(writer.into_inner().unwrap()).unwrap();
                    results
                }
                OutputFormat::JSONL => {
                    let results = match serde_json::to_string(data) {
                        Ok(s) => s,
                        Err(e) => {
                            error!(
                                "Unable to parse the record '{}' to JSONL format, ERROR: '{}'",
                                data, e
                            );
                            String::from("{}")
                        }
                    };
                    format!("{}\n", results)
                }
                OutputFormat::KJSON => {
                    let data = json!({
                        "Data": data,
                        "data_type": artifact.name,
                        "data_source": artifact.name,
                        "data_path": format!("{}.kjson",artifact.name)
                    });
                    let results = match serde_json::to_string(&data) {
                        Ok(s) => s,
                        Err(e) => {
                            error!(
                                "Unable to parse the record '{}' to JSONL format, ERROR: '{}'",
                                data, e
                            );
                            String::from("{}")
                        }
                    };
                    format!("{}\n", results)
                }
            },
        }
    }

    /// Allows setting `FileOptions` of the ZipWriter at runtime.
    pub fn set_options(mut self, foptions: FileOptions) -> Self {
        self._foptions = foptions;
        self
    }

    /// Allows the setting of collection artifact buffer size at runtime, Default is `1024 * 1024 * 5 (5MiB)`
    pub fn set_collection_buf_size(mut self, size: usize) -> Self {
        self._file_collect_buf_size = size;
        self
    }

    /// Change the output format, Default is 'OutputFormat::CSV'
    pub fn set_output_format(mut self, output_format: OutputFormat) -> Self {
        self._extension = output_format;
        self
    }

    /// Sets osquery binary file path, Default `/opt/osquery/bin/osqueryd`
    pub fn set_osquery_binary_path(mut self, path: &str) -> Self {
        self._osquery_binary_path = String::from(path);
        self
    }

    /// Start triage collection from the artifacts specified in the configuration
    pub fn triage(&mut self) -> Result<bool, FennecError> {
        let mut process_osquery_artifacts = true;
        let mut osquery_instance = OSQuery::new();
        match OSQuery::new()
            .spawn_instance(&self._osquery_binary_path)
            .map_err(|e| {
                FennecError::osquery_instance_error(format!(
                    "Unable to create osquery instance '{}', ERROR: {}",
                    &self._osquery_binary_path, e
                ))
            }) {
            Ok(instance) => osquery_instance = instance,
            Err(e) => {
                error!("{}", e.message);
                process_osquery_artifacts = false;
                warn!(
                    "Skiping artifact type '{:?}' duo to the previous error",
                    ArtifactType::Query
                );
            }
        };

        for artifact in self._config.artifacts.iter() {
            let artifact = artifact.clone();
            match artifact.artifact_type {
                ArtifactType::Query => {
                    if process_osquery_artifacts {
                        match self._output_file.start_file(
                            format!("{}.{}", artifact.name, self._extension),
                            self._foptions,
                        ) {
                            Ok(_) => {
                                info!(
                                    "Start writing the results for the artifact '{}' to '{}'",
                                    artifact.name,
                                    format!("{}.{}", artifact.name, self._extension)
                                );
                            }
                            Err(e) => {
                                error!("Unable to write the results for the artifact '{}' to '{}', ERROR: '{}'", artifact.name, format!("{}.{}",artifact.name,self._extension), e);
                            }
                        };
                        for sql in artifact.artifacts.iter() {
                            info!(
                                "Executing the osquery SQL query '{}' for the artifact '{}'",
                                sql, artifact.name
                            );
                            match osquery_instance.query(sql.to_string()) {
                                Ok(res) => {
                                    match res.response {
                                        Some(data) => {
                                            let status = res.status.unwrap();
                                            if status.code.unwrap().to_owned() == 0 {
                                                let mut csv_headers_printed = false;
                                                for row in data.iter() {
                                                    let mut json = json!({});
                                                    for (k, v) in row {
                                                        match json {
                                                            Value::Object(mut obj) => {
                                                                obj.insert(
                                                                    k.to_string(),
                                                                    Value::String(v.to_string()),
                                                                );
                                                                json = Value::Object(obj);
                                                            }
                                                            _ => {}
                                                        };
                                                    }

                                                    if let Some(data) = artifact.map(&json) {
                                                        json = data;
                                                    }

                                                    if let OutputFormat::CSV = self._extension {
                                                        if !csv_headers_printed {
                                                            let headers: Vec<_> = json
                                                                .as_object()
                                                                .unwrap()
                                                                .keys()
                                                                .collect();
                                                            let mut writer =
                                                                Writer::from_writer(vec![]);
                                                            writer.write_record(headers).unwrap();
                                                            let data = String::from_utf8(
                                                                writer.into_inner().unwrap(),
                                                            )
                                                            .unwrap();
                                                            match self
                                                                ._output_file
                                                                .write(data.as_bytes())
                                                            {
                                                                Ok(_) => {
                                                                    debug!("Wrote headers for the artifact '{}' to '{}'", artifact.name, format!("{}.{}",artifact.name,self._extension));
                                                                }
                                                                Err(e) => {
                                                                    error!("Unable to write the results for the artifact '{}' to '{}', ERROR: '{}'", artifact.name, format!("{}.{}",artifact.name,self._extension), e);
                                                                }
                                                            }
                                                            csv_headers_printed = true
                                                        }
                                                    }

                                                    let data = self.format(&json, &artifact);
                                                    match self._output_file.write(data.as_bytes()) {
                                                        Ok(n) => {
                                                            debug!("Wrote '{}' bytes for the artifact '{}' to '{}'", n, artifact.name, format!("{}.{}",artifact.name,self._extension));
                                                            if let Err(e) =
                                                                self._output_file.flush()
                                                            {
                                                                error!("Unable to flush stream, ERROR: {}", e);
                                                            };
                                                        }
                                                        Err(e) => {
                                                            error!("Unable to write the results for the artifact '{}' to '{}', ERROR: '{}'", artifact.name, format!("{}.{}",artifact.name,self._extension), e);
                                                        }
                                                    }
                                                }
                                            } else if status.code.unwrap() == 1 {
                                                error!(
                                                    "Unable to execute osquery SQL query '{}', ERROR: '{}'",
                                                    sql, status.message.unwrap()
                                                );
                                            }
                                        }
                                        None => {}
                                    };
                                }
                                Err(error) => {
                                    error!(
                                        "Unable to execute osquery SQL query '{}', ERROR: {}",
                                        sql, error
                                    );
                                }
                            };
                        }
                    }
                }
                ArtifactType::Collection => {
                    let mut files_metadata: Vec<String> = vec![];
                    for path in artifact.artifacts.iter() {
                        for entry in glob::glob(path).expect("Failed to read glob pattern") {
                            match entry {
                                Ok(entry) => {
                                    let dest_path: PathBuf = entry
                                        .as_path()
                                        .components()
                                        .collect::<Vec<_>>()
                                        .iter()
                                        .skip(1)
                                        .collect();

                                    let dest_path: PathBuf = [
                                        artifact.name.clone(),
                                        dest_path.as_path().to_string_lossy().to_string(),
                                    ]
                                    .iter()
                                    .collect();

                                    // Collect metadta for file/folder
                                    match std::fs::metadata(entry.as_path()) {
                                        Ok(metadata) => {
                                            let mtime: DateTime<Utc> = metadata
                                                .modified()
                                                .unwrap_or(SystemTime::now())
                                                .into();
                                            let atime: DateTime<Utc> = metadata
                                                .accessed()
                                                .unwrap_or(SystemTime::now())
                                                .into();
                                            let ctime: DateTime<Utc> = metadata
                                                .created()
                                                .unwrap_or(SystemTime::now())
                                                .into();
                                            // let per: u32 = .unix().into();
                                            let per = metadata.permissions().mode() & 0x1ff;
                                            let file_type = match metadata.is_file() {
                                                true => "file",
                                                false => match metadata.is_dir() {
                                                    true => "directory",
                                                    false => "other",
                                                },
                                            };
                                            let data = json!({
                                                "full_path": entry.as_path().to_string_lossy(),
                                                "type": file_type,
                                                "size": metadata.size(),
                                                "permessions": format!("{:03o}", per),
                                                "owner_uid": metadata.uid(),
                                                "owner_gid": metadata.gid(),
                                                "mtime": mtime.format("%Y-%m-%d %H:%M:%S").to_string(),
                                                "atime": atime.format("%Y-%m-%d %H:%M:%S").to_string(),
                                                "ctime": ctime.format("%Y-%m-%d %H:%M:%S").to_string(),

                                            });

                                            let data = self.format(&data, &artifact);
                                            files_metadata.push(data);
                                        }
                                        Err(e) => {
                                            error!("Unable to collect metadata for '{}' for the artifact '{}', ERROR: '{}'", entry.as_path().to_string_lossy(), artifact.name, e);
                                        }
                                    }

                                    if entry.as_path().is_dir() {
                                        match self._output_file.add_directory(
                                            dest_path.as_path().to_string_lossy(),
                                            self._foptions,
                                        ) {
                                            Ok(_) => {
                                                debug!("Created directory entry for '{}' in ZIP file for artifact '{}' successfully!", dest_path.as_path().to_string_lossy(), artifact.name);
                                            }
                                            Err(e) => {
                                                error!("Unable to create directory entry '{}' in ZIP file for the artifact '{}', ERROR: '{}'",dest_path.as_path().to_string_lossy(), artifact.name, e);
                                            }
                                        }
                                    } else {
                                        match self._output_file.start_file(
                                            dest_path.as_path().to_string_lossy(),
                                            self._foptions,
                                        ) {
                                            Ok(_) => {
                                                debug!("Created file entry for '{}' in ZIP file for artifact '{}' successfully!", dest_path.as_path().to_string_lossy(), artifact.name);
                                            }
                                            Err(e) => {
                                                error!("Unable to create file entry '{}' in ZIP file for the artifact '{}', ERROR: '{}'",dest_path.as_path().to_string_lossy(), artifact.name, e);
                                            }
                                        }

                                        info!(
                                            "Copying the file '{}' for the artifact '{}'",
                                            entry.as_path().to_string_lossy(),
                                            artifact.name
                                        );

                                        match File::open(entry.as_path()) {
                                            Ok(in_file) => {
                                                let mut reader = BufReader::with_capacity(
                                                    self._file_collect_buf_size,
                                                    in_file,
                                                );

                                                loop {
                                                    let buf = reader.fill_buf().unwrap();
                                                    if buf.len() == 0 {
                                                        debug!("Finished writing the file '{}' for the artifact '{}' to the ZIP file", dest_path.as_path().to_string_lossy(), artifact.name);
                                                        break;
                                                    }
                                                    let bytes =
                                                        self._output_file.write(&buf).unwrap();
                                                    debug!("Wrote '{}' bytes for the artifact '{}' to '{}' successfuly!", bytes, artifact.name, dest_path.as_path().to_string_lossy());
                                                    reader.consume(bytes);
                                                }
                                            }
                                            Err(e) => {
                                                error!("Unable to open the file '{}' for the artifact '{}', ERROR: '{}'", entry.as_path().to_string_lossy(), artifact.name, e);
                                            }
                                        }
                                    }
                                }
                                Err(e) => error!(
                                    "Error in glob for the artifact '{}', ERROR: '{:?}'",
                                    artifact.name, e
                                ),
                            }
                        }
                    }
                    match self._output_file.start_file(
                        format!(
                            "{}/{}_metadata.{}",
                            artifact.name, artifact.name, self._extension
                        ),
                        self._foptions,
                    ) {
                        Ok(_) => {
                            if let OutputFormat::CSV = self._extension {
                                let mut writer = Writer::from_writer(vec![]);
                                writer
                                    .write_record(vec![
                                        "full_path",
                                        "file_type",
                                        "size",
                                        "permessions",
                                        "owner_uid",
                                        "owner_gid",
                                        "mtime",
                                        "atime",
                                        "ctime",
                                    ])
                                    .unwrap();
                                let data = String::from_utf8(writer.into_inner().unwrap()).unwrap();
                                match self._output_file.write(data.as_bytes()) {
                                    Ok(_) => {
                                        debug!(
                                            "Wrote headers for the artifact '{}' to '{}'",
                                            artifact.name,
                                            format!("{}.{}", artifact.name, self._extension)
                                        );
                                        if let Err(e) = self._output_file.flush() {
                                            error!("Unable to flush stream, ERROR: {}", e);
                                        };
                                    }
                                    Err(e) => {
                                        error!("Unable to write the results for the artifact '{}' to '{}', ERROR: '{}'", artifact.name, format!("{}.{}",artifact.name,self._extension), e);
                                    }
                                }
                            }

                            for line in files_metadata.iter() {
                                self._output_file.write(line.as_bytes()).unwrap();
                                if let Err(e) = self._output_file.flush() {
                                    error!("Unable to flush stream, ERROR: {}", e);
                                };
                            }
                        }
                        Err(e) => {
                            error!("Unable to write the metadata for the artifact '{}' to '{}', ERROR: '{}'", artifact.name, format!("{}_metadata.{}",artifact.name,self._extension), e);
                        }
                    }
                }
                ArtifactType::Command => {
                    match self._output_file.start_file(
                        format!("{}.{}", artifact.name, self._extension),
                        self._foptions,
                    ) {
                        Ok(_) => {
                            info!(
                                "Start writing the results for the artifact '{}' to '{}'",
                                artifact.name,
                                format!("{}.{}", artifact.name, self._extension)
                            );
                        }
                        Err(e) => {
                            error!("Unable to write the results for the artifact '{}' to '{}', ERROR: '{}'", artifact.name, format!("{}.{}",artifact.name,self._extension), e);
                        }
                    };

                    let shell = match std::env::var_os("SHELL") {
                        Some(env) => env.to_string_lossy().to_string(),
                        None => {
                            if Path::new("/bin/bash").exists() {
                                String::from("/bin/bash")
                            } else if Path::new("/bin/sh").exists() {
                                String::from("/bin/sh")
                            } else {
                                error!("Unable to find shell ($SHELL, /bin/bash and /bin/sh not found), Skipping command execution");
                                continue;
                            }
                        }
                    };
                    for command in artifact.artifacts.iter() {
                        let res = Command::new(&shell).arg("-c").arg(command).output();
                        match res {
                            Ok(result) => {
                                let mut counter: usize = 0;
                                let mut csv_headers_printed = false;
                                for line in String::from_utf8_lossy(&result.stdout).split("\n") {
                                    if !line.is_empty() {
                                        let mut row = json!({
                                            "line": counter,
                                            "stdout": line
                                        });

                                        if let Some(data) = artifact.map(&row) {
                                            row = data;
                                        }

                                        if let OutputFormat::CSV = self._extension {
                                            if !csv_headers_printed {
                                                let mut writer = Writer::from_writer(vec![]);
                                                writer
                                                    .write_record(&["line", "stdout/stderr"])
                                                    .unwrap();
                                                let data =
                                                    String::from_utf8(writer.into_inner().unwrap())
                                                        .unwrap();
                                                match self._output_file.write(data.as_bytes()) {
                                                    Ok(_) => {
                                                        debug!("Wrote headers for the artifact '{}' to '{}'", artifact.name, format!("{}.{}",artifact.name,self._extension));
                                                        if let Err(e) = self._output_file.flush() {
                                                            error!(
                                                                "Unable to flush stream, ERROR: {}",
                                                                e
                                                            );
                                                        };
                                                    }
                                                    Err(e) => {
                                                        error!("Unable to write the results for the artifact '{}' to '{}', ERROR: '{}'", artifact.name, format!("{}.{}",artifact.name,self._extension), e);
                                                    }
                                                }
                                                csv_headers_printed = true
                                            }
                                        }

                                        let data = self.format(&row, &artifact);
                                        match self._output_file.write(data.as_bytes()) {
                                            Ok(n) => {
                                                debug!("Wrote '{}' bytes for the artifact '{}' to '{}'", n, artifact.name, format!("{}.{}",artifact.name,self._extension));
                                                if let Err(e) = self._output_file.flush() {
                                                    error!("Unable to flush stream, ERROR: {}", e);
                                                };
                                            }
                                            Err(e) => {
                                                error!("Unable to write the results for the artifact '{}' to '{}', ERROR: '{}'", artifact.name, format!("{}.{}",artifact.name,self._extension), e);
                                            }
                                        }
                                        counter += 1;
                                    }
                                }
                                counter = 0;
                                for line in String::from_utf8_lossy(&result.stderr).split("\n") {
                                    if !line.is_empty() {
                                        let mut row = json!({
                                            "line": counter,
                                            "stderr": line
                                        });

                                        if let Some(data) = artifact.map(&row) {
                                            row = data;
                                        }

                                        let data = self.format(&row, &artifact);
                                        match self._output_file.write(data.as_bytes()) {
                                            Ok(n) => {
                                                debug!("Wrote '{}' bytes for the artifact '{}' to '{}'", n, artifact.name, format!("{}.{}",artifact.name,self._extension));
                                                if let Err(e) = self._output_file.flush() {
                                                    error!("Unable to flush stream, ERROR: {}", e);
                                                };
                                            }
                                            Err(e) => {
                                                error!("Unable to write the results for the artifact '{}' to '{}', ERROR: '{}'", artifact.name, format!("{}.{}",artifact.name,self._extension), e);
                                            }
                                        }
                                        counter += 1;
                                    }
                                }
                            }
                            Err(error) => {
                                error!(
                                    "Unable to execute the command '{} -c {}', ERROR: {:?}",
                                    &shell, command, error
                                );
                            }
                        };
                    }
                }
                ArtifactType::Parse => {
                    match self._output_file.start_file(
                        format!("{}.{}", artifact.name, self._extension),
                        self._foptions,
                    ) {
                        Ok(_) => {
                            info!(
                                "Start writing the results for the artifact '{}' to '{}'",
                                artifact.name,
                                format!("{}.{}", artifact.name, self._extension)
                            );
                        }
                        Err(e) => {
                            error!("Unable to write the results for the artifact '{}' to '{}', ERROR: '{}'", artifact.name, format!("{}.{}",artifact.name,self._extension), e);
                            continue;
                        }
                    };
                    for path in artifact.artifacts.iter() {
                        for entry in glob::glob(path).expect("Failed to read glob pattern") {
                            match entry {
                                Ok(entry) => {
                                    if !entry.as_path().is_dir() {
                                        info!(
                                            "Parsing the file '{}' for the artifact '{}'",
                                            entry.as_path().to_string_lossy(),
                                            artifact.name
                                        );
                                        match File::open(entry.as_path()) {
                                            Ok(in_file) => {
                                                if let Some(regex) = &artifact.regex {
                                                    if let Ok(re) = Regex::new(regex.as_str()) {
                                                        let reader = match entry
                                                            .as_path()
                                                            .to_string_lossy()
                                                            .ends_with(".gz")
                                                        {
                                                            true => Box::new(BufReader::new(
                                                                GzDecoder::new(in_file),
                                                            ))
                                                                as Box<dyn BufRead>,
                                                            false => {
                                                                Box::new(BufReader::new(in_file))
                                                                    as Box<dyn BufRead>
                                                            }
                                                        };
                                                        let mut csv_headers_printed = false;
                                                        for line in reader.lines() {
                                                            if let Err(e) = &line {
                                                                error!("A line in the file '{}' is not a string, ERROR: {}", entry.as_path().to_string_lossy(), e);
                                                                continue;
                                                            }
                                                            let line = &line.unwrap();
                                                            if let Some(groups) = re.captures(line)
                                                            {
                                                                let mut data: serde_json::Map<
                                                                    String,
                                                                    Value,
                                                                > = serde_json::Map::new();

                                                                re.capture_names().for_each(|name| {
                                                                    if let Some(name) = name {
                                                                        let value = match groups
                                                                            .name(name)
                                                                        {
                                                                            Some(m) => Value::String(
                                                                                m.as_str().to_string(),
                                                                            ),
                                                                            None => Value::Null,
                                                                        };
                                                                        data.insert(
                                                                            name.to_string(),
                                                                            value,
                                                                        );
                                                                    }
                                                                });

                                                                data.insert(
                                                                    "full_path".to_string(),
                                                                    Value::String(
                                                                        entry
                                                                            .as_path()
                                                                            .to_string_lossy()
                                                                            .to_string(),
                                                                    ),
                                                                );

                                                                let mut json =
                                                                    Value::Object(data.clone());

                                                                if let Some(data) =
                                                                    artifact.map(&json)
                                                                {
                                                                    json = data;
                                                                }

                                                                data = json
                                                                    .as_object()
                                                                    .unwrap()
                                                                    .clone();

                                                                if let OutputFormat::CSV =
                                                                    self._extension
                                                                {
                                                                    if !csv_headers_printed {
                                                                        let headers: Vec<_> =
                                                                            data.keys().collect();
                                                                        let mut writer =
                                                                            Writer::from_writer(
                                                                                vec![],
                                                                            );
                                                                        writer
                                                                            .write_record(headers)
                                                                            .unwrap();
                                                                        let data =
                                                                            String::from_utf8(
                                                                                writer
                                                                                    .into_inner()
                                                                                    .unwrap(),
                                                                            )
                                                                            .unwrap();
                                                                        match self
                                                                            ._output_file
                                                                            .write(data.as_bytes())
                                                                        {
                                                                            Ok(_) => {
                                                                                debug!("Wrote headers for the artifact '{}' to '{}'", artifact.name, format!("{}.{}",artifact.name,self._extension));
                                                                            }
                                                                            Err(e) => {
                                                                                error!("Unable to write the results for the artifact '{}' to '{}', ERROR: '{}'", artifact.name, format!("{}.{}",artifact.name,self._extension), e);
                                                                            }
                                                                        }
                                                                        csv_headers_printed = true
                                                                    }
                                                                }

                                                                let data =
                                                                    self.format(&json, &artifact);
                                                                match self
                                                                    ._output_file
                                                                    .write(data.as_bytes())
                                                                {
                                                                    Ok(n) => {
                                                                        if let Ok(_) = self
                                                                            ._output_file
                                                                            .flush()
                                                                        {
                                                                            debug!("Wrote '{}' bytes for the file '{}' for the artifact '{}' to '{}'", n, entry.as_path().to_string_lossy(), artifact.name, format!("{}.{}",artifact.name,self._extension));
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        error!("Unable to write the results for the file '{}' for the artifact '{}' to '{}', ERROR: '{}'", entry.as_path().to_string_lossy(), artifact.name, format!("{}.{}",artifact.name,self._extension), e);
                                                                    }
                                                                }
                                                            } else {
                                                                error!("Unable to parse the line '{}' for the artifact '{}'", line, artifact.name);
                                                            }
                                                        }
                                                    } else {
                                                        error!("Unable to parse the regulare expretion for the artifact '{}'", artifact.name);
                                                    }
                                                } else {
                                                    error!("The artifact '{}' has the artifact type 'parse' which regires the field 'regex'", artifact.name);
                                                }
                                            }
                                            Err(e) => {
                                                error!("Unable to open the file '{}' for the artifact '{}', ERROR: '{}'", entry.as_path().to_string_lossy(), artifact.name, e);
                                            }
                                        };
                                    }
                                }
                                Err(e) => error!(
                                    "Error in glob for the artifact '{}', ERROR: '{:?}'",
                                    artifact.name, e
                                ),
                            }
                        }
                    }
                }
            };
        }
        Ok(true)
    }
}

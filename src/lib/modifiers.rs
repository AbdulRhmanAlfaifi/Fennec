use std::{fmt::Display, time::SystemTime};

use chrono::{DateTime, Datelike, FixedOffset, Local, NaiveDateTime, TimeZone, Utc};

use log::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Serialize, Deserialize)]
pub enum ModifierType {
    #[serde(rename = "epoch_to_iso")]
    EpochToISO,
    #[serde(rename = "datetime_to_iso")]
    DatetimeTimeToISO,
    #[serde(rename = "time_without_year_to_iso")]
    TimeWithoutYearToISO,
    #[serde(rename = "to_int")]
    ToInt,
}

impl Display for ModifierType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EpochToISO => f.write_str("epoch_to_iso"),
            Self::DatetimeTimeToISO => f.write_str("datetime_to_iso"),
            Self::TimeWithoutYearToISO => f.write_str("time_without_year_to_iso"),
            Self::ToInt => f.write_str("to_int"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Modifier {
    name: ModifierType,
    parameters: Option<Value>,
}

impl Modifier {
    pub fn get_param(&self, name: &str) -> Option<String> {
        match &self.parameters {
            Some(params) => match params {
                Value::Object(obj) => match obj.get(name) {
                    Some(param_value) => match param_value {
                        Value::String(value) => Some(value.clone()),
                        Value::Number(value) => Some(value.to_string()),
                        _ => Some(param_value.to_string()),
                    },
                    None => None,
                },
                _ => {
                    error!(
                        "The parameters for the modifier '{}' should be and object",
                        self.name
                    );
                    None
                }
            },
            None => None,
        }
    }
    pub fn run(&self, field: Value) -> Value {
        let time_format = match self.get_param("output_time_format") {
            Some(format) => format,
            None => "%Y-%m-%d %H:%M:%S".to_string(),
        };
        let local_timezone = match self.get_param("local_timezone") {
            Some(value) => {
                if value.to_lowercase() == "true" {
                    true
                } else {
                    false
                }
            }
            None => false,
        };
        match self.name {
            ModifierType::EpochToISO => match field {
                Value::String(ref epoch_str) => {
                    let secs: i64;
                    if epoch_str.contains(".") {
                        let parts = epoch_str.split(".").collect::<Vec<&str>>();
                        secs = match parts[0].parse() {
                            Ok(s) => s,
                            Err(e) => {
                                error!(
                                    "Unable to convert the seconds portion '{}' to i64 for {}, ERROR {}",
                                    parts[0],epoch_str, e
                                );
                                0
                            }
                        };
                    } else {
                        secs = match epoch_str.parse() {
                            Ok(s) => s,
                            Err(e) => {
                                error!(
                                    "Unable to convert string '{}' to i64, ERROR {}",
                                    epoch_str, e
                                );
                                0
                            }
                        };
                    }
                    match NaiveDateTime::from_timestamp_opt(secs, 0) {
                        Some(iso_time) => Value::String(iso_time.format(&time_format).to_string()),
                        None => {
                            error!(
                                "Unable to convert the epoch timestamp '{}' to ISO format",
                                secs
                            );
                            field
                        }
                    }
                }
                Value::Number(epoch) => {
                    if let Some(epoch) = epoch.as_i64() {
                        match NaiveDateTime::from_timestamp_opt(epoch, 0) {
                            Some(timestamp) => {
                                Value::String(timestamp.format(&time_format).to_string())
                            }
                            None => json!(epoch),
                        }
                    } else {
                        error!("Unable to parse '{}' as i64", epoch);
                        Value::Number(epoch)
                    }
                }
                _ => {
                    error!("The field '{}' is not of type String or i64, returning the unchanged value", field);
                    field
                }
            },
            ModifierType::DatetimeTimeToISO => match &field {
                Value::String(datetime_str) => {
                    let datetime_str = datetime_str.clone();
                    let input_time_format = match self.get_param("input_time_format") {
                        Some(format) => format,
                        None => {
                            error!("The parameter 'input_time_format' for the modifier 'datetime_to_iso' is required");
                            String::from("")
                        }
                    };

                    let tz_offset = match local_timezone {
                        true => Local.timestamp_opt(0, 0).unwrap().offset().clone(),
                        false => FixedOffset::east_opt(0).unwrap(),
                    };

                    // The input datetime have timezone info
                    if input_time_format.to_lowercase().contains("z") {
                        match DateTime::parse_from_str(&datetime_str, &input_time_format) {
                            Ok(datetime) => {
                                let utc_datetime =
                                    datetime.with_timezone(&FixedOffset::east_opt(0).unwrap());
                                Value::String(utc_datetime.format(&time_format).to_string())
                            }
                            Err(e) => {
                                error!("Unable to parser the date '{}' with the formate '{}', ERROR: '{}'", datetime_str, &input_time_format, e);
                                field
                            }
                        }
                    }
                    // The input datetime doesn't have timezone info.
                    // if 'local_timezone' is set to true it will take the local timezone of the system, otherwise it will process it as UTC timezone
                    else {
                        match NaiveDateTime::parse_from_str(&datetime_str, &input_time_format) {
                            Ok(datetime) => match tz_offset.from_local_datetime(&datetime) {
                                chrono::LocalResult::Single(datetime) => {
                                    let utc_datetime =
                                        DateTime::<Utc>::from_utc(datetime.naive_utc(), Utc);
                                    Value::String(utc_datetime.format(&time_format).to_string())
                                }
                                _ => {
                                    error!("Unable to convert '{:?}' to UTC timezone, retrning unchanged field", datetime);
                                    Value::String(datetime_str.to_string().clone())
                                }
                            },
                            Err(e) => {
                                error!("Unable to parser the date '{}' with the formate '{}', ERROR: '{}'", datetime_str, &input_time_format, e);
                                field
                            }
                        }
                    }
                }
                _ => field,
            },
            ModifierType::TimeWithoutYearToISO => match &field {
                Value::String(datetime_str) => {
                    // Works as follows:
                    // Add current year then check if parser time < current time, if it is then it is the correct time
                    // otherwise it is the previous year
                    let datetime_str = datetime_str.clone();
                    let input_time_format = match self.get_param("input_time_format") {
                        Some(format) => format,
                        None => {
                            error!("The parameter 'input_time_format' for the modifier 'time_without_year_to_iso' is required");
                            String::from("")
                        }
                    };
                    let tz_offset = match local_timezone {
                        true => Local.timestamp_opt(0, 0).unwrap().offset().clone(),
                        false => FixedOffset::east_opt(0).unwrap(),
                    };
                    let current_time: DateTime<Utc> = SystemTime::now().into();

                    let time_with_this_year = format!("{} {}", current_time.year(), &datetime_str);

                    match NaiveDateTime::parse_from_str(
                        &time_with_this_year,
                        &format!("%Y {}", input_time_format),
                    ) {
                        Ok(datetime) => {
                            // let utc_datetime = DateTime::<Utc>::from_utc(datetime, Utc);
                            let datetime = tz_offset.from_local_datetime(&datetime).unwrap();
                            let utc_datetime = DateTime::<Utc>::from_utc(datetime.naive_utc(), Utc);
                            if utc_datetime < current_time {
                                Value::String(utc_datetime.format(&time_format).to_string())
                            } else {
                                let time_with_last_year =
                                    format!("{} {}", current_time.year() - 1, &datetime_str);
                                match NaiveDateTime::parse_from_str(
                                    &time_with_last_year,
                                    &format!("%Y {}", input_time_format),
                                ) {
                                    Ok(datetime) => {
                                        let datetime =
                                            tz_offset.from_local_datetime(&datetime).unwrap();
                                        let utc_datetime =
                                            DateTime::<Utc>::from_utc(datetime.naive_utc(), Utc);
                                        Value::String(utc_datetime.format(&time_format).to_string())
                                    }
                                    Err(e) => {
                                        error!("Unable to parser the date '{}' with the formate '{}', ERROR: '{}'", time_with_last_year, input_time_format, e);
                                        field
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                "Unable to parser the date '{}' with the formate '{}', ERROR: '{}'",
                                time_with_this_year, input_time_format, e
                            );
                            field
                        }
                    }
                }
                _ => field,
            },
            ModifierType::ToInt => match &field {
                Value::String(num) => match num.parse::<i64>() {
                    Ok(n) => json!(n),
                    Err(e) => {
                        error!(
                            "Unable to parser the string '{}' to type 'i64', ERROR: {}",
                            num, e
                        );
                        field
                    }
                },
                _ => field,
            },
        }
    }
}

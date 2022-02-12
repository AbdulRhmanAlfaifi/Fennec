#[derive(Debug)]
pub enum ErrorType {
    Config,
    OSQueryInstance,
    Query,
}
#[derive(Debug)]
pub struct FennecError {
    pub message: String,
    pub kind: ErrorType,
}
impl FennecError {
    pub fn config_error(message: String) -> Self {
        Self {
            message: message,
            kind: ErrorType::Config,
        }
    }
    pub fn osquery_instance_error(message: String) -> Self {
        Self {
            message: message,
            kind: ErrorType::OSQueryInstance,
        }
    }
    pub fn query_error(message: String) -> Self {
        Self {
            message: message,
            kind: ErrorType::Query,
        }
    }
}

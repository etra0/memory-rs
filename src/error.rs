#[derive(Debug, Clone)]
pub enum ErrorType {
    WinAPI,
    Internal
}

#[derive(Debug, Clone)]
pub struct Error {
    kind: ErrorType,
    msg: String
}

impl Error {
    pub fn new(kind: ErrorType, msg: String) -> Error {
        Error {
            kind,
            msg
        }
    }
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

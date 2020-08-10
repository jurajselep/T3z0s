use std::error;
use std::fmt;


#[derive(Debug, Clone)]
pub struct CannotFindMessagesError;

impl fmt::Display for CannotFindMessagesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cannot find messages")
    }
}

impl error::Error for CannotFindMessagesError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
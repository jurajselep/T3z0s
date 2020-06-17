use std::error;
use std::fmt;


#[derive(Debug, Clone)]
pub struct UnexpectedAddressTypeError;

impl fmt::Display for UnexpectedAddressTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unexpected address type")
    }
}

impl error::Error for UnexpectedAddressTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}


#[derive(Debug, Clone)]
pub struct CannotReadIPv4BytesError;

impl fmt::Display for CannotReadIPv4BytesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cannot read IPv4 bytes")
    }
}

impl error::Error for CannotReadIPv4BytesError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}


#[derive(Debug, Clone)]
pub struct CannotReadIPv6BytesError;

impl fmt::Display for CannotReadIPv6BytesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cannot read IPv6 bytes")
    }
}

impl error::Error for CannotReadIPv6BytesError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

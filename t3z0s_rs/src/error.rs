use std::error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct NotT3z0sStreamError;
impl fmt::Display for NotT3z0sStreamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "not a t3z0s stream")
    }
}
impl error::Error for NotT3z0sStreamError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct T3z0sNodeIdentityNotLoadedError;
impl fmt::Display for T3z0sNodeIdentityNotLoadedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "t3z0s node identity not loaded")
    }
}
impl error::Error for T3z0sNodeIdentityNotLoadedError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct UnknownDecrypterError;
impl fmt::Display for UnknownDecrypterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "t3z0s decypter unknown")
    }
}
impl error::Error for UnknownDecrypterError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct PeerNotUpgradedError;
impl fmt::Display for PeerNotUpgradedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "t3z0s peer not upgraded")
    }
}
impl error::Error for PeerNotUpgradedError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
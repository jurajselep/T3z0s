use std::error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct NotTezosStreamError;
impl fmt::Display for NotTezosStreamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "not a tezos stream")
    }
}
impl error::Error for NotTezosStreamError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct TezosNodeIdentityNotLoadedError;
impl fmt::Display for TezosNodeIdentityNotLoadedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tezos node identity not loaded")
    }
}
impl error::Error for TezosNodeIdentityNotLoadedError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct UnknownDecrypterError;
impl fmt::Display for UnknownDecrypterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tezos decypter unknown")
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
        write!(f, "tezos peer not upgraded")
    }
}
impl error::Error for PeerNotUpgradedError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

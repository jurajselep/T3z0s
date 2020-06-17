pub mod packet;
pub mod ws;

use std::convert::{TryFrom, TryInto};
use std::net::IpAddr;
use std::slice::from_raw_parts;
use failure::Error;

mod error;
use error::{
    UnexpectedAddressTypeError,
    CannotReadIPv4BytesError,
    CannotReadIPv6BytesError,
};

impl TryFrom<packet::address> for IpAddr {
    type Error = failure::Error;

    fn try_from(addr: packet::address) -> Result<Self, Self::Error> {
        let to_ip4 = || {
                let slice = unsafe { std::slice::from_raw_parts(addr.data as *const u8, 4) };
                let arr: [u8; 4] = slice.try_into().or(Err(CannotReadIPv6BytesError))?;
                Ok(IpAddr::from(arr))
        };
        let to_ip6 = || {
                let slice = unsafe { std::slice::from_raw_parts(addr.data as *const u8, 16) };
                let arr: [u8; 16] = slice.try_into().or(Err(CannotReadIPv6BytesError))?;
                Ok(IpAddr::from(arr))
        };
        match addr.type_ {
            address_type_AT_IPv4 => to_ip4(),
            address_type_AT_IPv6 => to_ip6(),
            _ => Err(UnexpectedAddressTypeError)?,
        }
    }
}
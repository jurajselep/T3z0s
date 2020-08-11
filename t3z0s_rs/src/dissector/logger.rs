use std::fs::OpenOptions;
use std::io::{Result, Write};

/// This is simple logger introduced during development, because
/// it is not possible to print to stdout/stderr inside wireshark/tshark.
fn msg_detail(msg: &str) -> Result<()> {
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .open("/tmp/xyz.log")?;
    writeln!(f, "R: {}", msg)?;
    Ok(())
}

pub fn msg(m: String) {
    msg_detail(&m);
}

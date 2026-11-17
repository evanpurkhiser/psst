use std::io::Write;

use crate::error::Result;

const SKILL: &str = include_str!("../skill-data/SKILL.md");

pub fn write(mut output: impl Write) -> Result<()> {
    output.write_all(SKILL.as_bytes())?;
    Ok(())
}

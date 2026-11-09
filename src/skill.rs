use std::io::Write;

use crate::error::Result;

const SKILL: &str = include_str!("../skill-data/SKILL.md");

pub fn write(mut output: impl Write) -> Result<()> {
    output.write_all(SKILL.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_skill_covers_secret_and_passkey_handoffs() {
        assert!(SKILL.starts_with("---\nname: psst\n"));
        assert!(SKILL.contains("psst fields"));
        assert!(SKILL.contains("psst passkey arm"));
        assert!(SKILL.contains("psst close"));
    }
}

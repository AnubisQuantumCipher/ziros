#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZkTheme {
    pub colors_enabled: bool,
    pub unicode_enabled: bool,
    pub success_symbol: &'static str,
    pub failure_symbol: &'static str,
    pub warning_symbol: &'static str,
    pub info_symbol: &'static str,
    pub sealed_label: &'static str,
}

impl ZkTheme {
    pub fn plain() -> Self {
        Self {
            colors_enabled: false,
            unicode_enabled: false,
            success_symbol: "[ok]",
            failure_symbol: "[x]",
            warning_symbol: "[!]",
            info_symbol: "[i]",
            sealed_label: "SEALED",
        }
    }
}

impl Default for ZkTheme {
    fn default() -> Self {
        let colors_enabled = std::env::var_os("NO_COLOR").is_none();
        Self {
            colors_enabled,
            unicode_enabled: true,
            success_symbol: "✓",
            failure_symbol: "✕",
            warning_symbol: "!",
            info_symbol: "•",
            sealed_label: "SEALED",
        }
    }
}

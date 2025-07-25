/// Application configuration constants
pub struct Config;

impl Config {
    /// The replacement base URL
    pub const REPLACEMENT_BASE_URL: &'static str = "https://chatwise.deno.dev";
    
    /// The replacement user API endpoint
    pub const REPLACEMENT_USER_API_ENDPOINT: &'static str = "https://chatwise.deno.dev/api/user";

    /// The original ChatWise base URL for pattern matching
    pub const ORIGINAL_BASE_URL: &'static str = "https://chatwise.app";

    /// The original user API endpoint for pattern matching
    pub const ORIGINAL_USER_API_ENDPOINT: &'static str = "https://chatwise.app/api/user";
}

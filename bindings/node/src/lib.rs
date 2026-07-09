use napi::Error;
use napi_derive::napi;

/// Invoke the shared Rust FFI adapter and return its untouched canonical JSON payload.
///
/// The JavaScript package parses this string exactly once, preventing a language-side serializer
/// from becoming part of the ScrapeProof wire contract.
#[napi]
pub fn scrape_json(url: String, options_json: Option<String>) -> napi::Result<String> {
    basecrawl_ffi::scrape_json(&url, options_json.as_deref())
        .map_err(|error| Error::from_reason(error.to_json_string().to_owned()))
}

#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

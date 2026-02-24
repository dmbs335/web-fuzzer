// URL parser target — Rust `url` crate (WHATWG URL Standard).
//
// Parses URLs using the `url` crate which implements the WHATWG URL Standard,
// same as browsers and Node.js `new URL()`.
//
// Key differences from other WHATWG implementations:
//   - Rust-specific edge cases in percent-encoding
//   - Different Unicode normalization behavior
//   - Stricter memory safety guarantees
//   - Interesting to compare with Node.js WHATWG implementation
//
// References:
//   - https://docs.rs/url/
//   - WHATWG URL Standard (https://url.spec.whatwg.org/)

use std::env;
use std::fs;
use std::process;

fn parse_url(data: &str) -> Result<String, String> {
    let data = data.trim();
    if data.is_empty() {
        return Err("Empty input".to_string());
    }

    let parsed = match url::Url::parse(data) {
        Ok(u) => u,
        Err(_) => {
            // Retry with base URL for relative references
            match url::Url::parse("http://placeholder.invalid/") {
                Ok(base) => match base.join(data) {
                    Ok(u) => u,
                    Err(e) => return Err(format!("Invalid URL: {}", e)),
                },
                Err(e) => return Err(format!("Base URL error: {}", e)),
            }
        }
    };

    // Extract userinfo
    let username = parsed.username();
    let password = parsed.password().unwrap_or("");
    let userinfo = if !username.is_empty() {
        if !password.is_empty() {
            format!("{}:{}", username, password)
        } else {
            username.to_string()
        }
    } else {
        String::new()
    };

    // Extract host
    let host = parsed.host_str().unwrap_or("").to_string();

    // Extract port
    let port = match parsed.port() {
        Some(p) => p.to_string(),
        None => String::new(),
    };

    // Extract path
    let path = parsed.path().to_string();

    // Extract query
    let query = parsed.query().unwrap_or("").to_string();

    // Extract fragment
    let fragment = parsed.fragment().unwrap_or("").to_string();

    // Extract scheme
    let scheme = parsed.scheme().to_string();

    let result = serde_json::json!({
        "scheme": scheme,
        "userinfo": userinfo,
        "host": host,
        "port": port,
        "path": path,
        "query": query,
        "fragment": fragment,
    });

    Ok(result.to_string())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: url_rust_url <file>");
        process::exit(2);
    }

    let data = match fs::read_to_string(&args[1]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("IO error: {}", e);
            process::exit(2);
        }
    };

    match parse_url(&data) {
        Ok(result) => {
            println!("{}", result);
            process::exit(0);
        }
        Err(e) => {
            eprintln!("REJECT: {}", e);
            process::exit(1);
        }
    }
}

//! Ammonia sanitizer differential target.
//!
//! Self-contained binary implementing the persistent wrapper protocol:
//!   Request:  [4-byte BE length][input bytes]
//!   Response: [4-byte BE length][output bytes][4-byte BE exit code]
//!
//! Also supports process mode: sanitizer_ammonia.exe <input_file>

use scraper::{Html, Node};
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};
use std::io::{self, Read, Write};

#[derive(Serialize)]
struct Result {
    sanitized: String,
    elements_kept: Vec<String>,
    attributes_kept: Vec<String>,
    has_script: bool,
    has_event_handler: bool,
    has_javascript_uri: bool,
    has_data_uri: bool,
    has_svg: bool,
    has_math: bool,
    has_style: bool,
    has_form: bool,
    has_base: bool,
    has_iframe: bool,
    has_object_embed: bool,
    has_noscript: bool,
    empty_output: bool,
    error: Option<String>,
}

fn is_event_handler(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("on") && lower.len() > 2 && lower.as_bytes()[2].is_ascii_lowercase()
}

fn is_js_uri(value: &str) -> bool {
    let trimmed = value.trim_start();
    let lower: String = trimmed.chars().take(15).collect::<String>().to_ascii_lowercase();
    // Handle optional whitespace inside "javascript"
    lower.starts_with("javascript:")
        || lower.starts_with("javascript :")
}

fn is_data_html_uri(value: &str) -> bool {
    let trimmed = value.trim_start().to_ascii_lowercase();
    trimmed.starts_with("data:text/html")
        || trimmed.starts_with("data: text/html")
}

static URI_ATTRS: &[&str] = &["href", "src", "action", "formaction", "poster", "data", "codebase"];

fn build_result(sanitized: &str) -> Result {
    let mut elements = BTreeSet::new();
    let mut attributes = BTreeSet::new();
    let mut has_script = false;
    let mut has_event_handler = false;
    let mut has_javascript_uri = false;
    let mut has_data_uri = false;

    let uri_set: HashSet<&str> = URI_ATTRS.iter().copied().collect();

    if !sanitized.trim().is_empty() {
        let doc = Html::parse_fragment(sanitized);
        for node_ref in doc.tree.nodes() {
            if let Node::Element(ref el) = node_ref.value() {
                let tag = el.name().to_ascii_lowercase();
                if tag != "html" && tag != "head" && tag != "body" {
                    if tag == "script" {
                        has_script = true;
                    }
                    elements.insert(tag);
                }
                for (name, value) in el.attrs() {
                    let name_lower = name.to_ascii_lowercase();
                    attributes.insert(name_lower.clone());
                    if is_event_handler(&name_lower) {
                        has_event_handler = true;
                    }
                    if uri_set.contains(name_lower.as_str()) {
                        if is_js_uri(value) {
                            has_javascript_uri = true;
                        }
                        if is_data_html_uri(value) {
                            has_data_uri = true;
                        }
                    }
                }
            }
        }
    }

    let truncated = if sanitized.len() > 2000 {
        &sanitized[..2000]
    } else {
        sanitized
    };

    Result {
        sanitized: truncated.to_string(),
        elements_kept: elements.iter().cloned().collect(),
        attributes_kept: attributes.iter().cloned().collect(),
        has_script,
        has_event_handler,
        has_javascript_uri,
        has_data_uri,
        has_svg: elements.contains("svg"),
        has_math: elements.contains("math"),
        has_style: elements.contains("style"),
        has_form: elements.contains("form"),
        has_base: elements.contains("base"),
        has_iframe: elements.contains("iframe"),
        has_object_embed: elements.contains("object")
            || elements.contains("embed")
            || elements.contains("applet"),
        has_noscript: elements.contains("noscript"),
        empty_output: sanitized.trim().is_empty(),
        error: None,
    }
}

fn process_input(input: &str) -> (Vec<u8>, u32) {
    let sanitized = ammonia::clean(input);
    let res = build_result(&sanitized);
    match serde_json::to_vec(&res) {
        Ok(data) => (data, 0),
        Err(e) => {
            let err_res = Result {
                sanitized: String::new(),
                elements_kept: vec![],
                attributes_kept: vec![],
                has_script: false,
                has_event_handler: false,
                has_javascript_uri: false,
                has_data_uri: false,
                has_svg: false,
                has_math: false,
                has_style: false,
                has_form: false,
                has_base: false,
                has_iframe: false,
                has_object_embed: false,
                has_noscript: false,
                empty_output: true,
                error: Some(e.to_string()),
            };
            let data = serde_json::to_vec(&err_res).unwrap_or_default();
            (data, 1)
        }
    }
}

fn read_u32_be(reader: &mut impl Read) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn persistent_mode() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdin = stdin.lock();
    let mut stdout = stdout.lock();

    loop {
        let length = match read_u32_be(&mut stdin) {
            Ok(n) => n,
            Err(_) => return,
        };

        let mut buf = vec![0u8; length as usize];
        if stdin.read_exact(&mut buf).is_err() {
            return;
        }

        let input = String::from_utf8_lossy(&buf);
        let (output, exit_code) = process_input(&input);

        let _ = stdout.write_all(&(output.len() as u32).to_be_bytes());
        let _ = stdout.write_all(&output);
        let _ = stdout.write_all(&exit_code.to_be_bytes());
        let _ = stdout.flush();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() >= 2 {
        // Process mode: read file
        let data = match std::fs::read_to_string(&args[1]) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error reading file: {}", e);
                std::process::exit(1);
            }
        };
        let (output, exit_code) = process_input(&data);
        let _ = io::stdout().write_all(&output);
        std::process::exit(exit_code as i32);
    }

    // No args: persistent mode
    persistent_mode();
}

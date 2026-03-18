//! SAML parser target using Rust quick-xml.
//!
//! Parser: quick-xml (pure Rust) - different from libxml2, Xerces, encoding/xml.
//! Does NOT verify signatures (reports signature_valid=false).
//! Value: tests XML parser differentials (namespace handling, attribute
//! ordering, comment handling, entity processing, etc.)

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process;

const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

#[derive(Default)]
struct SamlInfo {
    assertion_count: u32,
    subject: Option<String>,
    subject_format: Option<String>,
    issuer: Option<String>,
    issuer_source: Option<String>,
    audience: Option<String>,
    audience_count: u32,
    sig_algo: String,
    digest_algo: String,
    attributes: BTreeMap<String, String>,
    has_signature: bool,
    signature_count: u32,
    assertion_id: Option<String>,
    selected_assertion_index: Option<u32>,
    selection_mode: Option<String>,
    reference_uri: Option<String>,
    reference_matches_selected_assertion: Option<bool>,
    nameid_count: u32,
    empty_nameid_semantics: Option<String>,
}

fn normalize_algo(uri: &str) -> String {
    if let Some(idx) = uri.rfind('#') {
        uri[idx + 1..].to_string()
    } else if let Some(idx) = uri.rfind('/') {
        uri[idx + 1..].to_string()
    } else {
        uri.to_string()
    }
}

fn parse_saml(xml: &str) -> Result<SamlInfo, String> {
    let mut reader = Reader::from_str(xml);
    let mut info = SamlInfo::default();

    // Namespace tracking via prefix -> URI map
    let mut ns_map: BTreeMap<String, String> = BTreeMap::new();
    // Stack of element names (local name)
    let mut elem_stack: Vec<String> = Vec::new();
    // Current text buffer
    let mut text_buf = String::new();
    // Track which assertion depth we're in
    let mut in_assertion = false;
    let mut assertion_depth: usize = 0;
    // Track current attribute Name
    let mut current_attr_name: Option<String> = None;
    // Track if we're in specific elements
    let mut in_signature = false;

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                let full_name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                // Collect namespace declarations
                for attr in e.attributes().flatten() {
                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                    let val = String::from_utf8_lossy(&attr.value).to_string();
                    if key.starts_with("xmlns:") {
                        let prefix = &key[6..];
                        ns_map.insert(prefix.to_string(), val);
                    } else if key == "xmlns" {
                        ns_map.insert(String::new(), val);
                    }
                }

                // Resolve element namespace
                let elem_ns = resolve_ns(&full_name, &ns_map);

                // Track Assertions
                if local_name == "Assertion" && is_saml_ns(&elem_ns) {
                    info.assertion_count += 1;
                    if info.assertion_count == 1 {
                        in_assertion = true;
                        assertion_depth = elem_stack.len();
                        info.selected_assertion_index = Some(0);
                        info.selection_mode = Some("first_assertion_parser_order".to_string());
                        // Extract ID attribute from first assertion
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            if key.as_ref() == "ID" {
                                info.assertion_id =
                                    Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                        }
                    }
                }

                // Track Signature
                if local_name == "Signature" && is_ds_ns(&elem_ns) {
                    info.has_signature = true;
                    info.signature_count += 1;
                    in_signature = true;
                }

                if local_name == "Reference" && is_ds_ns(&elem_ns) && info.reference_uri.is_none() {
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref());
                        if key.as_ref() == "URI" {
                            let uri = String::from_utf8_lossy(&attr.value).to_string();
                            if !uri.is_empty() {
                                info.reference_uri = Some(uri);
                            }
                        }
                    }
                }

                // Extract algorithm attributes
                if in_signature {
                    if local_name == "SignatureMethod" {
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            if key.as_ref() == "Algorithm" {
                                info.sig_algo =
                                    normalize_algo(&String::from_utf8_lossy(&attr.value));
                            }
                        }
                    } else if local_name == "DigestMethod" {
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            if key.as_ref() == "Algorithm" {
                                info.digest_algo =
                                    normalize_algo(&String::from_utf8_lossy(&attr.value));
                            }
                        }
                    }
                }

                // Track NameID format
                if in_assertion && local_name == "NameID" {
                    info.nameid_count += 1;
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref());
                        if key.as_ref() == "Format" {
                            info.subject_format =
                                Some(String::from_utf8_lossy(&attr.value).to_string());
                        }
                    }
                }

                // Track Attribute Name
                if in_assertion && local_name == "Attribute" {
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref());
                        if key.as_ref() == "Name" {
                            current_attr_name =
                                Some(String::from_utf8_lossy(&attr.value).to_string());
                        }
                    }
                }

                elem_stack.push(local_name);
                text_buf.clear();
            }
            Ok(Event::End(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();

                // Capture text content of specific elements
                if in_assertion {
                    match local_name.as_str() {
                        "NameID" => {
                            if info.subject.is_none() {
                                let trimmed = text_buf.trim().to_string();
                                if !trimmed.is_empty() {
                                    info.subject = Some(trimmed);
                                    info.empty_nameid_semantics = Some("nonempty".to_string());
                                }
                            }
                        }
                        "Issuer" => {
                            if info.issuer.is_none() {
                                let trimmed = text_buf.trim().to_string();
                                if !trimmed.is_empty() {
                                    info.issuer = Some(trimmed);
                                    info.issuer_source = Some("assertion".to_string());
                                }
                            }
                        }
                        "Audience" => {
                            info.audience_count += 1;
                            if info.audience.is_none() {
                                let trimmed = text_buf.trim().to_string();
                                if !trimmed.is_empty() {
                                    info.audience = Some(trimmed);
                                }
                            }
                        }
                        "AttributeValue" => {
                            if let Some(ref name) = current_attr_name {
                                let trimmed = text_buf.trim().to_string();
                                if !trimmed.is_empty() {
                                    info.attributes.insert(name.clone(), trimmed);
                                }
                            }
                        }
                        "Attribute" => {
                            current_attr_name = None;
                        }
                        _ => {}
                    }
                } else if local_name == "Issuer" && info.issuer.is_none() {
                    // Response-level Issuer (before assertion)
                    let trimmed = text_buf.trim().to_string();
                    if !trimmed.is_empty() {
                        info.issuer = Some(trimmed);
                        info.issuer_source = Some("response".to_string());
                    }
                }

                // Check if we're leaving assertion
                if local_name == "Assertion"
                    && in_assertion
                    && elem_stack.len() == assertion_depth + 1
                {
                    in_assertion = false;
                }

                if local_name == "Signature" && in_signature {
                    in_signature = false;
                }

                elem_stack.pop();
                text_buf.clear();
            }
            Ok(Event::Text(ref e)) => {
                if let Ok(t) = e.unescape() {
                    text_buf.push_str(&t);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {}", e)),
            _ => {}
        }
        buf.clear();
    }

    if info.selection_mode.is_none() {
        info.selection_mode = Some("no_assertion".to_string());
    }
    if info.issuer_source.is_none() {
        info.issuer_source = Some("none".to_string());
    }
    if info.nameid_count == 0 {
        info.empty_nameid_semantics = Some("missing".to_string());
    } else if info.subject.is_none() {
        info.empty_nameid_semantics = Some("empty".to_string());
    } else if info.empty_nameid_semantics.is_none() {
        info.empty_nameid_semantics = Some("nonempty".to_string());
    }
    if let (Some(reference_uri), Some(assertion_id)) = (&info.reference_uri, &info.assertion_id) {
        if let Some(target_id) = reference_uri.strip_prefix('#') {
            info.reference_matches_selected_assertion = Some(target_id == assertion_id);
        }
    }

    Ok(info)
}

fn resolve_ns(full_name: &str, ns_map: &BTreeMap<String, String>) -> String {
    if let Some(idx) = full_name.find(':') {
        let prefix = &full_name[..idx];
        ns_map.get(prefix).cloned().unwrap_or_default()
    } else {
        ns_map.get("").cloned().unwrap_or_default()
    }
}

fn is_saml_ns(ns: &str) -> bool {
    ns == SAML_NS || ns.contains("SAML:2.0:assertion") || ns.contains("SAML:2.0:Assertion")
}

fn is_ds_ns(ns: &str) -> bool {
    ns == DS_NS || ns.contains("xmldsig")
}

fn verify_saml(xml: &str) -> String {
    match parse_saml(xml) {
        Ok(info) => {
            let sig_error = if info.has_signature {
                json!("Signature verification not implemented (parser-only target)")
            } else {
                json!("No Signature element found")
            };

            let result = json!({
                "algorithms": {
                    "digest": info.digest_algo,
                    "signature": info.sig_algo,
                },
                "assertion_count": info.assertion_count,
                "assertion_id": info.assertion_id,
                "selected_assertion_index": info.selected_assertion_index,
                "selection_mode": info.selection_mode,
                "reference_uri": info.reference_uri,
                "reference_matches_selected_assertion": info.reference_matches_selected_assertion,
                "signature_count": info.signature_count,
                "attributes": info.attributes,
                "audience": info.audience,
                "audience_count": info.audience_count,
                "issuer": info.issuer,
                "issuer_source": info.issuer_source,
                "nameid_count": info.nameid_count,
                "empty_nameid_semantics": info.empty_nameid_semantics,
                "signature_error": sig_error,
                "signature_valid": false,
                "validated_signature_algorithm": null,
                "subject": info.subject,
                "subject_format": info.subject_format,
            });
            result.to_string()
        }
        Err(e) => {
            let result = json!({
                "algorithms": {"digest": "", "signature": ""},
                "assertion_count": 0,
                "selected_assertion_index": null,
                "selection_mode": "no_assertion",
                "reference_uri": null,
                "reference_matches_selected_assertion": null,
                "signature_count": 0,
                "attributes": {},
                "audience": null,
                "audience_count": 0,
                "issuer": null,
                "issuer_source": "none",
                "nameid_count": 0,
                "empty_nameid_semantics": "missing",
                "signature_error": format!("Parse error: {}", e),
                "signature_valid": false,
                "validated_signature_algorithm": null,
                "subject": null,
                "subject_format": null,
            });
            result.to_string()
        }
    }
}

fn persistent_mode() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    loop {
        let mut len_buf = [0u8; 4];
        if reader.read_exact(&mut len_buf).is_err() {
            break;
        }
        let length = u32::from_be_bytes(len_buf) as usize;

        let mut input_buf = vec![0u8; length];
        if reader.read_exact(&mut input_buf).is_err() {
            break;
        }

        let input = String::from_utf8_lossy(&input_buf);
        let output = verify_saml(&input);
        let exit_code: u32 = 0; // Always succeeds (parse errors in JSON)

        let out_bytes = output.as_bytes();
        let _ = writer.write_all(&(out_bytes.len() as u32).to_be_bytes());
        let _ = writer.write_all(out_bytes);
        let _ = writer.write_all(&exit_code.to_be_bytes());
        let _ = writer.flush();
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && args[1] == "--persistent" {
        persistent_mode();
        return;
    }

    if args.len() < 2 {
        eprintln!("Usage: saml_rust_xmlparser <file>");
        eprintln!("       saml_rust_xmlparser --persistent");
        process::exit(2);
    }

    let data = match fs::read_to_string(&args[1]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("IO error: {}", e);
            process::exit(2);
        }
    };

    let result = verify_saml(&data);
    println!("{}", result);
}

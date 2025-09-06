use serde_json::Value;
use crate::models::{Node, RegexPatterns};

// Parsing functions
pub fn parse_vmess(text: &str, patterns: &RegexPatterns) -> Vec<Node> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let mut nodes = Vec::new();
    
    for cap in patterns.vmess_regex.captures_iter(text) {
        if let Some(b64) = cap.get(1) {
            if let Ok(decoded) = STANDARD.decode(b64.as_str()) {
                if let Ok(json_str) = String::from_utf8(decoded) {
                    if let Ok(config) = serde_json::from_str::<Value>(&json_str) {
                        if let (Some(host), Some(port)) = (
                            config.get("add").and_then(|v| v.as_str()),
                            config.get("port").and_then(|v| v.as_u64())
                        ) {
                            if port <= 65535 {
                                nodes.push(Node::new(host.to_string(), port as u16));
                            }
                        }
                    }
                }
            }
        }
    }
    
    nodes
}

pub fn parse_protocol_url(text: &str, patterns: &RegexPatterns, protocol: &str) -> Vec<Node> {
    let mut nodes = Vec::new();
    let regex = match protocol {
        "vless" => &patterns.vless_regex,
        "trojan" => &patterns.trojan_regex,
        "ss" => &patterns.ss_regex,
        _ => return nodes,
    };
    
    for cap in regex.captures_iter(text) {
        if let Some(hostport) = cap.get(1) {
            let hostport = hostport.as_str();
            if let Some(colon_pos) = hostport.rfind(':') {
                let host = &hostport[..colon_pos];
                let port_str = &hostport[colon_pos + 1..];
                if let Ok(port) = port_str.parse::<u16>() {
                    nodes.push(Node::new(host.to_string(), port));
                }
            }
        }
    }
    
    nodes
}

pub fn parse_ssr(text: &str, patterns: &RegexPatterns) -> Vec<Node> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let mut nodes = Vec::new();
    
    for cap in patterns.ssr_regex.captures_iter(text) {
        if let Some(b64) = cap.get(1) {
            if let Ok(decoded) = STANDARD.decode(b64.as_str()) {
                if let Ok(decoded_str) = String::from_utf8(decoded) {
                    let parts: Vec<&str> = decoded_str.split(':').collect();
                    if parts.len() >= 6 {
                        if let Ok(port) = parts[1].parse::<u16>() {
                            nodes.push(Node::new(parts[0].to_string(), port));
                        }
                    }
                }
            }
        }
    }
    
    nodes
}

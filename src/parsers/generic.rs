use serde_json::Value;
use crate::models::{Node, RegexPatterns};
use crate::config::{MAX_JSON_MATCHES, MAX_HOSTPORT_MATCHES};

pub fn parse_inline_json(text: &str, patterns: &RegexPatterns) -> Vec<Node> {
    let mut nodes = Vec::new();
    
    for cap in patterns.json_inline_regex.captures_iter(text).take(MAX_JSON_MATCHES) {
        if let Some(json_str) = cap.get(1) {
            if let Ok(obj) = serde_json::from_str::<Value>(json_str.as_str()) {
                if let (Some(host), Some(port)) = (
                    obj.get("server").or_else(|| obj.get("address")).and_then(|v| v.as_str()),
                    obj.get("port").and_then(|v| v.as_u64())
                ) {
                    if port <= 65535 {
                        nodes.push(Node::new(host.to_string(), port as u16));
                    }
                }
            }
        }
    }
    
    nodes
}

pub fn parse_generic(text: &str, patterns: &RegexPatterns) -> Vec<Node> {
    let mut nodes = Vec::new();
    
    for cap in patterns.hostport_regex.captures_iter(text).take(MAX_HOSTPORT_MATCHES) {
        if let (Some(host), Some(port_str)) = (cap.get(1), cap.get(2)) {
            if let Ok(port) = port_str.as_str().parse::<u16>() {
                nodes.push(Node::new(host.as_str().to_string(), port));
            }
        }
    }
    
    nodes
}
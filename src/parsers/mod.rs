pub mod proxy_urls;
pub mod config_files;
pub mod generic;

// pub use proxy_urls::*;
// pub use config_files::*;

// Your detect_format_and_parse and parse_subscription_safe functions go here
use crate::models::{Node, RegexPatterns};
use crate::utils::{safe_limit_text};
use crate::parsers::{
    proxy_urls::{parse_vmess, parse_protocol_url, parse_ssr},
    config_files::{parse_clash_yaml, parse_v2ray_json},
    generic::{parse_generic, parse_inline_json},
};
use tokio::time::{Instant, timeout};
use crate::config::{PARSE_TIMEOUT};

pub fn detect_format_and_parse(text: &str, patterns: &RegexPatterns, verbose: bool) -> Vec<Node> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    
    let text = safe_limit_text(text);
    let text_lower = text.to_lowercase();
    
    if verbose {
        println!("VERBOSE: Detecting format for {} chars", text.len());
    }
    
    // Try format-specific parsers
    if text_lower.contains("proxies:") || text_lower.contains("proxy-groups:") {
        if verbose { println!("VERBOSE: Trying Clash YAML parser"); }
        let nodes = parse_clash_yaml(&text);
        if !nodes.is_empty() { return nodes; }
    }
    
    if text.trim_start().starts_with('{') && (text_lower.contains("outbounds") || text_lower.contains("inbounds")) {
        if verbose { println!("VERBOSE: Trying V2Ray JSON parser"); }
        let nodes = parse_v2ray_json(&text);
        if !nodes.is_empty() { return nodes; }
    }
    
    if text.contains("vmess://") {
        if verbose { println!("VERBOSE: Trying VMess parser"); }
        let nodes = parse_vmess(&text, patterns);
        if !nodes.is_empty() { return nodes; }
    }
    
    for protocol in &["vless", "trojan", "ss"] {
        if text.contains(&format!("{}://", protocol)) {
            if verbose { println!("VERBOSE: Trying {} parser", protocol); }
            let nodes = parse_protocol_url(&text, patterns, protocol);
            if !nodes.is_empty() { return nodes; }
        }
    }
    
    if text.contains("ssr://") {
        if verbose { println!("VERBOSE: Trying SSR parser"); }
        let nodes = parse_ssr(&text, patterns);
        if !nodes.is_empty() { return nodes; }
    }
    
    if text.contains('{') && (text_lower.contains("server") || text_lower.contains("address")) {
        if verbose { println!("VERBOSE: Trying inline JSON parser"); }
        let nodes = parse_inline_json(&text, patterns);
        if !nodes.is_empty() { return nodes; }
    }
    
    if verbose { println!("VERBOSE: Using generic parser"); }
    parse_generic(&text, patterns)
}

pub async fn parse_subscription_safe(
    url: String,
    body: String,
    patterns: &RegexPatterns,
    verbose: bool,
) -> (String, Vec<Node>) {
    let start = Instant::now();
    
    if body.is_empty() {
        if verbose {
            println!("VERBOSE: {} - No body to parse", url);
        }
        return (url, Vec::new());
    }
    
    if body.len() > 100 * 1024 * 1024 {
        println!("Skipping {} - too large ({} bytes)", url, body.len());
        return (url, Vec::new());
    }
    
    let result = timeout(PARSE_TIMEOUT, async {
        detect_format_and_parse(&body, patterns, verbose)
    }).await;
    
    let nodes = match result {
        Ok(nodes) => nodes,
        Err(_) => {
            println!("Parse timeout for {} - skipping", url);
            Vec::new()
        }
    };
    
    let elapsed = start.elapsed().as_secs_f64();
    if verbose {
        println!("VERBOSE: {} - Parse complete, found {} nodes in {:.1}s", url, nodes.len(), elapsed);
    }
    
    (url, nodes)
}
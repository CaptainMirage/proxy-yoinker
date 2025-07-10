use clap::Parser;
use regex::Regex;
use reqwest::Client;
#[allow(unused_imports)] // for the serilize stuff
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::sync::Semaphore;
use tokio::time::timeout;

// Optimized constants for Rust
const URL_TIMEOUT: Duration = Duration::from_secs(3);
const NODE_TIMEOUT: Duration = Duration::from_secs(2);  
const PARSE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IO_WORKERS: usize = 100;
const MAX_PARSE_WORKERS: usize = 30;
const MAX_TEXT_SIZE: usize = 50 * 1024 * 1024; // 50MB
const MAX_LINES: usize = 50000;

// ETA estimation constants
const EST_URL_CHECK_TIME: f64 = 0.15;
const EST_FETCH_TIME: f64 = 0.4;
const EST_PARSE_TIME: f64 = 0.2;
const EST_NODE_TIME: f64 = 0.1;
const EST_NODES_PER_SUB: f64 = 50.0;

#[derive(Parser)]
#[command(about = "Concurrent Subscription Node Latency Tester")]
struct Args {
    /// Input folder or file to scan
    input: String,
    
    /// Output file for working URLs
    #[arg(short = 'u', long, default_value = "working_links.md")]
    url_out: String,
    
    /// Output file for node latencies
    #[arg(short = 'n', long, default_value = "node_latencies.md")]
    node_out: String,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
    
    /// Maximum IO workers
    #[arg(long, default_value_t = MAX_IO_WORKERS)]
    max_io_workers: usize,
    
    /// Maximum parse workers
    #[arg(long, default_value_t = MAX_PARSE_WORKERS)]
    max_parse_workers: usize,
}

#[derive(Debug, Clone)]
struct Node {
    host: String,
    port: u16,
}

impl Node {
    fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }
    
    fn url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }
}

impl std::hash::Hash for Node {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.host.hash(state);
        self.port.hash(state);
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.host == other.host && self.port == other.port
    }
}

impl Eq for Node {}

#[derive(Debug)]
struct UrlResult {
    url: String,
    status: Option<u16>,
    latency: Option<f64>,
}

#[derive(Debug, Clone)]
struct NodeResult {
    node: Node,
    status: Option<u16>,
    latency: Option<f64>,
}

struct RegexPatterns {
    url_regex: Regex,
    hostport_regex: Regex,
    vmess_regex: Regex,
    vless_regex: Regex,
    trojan_regex: Regex,
    ss_regex: Regex,
    ssr_regex: Regex,
    json_inline_regex: Regex,
}

impl RegexPatterns {
    fn new() -> Self {
        Self {
            url_regex: Regex::new(r"https?://[^\s)]+").unwrap(),
            hostport_regex: Regex::new(r"([0-9a-zA-Z.\-]+):(\d{2,5})").unwrap(),
            vmess_regex: Regex::new(r"vmess://([A-Za-z0-9+/=]+)").unwrap(),
            vless_regex: Regex::new(r"vless://[^@]+@([^/?#]+)").unwrap(),
            trojan_regex: Regex::new(r"trojan://[^@]+@([^/?#]+)").unwrap(),
            ss_regex: Regex::new(r"ss://[^@]+@([^/?#]+)").unwrap(),
            ssr_regex: Regex::new(r"ssr://([A-Za-z0-9+/=]+)").unwrap(),
            json_inline_regex: Regex::new(r"-\s*(\{[^}]*\})").unwrap(),
        }
    }
}

fn format_duration(seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{:.0}s", seconds)
    } else if seconds < 3600.0 {
        format!("{:.0}m {:.0}s", seconds / 60.0, seconds % 60.0)
    } else {
        let hours = seconds / 3600.0;
        let minutes = (seconds % 3600.0) / 60.0;
        format!("{:.0}h {:.0}m", hours, minutes)
    }
}

fn estimate_total_time(num_urls: usize) -> (f64, f64) {
    let num_urls = num_urls as f64;
    let url_phase = (num_urls * EST_URL_CHECK_TIME) / MAX_IO_WORKERS as f64;
    let fetch_phase = (num_urls * 0.7 * EST_FETCH_TIME) / MAX_IO_WORKERS as f64;
    let parse_phase = (num_urls * 0.7 * EST_PARSE_TIME) / MAX_PARSE_WORKERS as f64;
    let node_phase = (num_urls * 0.7 * EST_NODES_PER_SUB * EST_NODE_TIME) / MAX_IO_WORKERS as f64;
    
    let total = url_phase + fetch_phase + parse_phase + node_phase;
    (total, url_phase + fetch_phase + parse_phase)
}

fn extract_urls(text: &str, patterns: &RegexPatterns) -> Vec<String> {
    patterns.url_regex
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

fn safe_limit_text(text: &str) -> String {
    let mut result = text;
    
    // Limit by size
    if result.len() > MAX_TEXT_SIZE {
        result = &result[..MAX_TEXT_SIZE];
    }
    
    // Limit by lines
    let lines: Vec<&str> = result.lines().collect();
    if lines.len() > MAX_LINES {
        lines[..MAX_LINES].join("\n")
    } else {
        result.to_string()
    }
}

async fn http_check(client: &Client, url: &str, timeout_duration: Duration) -> UrlResult {
    let start = Instant::now();
    
    let result = timeout(timeout_duration, async {
        // Try HEAD first, then GET if it fails
        let response = client.head(url).send().await;
        match response {
            Ok(resp) if resp.status().as_u16() < 400 => Ok(resp),
            _ => client.get(url).send().await,
        }
    }).await;
    
    let latency = start.elapsed().as_secs_f64() * 1000.0;
    
    match result {
        Ok(Ok(response)) => UrlResult {
            url: url.to_string(),
            status: Some(response.status().as_u16()),
            latency: Some(latency),
        },
        _ => UrlResult {
            url: url.to_string(),
            status: None,
            latency: None,
        },
    }
}

async fn fetch_body(client: &Client, url: &str, timeout_duration: Duration) -> (String, Option<String>) {
    let result = timeout(timeout_duration, client.get(url).send()).await;
    
    match result {
        Ok(Ok(response)) => {
            if let Ok(text) = response.text().await {
                (url.to_string(), Some(text))
            } else {
                (url.to_string(), None)
            }
        }
        _ => (url.to_string(), None),
    }
}

// Parsing functions
fn parse_vmess(text: &str, patterns: &RegexPatterns) -> Vec<Node> {
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

fn parse_protocol_url(text: &str, patterns: &RegexPatterns, protocol: &str) -> Vec<Node> {
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

fn parse_ssr(text: &str, patterns: &RegexPatterns) -> Vec<Node> {
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

fn parse_clash_yaml(text: &str) -> Vec<Node> {
    let mut nodes = Vec::new();

    if let Ok(yaml_value) = serde_yaml::from_str::<serde_yaml::Value>(text) {
        if let Some(proxies) = yaml_value.get("proxies").and_then(|v| v.as_sequence()) {
            for proxy in proxies.iter().take(2000) {
                if let (Some(server), Some(port)) = (
                    proxy.get("server").and_then(|v| v.as_str()),
                    proxy.get("port").and_then(|v| v.as_u64())
                ) {
                    if port <= 65535 {
                        nodes.push(Node::new(server.to_string(), port as u16));
                    }
                }
            }
        }
    }

    nodes
}

fn parse_v2ray_json(text: &str) -> Vec<Node> {
    let mut nodes = Vec::new();
    
    if let Ok(config) = serde_json::from_str::<Value>(text) {
        if let Some(outbounds) = config.get("outbounds").and_then(|v| v.as_array()) {
            for outbound in outbounds {
                if let Some(vnext_array) = outbound
                    .get("settings")
                    .and_then(|s| s.get("vnext"))
                    .and_then(|v| v.as_array())
                {
                    for vnext in vnext_array {
                        if let (Some(address), Some(port)) = (
                            vnext.get("address").and_then(|v| v.as_str()),
                            vnext.get("port").and_then(|v| v.as_u64())
                        ) {
                            if port <= 65535 {
                                nodes.push(Node::new(address.to_string(), port as u16));
                            }
                        }
                    }
                }
            }
        }
    }
    
    nodes
}

fn parse_inline_json(text: &str, patterns: &RegexPatterns) -> Vec<Node> {
    let mut nodes = Vec::new();
    
    for cap in patterns.json_inline_regex.captures_iter(text).take(1000) {
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

fn parse_generic(text: &str, patterns: &RegexPatterns) -> Vec<Node> {
    let mut nodes = Vec::new();
    
    for cap in patterns.hostport_regex.captures_iter(text).take(5000) {
        if let (Some(host), Some(port_str)) = (cap.get(1), cap.get(2)) {
            if let Ok(port) = port_str.as_str().parse::<u16>() {
                nodes.push(Node::new(host.as_str().to_string(), port));
            }
        }
    }
    
    nodes
}

fn detect_format_and_parse(text: &str, patterns: &RegexPatterns, verbose: bool) -> Vec<Node> {
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

async fn parse_subscription_safe(
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

async fn node_http_check(client: &Client, node: Node, timeout_duration: Duration) -> NodeResult {
    let url = node.url();
    let result = http_check(client, &url, timeout_duration).await;
    
    NodeResult {
        node,
        status: result.status,
        latency: result.latency,
    }
}

async fn gather_text(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = Path::new(path);
    let mut texts = Vec::new();
    
    if path.is_dir() {
        let mut entries = fs::read_dir(path).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_file() {
                if let Ok(content) = fs::read_to_string(&path).await {
                    texts.push(content);
                }
            }
        }
    } else {
        if let Ok(content) = fs::read_to_string(path).await {
            texts.push(content);
        }
    }
    
    Ok(texts.join("\n"))
}

async fn write_url_report(path: &str, working_urls: &[(String, f64)]) -> Result<(), Box<dyn std::error::Error>> {
    let mut content = String::from("# Working Subscription URLs\n\n| URL | Latency (ms) |\n|:----|------------:|\n");
    
    let mut sorted_urls = working_urls.to_vec();
    sorted_urls.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    
    for (url, latency) in sorted_urls {
        content.push_str(&format!("| {} | {:.1} |\n", url, latency));
    }
    
    fs::write(path, content).await?;
    Ok(())
}

async fn write_node_report(path: &str, node_results: &[NodeResult]) -> Result<(), Box<dyn std::error::Error>> {
    let mut content = String::from("# Node URL Latencies\n\n| Host | Port | Status | Latency (ms) |\n|:-----|-----:|------:|------------:|\n");
    
    let mut sorted_results = node_results.to_vec();
    sorted_results.sort_by(|a, b| {
        a.node.host.cmp(&b.node.host)
            .then_with(|| a.node.port.cmp(&b.node.port))
    });
    
    for result in sorted_results {
        let status = result.status.map_or("—".to_string(), |s| s.to_string());
        let latency = result.latency.map_or("—".to_string(), |l| format!("{:.1}", l));
        content.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            result.node.host, result.node.port, status, latency
        ));
    }
    
    fs::write(path, content).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let start_time = Instant::now();
    
    println!("🚀 Starting subscription analysis...");
    
    let patterns = Arc::new(RegexPatterns::new());
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    
    // Gather text and extract URLs
    let raw_text = gather_text(&args.input).await?;
    let urls: Vec<String> = extract_urls(&raw_text, &patterns)
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    
    let total_urls = urls.len();
    let (total_eta, pre_node_eta) = estimate_total_time(total_urls);
    
    println!("📊 Found {} URLs - Estimated total time: {}", total_urls, format_duration(total_eta));
    println!("   (URL check + fetch + parse: ~{}, node testing: ~{})", 
             format_duration(pre_node_eta), format_duration(total_eta - pre_node_eta));
    println!();
    
    // Phase 1: URL checking
    println!("🔍 Testing {} subscription URLs with {} workers...", total_urls, args.max_io_workers);
    let url_semaphore = Arc::new(Semaphore::new(args.max_io_workers));
    let url_counter = Arc::new(AtomicUsize::new(0));
    
    let mut url_tasks = Vec::new();
    for url in urls {
        let client = client.clone();
        let semaphore = url_semaphore.clone();
        let counter = url_counter.clone();
        
        url_tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let result = http_check(&client, &url, URL_TIMEOUT).await;
            let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
            
            let status = result.status.map_or("FAIL".to_string(), |s| s.to_string());
            let latency = result.latency.map_or("—".to_string(), |l| format!("{:.1} ms", l));
            println!("URL [{}/{}] {} -> {}, {}", count, total_urls, result.url, status, latency);
            
            result
        }));
    }
    
    let mut url_results = Vec::new();
    for task in url_tasks {
        url_results.push(task.await?);
    }
    
    let working_urls: Vec<(String, f64)> = url_results
        .into_iter()
        .filter_map(|r| {
            if r.status == Some(200) {
                Some((r.url, r.latency.unwrap_or(0.0)))
            } else {
                None
            }
        })
        .collect();
    
    println!("✅ Found {} working URLs out of {}", working_urls.len(), total_urls);
    
    // Write URL report
    write_url_report(&args.url_out, &working_urls).await?;
    
    // Phase 2: Fetch bodies
    println!("📥 Fetching bodies for {} subscriptions with {} workers...", working_urls.len(), args.max_io_workers);
    let fetch_semaphore = Arc::new(Semaphore::new(args.max_io_workers));
    let fetch_counter = Arc::new(AtomicUsize::new(0));
    
    let mut fetch_tasks = Vec::new();
    let fetch_tasks_len = working_urls.len();
    for (url, _) in working_urls {
        let client = client.clone();
        let semaphore = fetch_semaphore.clone();
        let counter = fetch_counter.clone();
        
        fetch_tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let (url, body) = fetch_body(&client, &url, URL_TIMEOUT).await;
            let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
            
            let size = body.as_ref().map_or(0, |b| b.len());
            let status = if body.is_some() { "OK" } else { "FAIL" };
            println!("Fetch [{}/{}] {} -> {}, {} chars", count, fetch_tasks_len, url, status, size);
            
            (url, body)
        }));
    }
    
    let mut bodies = Vec::new();
    for task in fetch_tasks {
        let (url, body) = task.await?;
        if let Some(body) = body {
            bodies.push((url, body));
        }
    }
    
    // Phase 3: Parse subscriptions
    println!("🔧 Parsing nodes from {} subscriptions with {} workers...", bodies.len(), args.max_parse_workers);
    let parse_semaphore = Arc::new(Semaphore::new(args.max_parse_workers));
    let parse_counter = Arc::new(AtomicUsize::new(0));
    
    let mut parse_tasks = Vec::new();
    let parse_tasks_len = bodies.len();
    for (url, body) in bodies {
        let semaphore = parse_semaphore.clone();
        let counter = parse_counter.clone();
        let patterns = patterns.clone();
        
        parse_tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let parse_start = Instant::now();
            let (url, nodes) = parse_subscription_safe(url, body, &patterns, args.verbose).await;
            let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
            let elapsed = parse_start.elapsed().as_secs_f64();
            
            println!("Parse [{}/{}] {} -> {} nodes (took {:.1}s)", 
                     count, parse_tasks_len, url, nodes.len(), elapsed);
            
            nodes
        }));
    }
    
    let mut all_nodes = HashSet::new();
    for task in parse_tasks {
        let nodes = task.await?;
        all_nodes.extend(nodes);
    }
    
    println!("🎯 Total unique nodes parsed: {}", all_nodes.len());
    
    // Phase 4: Test nodes
    println!("🌐 Testing {} node URLs with {} workers...", all_nodes.len(), args.max_io_workers);
    let node_semaphore = Arc::new(Semaphore::new(args.max_io_workers));
    let node_counter = Arc::new(AtomicUsize::new(0));
    
    let mut node_tasks = Vec::new();
    let node_tasks_len = all_nodes.len();
    for node in all_nodes {
        let client = client.clone();
        let semaphore = node_semaphore.clone();
        let counter = node_counter.clone();
        let node_tasks_len = node_tasks_len;
        
        node_tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let result = node_http_check(&client, node, NODE_TIMEOUT).await;
            let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
            
            let status = result.status.map_or("FAIL".to_string(), |s| s.to_string());
            let latency = result.latency.map_or("—".to_string(), |l| format!("{:.1} ms", l));
            println!("Node [{}/{}] {}:{} -> {}, {}", 
                     count, node_tasks_len, result.node.host, result.node.port, status, latency);
            
            result
        }));
    }
    
    let mut node_results = Vec::new();
    for task in node_tasks {
        node_results.push(task.await?);
    }
    
    // Write node report
    write_node_report(&args.node_out, &node_results).await?;
    
    // Final timing
    let total_elapsed = start_time.elapsed().as_secs_f64();
    println!("\n🏁 Done! Total time: {} (estimated: {})", 
             format_duration(total_elapsed), format_duration(total_eta));
    
    Ok(())
}
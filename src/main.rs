use clap::Parser;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use std::collections::HashSet;

// Import from your modules
use crate::config::*;
use crate::models::*;
use crate::parsers::*;
use crate::network::*;
use crate::io::*;
use crate::utils::*;


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
use clap::Parser;
use std::time::Duration;


// Optimized constants for Rust
pub const URL_TIMEOUT: Duration = Duration::from_secs(3);
pub const NODE_TIMEOUT: Duration = Duration::from_secs(2);  
pub const PARSE_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_IO_WORKERS: usize = 100;
pub const MAX_PARSE_WORKERS: usize = 30;
pub const MAX_TEXT_SIZE: usize = 50 * 1024 * 1024; // 50MB
pub const MAX_LINES: usize = 50000;
pub const MAX_PROXIES_PER_CONFIG: usize = 2000;
pub const MAX_HOSTPORT_MATCHES: usize = 5000;
pub const MAX_JSON_MATCHES: usize = 1000;

// ETA estimation constants
pub const EST_URL_CHECK_TIME: f64 = 0.15;
pub const EST_FETCH_TIME: f64 = 0.4;
pub const EST_PARSE_TIME: f64 = 0.2;
pub const EST_NODE_TIME: f64 = 0.1;
pub const EST_NODES_PER_SUB: f64 = 50.0;

#[derive(Parser)]
#[command(about = "Concurrent Subscription Node Latency Tester")]
pub struct Args {
    /// Input folder or file to scan
    pub input: String,
    
    /// Output file for working URLs
    #[arg(short = 'u', long, default_value = "working_links.md")]
    pub url_out: String,
    
    /// Output file for node latencies
    #[arg(short = 'n', long, default_value = "node_latencies.md")]
    pub node_out: String,
    
    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,
    
    /// Maximum IO workers
    #[arg(long, default_value_t = MAX_IO_WORKERS)]
    pub max_io_workers: usize,
    
    /// Maximum parse workers
    #[arg(long, default_value_t = MAX_PARSE_WORKERS)]
    pub max_parse_workers: usize,
}

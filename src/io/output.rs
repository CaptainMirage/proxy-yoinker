use tokio::fs;
use crate::models::NodeResult;

pub async fn write_url_report(path: &str, working_urls: &[(String, f64)]) -> Result<(), Box<dyn std::error::Error>> {
    let mut content = String::from("# Working Subscription URLs\n\n| URL | Latency (ms) |\n|:----|------------:|\n");
    
    let mut sorted_urls = working_urls.to_vec();
    sorted_urls.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    
    for (url, latency) in sorted_urls {
        content.push_str(&format!("| {} | {:.1} |\n", url, latency));
    }
    
    fs::write(path, content).await?;
    Ok(())
}

pub async fn write_node_report(path: &str, node_results: &[NodeResult]) -> Result<(), Box<dyn std::error::Error>> {
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

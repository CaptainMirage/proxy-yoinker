use reqwest::Client;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use crate::models::{UrlResult, NodeResult, Node};

pub async fn http_check(client: &Client, url: &str, timeout_duration: Duration) -> UrlResult {
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

pub async fn node_http_check(client: &Client, node: Node, timeout_duration: Duration) -> NodeResult {
    let url = node.url();
    let result = http_check(client, &url, timeout_duration).await;
    
    NodeResult {
        node,
        status: result.status,
        latency: result.latency,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    use std::time::Duration;

    #[tokio::test]
    async fn test_node_http_check() {
        let client = Client::new();
        let node = crate::models::Node::new("127.0.0.1".to_string(), 8080);
        let _ = node_http_check(&client, node, Duration::from_secs(1)).await;
    }
}

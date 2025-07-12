use reqwest::Client;
use std::time::Duration;
use tokio::time::timeout;

pub async fn fetch_body(client: &Client, url: &str, timeout_duration: Duration) -> (String, Option<String>) {
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
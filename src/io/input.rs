use std::path::Path;
use tokio::fs;

pub async fn gather_text(path: &str) -> Result<String, Box<dyn std::error::Error>> {
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
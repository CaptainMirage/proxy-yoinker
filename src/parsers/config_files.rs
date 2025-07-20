use serde_json::Value;
use crate::models::{Node};
use crate::config::{MAX_PROXIES_PER_CONFIG};

pub fn parse_clash_yaml(text: &str) -> Vec<Node> {
    let mut nodes = Vec::new();

    if let Ok(yaml_value) = serde_yaml::from_str::<serde_yaml::Value>(text) {
        if let Some(proxies) = yaml_value.get("proxies").and_then(|v| v.as_sequence()) {
            for proxy in proxies.iter().take(MAX_PROXIES_PER_CONFIG) {
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

pub fn parse_v2ray_json(text: &str) -> Vec<Node> {
    let mut nodes = Vec::new();
    
    if let Ok(config) = serde_json::from_str::<Value>(text) {
        if let Some(outbounds) = config.get("outbounds").and_then(|v| v.as_array()) {
            for outbound in outbounds {
                if let Some(server_configs) = outbound
                    .get("settings")
                    .and_then(|s| s.get("vnext"))
                    .and_then(|v| v.as_array())
                {
                    for vnext in server_configs {
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

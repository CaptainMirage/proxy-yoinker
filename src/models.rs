use regex::Regex;


#[derive(Debug, Clone)]
pub struct Node {
    pub host: String,
    pub port: u16,
}

impl Node {
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }
    
    pub fn url(&self) -> String {
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
pub struct UrlResult {
    pub url: String,
    pub status: Option<u16>,
    pub latency: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct NodeResult {
    pub node: Node,
    pub status: Option<u16>,
    pub latency: Option<f64>,
}

pub struct RegexPatterns {
    pub url_regex: Regex,
    pub hostport_regex: Regex,
    pub vmess_regex: Regex,
    pub vless_regex: Regex,
    pub trojan_regex: Regex,
    pub ss_regex: Regex,
    pub ssr_regex: Regex,
    pub json_inline_regex: Regex,
}

impl RegexPatterns {
    pub fn new() -> Self {
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
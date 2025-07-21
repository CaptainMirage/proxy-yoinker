use crate::models::RegexPatterns;

pub fn extract_urls(text: &str, patterns: &RegexPatterns) -> Vec<String> {
    patterns.url_regex
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

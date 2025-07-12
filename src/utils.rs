use crate::config::*;

pub fn format_duration(seconds: f64) -> String {
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

pub fn estimate_total_time(num_urls: usize) -> (f64, f64) {
    let num_urls = num_urls as f64;
    let url_phase = (num_urls * EST_URL_CHECK_TIME) / MAX_IO_WORKERS as f64;
    let fetch_phase = (num_urls * 0.7 * EST_FETCH_TIME) / MAX_IO_WORKERS as f64;
    let parse_phase = (num_urls * 0.7 * EST_PARSE_TIME) / MAX_PARSE_WORKERS as f64;
    let node_phase = (num_urls * 0.7 * EST_NODES_PER_SUB * EST_NODE_TIME) / MAX_IO_WORKERS as f64;
    
    let total = url_phase + fetch_phase + parse_phase + node_phase;
    (total, url_phase + fetch_phase + parse_phase)
}



pub fn safe_limit_text(text: &str) -> String {
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
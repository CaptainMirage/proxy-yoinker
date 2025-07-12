use reqwest::Client;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use crate::models::*;

// http_check, node_http_check functions go here
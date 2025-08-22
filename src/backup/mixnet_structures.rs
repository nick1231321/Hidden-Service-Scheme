// src/mixnet_types.rs

use reqwest::Error;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Mixnode {
    pub identity_key: String,
    pub host: String,
    #[serde(rename = "custom_http_port")]
    pub http_api_port: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BondInformation {
    pub node: Mixnode,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeEntry {
    pub bond_information: BondInformation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Pagination {
    pub start_next_after: Option<String>,
    pub limit: Option<usize>,
    pub total: Option<usize>,
    pub per_page: Option<usize>, // Keep it if you still want to support it
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MixnodeResponse {
    pub data: Vec<NodeEntry>,
    pub pagination: Pagination,
}
pub async fn fetch_mixnodes() -> Result<MixnodeResponse, Error> {
    let url = "https://validator.nymtech.net/api/v1/nym-nodes/bonded";
    let response = reqwest::get(url).await?;
    let nodes = response.json::<MixnodeResponse>().await?;
    Ok(nodes)
}

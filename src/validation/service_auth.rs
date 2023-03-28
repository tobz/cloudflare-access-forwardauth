use std::{collections::HashMap, path::Path, str::FromStr};

use axum::{headers::HeaderName, http::HeaderValue};
use hyper::HeaderMap;

#[derive(Debug, Default)]
pub struct ServiceAuthTokenHeaderMap {
    token_map: HashMap<String, HeaderMap>,
}

impl ServiceAuthTokenHeaderMap {
    pub fn from_mapping_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        // Open the path as a file and deserialize it with serde_yaml.
        let file = std::fs::File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
        let raw_token_map: HashMap<String, HashMap<String, String>> = serde_yaml::from_reader(file)
            .map_err(|e| format!("Failed to deserialize YAML: {}", e))?;

        // Convert the deserialized map into a map of HeaderMaps.
        let mut token_map = HashMap::new();
        for (token_client_id, raw_header_map) in raw_token_map {
            let mut header_map = HeaderMap::new();
            for (key, value) in raw_header_map {
                let key = HeaderName::from_str(&key)
                    .map_err(|e| format!("Failed to parse header key '{}': {}", key, e))?;
                let value = HeaderValue::from_str(&value)
                    .map_err(|e| format!("Failed to parse header value '{}': {}", value, e))?;
                header_map.insert(key, value);
            }
            token_map.insert(token_client_id, header_map);
        }

        Ok(Self { token_map })
    }

    pub fn get_header_map_for_token(&self, token_client_id: &str) -> Option<&HeaderMap> {
        self.token_map.get(token_client_id)
    }
}

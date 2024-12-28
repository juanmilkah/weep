#[derive(Debug, Clone, Default)]
pub struct MasterKey {
    pub key: String,
    pub filepath: String,
}

impl MasterKey {
    pub fn new(key: &str, filepath: String) -> MasterKey {
        MasterKey {
            key: key.to_string(),
            filepath,
        }
    }
}

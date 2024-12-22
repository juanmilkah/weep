#[derive(Debug)]
pub struct MasterKey {
    pub key: String,
}

impl MasterKey {
    pub fn new(key: &str) -> MasterKey {
        MasterKey {
            key: key.to_string(),
        }
    }
}

use reqwest::ClientBuilder;

pub struct DNSManager {
    username: String,
    password: String
}

impl DNSManager {
    const LOGIN_URL: &'static str = "https://";

    fn new(username: &str, password: &str) -> Result<Self, String> {
        
        Ok(Self {
            username: String::from(username),
            password: String::from(password),
        })
    }
}
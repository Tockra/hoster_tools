use reqwest::blocking::ClientBuilder;

pub struct DNSManager {
    login_form: [(&'static str,&'static str);3]
}

impl DNSManager {
    const LOGIN_URL: &'static str = "https://onyxhosting.de/dologin.php";

    pub fn new(username: &'static str, password: &'static str) -> Result<Self, String> {
        
        Ok(Self {
            login_form: [("token","bd13711ac7c20c4851b6879460b27f02f5101596"), ("username",username),("password",password)]
        })
    }

    pub fn check_login(&self) -> Result<bool, String> {
        let client = ClientBuilder::new().cookie_store(true).build().unwrap();
 
        let response = client.post(Self::LOGIN_URL)
            .form(&self.login_form)
            .send()
            .map_err(|_|format!("Probleme bei Verbindungsaufbau mit {}", Self::LOGIN_URL))?;
 
        Ok(!response.url().as_str().contains("incorrect=true"))
    }
}
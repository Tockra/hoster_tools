use reqwest::ClientBuilder;

pub struct DNSManager {
    login_form: [(&'static str,&'static str);3]
}

impl DNSManager {
    const LOGIN_URL: &'static str = "https://onyxhosting.de/dologin.php";

    pub fn new(username: &'static str, password: &'static str) -> Result<Self, String> {
        
        Ok(Self {
            login_form: [("token","30d57bc7df699adbe7809bf97293c92bc7fe9d5c"), ("username",username),("password",password)]
        })
    }

    pub async fn check_login(&self) -> Result<(), String> {
        let client = ClientBuilder::new().cookie_store(true).build().unwrap();
        println!("{:?}", client.post(Self::LOGIN_URL)
            .form(&self.login_form));
        println!("{:?}", self.login_form);
        let response = client.post(Self::LOGIN_URL)
            .form(&self.login_form)
            .send()
            .await.map_err(|_|format!("Probleme bei Verbindungsaufbau mit {}", Self::LOGIN_URL))?;
            
        println!("{:?}", response.url().as_str().contains("incorrect=true"));
        Ok(())
    }
}
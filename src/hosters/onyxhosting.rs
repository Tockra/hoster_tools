use reqwest::blocking::ClientBuilder;
use reqwest::blocking::Client;
use std::fmt::Debug;

pub struct DNSManager {
    username: String,
    password: String,
    client: Client,
}

#[derive(Debug)]
pub enum LoginError {
    WrongLoginData,
    HTTPConnectionError(String),
    UnknownParseError(String),
}

impl DNSManager {
    const LOGIN_URL: &'static str = "https://onyxhosting.de/dologin.php";
    const CLIENTAREA_URL: &'static str = "https://onyxhosting.de/clientarea.php";
    const DOMAIN_URL: &'static str = "https://onyxhosting.de/clientarea.php?action=domains";

    pub fn new(username: &str, password: &str) -> Result<Self, LoginError> {
        let client = ClientBuilder::new().cookie_store(true).build().unwrap();

        let manager = Self {
            username: String::from(username),
            password: String::from(password),
            client: client,
        };
        
        manager.login()?;

        Ok(manager)
    }

    /// trys to login with the username and password given to the constructor
    fn login(&self) -> Result<(),LoginError> {
        // requests a token
        let token = self.get_token()?;

        // Builds the post form.
        let login_form: [(String,&String);4] = [(String::from("token"), &token), (String::from("username"), &self.username), (String::from("password"), &self.password), (String::from("rememberme"),&String::from("on"))];

        let response = self.client.post(Self::LOGIN_URL)
            .form(&login_form)
            .send()
            .map_err(|_| LoginError::HTTPConnectionError(String::from(Self::LOGIN_URL)))?;

        if response.url().as_str().contains("incorrect=true") {
            Err(LoginError::WrongLoginData)
        } else {
            Ok(())
        }
    }

    /// This method returns the token String 
    /// catched from `CLIENTAREA_URL`. If something fails it returns a corresponding LoginError.
    fn get_token(&self) -> Result<String, LoginError> {
        let response = self.client.get(Self::CLIENTAREA_URL).send().map_err(|_| LoginError::HTTPConnectionError(String::from(Self::CLIENTAREA_URL)))?.text().map_err(|_| LoginError::HTTPConnectionError(String::from(Self::CLIENTAREA_URL)))?;
        
        let mut token_lines = response.lines().filter(|x| x.contains("var csrfToken ="));

        match token_lines.nth(0) {
            None => Err(LoginError::UnknownParseError(format!("There wasn't at least one line with 'var csrfToken =' in the response from {}", Self::CLIENTAREA_URL))),
            Some(line) => 
                Ok(String::from(line
                            .split("'")
                            .nth(1)
                            .map_or(Err(LoginError::UnknownParseError(format!("In the response from {} aren't \"'\" after the \"var csrfToken\" part", Self::CLIENTAREA_URL))),|x| Ok(x))?
                ))
                
        }
    }

    pub fn get_domains(&self) {
        println!("{}", self.client.get(Self::DOMAIN_URL).send().unwrap().text().unwrap());
    }
}
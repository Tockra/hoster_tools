use reqwest::blocking::ClientBuilder;
use reqwest::blocking::Client;
use std::fmt::Debug;
use select::document::Document;
use select::node::Node;
use select::predicate::{Predicate, Attr, Name};

pub struct DNSManager {
    username: String,
    password: String,
    client: Client,
}

#[derive(Debug)]
pub enum LoginError {
    WrongLoginData,
    DomainNotFound,
    HTTPConnectionError(String),
    UnknownParseError(String),
    UnknownRecordType,
}

#[derive(Debug)]
pub struct Record {
    id: String,
    host: String,
    rtype: String,
    address: String,
    priority: String,
}

impl PartialEq for Record {
    fn eq(&self, other: &Self) -> bool {
        self.host == other.host && self.rtype == other.rtype
    }
}

struct RecordBuilder {
    record: Record,
}

impl RecordBuilder {
    pub fn new() -> RecordBuilder {
        Self {
            record: Record {
                id: String::from(""),
                host: String::from(""),
                rtype: String::from(""),
                address: String::from(""),
                priority: String::from(""),
            }
        }
    }

    pub fn id(&mut self, id: String) -> &mut Self {
        self.record.id = id;
        self
    }

    pub fn host(&mut self, host: String) -> &mut Self {
        self.record.host = host;
        self
    }

    pub fn rtype(&mut self, rtype: String) -> &mut Self {
        self.record.rtype = rtype;
        self
    }

    pub fn address(&mut self, address: String) -> &mut Self {
        self.record.address = address;
        self
    }

    
    pub fn priority(&mut self, priority: String) -> &mut Self {
        self.record.priority = priority;
        self
    }

    pub fn build(self) -> Result<Record, LoginError> {
        if self.record.rtype.is_empty() {
            Err(LoginError::UnknownParseError(format!("Tried to build a record without RecordType")))
        } else {
            Ok(self.record)
        }
    }
}

impl DNSManager {
    const LOGIN_URL: &'static str = "https://onyxhosting.de/dologin.php";
    const CLIENTAREA_URL: &'static str = "https://onyxhosting.de/clientarea.php";
    const DOMAIN_URL: &'static str = "https://onyxhosting.de/clientarea.php?action=domains";
    const DOMAINDNS_URL: &'static str = "https://onyxhosting.de/clientarea.php?action=domaindns&domainid=";

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

    fn get_domain_id(&self, domain: &str) -> Result<String,LoginError> {
        let document = Document::from(self.client.get(Self::DOMAIN_URL).send().unwrap().text().unwrap().as_str());
        let tmp = document.find(Attr("id", "tableDomainsList"));
        let domain_tables: Vec<Node> = tmp.collect();

        if domain_tables.len() != 1 {
            return Err(LoginError::UnknownParseError(format!("More than one tableDomainList on website.")));
        } 

        let domain_table = document.find(Attr("id", "tableDomainsList").descendant(Name("tbody")));
        for body in domain_table {
            for node in body.children() {
                if node.attr("onclick").is_some() {
                    if !node.text().contains(domain) {
                        return Err(LoginError::DomainNotFound);
                    } else {
                        // this confusion line just parses the onclick attribute to extract the domain id from the given url
                        let domain_id = node.attr("onclick").unwrap().split("=").collect::<Vec<_>>().last().map_or(Err(LoginError::UnknownParseError(format!("Problems to parse the domain-id"))), |x| Ok(x))?.split("\'").nth(0).map_or(Err(LoginError::UnknownParseError(format!("Problems to parse the domain-id"))), |x| Ok(x))?;
                        return Ok(String::from(domain_id));
                    }
                    
                }

            } 
        }
        Err(LoginError::UnknownParseError(format!("Unexspected structure of the response of {}", Self::DOMAIN_URL)))
    }

    fn get_current_records(&self, domain: &str) -> Result<Vec<Record>, LoginError> {
        let domain_id = self.get_domain_id(domain)?;

        let document = Document::from(self.client.get(format!("{}{}", Self::DOMAINDNS_URL, domain_id).as_str()).send().unwrap().text().unwrap().as_str());

        let domain_info_tables = document.find(Name("table")).collect::<Vec<_>>();
        
        if domain_info_tables.len() != 1 {
            return Err(LoginError::UnknownParseError(format!("There is more then one table on {}{}", Self::DOMAINDNS_URL, domain_id))); 
        }

        let domain_info_table_content = document.find(Name("table").descendant(Name("tbody").descendant(Name("tr"))));
        let mut record_list: Vec<Record> = vec![];

        for record_entry in domain_info_table_content {
            let mut builder = RecordBuilder::new();

            for record_info in record_entry.find(Name("input")) {
                match record_info.attr("name") {
                    Some("dnsrecid[]") => builder.id(String::from(record_info.attr("value").map_or("",|x| x))),
                    Some("dnsrecordhost[]") => builder.host(String::from(record_info.attr("value").map_or("",|x| x))),
                    Some("dnsrecordaddress[]") => builder.address(String::from(record_info.attr("value").map_or("",|x| x))),
                    Some("dnsrecordpriority[]") => builder.priority(String::from(record_info.attr("value").map_or("",|x| x))),
                    _ => return Err(LoginError::UnknownParseError(format!("Problem while parsing current status of record: {:?}",record_info.attr("name")))),
                };
            }
            builder.rtype(String::from(record_entry.find(Name("option").and(Attr("selected","selected"))).collect::<Vec<_>>().get(0).map_or("A",|x| x.attr("value").unwrap())));

            record_list.push(builder.build()?);
        }
        Ok(record_list)
    }

    /// Checks the current login status. If the login run out this method logins again. 
    fn check_login_status(&self) -> Result<(),LoginError> {
        if !self.client.get(Self::CLIENTAREA_URL).send().unwrap().text().unwrap().as_str().contains("Willkommen zurück") {
            self.login()?;

            if !self.client.get(Self::CLIENTAREA_URL).send().unwrap().text().unwrap().as_str().contains("Willkommen zurück") {
                return Err(LoginError::WrongLoginData);
            }
        }
        Ok(())
    }

    /// This method will update the address (`address`) of the given record of the domain (`domain`). If there isn't still a record it will add a new record
    pub fn add_dns_record(&self, domain: &str, host: &str, rtype: &str, address: &str) -> Result<(),LoginError> {
        if rtype != "A" && rtype != "AAAA" && rtype != "MXE" && rtype != "MX" && rtype != "CNAME" && rtype != "URL" && rtype != "FRAME" && rtype != "TXT" {
            return Err(LoginError::UnknownRecordType);
        }

        // for all following methods should this method make a new login if the cookie isn't still logged in.
        self.check_login_status()?;

        //setting priority and id isn't supported at the moment
        let new_record = 
            Record {    id: String::from(""),
                        host: String::from(host),
                        rtype: String::from(rtype),
                        address: String::from(address),
                        priority: String::from("N/A"),
            };

        let mut current_records = self.get_current_records(domain)?;

        if current_records.contains(&new_record) { 
            for i in 0..current_records.len() {
                if current_records[i] == new_record {
                    current_records[i].address = new_record.address.clone();
                }
            }
        } else {
            current_records.push(new_record);
        }

        Ok(self.push_record_list(current_records)?)
    }

    /// This method pushs the Records in `records` to the dns server
    fn push_record_list(&self, records: Vec<Record>) -> Result<(),LoginError> {
        for record in records {
            println!("Record: {:?}", record);
        }
        unimplemented!();
    }
}
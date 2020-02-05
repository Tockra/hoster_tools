use hosters::onyxhosting::DNSManager;

fn main() {
    let dns_manager = DNSManager::new("", "");

    match dns_manager {
        Err(e) => println!("LoginProblem {:?}", e),
        Ok(x) => {
           x.add_dns_record("", "mail2", "A", "").unwrap();
        },
    }

}

mod hosters;
use hosters::onyxhosting::DNSManager;

fn main() {
    let dns_manager = DNSManager::new("tim.tannert@tu-dortmund.de", "");

    match dns_manager {
        Err(e) => println!("LoginProblem {:?}", e),
        Ok(x) => x.get_domains(),
    }

}

mod hosters;
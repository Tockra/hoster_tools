use hosters::onyxhosting::DNSManager;

fn main() {
    let dns_manager = DNSManager::new("tim.tannert@tu-dortmund.de", "pw");

    match dns_manager {
        Err(e) => println!("LoginProblem {:?}", e),
        Ok(x) => {
           x.add_dns_record("oh12.de", "penis", "A", "1.2.3.4.5").unwrap();
        },
    }

}

mod hosters;
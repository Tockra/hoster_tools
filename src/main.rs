use hosters::onyxhosting::DNSManager;

fn main() {
    let dns_manager = DNSManager::new("tim.tannert@tu-dortmund.de", "").unwrap();

    println!("Login {}",if dns_manager.check_login().unwrap() {"Korrekt"} else {"Inkorrekt"});

}

mod hosters;
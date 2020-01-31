use hosters::onyxhosting::DNSManager;

fn main() {
    let dns_manager = DNSManager::new("", "").unwrap();

    dns_manager.check_login();

}

mod hosters;
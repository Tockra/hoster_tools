use hosters::onyxhosting::DNSManager;

#[tokio::main]
async fn main() {
    let dns_manager = DNSManager::new("tim.tannert@tu-dormund.de", "debug").unwrap();

    dns_manager.check_login().await;

}

mod hosters;
use nym_sdk::mixnet;
use nym_sdk::mixnet::MixnetMessageSender;
 
#[tokio::main]
async fn main() {
    //nym_bin_common::logging::setup_logging();
 
    // Passing no config makes the client fire up an ephemeral session and figure shit out on its own
    let mut client = mixnet::MixnetClient::connect_new().await.unwrap();
 
    // Be able to get our client address
    let our_address = client.nym_address();
    println!("Our client nym address is: {our_address}");
 
    println!("Waiting for message (ctrl-c to exit)");
loop {

        client
            .on_messages(|msg| println!("Received: {}", String::from_utf8_lossy(&msg.message)))
            .await;
    }
}

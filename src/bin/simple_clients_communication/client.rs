use nym_sdk::mixnet;
use nym_sdk::mixnet::MixnetMessageSender;
 use std::io::{self, Write};
use nym_sphinx::addressing::clients::Recipient;

#[tokio::main]
async fn main() {
    //nym_bin_common::logging::setup_logging();
 
    // Passing no config makes the client fire up an ephemeral session and figure shit out on its own
    let mut client = mixnet::MixnetClient::connect_new().await.unwrap();
 
    // Be able to get our client address
    let our_address = client.nym_address();
    println!("Our client nym address is: {our_address}");
     let mut input_address = String::new();
    io::stdin().read_line(&mut input_address).unwrap();
let server_address: Recipient = input_address
        .trim()
        .parse()
        .expect("Invalid Nym address");
    print!("💬 Enter a message to send: ");
    io::stdout().flush().unwrap();
    let mut message = String::new();
    io::stdin().read_line(&mut message).unwrap();
    client
        .send_plain_message(server_address,"hello there").await
        .unwrap();
    println!("Recepient address11 is {}",server_address);

    // Send a message through the mixnet to ourselve

 
    println!("📤 Message sent. Waiting for reply...");

    if let Some(response) = client.wait_for_messages().await {
        if let Some(reply) = response.first() {
            println!("📩 Got reply: {}", String::from_utf8_lossy(&reply.message));
        }
    }
}

mod mixnet_structures;
use mixnet_structures::{MixnodeResponse,fetch_mixnodes};
use reqwest::Error;
use rand::{CryptoRng, Rng};
use std::time::Duration;
use tokio::sync::mpsc;
use nym_sdk::mixnet;
use nym_sdk::mixnet::{
    AnonymousSenderTag, MixnetClientBuilder, MixnetMessageSender, ReconstructedMessage,
    StoragePaths,
};
use crate::mixnet::IncludedSurbs;

/*use nym_sphinx::preparer::MessagePreparer;
use nym_sphinx::anonymous_replies::ReplySurbWithKeyRotation;
use nym_topology::NymTopology;
use nym_sphinx::addressing::clients::Recipient;
use nym_crypto::asymmetric::identity;
use rand::rngs::OsRng; // or any public item*/

async fn PrintMixNodesAndKeys() {
        match fetch_mixnodes().await {
        Ok(data) => {
println!("Total nodes: {}", data.pagination.total.unwrap_or(0));
            for entry in data.data {
                let node = entry.bond_information.node;
println!("{} @ {}:{:?}", node.identity_key, node.host, node.http_api_port);
            }
        }
        Err(err) => {
            eprintln!("Error fetching mixnodes: {}", err);
        }
    }
}

#[tokio::main]
async fn main() {
    // Optional: Print known mixnodes
    PrintMixNodesAndKeys().await;
    println!("2");
    let mut client = mixnet::MixnetClient::connect_new().await.unwrap();
 
    // Now we connect to the mixnet, using keys now stored in the paths provided.
    let our_address = client.nym_address();

client
    .send_plain_message_with_surbs(*our_address, "hello", IncludedSurbs::new(1))
    .await;
    // Start a new Nym client
       println!("Waiting for message (ctrl-c to exit)");
    let mut message: Vec<ReconstructedMessage> = Vec::new();
      while let Some(new_message) = client.wait_for_messages().await {
        if new_message.is_empty() {
            println!("aa");
            continue;
        }
        message = new_message;
        break;
    }
 
    let mut parsed = String::new();
    if let Some(r) = message.first() {
        parsed = String::from_utf8(r.message.clone()).unwrap();
    }
    // parse sender_tag: we will use this to reply to sender without needing their Nym address
    let return_recipient: AnonymousSenderTag = message[0].sender_tag.unwrap();
    println!(
        "\nReceived the following message: {} \nfrom sender with surb bucket {}",
        parsed, return_recipient
    );

        println!("Replying with using SURBs");
    client
        .send_reply(return_recipient, "hi an0n!")
        .await
        .unwrap();

    println!("Waiting for message (once you see it, ctrl-c to exit)\n");
    client
        .on_messages(|msg| println!("\nReceived: {}", String::from_utf8_lossy(&msg.message)))
        .await;




}


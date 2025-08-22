mod mixnet_structures;
use mixnet_structures::{MixnodeResponse, fetch_mixnodes};
use nym_sdk::mixnet;
use nym_sdk::mixnet::{
    AnonymousSenderTag, MixnetClientBuilder, MixnetMessageSender, ReconstructedMessage,
    StoragePaths,
};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use reqwest::Error;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::mixnet::IncludedSurbs;
use nym_crypto;
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
                println!(
                    "{} @ {}:{:?}",
                    node.identity_key, node.host, node.http_api_port
                );
            }
        }
        Err(err) => {
            eprintln!("Error fetching mixnodes: {}", err);
        }
    }
}

#[tokio::main]
async fn main() {
    let mut rng = OsRng;

    // Optional: Print known mixnodes
    PrintMixNodesAndKeys().await;
    println!("2");
    let mut client = mixnet::MixnetClient::connect_new().await.unwrap();
    //I should see how i can create a static address
    let keypair = nym_crypto::asymmetric::ed25519::KeyPair::new(&mut rng); // depends on your lib
    let privatekey = keypair.private_key();
    let pubkey = keypair.public_key();
    let sig = privatekey.sign("a");
    println!("sig {}", sig);
    //  let tag: AnonymousSenderTag = (&pubkey).into();
    //  println!("Sender tag: {}", tag);
    //let mut rng = OsRng;
    // let tag = AnonymousSenderTag::new_random(&mut rng);
    //SO IF we have the public key of the anonymous service we can build a specific tag
    let tag2 = AnonymousSenderTag::from_pubkey(&pubkey.to_bytes());
    println!("tag58 {}", tag2);

    //  let tag = nym_sdk::mixnet::generate_anonymous_sender_tag(pubkey.as_bytes());

    // Now we connect to the mixnet, using keys now stored in the paths provided.
    let our_address = client.nym_address();
    println!("my tag {}", our_address);

    let public_key_bytes: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
        0xba, 0xbe,
    ];
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(&public_key_bytes);

    //Here I should put the address of
    /*
        async fn share_anonymous_service_surbs<M>(
            &self,
            anonymousServiceTag: AnonymousSenderTag,
            keypair: nym_crypto::asymmetric::ed25519::KeyPair,
            address: Recipient,
            message: M,
            surbs: IncludedSurbs,
        ) -> Result<()>

    */
    /*
    client
        .share_anonymous_service_surbs(tag2, keypair, *our_address, "hi", IncludedSurbs::new(7))
        .await;
    // Start a new Nym client
    /* */
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
        .await;*/
}

use crate::mixnet::IncludedSurbs;
use bs58;
use nym_client_core::client::real_messages_control::message_handler::*;
use nym_client_core::client::received_buffer;
use nym_client_core::config::Client;
use nym_crypto::asymmetric::ed25519::PublicKey;
use nym_sdk::mixnet;
use nym_sdk::mixnet::{
    AnonymousSenderTag, MixnetClientBuilder, MixnetMessageSender, ReconstructedMessage,
    StoragePaths,
};
use base64::Engine;

use nym_sphinx::addressing::clients::Recipient;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::collections::HashSet;
use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::io::stdin;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;

async fn read_authority_address() -> Recipient {
    println!("Enter the authority address:");
    let mut address = String::new();
    io::stdin().read_line(&mut address).unwrap();
    address.trim().parse().expect("Invalid Nym address")
}

/// Ask the user if the service is of Oscar Wilde type
fn ask_if_oscar_wilde() -> bool {
    loop {
        println!("Is this an Oscar Wilde anonymous service? (y/n): ");

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .expect("Failed to read input");

        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => {
                println!("Please type 'y' or 'n'.");
            }
        }
    }
}

async fn ask_for_surbs(
    client: &mut mixnet::MixnetClient,
    saved_pubkeys: Arc<Mutex<HashSet<PublicKey>>>,
) {
    if let Some(public_key) = read_public_key() {
        let mut rng = OsRng;
        let keypair = nym_crypto::asymmetric::ed25519::KeyPair::new(&mut rng);
        insert_keypair(&public_key, &keypair);

        saved_pubkeys.lock().await.insert(public_key.clone());

        // Call the separate function
        let is_oscar_wilde = ask_if_oscar_wilde();

        client
            .request_anonymous_service_surbs(public_key, IncludedSurbs::new(100), is_oscar_wilde)
            .await;
    }
}


async fn send_webapp_request(
    client: &mut mixnet::MixnetClient,
    saved_pubkeys: Arc<Mutex<HashSet<PublicKey>>>,
) {
    let pubkeys = saved_pubkeys.lock().await;
    if pubkeys.is_empty() {
        println!("❌ No saved public keys available. Please request SURBs first.");
        return;
    }

    println!("Select a public key to send the WebAppRequest:");
    for (i, pk) in pubkeys.iter().enumerate() {
        println!("{}: {}", i + 1, bs58::encode(pk.to_bytes()).into_string());
    }

    println!("Or enter a new public key manually (type 'manual')");

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();

    let public_key = if input.eq_ignore_ascii_case("manual") {
        if let Some(pk) = read_public_key() {
            pk
        } else {
            println!("❌ Invalid key input. Aborting.");
            return;
        }
    } else if let Ok(index) = input.parse::<usize>() {
        pubkeys.iter().nth(index - 1).cloned().unwrap_or_else(|| {
            println!("❌ Invalid index selected.");
            panic!();
        })
    } else {
        println!("❌ Invalid input.");
        return;
    };

    let mut rng = OsRng;
    let keypair = get_or_create_keypair_for_pubkey(&public_key);
    //Na valo na rota an thelume  na kanume new identity  kai na allazo to keypairan thelei.
    // ---- Collect structured request data ----
    let allowed_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
    let method = loop {
        println!("Enter HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS):");
        let mut method = String::new();
        io::stdin().read_line(&mut method).unwrap();
        let method = method.trim().to_uppercase();

        if allowed_methods.contains(&method.as_str()) {
            break method;
        } else {
            println!(
                "⚠️ Invalid HTTP method '{}'. Allowed: {:?}",
                method, allowed_methods
            );
        }
    };

    println!("Enter request path (e.g., /, /api/data):");
    let mut path = String::new();
    io::stdin().read_line(&mut path).unwrap();
    let path = path.trim().to_string();

    println!("Select content type [json/form/plain/binary]:");
    let mut content_type = String::new();
    io::stdin().read_line(&mut content_type).unwrap();
    let content_type = content_type.trim().to_lowercase();

    // --- Handle body input with file option ---
    let body = if method == "POST" || method == "PUT" || method == "PATCH" {
        println!("Would you like to (1) type the body manually or (2) load from a file?");
        println!("Enter 1 for manual or 2 for file:");

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();
        let choice = choice.trim();

        if choice == "2" {
            println!("Enter file path to load body from:");
            let mut file_path = String::new();
            io::stdin().read_line(&mut file_path).unwrap();
            let file_path = file_path.trim();

            match std::fs::read_to_string(file_path) {
                Ok(contents) => {
                    println!(
                        "✅ Loaded body from '{}', size: {} bytes",
                        file_path,
                        contents.len()
                    );
                    Some(contents)
                }
                Err(e) => {
                    println!("❌ Failed to read file '{}': {}", file_path, e);
                    None
                }
            }
        } else {
            println!("Enter request body (press ENTER when done):");
            let mut body_input = String::new();
            io::stdin().read_line(&mut body_input).unwrap();
            Some(body_input.trim().to_string())
        }
    } else {
        None
    };

    // Ask for optional headers
    println!("Do you want to add custom headers? (yes/no):");
    let mut add_headers = String::new();
    io::stdin().read_line(&mut add_headers).unwrap();

    let headers = if add_headers.trim().eq_ignore_ascii_case("yes") {
        let mut headers_map = HashMap::new();
        loop {
            println!("Enter header key (or leave empty to finish):");
            let mut key = String::new();
            io::stdin().read_line(&mut key).unwrap();
            let key = key.trim().to_string();
            if key.is_empty() {
                break;
            }

            println!("Enter value for '{}':", key);
            let mut value = String::new();
            io::stdin().read_line(&mut value).unwrap();
            let value = value.trim().to_string();

            headers_map.insert(key, value);
        }
        Some(headers_map)
    } else {
        None
    };

    let payload = WebAppRequestPayload {
        method,
        path,
        content_type,
        body,
        headers,
        http_version: "HTTP/1.1".to_string(),
    };

    // ---- Serialize and send ----
    let kind = AnonymousServiceRequestKind::WebAppRequest(payload);
    let nonce = generate_crypto_number();
if let Some(share) = get_blind_signature_for_secret(&public_key, 3) {
    let request=AnonymousServiceRequest::new_signed_for_oscar_wilde(&keypair, kind, nonce, share);
        client
        .send_nym_http_reply(
            AnonymousSenderTag::from_pubkey(&public_key.to_bytes()),
            request.to_bytes(),
        )
        .await;
    }
    else
    {
    let request = AnonymousServiceRequest::new_signed(&keypair, kind, nonce);
    client
        .send_nym_http_reply(
            AnonymousSenderTag::from_pubkey(&public_key.to_bytes()),
            request.to_bytes(),
        )
        .await;
    }
}

#[tokio::main]
async fn main() {
    println!(
        r#"
    ==============================================
     🚀 Welcome to the NYM Client CLI Interface 🚀
    ==============================================

    🕶️  Connect to Anonymous Services like a Shadow Hacker
    💻  Bypass the ordinary. Speak through cryptographic whispers.
    🌐  You are now inside the encrypted matrix.

    Let's begin your journey into the anonymous web...
    "#
    );
    let saved_pubkeys = Arc::new(Mutex::new(HashSet::<PublicKey>::new()));
    set_client_role(ClientRole::NormalClient);
    let mut client = mixnet::MixnetClient::connect_new().await.unwrap();
    init_authority_addresses();

    println!("🔑 First, you must request SURBs for an anonymous service...");
    ask_for_surbs(&mut client, saved_pubkeys.clone()).await;

    println!("📡 Entering listening loop... Type MENU then ENTER to access options.");
    let stdin = BufReader::new(stdin());
    let mut input_lines = stdin.lines();

    loop {
        tokio::select! {
            // Handle incoming Nym messages
            Some(messages) = client.wait_for_messages() => {
                for msg in messages {
                    if let Some(request) = AnonymousServiceRequest::from_bytes_(&msg.message) {
                        println!("📦 Received request: {}", request.kind);
                        if let Some((public_key, keypair)) = find_keypair_by_anonymous_tag(
                            AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes())
                        ) {
                            handle_nym_http_request(request, &client, &keypair).await;
                        } else {
                            println!("We had not communicated with the sender before, we are generating a new keypair for this session: {}", request.sender_tag);
                            let mut rng = OsRng;
                            let keypair = nym_crypto::asymmetric::ed25519::KeyPair::new(&mut rng);
                            insert_keypair(&request.sender_tag, &keypair);
                            handle_nym_http_request(request, &client, &keypair).await;
                        }
                    }
                }
            }

            // Handle user input concurrently
            Ok(Some(line)) = input_lines.next_line() => {
                let input = line.trim();
                if input.eq_ignore_ascii_case("menu") {
                    println!("🧭 Interactive Menu:");
                    println!("1) Ask for anonymous SURBs");
                    println!("2) Send WebAppRequest");
                    println!("Enter choice:");

                    if let Ok(Some(choice)) = input_lines.next_line().await {
                    match choice.trim() {
                        "1" => ask_for_surbs(&mut client, saved_pubkeys.clone()).await,
                        "2" => send_webapp_request(&mut client, saved_pubkeys.clone()).await,
                        _ => println!("⚠️  Invalid choice. Try again."),
                    }
                    }
                } else if !input.is_empty() {
                    println!("💬 Unknown command: '{}'", input);
                }
            }
        }
    }
}
async fn handle_nym_http_request(
    request: AnonymousServiceRequest,
    client: &mixnet::MixnetClient,
    keypair: &nym_crypto::asymmetric::ed25519::KeyPair,
) {
    match request.kind {
        AnonymousServiceRequestKind::WebAppRequest(data) => {
                                println!("🌐 WebAppRequest received ");
                                if !is_anonymous_service_mode_enabled() {
                                    println!("We are not anonymous service. rejecting the request");
                                    return;
                                }
                    }
        AnonymousServiceRequestKind::WebAppResponse(ref data) => {
                        println!("🖥️ WebAppResponse: {} bytes", request);
                        match std::str::from_utf8(&data) {
                            Ok(text) => println!("📄 WebAppResponse: {} bytes, content: {}", data.len(), text),
                            Err(e) => println!(
                                "📄 WebAppResponse: {} bytes, but failed to decode as UTF-8: {}",
                                data.len(),
                                e
                            ),
                        }
                    }
        AnonymousServiceRequestKind::CanYouEstablishRendezvousPointRequestAndAskingToPutThereSomeSurbs {
                        amount,
                        x25519_pubkey,
                    } => {
                        println!("Establishing a rendezvous point...");
                        client
                            .serve_surb_request_by_initializing_a_rendevouz_point(
                                AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()),
                                x25519_pubkey,
                                amount as usize,
                            )
                            .await;
                    }
        AnonymousServiceRequestKind::AcknowledgementOfEstablishingRendevouzPoint {
                        nonce_of_packet_acknowledgment,
                    } => {
                        println!(
                            "📬 ACK for rendezvous packet nonce {}",
                            nonce_of_packet_acknowledgment
                        );
                        match take_pending_ack(&nonce_of_packet_acknowledgment) {
                            Some((tag, original_request)) => {
                                println!("✅ Found pending ack. Sending stored request...");
                                let _ = client
                                    .send_nym_http_reply(tag, original_request.to_bytes())
                                    .await;
                            }
                            None => {
                                println!(
                                    "❌ No pending ack found for nonce: {}",
                                    nonce_of_packet_acknowledgment
                                );
                            }
                        }
                    }
        AnonymousServiceRequestKind::RendezvousSurbResponse { ref surbs } => {
                        println!("📩 Received {} reply SURBs from rendezvous", surbs.len());
                        if should_i_act_as_rendezvous_point() {
                            println!("buffering..");
                            insert_buffered_rendezvous_message(request.nonce.clone(), request.clone());
                        } else {
                            println!("I should save the surbs");
                            client
                                .save_received_surbs(
                                    AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()),
                                    surbs.clone(),
                                    true,
                                )
                                .await;
                        }
                    }
        AnonymousServiceRequestKind::RendezvousGeneralPacketResponse { data } => {
                        println!("📥 Received general rendezvous data: {} bytes", data.len());
                    }
        AnonymousServiceRequestKind::RendezvousPoint {
                        amount_to_receive,
                        recipient,
                        nonce_of_packet_stored_there,
                    } => {
                        println!(
                            "📍 RendezvousPoint setup: {} SURBs needed, recipient: {:?}, nonce: {}",
                            amount_to_receive, recipient, nonce_of_packet_stored_there
                        );
                        create_rendezvous_keypair(recipient.clone());
                        if let Some(rendezvous_keypair) = get_rendezvous_keypair(&recipient) {
                            let new_kind = AnonymousServiceRequestKind::CanYouGiveMeThePacketWithThisNonce {
                                nonce: nonce_of_packet_stored_there.clone(),
                            };
                            let new_request = AnonymousServiceRequest::new_signed(
                                &rendezvous_keypair,
                                new_kind,
                                generate_crypto_number(),
                            );

                            client
                                .send_message(
                                    recipient,
                                    new_request.to_bytes(),
                                    IncludedSurbs::Amount((amount_to_receive + 5) as u32),
                                )
                                .await;
                        } else {
                            println!("❌ Failed to retrieve rendezvous keypair.");
                        }
                    }
        AnonymousServiceRequestKind::EncryptedContent(ref data) => {
                        println!("🔐 Received EncryptedContent: {} bytes", data.len());
                        if should_i_act_as_rendezvous_point() {
                            insert_buffered_rendezvous_message(request.nonce.clone(), request.clone());
                            let ack_kind = AnonymousServiceRequestKind::AcknowledgementOfEstablishingRendevouzPoint {
                                nonce_of_packet_acknowledgment: request.nonce.clone(),
                            };
                            let ack_request =
                                AnonymousServiceRequest::new_signed(keypair, ack_kind, generate_crypto_number());
                            let public_key = request.sender_tag.clone();
                            client
                                .send_reply(
                                    AnonymousSenderTag::from_pubkey(&public_key.to_bytes()),
                                    ack_request.to_bytes(),
                                )
                                .await;
                        } else if let Some(keypair) = find_x25519_keypair_by_nonce(&request.nonce) {
                            println!("✅ Found matching X25519 keypair.");
                            if let Some(ref inner) = decrypt_request_kind(&request.kind, &keypair.private) {
                                println!("🔓 Decryption successful: {}", inner);
                                if let AnonymousServiceRequestKind::RendezvousSurbResponse { surbs } = inner {
                                    client
                                        .save_received_surbs(
                                            AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()),
                                            surbs.clone(),
                                            true,
                                        )
                                        .await;
                                }
                            } else {
                                println!("❌ Decryption failed.");
                            }
                        } else {
                            println!("❌ No X25519 keypair found for nonce: {}", request.nonce);
                        }
                    }
        AnonymousServiceRequestKind::CanYouGiveMeThePacketWithThisNonce { nonce } => {
                        println!("📦 Received request to fetch packet with nonce: {}", nonce);
                        if should_i_act_as_rendezvous_point() {
                            match take_buffered_rendezvous_message(&nonce) {
                                Some(buffered) => {
                                    println!("✅ Found stored message. Sending...");
                                    client
                                        .send_nym_http_reply(
                                            AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()),
                                            buffered.to_bytes(),
                                        )
                                        .await;
                                }
                                None => {
                                    println!("❌ No message found in buffer for nonce {}", nonce);
                                }
                            }
                        } else {
                            println!("I do not buffer images");
                        }
                    }
        AnonymousServiceRequestKind::PostSomeMoreSURBsToMyNode { nonce } => {
                        println!(
                            "[DEBUG] Authority requested to post more SURBs for nonce: {}",
                            nonce
                        );
                        if !matches!(get_client_role(), ClientRole::AnonymousService) {
                            println!(
                                "I was asked to post some surbs, but i am not anonymous service.. continuing"
                            );
                        }
                        // Lookup the recipient that corresponds to this nonce
                        if let Some(recipient) = find_recipient_by_crypto_number(&nonce) {
                            println!(
                                "[DEBUG] Found recipient {:?} for nonce {}",
                                recipient, nonce
                            );

                            // Send SURBs to this recipient (reuse share_anonymous_service_surbs with Some)
                            client
                                .share_anonymous_service_surbs(
                                    AnonymousSenderTag::from_pubkey(&keypair.public_key().to_bytes()),
                                    keypair.clone(),
                                    Some(recipient),
                                    "More SURBs requested",    // placeholder message
                                    IncludedSurbs::Amount(10), // arbitrary amount; adjust if needed
                                )
                                .await;
                        } else {
                            println!(
                                "[WARN] No recipient found for nonce {}. Cannot post SURBs.",
                                nonce
                            );
                        }
                    }
        AnonymousServiceRequestKind::PostingSurbsStatus { success, nonce } => {
                        // Check if current client role is NOT AnonymousService
                        if !matches!(get_client_role(), ClientRole::AnonymousService) {
                            println!(
                                "[WARN] Received PostingSurbsStatus message, but we are NOT an AnonymousService. This is unexpected."
                            );
                            // Continue processing or return early (your choice). Here we just log and continue.
                        }

                        // Convert success Vec<u8> into string
                        let success_str = String::from_utf8_lossy(&success);

                        println!(
                            "[DEBUG] PostingSurbsStatus received: success='{}', nonce={}",
                            success_str, nonce
                        );

                        // Optional follow-up action based on success/failure
                        if success_str == "ok" {
                            println!("✅ SURBs were successfully posted for nonce {}", nonce);
                        } else {
                            println!(
                                "❌ Failed to post SURBs for nonce {}: {}",
                                nonce, success_str
                            );
                        }
                    }
        AnonymousServiceRequestKind::ReturnedOscarWildeDescriptorAndSurbs(oscar_wilde_anonymous_service_descriptor, encrypted_surbs_with_signature,msg) =>{
                    if !matches!(get_client_role(),ClientRole::NormalClient)
                    {
                        println!("Received encrypted surbs and oscar wild descriptors while I am not a client, this was unexpected");
                    }
                    else
                    {
                            if let Some(descriptor) = oscar_wilde_anonymous_service_descriptor {
                            println!("Descriptor received: {:?}", descriptor);
                            let pubkey=descriptor.ed25519_public_key.clone();
                        insert_oscar_wilde_data(descriptor,Some(encrypted_surbs_with_signature),None);
                                //Now we ask for secrets

                                client.ask_for_oscar_wilde_secrets_to_decrypt_surbs(pubkey).await;
                            
                        } else {
                            println!("Descriptor is None, {}",msg);
                        }

                    }

                }
        AnonymousServiceRequestKind::PostOscarWildeEncryptedSurbsWithSignature(oscar_wilde_anonymous_service_descriptor, encrypted_surbs_with_signature, shamir_secret_share) => todo!(),
        AnonymousServiceRequestKind::RequestForShamirSecretShare(public_key, big_uint) => todo!(),
        AnonymousServiceRequestKind::ReturnedSecretsOfOscarWildeScheme(shamir_secret_share, msg) =>{

           if !matches!(get_client_role(),ClientRole::NormalClient)
                            {  
                                println!("received ShamirSecretShare packet but i am not a client.error");

                            }
                            else
                            {
                                    if let Some(secret) = shamir_secret_share {
            // Τώρα έχεις το descriptor σαν τοπική μεταβλητή
            println!("secret received: {:?}", secret);

            // Μπορείς να το χρησιμοποιήσεις π.χ. να το αποθηκεύσεις σε δομή ή να καλέσεις συνάρτηση
    

                                let maybe_surbs = insert_shamir_share(secret.clone());

                                if let Some(decrypted_surbs) = maybe_surbs {
                                    if !decrypted_surbs.is_empty() {
                                        println!("Successfully decrypted {} SURBs!", decrypted_surbs.len());
                                        // Process the decrypted SURBs here
                                        client
                                        .save_received_surbs(
                                            AnonymousSenderTag::from_pubkey(&secret.public_key.to_bytes()),
                                            decrypted_surbs,
                                            true,
                                        )
                                        .await;

                                    } else {
                                        println!("Decryption completed, but no SURBs were found.");
                                    }
                                } else {
                                    println!("Not enough shares yet, waiting for more...");
                                }
                            }
                            else
                            {
                                println!("{}",msg);
                            }

                        }
                    

            }
AnonymousServiceRequestKind::PostOscarExtraWildeEncryptedSurbsWithSignature(public_key, encrypted_surbs_with_signature) => todo!(),
    }
}

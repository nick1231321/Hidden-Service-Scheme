use crate::mixnet::IncludedSurbs;
use num_bigint::BigUint;
use nym_client_core::client::real_messages_control::{message_handler::*};
use rsa::signature;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use bs58;
use nym_crypto::asymmetric::ed25519::{KeyPair, PrivateKey, PublicKey};
use nym_sdk::mixnet::{self, AnonymousSenderTag, MixnetMessageSender};
use nym_sphinx::addressing::clients::Recipient;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{fs, path::Path};
const SERVER_KEYS_FILE: &str = "server_keys.json";

#[derive(Serialize, Deserialize)]
struct StoredKey {
    pub public: String,
    pub private: String,
}

type KeyMap = HashMap<String, StoredKey>;
use sha2::{Digest, Sha256};

fn print_identity_banner(name: &str, pubkey: &PublicKey) {
    let mut hasher = Sha256::new();
    hasher.update(pubkey.to_bytes());
    let hash = hasher.finalize();
    let fingerprint = &hex::encode(&hash)[..12]; // Short fingerprint

    println!(
        r#"
╔═══════════════════════════════════════════════════════╗
║    Welcome {name}
║    PublicKey: {fingerprint}...
╚═══════════════════════════════════════════════════════╝
"#
    );
}

fn load_key_from_disk(label: &str) -> Option<KeyPair> {
    if !Path::new(SERVER_KEYS_FILE).exists() {
        println!("No keys saved yet.");
        return None;
    }

    let content = fs::read_to_string(SERVER_KEYS_FILE).ok()?;
    let map: KeyMap = serde_json::from_str(&content).ok()?;

    map.get(label).and_then(|entry| {
        let pub_bytes = bs58::decode(&entry.public).into_vec().ok()?;
        let priv_bytes = bs58::decode(&entry.private).into_vec().ok()?;

        let public = PublicKey::from_bytes(&pub_bytes).ok()?;
        let private = PrivateKey::from_bytes(&priv_bytes).ok()?;

        Some(KeyPair::from_bytes(&priv_bytes, &pub_bytes).ok()?)
    })
}

fn init_or_load_keypair_and_prompt_name() -> Option<(KeyPair, String)> {
    println!("🔐 Do you want to [L]oad a saved key or [G]enerate a new one?");
    let mut mode = String::new();
    io::stdin().read_line(&mut mode).unwrap();
    let mode = mode.trim().to_lowercase();

    let keypair = match mode.as_str() {
        "l" | "load" => {
            println!("📁 Enter label of the saved key:");
            let mut label = String::new();
            io::stdin().read_line(&mut label).unwrap();
            let label = label.trim();

            match load_key_from_disk(label) {
                Some(loaded) => {
                    println!("✅ Loaded key: {}", label);
                    loaded
                }
                None => {
                    println!("❌ Failed to load key '{}'.", label);
                    return None;
                }
            }
        }

        "g" | "generate" => {
            let mut rng = OsRng;
            let generated = KeyPair::new(&mut rng);
            println!("🆕 Key generated.");

            println!("💾 Do you want to save this key to disk? (yes/no):");
            let mut answer = String::new();
            io::stdin().read_line(&mut answer).unwrap();
            if answer.trim().eq_ignore_ascii_case("yes") {
                println!("📝 Enter label to save this key:");
                let mut label = String::new();
                io::stdin().read_line(&mut label).unwrap();
                let label = label.trim();
                save_key_to_disk(label, &generated);
                println!("🔒 Key saved under '{}'", label);
            }

            generated
        }

        _ => {
            println!("⚠️ Invalid option.");
            return None;
        }
    };

    // Prompt for user's name AFTER key is ready
    println!("👤 Enter your nickname:");
    let mut name = String::new();
    io::stdin().read_line(&mut name).unwrap();
    let name = name.trim().to_string();

    println!("💀 Identity set as '{}'. Keypair ready for use.", name);

    Some((keypair, name))
}

fn save_key_to_disk(label: &str, keypair: &KeyPair) {
    let mut map = if Path::new(SERVER_KEYS_FILE).exists() {
        let content = fs::read_to_string(SERVER_KEYS_FILE).unwrap_or_default();
        serde_json::from_str::<KeyMap>(&content).unwrap_or_default()
    } else {
        HashMap::new()
    };

    let public = bs58::encode(keypair.public_key().to_bytes()).into_string();
    let private = bs58::encode(keypair.private_key().to_bytes()).into_string();

    map.insert(label.to_string(), StoredKey { public, private });

    let serialized = serde_json::to_string_pretty(&map).unwrap();
    fs::write(SERVER_KEYS_FILE, serialized).expect("Failed to write keys to disk");
}
async fn send_web_request_to_local_server(
    payload: WebAppRequestPayload,
    blind_signature: Option<BlindSignatureForSecret>,
    
) -> Result<String, Box<dyn std::error::Error>> {
    const COOKIE_NAME_OF_PSEUDOIDENTITY_OF_BLIND_SIGNATURE:  &str = "IDENTITY_OF_USER"; 
    // 1. Validate HTTP method
    let method = match payload.method.to_uppercase().as_str() {
        "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" => {
            payload.method.to_uppercase()
        }
        _ => return Err("Unsupported HTTP method".into()),
    };

    // 2. Normalize path
    let path = if payload.path.starts_with('/') {
        payload.path.clone()
    } else {
        format!("/{}", payload.path)
    };

    // 3. Start building the HTTP request
    let mut request = format!(
        "{method} {path} {}\r\nHost: localhost\r\nUser-Agent: NymClient/1.0\r\nAccept: */*\r\n",
        payload.http_version
    );

    // 4. Content-Type mapping
    let content_type = match payload.content_type.as_str() {
        "json" => "application/json",
        "form" => "application/x-www-form-urlencoded",
        "binary" => "application/octet-stream",
        _ => "text/plain",
    };
    request.push_str(&format!("Content-Type: {}\r\n", content_type));

    // 5. Add custom headers
    if let Some(headers) = &payload.headers {
        for (key, value) in headers {
            // CRLF injection prevention
            if key.contains('\r')
                || key.contains('\n')
                || value.contains('\r')
                || value.contains('\n')
            {
                return Err("Invalid header detected".into());
            }
            if key.trim().is_empty() {
                return Err("Header key cannot be empty".into());
            }
            if(value!=COOKIE_NAME_OF_PSEUDOIDENTITY_OF_BLIND_SIGNATURE){
            request.push_str(&format!("{}: {}\r\n", key.trim(), value.trim()));
            }
        }
    }
if let Some(sig) = &blind_signature {
    // assuming `random_id` (or whatever) implements Display or is a &str/String
    request.push_str(&format!("{}: {}\r\n", COOKIE_NAME_OF_PSEUDOIDENTITY_OF_BLIND_SIGNATURE.trim(), BigUint::from_bytes_be(&sig.random_id).to_string().trim()));//I am not sure if i need to trim it
}


    // 6. Add body if present
    if let Some(body) = &payload.body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        request.push_str("Connection: close\r\n\r\n");
        request.push_str(body);
    } else {
        request.push_str("Connection: close\r\n\r\n");
    }

    println!(
        "--- Sending HTTP Request ---\n{}\n---------------------------",
        request
    );

    // 7. Send request to localhost
    let mut stream = TcpStream::connect("127.0.0.1:80").await?;
    stream.write_all(request.as_bytes()).await?;

    // 8. Read response
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    Ok(String::from_utf8_lossy(&response).to_string())
}
/// Prompt user until a valid role (1 or 2) is selected and set the client role.
fn prompt_and_set_client_role() {
    loop {
        println!("Do you want to run as:");
        println!("[1] Regular Anonymous Service");
        println!("[2] Oscar Wilde Anonymous Service");
        print!("Enter choice (1 or 2): ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();
        let choice = choice.trim();

        match choice {
            "1" => {
                println!("Starting in regular Anonymous Service mode...");
                set_client_role(ClientRole::AnonymousService);
                break;
            }
            "2" => {
                println!("Starting in Oscar Wilde Anonymous Service mode...");
                set_client_role(ClientRole::OscarWildeAnonymousService);
                break;
            }
            _ => {
                println!("Invalid choice. Please enter 1 or 2.");
            }
        }
    }
}

#[tokio::main]
async fn main() {
    println!(
        r#"
                           NYM ANONYMOUS SERVICE TERMINAL
                       ── Defend your packets. Mask your path. ──
              🕵️‍♂️ "Obscurity is not weakness. It is freedom encrypted." 🕶️
"#
    );
     //  nym_client_core::client::real_messages_control::anonymous_service_functionality::test_anonymous_service();

    prompt_and_set_client_role();

    let mut client = mixnet::MixnetClient::connect_new().await.unwrap();

    println!("Welcome to the Anonymous Server terminal.");

    let mut rng = OsRng;
    let (keypair, hacker_name) = match init_or_load_keypair_and_prompt_name() {
        Some(pair) => pair,
        None => return,
    };

    let pubkey = keypair.public_key();
    set_static_keypair(&keypair);
    print_identity_banner(&hacker_name, &pubkey);

    init_authority_addresses();

    println!("pubkey: {}", pubkey);
    let anonymous_service_tag = AnonymousSenderTag::from_pubkey(&pubkey.to_bytes());
    //I should remove unused parameters
    if matches!(get_client_role(), ClientRole::AnonymousService) {
        println!("📤 Posting our surbs of our anonymous service.");

        // Regular anonymous service
        client
            .share_anonymous_service_surbs(
                anonymous_service_tag,
                keypair.clone(),
                None,
                "hi",
                IncludedSurbs::new(60),
            )
            .await;
    } else if matches!(get_client_role(), ClientRole::OscarWildeAnonymousService) {
        println!("📤 Posting our descriptor and encrypted surbs of OscarWildeAnonymousService.");

        // Oscar Wilde anonymous service
        client
            .share_oscar_wilde_anonymous_service_anonymous_service_surbs(
                keypair.clone(),
                IncludedSurbs::new(60),
            )
            .await;
    } else {
        println!("Unknown client role – cannot share SURBs.");
        return;
    }
    wait_for_n_messages(&mut client, &keypair, anonymous_service_tag, 1000).await;
}

async fn wait_for_n_messages(
    client: &mut mixnet::MixnetClient,
    keypair: &nym_crypto::asymmetric::ed25519::KeyPair,
    anonymous_service_tag: AnonymousSenderTag,
    target_count: usize,
) {
    let mut counter = 0;
    while counter < target_count {
        if let Some(messages) = client.wait_for_messages().await {
            for msg in messages {
                let latest = msg.message;

                if let Some(request) = AnonymousServiceRequest::from_bytes_(&latest) {
                    handle_request(client, &request, keypair).await;
                } else {
                    println!("Unrecognized message: {}", String::from_utf8_lossy(&latest));
                }

                counter += 1;
                if counter >= target_count {
                    println!("✅ Processed {counter} messages.");
                    return;
                }
            }
        }
    }
}

async fn handle_request(
    client: &mut mixnet::MixnetClient,
    request: &AnonymousServiceRequest,
    keypair: &nym_crypto::asymmetric::ed25519::KeyPair,
) {
if matches!(get_client_role(), ClientRole::OscarWildeAnonymousService) && matches!(request.kind,AnonymousServiceRequestKind::WebAppRequest(_)) {
    if let Some(signature_info) = request.oscar_wilde_authorization_proof.clone() {
        let main_rsa_key = match get_main_rsa_key() {
            Some(key) => key,
            None => {
                eprintln!("Error: Main RSA key is not initialized or failed to load!");
                std::process::exit(-3);
            }
        };

        let verification = verify_unblinded_signature(
            &signature_info.signature,
            &main_rsa_key,
            (SHAMIR_THRESHOLD + 1) as u32,
            &signature_info.random_id,
        );

        if verification.is_err() {
            println!(
                "Signature verification failed for {:?}",
                signature_info.random_id
            );
            return;
        }
    } else {
         println!("No signature provided");
        return;
    }
}


    match &request.kind {
        AnonymousServiceRequestKind::WebAppRequest(data) => {
            println!("🌐 Handling WebAppRequest");

            if !is_anonymous_service_mode_enabled() {
                println!("We are not an anonymous service. Rejecting request.");
                return;
            }

            let result_string = send_web_request_to_local_server(data.clone(),request.oscar_wilde_authorization_proof.clone())
                .await
                .map_or_else(
                    |e| format!("❌ Error occurred: {}", e),
                    |resp| format!("✅ Response: {}", resp),
                );

            let response = AnonymousServiceRequest::new_signed(
                keypair,
                AnonymousServiceRequestKind::WebAppResponse(result_string.into_bytes()),
                generate_crypto_number(),
            );

            client
                .send_nym_http_reply(
                    AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()),
                    response.to_bytes(),
                )
                .await;
        }
        AnonymousServiceRequestKind::WebAppResponse(data) => {
            println!("🖥️ WebAppResponse received: {} bytes", data.len());
        }
        AnonymousServiceRequestKind::AcknowledgementOfEstablishingRendevouzPoint {
            nonce_of_packet_acknowledgment,
        } => {
            println!(
                "📬 ACK for rendezvous nonce {}",
                nonce_of_packet_acknowledgment
            );
            if let Some((tag, original_request)) = take_pending_ack(nonce_of_packet_acknowledgment)
            {
                client
                    .send_nym_http_reply(tag, original_request.to_bytes())
                    .await;
            } else {
                println!("❌ No pending ack found for nonce");
            }
        }
        AnonymousServiceRequestKind::CanYouEstablishRendezvousPointRequestAndAskingToPutThereSomeSurbs {
            amount,
            x25519_pubkey,
        } => {
            if is_anonymous_service_mode_enabled() || is_normal_client() {
                client
                    .serve_surb_request_by_initializing_a_rendevouz_point(
                        AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()),
                        x25519_pubkey.clone(),
                        *amount as usize,
                    )
                    .await;
            }
        }
        AnonymousServiceRequestKind::RendezvousPoint {
            amount_to_receive,
            recipient,
            nonce_of_packet_stored_there,
        } => {
            if is_anonymous_service_mode_enabled() || is_normal_client() {
                insert_nonce_for_tag(
                    &AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()),
                    nonce_of_packet_stored_there.clone(),
                );
                let req = AnonymousServiceRequest::new_signed(
                    keypair,
                    AnonymousServiceRequestKind::CanYouGiveMeThePacketWithThisNonce {
                        nonce: nonce_of_packet_stored_there.clone(),
                    },
                    generate_crypto_number(),
                );
                client
                    .send_message(
                        recipient.clone(),
                        req.to_bytes(),
                        IncludedSurbs::Amount((*amount_to_receive + 5) as u32),
                    )
                    .await;
            }
        }
        AnonymousServiceRequestKind::RendezvousSurbResponse { surbs } => {
            //Here I should remove the rendevouz keypair.
            if should_i_act_as_rendezvous_point() {
                insert_buffered_rendezvous_message(request.nonce.clone(), request.clone());
                let ack = AnonymousServiceRequest::new_signed(
                    keypair,
                    AnonymousServiceRequestKind::AcknowledgementOfEstablishingRendevouzPoint {
                        nonce_of_packet_acknowledgment: request.nonce.clone(),
                    },
                    generate_crypto_number(),
                );
                client
                    .send_reply(
                        AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()),
                        ack.to_bytes(),
                    )
                    .await;
            } else {
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
            println!("📥 General rendezvous response: {} bytes", data.len());
        }
        AnonymousServiceRequestKind::EncryptedContent(data) => {
            //Here I should remove the rendevouz keypair
            println!("🔐 Received EncryptedContent: {} bytes", data.len());
            if should_i_act_as_rendezvous_point() {
                insert_buffered_rendezvous_message(request.nonce.clone(), request.clone());
                let ack = AnonymousServiceRequest::new_signed(
                    keypair,
                    AnonymousServiceRequestKind::AcknowledgementOfEstablishingRendevouzPoint {
                        nonce_of_packet_acknowledgment: request.nonce.clone(),
                    },
                    generate_crypto_number(),
                );
                client
                    .send_reply(
                        AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()),
                        ack.to_bytes(),
                    )
                    .await;
            } else if let Some(keypair) = find_x25519_keypair_by_nonce(&request.nonce) {
                if let Some(inner) = decrypt_request_kind(&request.kind, &keypair.private) {
                    println!("🔓 Decrypted: {inner}");
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
                    println!("❌ Failed to decrypt");
                }
            } else {
                println!("❌ No keypair found for nonce {}", request.nonce);
            }
        }
        AnonymousServiceRequestKind::CanYouGiveMeThePacketWithThisNonce { nonce } => {
            if should_i_act_as_rendezvous_point() {
                if let Some(buffered) = take_buffered_rendezvous_message(nonce) {
                    client
                        .send_nym_http_reply(
                            AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()),
                            buffered.to_bytes(),
                        )
                        .await;
                } else {
                    println!("❌ No buffered message found for nonce {nonce}");
                }
            }
        }
        AnonymousServiceRequestKind::PostSomeMoreSURBsToMyNode { nonce } => {
            println!(
                "[DEBUG] Authority requested to post more SURBs for nonce: {}",
                nonce
            );
            if !is_anonymous_service_mode_enabled() {
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
                if matches!(get_client_role(), ClientRole::AnonymousService) {
                    // Send SURBs to this recipient (reuse share_anonymous_service_surbs with Some)
                    client
                        .share_anonymous_service_surbs(
                            AnonymousSenderTag::from_pubkey(&keypair.public_key().to_bytes()),
                            keypair.clone(),
                            Some(recipient),
                            "More SURBs requested",    // placeholder message
                            IncludedSurbs::Amount(50), // arbitrary amount; adjust if needed
                        )
                        .await;
                } else if matches!(get_client_role(), ClientRole::OscarWildeAnonymousService)
                //oscarwilde
                {
                    client
                                    .share_oscar_wilde_anonymous_service_anonymous_service_surbs_with_a_specific_node(
                                        IncludedSurbs::Amount(50),
                                        recipient // arbitrary amount; adjust if needed
                                    )
                                    .await;
                }
            } else {
                println!(
                    "[WARN] No recipient found for nonce {}. Cannot post SURBs.",
                    nonce
                );
            }
        }
        AnonymousServiceRequestKind::PostingSurbsStatus { success, nonce } => {
            // Check if current client role is NOT AnonymousService
            if !matches!(get_client_role(), ClientRole::AnonymousService)
                && !matches!(get_client_role(), ClientRole::OscarWildeAnonymousService)
            {
                println!(
                    "[WARN] Received PostingSurbsStatus message, but we are NOT an AnonymousService. This is unexpected."
                );
                // Continue processing or stop etaration early (your choice). Here we just log and continue.
            }

            // Convert success Vec<u8> into string
            let success_str = String::from_utf8_lossy(success);

            println!(
                "[DEBUG] PostingSurbsStatus received: success='{}', nonce={}",
                success_str, nonce
            );
        }
        AnonymousServiceRequestKind::PostOscarWildeEncryptedSurbsWithSignature(
            oscar_wilde_anonymous_service_descriptor,
            encrypted_surbs_with_signature,
            shamir_secret_share,
        ) => {
            if !matches!(get_client_role(), ClientRole::Authority) {
                println!(
                    "someone posted its OscarWilde anonymous service to us but we are not authority. Skipping this message"
                );
            } else {
            }
        }
        AnonymousServiceRequestKind::ReturnedOscarWildeDescriptorAndSurbs(
            oscar_wilde_anonymous_service_descriptor,
            encrypted_surbs_with_signature,
            _,
        ) => todo!(),
        AnonymousServiceRequestKind::ReturnedSecretsOfOscarWildeScheme(shamir_secret_share, _) => todo!(),
        AnonymousServiceRequestKind::RequestForShamirSecretShare(public_key, blind_signature_for_secret) => {
            todo!()
        }
        AnonymousServiceRequestKind::PostOscarExtraWildeEncryptedSurbsWithSignature(
            public_key,
            encrypted_surbs_with_signature,
        ) => todo!(),
    }
}

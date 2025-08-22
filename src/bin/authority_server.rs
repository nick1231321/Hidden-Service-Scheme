use crate::mixnet::IncludedSurbs;
use num_traits::sign;
use nym_client_core::client::real_messages_control::message_handler::*;
use nym_sdk::mixnet::{
    AnonymousSenderTag, MixnetClientBuilder, ReconstructedMessage, StoragePaths,
};
use rand::rngs::OsRng;
use std::io::{Write, stdin, stdout};

use nym_sdk::mixnet;
use nym_sdk::mixnet::MixnetMessageSender;

#[tokio::main]
async fn main() {
    //nym_bin_common::logging::setup_logging();
    nym_client_core::client::real_messages_control::message_handler::set_client_role(
        nym_client_core::client::real_messages_control::message_handler::ClientRole::Authority,
    );
    // Passing no config makes the client fire up an ephemeral session and figure shit out on its own
    let mut client = mixnet::MixnetClient::connect_new().await.unwrap();
    let mut rng = OsRng;

    let keypair = nym_crypto::asymmetric::ed25519::KeyPair::new(&mut rng); // depends on your lib
    let cloned_arc = client.identity_keys.clone();
    let keypair_ref = &*cloned_arc;
    init_authority_keypair(keypair_ref.clone());

    // Be able to get our client address
    let our_address = client.nym_address();
    println!("Our client nym address is: {our_address}");

    println!("Waiting for message (ctrl-c to exit)");
    loop {
        if let Some(messages) = client.wait_for_messages().await {
            println!("✅ Received messages in main loop");

            for msg in messages {
                if let Some(request) = AnonymousServiceRequest::from_bytes_(&msg.message) {
                    println!("📦 Successfully parsed AnonymousServiceRequest: {}", request.kind);

                    match request.kind {
                    AnonymousServiceRequestKind::WebAppRequest(data) => {
                        println!("🌐 WebAppRequest: received");

                        if !is_anonymous_service_mode_enabled()
                        {
                            println!("We are not anonymous service. rejecting the request");
                            continue;
                        }

                    }

                    AnonymousServiceRequestKind::WebAppResponse(ref data) => {
                        println!("🖥️ WebAppResponse: {} bytes", request);
                    }

                    AnonymousServiceRequestKind::CanYouEstablishRendezvousPointRequestAndAskingToPutThereSomeSurbs { amount,x25519_pubkey } => {
                        //Here I should create a rendevouz Point
                        println!("Establishing a rendevouz point. I should put a check from whom I serve these requests");
                        if(is_anonymous_service_mode_enabled() || is_normal_client())
                        {
                             client.serve_surb_request_by_initializing_a_rendevouz_point(AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()),x25519_pubkey, amount as usize).await;
                        }
                    }

                    AnonymousServiceRequestKind::AcknowledgementOfEstablishingRendevouzPoint { nonce_of_packet_acknowledgment } => {
                        println!("📬 ACK for rendezvous packet nonce {}", nonce_of_packet_acknowledgment);

                        match take_pending_ack(&nonce_of_packet_acknowledgment) {
                            Some((tag, original_request)) => {
                                println!("✅ Found pending ack. Sending stored request...");
                                let _ = client
                                    .send_nym_http_reply(tag, original_request.to_bytes())
                                    .await;
                            }
                            None => {
                                println!("❌ No pending ack found for nonce: {}", nonce_of_packet_acknowledgment);
                                continue;
                            }
                        }
                    }

                    AnonymousServiceRequestKind::RendezvousSurbResponse {ref surbs } => {
                        //I should create a function that stores these surbs.
                        println!("📩 Received {} reply SURBs from rendezvous", surbs.len());
                        // TODO: Store or use the SURBs
                        if(should_i_act_as_rendezvous_point())
                        {
                            println!("buffering..");
                            insert_buffered_rendezvous_message(request.nonce.clone(),request.clone());
                            let kind_to_send=AnonymousServiceRequestKind::AcknowledgementOfEstablishingRendevouzPoint { nonce_of_packet_acknowledgment: (request.nonce.clone()) };
                            let req_to_send=AnonymousServiceRequest::new_signed(&keypair, kind_to_send, generate_crypto_number());
                            let public_key=request.sender_tag.clone();
                            client.send_reply(AnonymousSenderTag::from_pubkey(&public_key.to_bytes()), req_to_send.to_bytes()).await;
                        }
                        else 
                        {
                            println!("I should save the surbs");
                            
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
                        if(is_anonymous_service_mode_enabled() || is_normal_client())
                        {
                            let new_kind=AnonymousServiceRequestKind::CanYouGiveMeThePacketWithThisNonce{nonce: nonce_of_packet_stored_there.clone()};
                            let new_request = AnonymousServiceRequest::new_signed(&keypair, new_kind, generate_crypto_number());
                            client.send_message(recipient, new_request.to_bytes(), IncludedSurbs::Amount((amount_to_receive+5) as u32)).await;
                        }
                        else
                        {
                            println!("Rejecting the packet as we are not either client or anonymous service");
                            continue;
                        }
                        
                    }

                    AnonymousServiceRequestKind::EncryptedContent(ref data) => {
                        println!("🔐 Received EncryptedContent with data of length: {}", data.len());
                            if(should_i_act_as_rendezvous_point())
                        {
                            println!("I buffer it as I act as rendevouz point");
                            insert_buffered_rendezvous_message(request.nonce.clone(),request.clone());
                            let kind_to_send=AnonymousServiceRequestKind::AcknowledgementOfEstablishingRendevouzPoint { nonce_of_packet_acknowledgment: (request.nonce.clone()) };
                            let req_to_send=AnonymousServiceRequest::new_signed(&keypair, kind_to_send, generate_crypto_number());
                            let public_key=request.sender_tag.clone();
                            client.send_reply(AnonymousSenderTag::from_pubkey(&public_key.to_bytes()), req_to_send.to_bytes()).await;

                        }
                        else
                        {
                            println!("I will decrypt it.");

                            if let Some(keypair) = find_x25519_keypair_by_nonce(&request.nonce) {
                                println!("✅ Found matching X25519 keypair.");
                                println!("request {} and kind {}",request,request.kind);
                                let decrypted: Option<AnonymousServiceRequestKind> =
                                    decrypt_request_kind(&request.kind, &keypair.private);
                                match decrypted {
                                    Some(ref inner) => {
                                        println!("🔓 Decryption successful: {}", inner);
                                        
                                    }
                                    None => {
                                        println!("❌ Decryption failed.");
                                    }
                                }
                            } else {
                                println!("❌ No X25519 keypair found for nonce: {}", request.nonce);
                            }
                    }
                    }
                    AnonymousServiceRequestKind::CanYouGiveMeThePacketWithThisNonce { nonce } => {
                    println!("📦 Received request to fetch packet with nonce: {}", nonce);
                    if(should_i_act_as_rendezvous_point()){
                        // TODO: Look up `BufferMessagesOfRendezvousPoint` using the nonce
                        match take_buffered_rendezvous_message(&nonce) {
                            Some(buffered) => {
                                println!("✅ Found stored message. Sending...");
                                //Maybe I can use a random key here?
                                client
                                    .send_reply(
                                        AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()),
                                        buffered.to_bytes(),
                                    )
                                    .await;
                            }
                            None => {
                                println!("❌ No message found in buffer for nonce {}", nonce);
                            }
                        }
                }
                else
                {
                    println!("I do not buffer images");
                }
                }
      AnonymousServiceRequestKind::PostSomeMoreSURBsToMyNode { nonce } => {
    println!("[DEBUG] Authority requested to post more SURBs for nonce: {}", nonce);
    if !matches!(get_client_role(),ClientRole::AnonymousService)
    {
        println!("I was asked to post some surbs, but i am not anonymous service.. continuing");
    }
    // Lookup the recipient that corresponds to this nonce
    if let Some(recipient) = find_recipient_by_crypto_number(&nonce) {
        println!("[DEBUG] Found recipient {:?} for nonce {}", recipient, nonce);

        // Send SURBs to this recipient (reuse share_anonymous_service_surbs with Some)
        client
            .share_anonymous_service_surbs(
                AnonymousSenderTag::from_pubkey(&keypair.public_key().to_bytes()),
                keypair.clone(),
                Some(recipient),
                "More SURBs requested",      // placeholder message
                IncludedSurbs::Amount(10),   // arbitrary amount; adjust if needed
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
        println!("❌ Failed to post SURBs for nonce {}: {}", nonce, success_str);
    }
}        AnonymousServiceRequestKind::ReturnedOscarWildeDescriptorAndSurbs(oscar_wilde_anonymous_service_descriptor,encrypted_surbs,msg) => {
    if !matches!(get_client_role(),ClientRole::NormalClient)
    {
        println!("Received ReturnedOscarWildeDescriptorAndSurbs but we are not client..Discarding");
    }
    else
    {
        
    }

}
        AnonymousServiceRequestKind::PostOscarWildeEncryptedSurbsWithSignature(oscar_wilde_anonymous_service_descriptor, encrypted_surbs_with_signature, shamir_secret_share) =>{
            let mut msg_to_return_to_client=String::from("");

            if !matches!(get_client_role(),ClientRole::Authority)
            {
                println!("received PostOscarWildeEncryptedSurbsWithSignature but rejecting and continuing.. ");
                msg_to_return_to_client=String::from("500 I am not supposed to store descriptors for anonymous services");
                continue;

            }
             if(does_oscar_wilde_service_exist(&oscar_wilde_anonymous_service_descriptor.ed25519_public_key))
            {
                msg_to_return_to_client=String::from("500  This descriptor exists");
            }
            else {
                let (validity_of_signatures,returned_msg_to_return_to_client)=verify_all_surb_signatures_with_message(&oscar_wilde_anonymous_service_descriptor.ed25519_public_key,&encrypted_surbs_with_signature);
                if(validity_of_signatures)
                {
                    store_oscar_wilde_data(oscar_wilde_anonymous_service_descriptor.clone(),encrypted_surbs_with_signature,shamir_secret_share);
                    insert_bigint_for_key(oscar_wilde_anonymous_service_descriptor.ed25519_public_key.clone(), request.nonce.clone());

                }
                msg_to_return_to_client=returned_msg_to_return_to_client;
            }
                let kindOfPostStatus=AnonymousServiceRequestKind::PostingSurbsStatus{success: (msg_to_return_to_client.into_bytes()),nonce: (request.nonce.clone())};
                let request=AnonymousServiceRequest::new_signed(&keypair, kindOfPostStatus, generate_crypto_number());
                client.send_reply(AnonymousSenderTag::from_pubkey(&oscar_wilde_anonymous_service_descriptor.ed25519_public_key.to_bytes()), request.to_bytes()).await;
        }
        AnonymousServiceRequestKind::ReturnedSecretsOfOscarWildeScheme(shamir_secret_share,msg) => {
                if !matches!(get_client_role(),ClientRole::NormalClient)
                {
                    println!("Received ShamirSecretShare but I am not client");
                }
                else
                {
                        // Check if shamir_secret_share is Some and bind to a local variable
    if let Some(secret) = shamir_secret_share {
        println!("Got Shamir Secret Share with rank: {}", secret.rank);
            if(secret.verify())
            {
                println!("Verification for shamir secret share succeed");
             //   insert_shamir_share_for_ed25519_key(secret.clone());

            }
            else
            {
                println!("signature verification of shamir secret share failed. ");
            }
        
        } else {
            println!("No Shamir Secret Share received");
        }


        }
    }
        AnonymousServiceRequestKind::RequestForShamirSecretShare(public_key, proof) => {
            if !matches!(get_client_role(),ClientRole::Authority){
                println!("Received RequestForShamirSecretShare but I am not authority.");
            }
            else {
                    if(proof.secret_index!=0)
                    {
                    let (maybe_share,msg) = get_shamir_secret_if_signature_valid(&public_key, &proof.signature,&proof.random_id);
                
                        let kind=AnonymousServiceRequestKind::ReturnedSecretsOfOscarWildeScheme(maybe_share,msg);
                        let request_to_send=AnonymousServiceRequest::new_signed(&keypair, kind, generate_crypto_number());
                        client.send_reply(AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()), request_to_send.to_bytes()).await;
                    }
                    else
                    {
                    let (maybe_descriptor, encrypted_surbs_vec, msg,should_i_request_more_surbs) =
                    get_descriptor_with_surbs_if_valid(&public_key, &proof.signature, &proof.random_id);
                    let encrypted_surbs_struct = EncryptedSurbsWithSignature {
                        surbs_with_signatures: encrypted_surbs_vec,
                    };
                        println!("tag: {}",AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()));
                        let kind=AnonymousServiceRequestKind::ReturnedOscarWildeDescriptorAndSurbs((maybe_descriptor), (encrypted_surbs_struct),(msg));
                        let request_to_send=AnonymousServiceRequest::new_signed(&keypair, kind, generate_crypto_number());
                        client.send_reply(AnonymousSenderTag::from_pubkey(&request.sender_tag.to_bytes()), request_to_send.to_bytes()).await;
                        if(should_i_request_more_surbs)
                        {
                        match get_bigint_for_key(&public_key) {
                             Some(number) => {

                                let posting_status_kind = AnonymousServiceRequestKind::PostSomeMoreSURBsToMyNode { nonce: (number.clone()) };

                                let request_struct = AnonymousServiceRequest::new_signed(
                                    &keypair,              // pass reference to cloned keypair
                                    posting_status_kind,
                                    generate_crypto_number(),  // Use same nonce as stored/processed if required
                                );
                                client.send_reply(AnonymousSenderTag::from_pubkey(&public_key.to_bytes()),request_struct.to_bytes()).await;
                            }
                            None => {
                            println!("❌ Failed to extract BigUint for the provided public key.");
                            continue;
                        }
                    }
                        }
                    }
                  
            }

        }
                        AnonymousServiceRequestKind::PostOscarExtraWildeEncryptedSurbsWithSignature(public_key, encrypted_surbs_with_signature) => {


                let (succeed,msg)=verify_and_append_surbs_to_storage(&public_key,encrypted_surbs_with_signature);
                if(succeed)
                {
                    insert_bigint_for_key(public_key.clone(), request.nonce.clone());

                }
                let post_status=AnonymousServiceRequestKind::PostingSurbsStatus{success: (msg.into_bytes()),nonce: (request.nonce.clone())};
                let request_to_send=AnonymousServiceRequest::new_signed(&keypair, post_status, generate_crypto_number());
                client.send_reply(AnonymousSenderTag::from_pubkey(&public_key.to_bytes()), request_to_send.to_bytes()).await;
                        }

                }
                } else {
                    println!("❌ Failed to parse message into AnonymousServiceRequest");
                }
            }
        }
    }
}

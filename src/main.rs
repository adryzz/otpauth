use protobuf::Message;
use protos::cum::MigrationPayload;
use base64::prelude::*;

use crate::protos::cum::migration_payload::OtpType;
pub mod protos;

fn main() {

    println!("enter code");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    if &line[..33] != "otpauth-migration://offline?data=" {
        println!("BAD format");
        return;
    }
    let decoded = urlencoding::decode(&line[33..]).unwrap().to_string();
    let out = BASE64_STANDARD.decode(&decoded[..decoded.len()-1]).unwrap();
    let msg = MigrationPayload::parse_from_bytes(&out).unwrap();

    println!("QRCode {} of {}", msg.batch_index+1, msg.batch_size);
    for p in msg.otp_parameters {
        println!("\t {:?} Code \"{}\", issued by \"{}\"", p.type_, p.name, p.issuer);
        println!("\t Algorithm: {:?}, Digits: {:?}", p.algorithm, p.digits);
        let secret = base32::encode(base32::Alphabet::RFC4648 { padding: true }, &p.secret);
        println!("\t Secret (base32): {}\n", secret);
        if let OtpType::OTP_TYPE_HOTP = p.type_.unwrap() {
            println!("\t Counter: {}", p.counter);
        }
    }
}

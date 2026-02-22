use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process;

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct AddRequest {
    packages: Vec<String>,
    ephemeral: bool,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct AddResponse {
    status: String,
    #[serde(default)]
    added: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    message: String,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: min add [--ephemeral] <pkg> [pkg...]");
        process::exit(1);
    }

    match args[0].as_str() {
        "add" => cmd_add(&args[1..]),
        _ => {
            eprintln!("usage: min add [--ephemeral] <pkg> [pkg...]");
            process::exit(1);
        }
    }
}

fn cmd_add(args: &[String]) {
    let port = read_port();
    let mut ephemeral = false;
    let mut packages = Vec::new();

    for arg in args {
        if arg == "--ephemeral" {
            ephemeral = true;
        } else {
            packages.push(arg.clone());
        }
    }

    if packages.is_empty() {
        eprintln!("usage: min add [--ephemeral] <pkg> [pkg...]");
        process::exit(1);
    }

    let req = AddRequest {
        packages,
        ephemeral,
    };
    let body = serde_json::to_string(&req).unwrap();

    let resp_body = http_post(&format!("127.0.0.1:{}", port), "/v1/add", &body);
    let resp: AddResponse = match serde_json::from_str(&resp_body) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to parse response: {}", e);
            process::exit(1);
        }
    };

    if resp.status == "error" {
        eprintln!("error: {}", resp.message);
        process::exit(1);
    }

    // Print export statements to stdout (eval'd by bashrc wrapper)
    for (key, value) in &resp.env {
        println!("export {}={}", key, shell_escape(value));
    }

    // Print message to stderr
    if !resp.message.is_empty() {
        eprintln!("{}", resp.message);
    }
}

fn read_port() -> u16 {
    let content = match std::fs::read_to_string("/state/.min/port") {
        Ok(c) => c,
        Err(_) => {
            eprintln!("error: not running in a managed minimal environment");
            process::exit(1);
        }
    };
    match content.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("error: invalid port file");
            process::exit(1);
        }
    }
}

fn http_post(addr: &str, path: &str, body: &str) -> String {
    let mut stream = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: could not connect to metadata service: {}", e);
            process::exit(1);
        }
    };
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok();

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();

    // Extract body after headers
    match response.find("\r\n\r\n") {
        Some(i) => response[i + 4..].to_string(),
        None => {
            eprintln!("error: malformed HTTP response");
            process::exit(1);
        }
    }
}

fn shell_escape(s: &str) -> String {
    // Single-quote the value, escaping any embedded single quotes
    format!("'{}'", s.replace('\'', "'\\''"))
}

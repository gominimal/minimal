use std::process;

use min_client::min_proto::min_service_client::MinServiceClient;
use min_client::min_proto::AddRequest;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: min add [--ephemeral] <pkg> [pkg...]");
        process::exit(1);
    }

    match args[0].as_str() {
        "add" => cmd_add(&args[1..]).await,
        _ => {
            eprintln!("usage: min add [--ephemeral] <pkg> [pkg...]");
            process::exit(1);
        }
    }
}

async fn cmd_add(args: &[String]) {
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

    let mut client =
        match MinServiceClient::connect(format!("http://127.0.0.1:{}", port)).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: could not connect to metadata service: {}", e);
                process::exit(1);
            }
        };

    let request = tonic::Request::new(AddRequest {
        packages,
        ephemeral,
    });

    match client.add(request).await {
        Ok(response) => {
            let resp = response.into_inner();
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
        Err(e) => {
            eprintln!("error: {}", e.message());
            process::exit(1);
        }
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

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

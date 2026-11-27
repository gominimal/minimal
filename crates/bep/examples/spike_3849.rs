//! SPIKE (gominimal/minimal#3849): drive `bep::ss_dbus` from a shell.
//! Never prints a secret: a read prints its length and sha256 only.
//!
//!   spike_3849 store <label> k=v...   (value on stdin, raw bytes)
//!   spike_3849 lookup k=v...
//!   spike_3849 list <key> k=v...
//!   spike_3849 attrs k=v...
//!   spike_3849 clear k=v...
//!   spike_3849 keyerr k=v...          (lookup, mapped to KeyError)

#[cfg(target_os = "linux")]
fn main() {
    use bep::ss_dbus as ss;
    use sha2::Digest as _;
    use std::io::Read as _;
    use std::time::Duration;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let pairs = |from: &[String]| -> Vec<(String, String)> {
        from.iter()
            .map(|a| {
                let (k, v) = a.split_once('=').expect("k=v");
                (k.to_owned(), v.to_owned())
            })
            .collect()
    };
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = &args[1.min(args.len())..];
    let fail = |c: ss::Cause| -> ! {
        println!("error: {c:?}");
        std::process::exit(3);
    };
    let ss = match ss::connect(Duration::from_secs(10)) {
        Ok(s) => s,
        Err(c) => {
            if cmd == "keyerr" {
                println!("{:?}", c.into_key_error(bep::keys::Role::Root));
                std::process::exit(3);
            }
            fail(c)
        }
    };
    match cmd {
        "store" => {
            let label = &rest[0];
            let p = pairs(&rest[1..]);
            let attrs: Vec<(&str, &str)> =
                p.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let mut value = Vec::new();
            std::io::stdin().read_to_end(&mut value).unwrap();
            ss::store(&ss, label, &attrs, &value).unwrap_or_else(|c| fail(c));
            println!(
                "stored len={} sha256={}",
                value.len(),
                hex(&sha2::Sha256::digest(&value))
            );
        }
        "lookup" | "keyerr" => {
            let p = pairs(rest);
            let attrs: Vec<(&str, &str)> =
                p.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            match ss::lookup(&ss, &attrs) {
                Ok(Some(v)) => println!(
                    "found len={} sha256={}",
                    v.len(),
                    hex(&sha2::Sha256::digest(&v[..]))
                ),
                Ok(None) => println!("none"),
                Err(c) if cmd == "keyerr" => {
                    println!("{:?}", c.into_key_error(bep::keys::Role::Root));
                    std::process::exit(3);
                }
                Err(c) => fail(c),
            }
        }
        "list" => {
            let key = &rest[0];
            let p = pairs(&rest[1..]);
            let attrs: Vec<(&str, &str)> =
                p.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            for v in ss::list_attribute(&ss, &attrs, key).unwrap_or_else(|c| fail(c)) {
                println!("{key}={v}");
            }
        }
        "attrs" => {
            let p = pairs(rest);
            let attrs: std::collections::HashMap<&str, &str> =
                p.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let found = ss
                .search_items(attrs)
                .unwrap_or_else(|e| fail(ss::sort(&e)));
            for (locked, item) in found
                .unlocked
                .iter()
                .map(|i| (false, i))
                .chain(found.locked.iter().map(|i| (true, i)))
            {
                let mut a: Vec<_> = item.get_attributes().unwrap().into_iter().collect();
                a.sort();
                println!(
                    "locked={locked} label={:?} attrs={a:?}",
                    item.get_label().unwrap()
                );
            }
        }
        "clear" => {
            let p = pairs(rest);
            let attrs: Vec<(&str, &str)> =
                p.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            println!(
                "cleared {}",
                ss::clear(&ss, &attrs).unwrap_or_else(|c| fail(c))
            );
        }
        other => panic!("unknown command {other:?}"),
    }
}

#[cfg(target_os = "linux")]
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(not(target_os = "linux"))]
fn main() {}

//! Time one ECDH and one ECDSA signature through tss-esapi, and check the key
//! is fixedTPM, refuses duplication and refuses a wrong authorization.
use std::{str::FromStr, time::Instant};

use p256::{ecdsa::signature::hazmat::PrehashVerifier, elliptic_curve::sec1::ToEncodedPoint};
use sha2::{Digest as _, Sha256};
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::AesKeyBits,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        Auth, Digest, EccParameter, EccPoint, EccScheme, HashScheme, HashcheckTicket,
        KeyDerivationFunctionScheme, Private, Public, PublicBuilder, PublicEccParametersBuilder,
        Signature, SignatureScheme, SymmetricDefinitionObject,
    },
    tss2_esys::TPMT_TK_HASHCHECK,
    Context, TctiNameConf,
};

fn srk_template() -> Public {
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(
            ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_no_da(true)
                .with_restricted(true)
                .with_decrypt(true)
                .build()
                .unwrap(),
        )
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::Aes { key_bits: AesKeyBits::Aes128, mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb },
                EccCurve::NistP256,
            )
            .build()
            .unwrap(),
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .unwrap()
}

fn key_template(sign: bool) -> Public {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_sign_encrypt(sign)
        .with_decrypt(!sign)
        .build()
        .unwrap();
    let scheme = if sign {
        EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256))
    } else {
        EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256))
    };
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new()
                .with_ecc_scheme(scheme)
                .with_curve(EccCurve::NistP256)
                .with_is_signing_key(sign)
                .with_is_decryption_key(!sign)
                .with_restricted(false)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .build()
                .unwrap(),
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .unwrap()
}

fn null_ticket() -> HashcheckTicket {
    HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    })
    .unwrap()
}

fn report(name: &str, mut ms: Vec<f64>) {
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = ms.len();
    println!(
        "{name:<44}median {:.1} ms  p90 {:.1} ms  (n={n})",
        ms[(n - 1) / 2],
        ms[((n as f64) * 0.9).round() as usize - 1]
    );
}

fn time<T>(f: impl FnOnce() -> T) -> (T, f64) {
    let s = Instant::now();
    let r = f();
    (r, s.elapsed().as_secs_f64() * 1000.0)
}

fn point(p: &Public) -> (Vec<u8>, Vec<u8>) {
    match p {
        Public::Ecc { unique, .. } => (unique.x().value().to_vec(), unique.y().value().to_vec()),
        _ => unreachable!(),
    }
}

fn main() {
    let tcti = std::env::args().nth(1).expect("usage: esapi-bench <tcti> [n]");
    let n: usize = std::env::args().nth(2).map_or(20, |s| s.parse().unwrap());
    println!("== {tcti}");
    let conf = TctiNameConf::from_str(&tcti).unwrap();

    let opens: Vec<f64> = (0..n).map(|_| time(|| drop(Context::new(conf.clone()).unwrap())).1).collect();
    report("open a context (TCTI + ESYS init):", opens);

    let mut ctx = Context::new(conf.clone()).unwrap();
    ctx.set_sessions((Some(AuthSession::Password), None, None));
    let mut a = [0u8; 16];
    rand_core::OsRng.fill_bytes_compat(&mut a);
    let auth = Auth::try_from(a.to_vec()).unwrap();

    let srk = ctx.create_primary(Hierarchy::Owner, srk_template(), None, None, None, None).unwrap().key_handle;
    let s = ctx.create(srk, key_template(true), Some(auth.clone()), None, None, None).unwrap();
    let e = ctx.create(srk, key_template(false), Some(auth.clone()), None, None, None).unwrap();
    let (s_priv, s_pub): (Private, Public) = (s.out_private, s.out_public);
    let (e_priv, e_pub): (Private, Public) = (e.out_private, e.out_public);
    let load = |ctx: &mut Context, parent: KeyHandle, pr: &Private, pu: &Public| -> KeyHandle {
        let h = ctx.load(parent, pr.clone(), pu.clone()).unwrap();
        ctx.tr_set_auth(h.into(), auth.clone()).unwrap();
        h
    };
    let sk = load(&mut ctx, srk, &s_priv, &s_pub);
    let ek = load(&mut ctx, srk, &e_priv, &e_pub);

    let msg = b"bep t127";
    let dig = Digest::try_from(Sha256::digest(msg).to_vec()).unwrap();
    let peer = p256::SecretKey::random(&mut rand_core::OsRng);
    let pp = peer.public_key().to_encoded_point(false);
    let peer_pt = EccPoint::new(
        EccParameter::try_from(pp.x().unwrap().to_vec()).unwrap(),
        EccParameter::try_from(pp.y().unwrap().to_vec()).unwrap(),
    );

    let signs: Vec<f64> = (0..n)
        .map(|_| time(|| ctx.sign(sk, dig.clone(), SignatureScheme::Null, null_ticket()).unwrap()).1)
        .collect();
    report("ECDSA, key loaded, in process:", signs);
    let zs: Vec<f64> = (0..n).map(|_| time(|| ctx.ecdh_z_gen(ek, peer_pt.clone()).unwrap()).1).collect();
    report("ECDH,  key loaded, in process:", zs);

    // Checks.
    let sig = ctx.sign(sk, dig.clone(), SignatureScheme::Null, null_ticket()).unwrap();
    let (x, y) = point(&s_pub);
    let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&p256::EncodedPoint::from_affine_coordinates(
        x.as_slice().into(),
        y.as_slice().into(),
        false,
    ))
    .unwrap();
    if let Signature::EcDsa(es) = sig {
        let rs = p256::ecdsa::Signature::from_scalars(
            <[u8; 32]>::try_from(es.signature_r().value()).unwrap(),
            <[u8; 32]>::try_from(es.signature_s().value()).unwrap(),
        )
        .unwrap();
        println!("check: signature verifies with p256: {}", vk.verify_prehash(&Sha256::digest(msg), &rs).is_ok());
    }
    let z = ctx.ecdh_z_gen(ek, peer_pt.clone()).unwrap();
    let (ex, ey) = point(&e_pub);
    let tpm_pub = p256::PublicKey::from_sec1_bytes(
        p256::EncodedPoint::from_affine_coordinates(ex.as_slice().into(), ey.as_slice().into(), false).as_bytes(),
    )
    .unwrap();
    let soft = p256::ecdh::diffie_hellman(peer.to_nonzero_scalar(), tpm_pub.as_affine());
    println!("check: ECDH Z matches p256: {}", z.x().value() == soft.raw_secret_bytes().as_slice());
    for (name, h) in [("signing", sk), ("ecdh", ek)] {
        let (p, _, _) = ctx.execute_without_session(|c| c.read_public(h)).unwrap();
        let a = p.object_attributes();
        println!("check: {name} key as the TPM reports it: fixedTPM={} fixedParent={} noDA={} userWithAuth={}",
            a.fixed_tpm(), a.fixed_parent(), a.no_da(), a.user_with_auth());
    }
    ctx.tr_set_auth(sk.into(), Auth::try_from(vec![0u8; 16]).unwrap()).unwrap();
    let bad = ctx.sign(sk, dig.clone(), SignatureScheme::Null, null_ticket());
    println!("check: wrong auth refused: {}", bad.is_err());
    for h in [sk, ek, srk] {
        ctx.flush_context(h.into()).unwrap();
    }
    // Close the TCTI too: a raw device such as /dev/tpm0 takes one open.
    drop(ctx);
    // A restart: new context, primary, load the blob, one use, flush.
    let cold = |is_sign: bool| -> Vec<f64> {
        (0..n)
            .map(|_| {
                time(|| {
                    let mut c = Context::new(conf.clone()).unwrap();
                    c.set_sessions((Some(AuthSession::Password), None, None));
                    let p = c.create_primary(Hierarchy::Owner, srk_template(), None, None, None, None).unwrap().key_handle;
                    let (pr, pu) = if is_sign { (&s_priv, &s_pub) } else { (&e_priv, &e_pub) };
                    let k = c.load(p, pr.clone(), pu.clone()).unwrap();
                    c.tr_set_auth(k.into(), auth.clone()).unwrap();
                    if is_sign {
                        c.sign(k, dig.clone(), SignatureScheme::Null, null_ticket()).unwrap();
                    } else {
                        c.ecdh_z_gen(k, peer_pt.clone()).unwrap();
                    }
                    c.flush_context(k.into()).unwrap();
                    c.flush_context(p.into()).unwrap();
                })
                .1
            })
            .collect()
    };
    report("ECDSA, from blob (open+primary+load+sign):", cold(true));
    report("ECDH,  from blob (open+primary+load+zgen):", cold(false));

}

trait FillCompat {
    fn fill_bytes_compat(&mut self, b: &mut [u8]);
}
impl FillCompat for rand_core::OsRng {
    fn fill_bytes_compat(&mut self, b: &mut [u8]) {
        rand_core::RngCore::fill_bytes(self, b)
    }
}

//! SRP-6a (RFC 5054 3072-bit group, `g = 5`, SHA-512) server and client for AirPlay `/pair-setup`.

use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;

use crate::crypto::sha512_concat;

const N_BYTES: usize = 384;
const N_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183",
    "995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A",
    "85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7AB",
    "F5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D8",
    "7602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208",
    "E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
);

fn modulus() -> BigUint {
    BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("valid RFC 5054 3072-bit prime")
}

fn generator() -> BigUint {
    BigUint::from(5u32)
}

fn to_minimal_be(v: &BigUint) -> Vec<u8> {
    if v.is_zero() {
        vec![0]
    } else {
        v.to_bytes_be()
    }
}

fn pad_n(v: &BigUint) -> Vec<u8> {
    let raw = to_minimal_be(v);
    if raw.len() >= N_BYTES {
        return raw;
    }
    let mut out = vec![0u8; N_BYTES];
    out[N_BYTES - raw.len()..].copy_from_slice(&raw);
    out
}

fn multiplier_k(n: &BigUint, g: &BigUint) -> BigUint {
    let n_bytes = to_minimal_be(n);
    let g_padded = pad_n(g);
    BigUint::from_bytes_be(&sha512_concat(&[&n_bytes, &g_padded]))
}

fn compute_x(salt: &[u8], username: &[u8], password: &[u8]) -> BigUint {
    let user_pass = sha512_concat(&[username, b":", password]);
    BigUint::from_bytes_be(&sha512_concat(&[salt, &user_pass]))
}

fn compute_m1_proof(
    n: &BigUint,
    g: &BigUint,
    username: &[u8],
    salt: &[u8],
    pub_a: &BigUint,
    pub_b: &BigUint,
    session_key: &[u8; 64],
) -> [u8; 64] {
    let hn = sha512_concat(&[&to_minimal_be(n)]);
    let hg = sha512_concat(&[&to_minimal_be(g)]);
    let mut h_xor = [0u8; 64];
    for i in 0..64 {
        h_xor[i] = hn[i] ^ hg[i];
    }
    let hi = sha512_concat(&[username]);
    sha512_concat(&[&h_xor, &hi, salt, &pad_n(pub_a), &pad_n(pub_b), session_key])
}

pub struct Srp6aVerifyResult {
    pub session_key: [u8; 64],
    pub server_proof: [u8; 64],
}

/// Accessory (responder) SRP-6a session.
pub struct Srp6aServerSession {
    pub salt: [u8; 16],
    pub public_key_b: Vec<u8>,
    b_int: BigUint,
    priv_b: BigUint,
    verifier: BigUint,
    identifier: Vec<u8>,
}

impl Srp6aServerSession {
    pub fn start(username: &str, password: &str) -> Self {
        let n = modulus();
        let g = generator();
        let k = multiplier_k(&n, &g);

        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let mut priv_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut priv_bytes);

        let x = compute_x(&salt, username.as_bytes(), password.as_bytes());
        let verifier = g.modpow(&x, &n);
        let priv_b = BigUint::from_bytes_be(&priv_bytes);
        let b_int = (&k * &verifier + g.modpow(&priv_b, &n)) % &n;

        Self {
            salt,
            public_key_b: pad_n(&b_int),
            b_int,
            priv_b,
            verifier,
            identifier: username.as_bytes().to_vec(),
        }
    }

    pub fn verify(
        &self,
        public_key_a_bytes: &[u8],
        client_proof: &[u8],
    ) -> Option<Srp6aVerifyResult> {
        let n = modulus();
        let g = generator();
        let a_int = BigUint::from_bytes_be(public_key_a_bytes);
        if (&a_int % &n).is_zero() {
            return None;
        }

        let u = BigUint::from_bytes_be(&sha512_concat(&[&pad_n(&a_int), &pad_n(&self.b_int)]));
        let s = ((&a_int * self.verifier.modpow(&u, &n)) % &n).modpow(&self.priv_b, &n);
        let session_key = sha512_concat(&[&to_minimal_be(&s)]);

        let expected = compute_m1_proof(
            &n,
            &g,
            &self.identifier,
            &self.salt,
            &a_int,
            &self.b_int,
            &session_key,
        );
        if expected.as_slice() != client_proof {
            return None;
        }

        let server_proof = sha512_concat(&[&pad_n(&a_int), client_proof, &session_key]);
        Some(Srp6aVerifyResult {
            session_key,
            server_proof,
        })
    }
}

/// Controller (initiator / simulated iPhone) SRP-6a client for end-to-end testing & desktop simulator.
pub struct Srp6aClientSession {
    pub public_key_a: Vec<u8>,
    pub client_proof: [u8; 64],
    pub session_key: [u8; 64],
    a_int: BigUint,
}

impl Srp6aClientSession {
    pub fn respond_to_challenge(
        username: &str,
        password: &str,
        salt: &[u8],
        server_pub_b: &[u8],
    ) -> Option<Self> {
        let n = modulus();
        let g = generator();
        let k = multiplier_k(&n, &g);

        let b_int = BigUint::from_bytes_be(server_pub_b);
        if (&b_int % &n).is_zero() {
            return None;
        }

        let mut priv_a_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut priv_a_bytes);
        let priv_a = BigUint::from_bytes_be(&priv_a_bytes);
        let a_int = g.modpow(&priv_a, &n);

        let u = BigUint::from_bytes_be(&sha512_concat(&[&pad_n(&a_int), &pad_n(&b_int)]));
        let x = compute_x(salt, username.as_bytes(), password.as_bytes());
        let gx = g.modpow(&x, &n);
        let kgx = (&k * &gx) % &n;
        // (B - k * g^x) mod N
        let base = if b_int >= kgx {
            (&b_int - &kgx) % &n
        } else {
            (&n + &b_int - &kgx) % &n
        };
        let exp = &priv_a + (&u * &x);
        let s = base.modpow(&exp, &n);
        let session_key = sha512_concat(&[&to_minimal_be(&s)]);

        let client_proof = compute_m1_proof(
            &n,
            &g,
            username.as_bytes(),
            salt,
            &a_int,
            &b_int,
            &session_key,
        );

        Some(Self {
            public_key_a: pad_n(&a_int),
            client_proof,
            session_key,
            a_int,
        })
    }

    pub fn verify_server_proof(&self, server_proof: &[u8]) -> bool {
        let expected = sha512_concat(&[
            &pad_n(&self.a_int),
            &self.client_proof,
            &self.session_key,
        ]);
        expected.as_slice() == server_proof
    }
}

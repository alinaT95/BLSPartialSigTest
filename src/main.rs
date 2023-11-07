use blst::*;
use blst::min_pk::*;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Instant, Duration};
use rand::Rng;
use std::collections::HashSet;

use std::{ptr, slice};
use std::mem;

use std::fs::File;
use std::io::prelude::*;

use rand::thread_rng;


struct BenchData {
    sk: SecretKey,
    pk: PublicKey,
    msg: Vec<u8>,
    dst: Vec<u8>,
    sig: Signature,
}

pub struct KeyPair {
    sk: SecretKey,
    pk: PublicKey,
}

struct Node {
    key_pair: KeyPair,
    index: u32
}

const DST:[u8; 43] = *b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

fn gen_key_pair() -> KeyPair {
    let mut seed = [0u8; 32];
    thread_rng().try_fill(&mut seed[..]);
    println!("Random number array {:?}", seed);

    let mut
    rng = ChaCha20Rng::from_seed(seed);

    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();

    return KeyPair{sk: sk, pk: pk};
}


pub fn gen_signer_indexes(n: u32, k: u32) -> HashSet<u32> {
    let mut rng = rand::thread_rng();

    loop {
        let mut indexes = HashSet::new();

        for i in 0..k {
            indexes.insert(rng.gen_range(0, n-1));
        }

        if indexes.len() == (k as usize) {
            return indexes;
        }
    }
}

pub fn aggregate_signatures_from_nodes(sigs: Vec<&Signature>) -> Signature {
    let agg =
        match AggregateSignature::aggregate(&sigs, false)
            {
                Ok(agg) => agg,
                Err(err) => panic!("aggregate failure: {:?}", err),
            };
    return agg.to_signature()
}

pub fn verify_signatures_from_nodes(agg_sig: &Signature, apk: &PublicKey, msg: &Vec<u8>)  {
    let result = agg_sig.fast_aggregate_verify_pre_aggregated(
        false, &msg, &DST, &apk,
    );
    assert_eq!(result, BLST_ERROR::BLST_SUCCESS);
}

pub fn create_mask(indexes : HashSet<u32>, n: u32) -> Vec<bool> {
    let mut mask = Vec::new();
    for i in 0..n {
        if indexes.contains(&i) {
            //println!("Found = {}", i);
            mask.push(true);
        }
        else {
            mask.push(false);
        }
    }
    return mask;
}

pub fn aggregate_public_key(pks_refs: &Vec<&PublicKey>, bit_mask: &Vec<bool>) -> PublicKey {
    let mut pks_refs_slashed: Vec<&PublicKey> = Vec::new();
    let mut i: u32 = 0;
    println!("Len = {}", bit_mask.len());
    for i in 0..bit_mask.len()  {
        if bit_mask[i as usize] == true {
            println!("Found = {}", i);
            pks_refs_slashed.push(&pks_refs[i as usize]);
        }
    }

    let agg_pk =
        match AggregatePublicKey::aggregate(&pks_refs_slashed, false)
            {
                Ok(agg_pk) => agg_pk,
                Err(err) => panic!("aggregate failure: {:?}", err),
            };
    return agg_pk.to_public_key()
}

pub fn verify(sig: &Signature, msg: &Vec<u8>, pk: &PublicKey) -> bool {
    let res = sig.verify(true, msg, &DST, &[], &pk, true);
    return res == BLST_ERROR::BLST_SUCCESS;
}


fn main() {
    let n: u32 = 100;
    let k: u32 = 3;

    let seed = [0u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut nodes = Vec::new();
    for i in 0..n {
        let node = Node{
            key_pair: gen_key_pair(),
            index: i
        };
        nodes.push(node);
    }

    let mut pks_refs: Vec<&PublicKey> =  Vec::new();
    for node in &nodes {
        pks_refs.push(&node.key_pair.pk);
    }

    let msg_len = (rng.next_u64() & 0x3F) + 1;
    println!("Msg len = {}", msg_len);
    let mut msg = vec![0u8; msg_len as usize];
    rng.fill_bytes(&mut msg);

    let mut indexes: HashSet<u32> = gen_signer_indexes(n, k);
    let mut sigs_from_nodes: Vec<Signature> = Vec::new();
    for ind in &indexes {
        println!("{}", ind);
        sigs_from_nodes.push(nodes[*ind as usize].key_pair.sk.sign(&msg, &DST, &[]));
    }

    let bit_mask = create_mask(indexes, n);

    //let sig_refs =
       // sigsFromNodes.iter().map(|s| s).collect::<Vec<&Signature>>();

    let mut sig_refs: Vec<&Signature> =  Vec::new();
    for sig in &sigs_from_nodes {
        sig_refs.push(&sig);
    }


    let aggSig = aggregate_signatures_from_nodes(sig_refs);

    let aggPk = aggregate_public_key(&pks_refs, &bit_mask);

    verify_signatures_from_nodes(&aggSig, &aggPk, &msg); // this will fail verification of sig

    println!("Verified!");


}

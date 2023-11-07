# BLSPartialSigTest

The following example for BLS aggregated signature is implemented here:

- There is a set **G** of **n** nodes **N_i, i=0..n-1**. Each node generates BLS keypair **K_i = (sk_i, pk_i)**.

- There is subset **S** of nodes, s.t. **|S|=k (0 < k <= n)**, that want to sign a message **M**.

- Each node from **S** prepares a signature **Sigma_i** using its secret key **sk_i** and sends **Sigma_i** to Aggregator entity.

- Agrregator entity has a collection **{Sigma_i, i \in S}**. He aggregates them into one signature **AggSigma**.
  Here:

  **AggSigma = a_{i_1} * Sigma_{i_1} + ... + a_{i_k} * Sigma_{i_k}**, **a_{i_j} = Hash(pk_{i_j} || pk_{i_1} || ... || pk_{i_k}), j \in S**.

- Verifier entity has a list of all public keys **P={pk_i, i = 0..n-1}**.

- Verifier entity gets **AggSigma** and **BitMask**. **BitMask** is a boolen vector of length **n**, **i-th** coordinate of **BitMask** is 1 if node with index **i** is in **S**. Based on BitMask Verifier will compute aggregated public key **AggPK** for parties belonging to **S**.
  Here:
  
  **AggPK = a_{i_1} * pk_{i_1} + ... + a_{i_k} * pk_{i_k}**, **a_{i_j} = Hash(pk_{i_j} || pk_{i_1} || ... || pk_{i_k}), j \in S**.

- Verifier validates signature **AggSigma** for message **M** using public key **AggPK**. 

---
title: "Exploring TLS: Securing TCP Communication"
date: 2024-09-21 23:00:00 +0530
categories: [Blogging, Writeup, Cybersecurity]
tags: [Blogging, Tutorial, Writeup, TLS, Secure, TCP]  
pin: false
math: true
mermaid: true
author: 7h3h0und
image:
  path: /assets/img/headers/tls.webp
  lqip: data:image/png;base64,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
---

## What is TLS?

`Transport Layer Security (TLS)` is a cryptographic protocol that provides privacy and data security for communication over the internet. TLS is the successor to SSL (Secure Sockets Layer) and is primarily used to encrypt communication between web applications and servers.

If you've ever made a purchase online using your credit or debit card, the communication between your browser and the server for this transaction was almost certainly protected by TLS.

While this example highlights one common use case, TLS applications extend far beyond online purchases. TLS is most used to secure HTTP transactions, but since it operates over TCP, it can also be used by other applications that rely on TCP for communication, such as email protocols (SMTP, IMAP, POP3), and even Voice over IP (VoIP) communications.

TLS was first proposed by the `Internet Engineering Task Force (IETF)` in 1999 with RFC 4346, and the most recent version, TLS 1.3, was published in 2018.

## How TLS works?
To better understand how TLS secures communication, we can break down its operation into three key phases: Handshake, Key Derivation, and Data Transfer.

### Handshake:

The handshake process is the first step in establishing a secure connection between the client (e.g., your browser) and the server. During this phase, both parties agree on cryptographic algorithms and exchange keys.

-	__ClientHello__: The client sends a "hello" message to the server, which includes supported cryptographic algorithms and a randomly generated number.
-	__ServerHello__: The server responds with its choice of algorithm, its certificate (to prove its identity), and its own random number.
-	__Authentication__ and Pre-Master Secret: If the client trusts the server’s certificate, it encrypts a pre-master secret using the server's public key and sends it to the server. Only the server can decrypt this secret with its private key.

![img-description](/assets/img/posts/tls/1.webp) _TLS Handshake_

>In TLS 1.3, the handshake has been simplified, reducing the number of round trips, making the connection establishment faster compared to TLS 1.2.
{:.prompt-info }

### Key Derivation
Once both parties have exchanged the premaster secret, they use this value along with the random numbers exchanged during the handshake (client random and server random) to derive the master secret. From the master secret, the client and server generate the symmetric keys, message authentication codes (MAC) keys, and sometimes `Initialization Vectors (IVs)` for certain encryption modes. These keys will be used to encrypt, decrypt, and authenticate the actual data, ensuring confidentiality and integrity for the duration of the session.

>__Initialization Vectors (IVs)__ are critical for block cipher modes like CBC (Cipher Block Chaining) because they help ensure that identical plaintext blocks produce different ciphertext blocks, enhancing security.
{: .prompt-info }

### Data Transfer
With the handshake and key derivation complete, secure data transfer can begin. All further communication between the client and server is encrypted using the symmetric key. TLS ensures not only encryption but also integrity, using MACs or Authenticated Encryption with Associated Data (AEAD) to detect tampering and prevent unauthorized modifications.

At the end of the session, both the client and server can agree to terminate the connection, clearing the session keys to prevent reuse in future sessions, which helps maintain forward secrecy if supported (e.g., with ECDHE key exchange).

>__Forward secrecy__ ensures that even if the private key of the server is compromised in the future, past sessions remain secure because they rely on ephemeral key exchange methods like ECDHE.
{: .prompt-info }

## Deeper dive into Handshake
TLS does not mandate the use of specific symmetric or asymmetric algorithms; instead, it allows the client and server to negotiate and agree on cryptographic algorithms at the beginning of the session. The detailed steps of the TLS handshake are as follows:

1. __ClientHello:__ The client sends a list of supported cryptographic algorithms (cipher suites), including symmetric ciphers (like AES or ChaCha20), key exchange methods (like RSA or ECDHE), and MAC algorithms. The client also sends a random value, called the client nonce (or client random).

> A typical TLS cipher suite looks like this: `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` 
{:.prompt-tip}
  
2. __ServerHello:__ The server selects a cipher suite from the client’s list, specifying the symmetric algorithm (e.g., AES), the public key algorithm (e.g., RSA or ECDHE), and the MAC algorithm (e.g., HMAC-SHA256). The server also sends its digital certificate containing its public key, and a server nonce (server random).

3. __Certificate Verification:__ The client verifies the server’s certificate, ensuring it was issued by a trusted Certificate Authority (CA) and that it matches the server’s identity. The client then extracts the server’s public key from the certificate.

4.	__Pre-Master Secret Exchange:__
    -	In RSA key exchange, the client generates a premaster secret, encrypts it with the server’s public key, and sends it to the server.
    -	In ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) key exchange, the client and server exchange Diffie-Hellman parameters to securely compute a shared  premaster secret without directly transmitting it over the network.

    >In modern TLS versions (like 1.3), RSA key exchange is deprecated in favor of ephemeral Diffie-Hellman methods, which provide forward secrecy.
    {: .prompt-info }

5.	__Master Secret Generation:__ 
  Both the client and server use the premaster secret along with the client and server random values to compute the master secret. From the master secret, they independently derive the symmetric encryption keys, MAC keys, and IVs (if needed). These keys are used for encrypting and authenticating the session data.

6.	__Finished Messages:__
    - The client sends a Finished message, containing a MAC of all handshake messages up to this point, encrypted with the new symmetric key.
    - The server also sends a Finished message, similarly, containing a MAC of the handshake messages.

7.	__Secure Communication:__ Once the Finished messages are successfully exchanged, the handshake is complete, and secure data transfer can begin. All further messages are encrypted and authenticated using the negotiated cipher suite.

## Summary:
TLS provides a robust and widely used method for securing communication across the internet. By utilizing a combination of encryption, integrity verification, and authentication, TLS ensures that data is protected from interception, tampering, and unauthorized access. Understanding the TLS handshake and how keys are derived helps clarify why it's such a critical protocol for internet security today.


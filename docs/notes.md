# Notes
A collection of notes / references. 
Tracks progress, make sure we implement everything necessary.

---

# SSH
1. Establish TCP connection.
2. Data exchange:
   - Identification string exchange
   - Algorithm negotiation
   - Key exchange / end of key exchange
   - Service request

## Three major components:
1. Transport Layer Protocol
   - server authentication
   - confidentiality
   - integrity with perfect forward secrecy.
   - (optionally) compression
Typically, this is done over a TCP/IP connection, but could be any reliable data stream.

2. User Authentication Protocol
   - authenticates client to the server
This runs over the transport layer protocol.

3. Connection Protocol
   - multiplexes the encrypted tunnel into several logical channels
This runs over the user authentication protocol.

> The client sends a service request once a secure transport layer
   connection has been established.  A second service request is sent
   after user authentication is complete.  This allows new protocols to
   be defined and coexist with the protocols listed above.

---

# Implementation Details
This is straight from the [project document](project.pdf).

## Required cipher implementations
 - [ ] Symmetric key (AES, probably?)
 - [ ] PKC (RSA)
 - [ ] Semantically secure PKC
 - [ ] Homomorphic cipher

## Digital signature schemes
 - [ ] One based on PKC + HMAC w/ SHA1

---

# Other details

## Host keys ?

Host keys to identify who you're connecting to are recommended, but is this necessary for our
implementation? Storing host keys the first time you connect helps to avoid MITM, but this is
not an vector we worry about, correct?

Yes, I'm correct... I think. We're pretending to be an ATM connecting to a bank. Obviously, it is known
to the ATM who the bank really is. I think.

## Database?

I think it's reasonable to use a lightweight database like sqlite to manage user data.

---

# Further Reading
 - [Relevant RFCs](https://www.omnisecu.com/tcpip/important-rfc-related-with-ssh.php)


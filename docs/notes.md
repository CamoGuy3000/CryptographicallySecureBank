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

---

# Three major components:
## 1. Transport Layer Protocol
   - server authentication
   - confidentiality
   - integrity with perfect forward secrecy.
   - (optionally) compression
Typically, this is done over a TCP/IP connection, but could be any reliable data stream.

### Steps
1. Protocol Version Exchange
2. Algorithm Negotiation
3. Key Exchange
4. Service Request ( ssh-userauth OR ssh-connection )

### Binary Packet Protocol
Each packet is in the format:

| Data Type | Description |
| --- | --- |
| uint32 | packet_length |
| byte | padding_length |
| byte[n1] | payload; n1 = packet_length - padding_length - 1 |
| byte[n2] | random padding; n2 = padding_length |
| byte[m] | mac; m = mac_length | 

See [RFC4253 Section 6](https://datatracker.ietf.org/doc/html/rfc4253#section-6)
for additional details.

---

## 2. User Authentication Protocol
   - authenticates client to the server
This runs over the transport layer protocol.

### Steps
1. Initiate via `ssh-userauth`
2. Request authentication

### Authentication Requests
Requests should be formatted as follows:

| Data Type | Description |
| --- | --- |
| byte | SSH_MSG_USERAUTH_REQUEST |
| string | user name in UTF-8 |
| string | service name in US-ASCII |
| string | method name in US-ASCII |
| ... | method specific fields |

See [RFC4252 Section 5](https://datatracker.ietf.org/doc/html/rfc4252#section-5)
for additional details.

For our purposes, 'method name' should always be `publickey`.

>  Any non-authentication messages sent by the client after the request
   that resulted in SSH_MSG_USERAUTH_SUCCESS being sent MUST be passed
   to the service being run on top of this protocol.  Such messages can
   be identified by their message numbers (see [Section 6](https://datatracker.ietf.org/doc/html/rfc4252#section-6)).



---

## 3. Connection Protocol
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
 - [ ] Symmetric key (AES, probably? don't do CBC)
 - [ ] PKC (RSA)
 - [ ] Semantically secure PKC
 - [ ] Homomorphic cipher

## Digital signature schemes
 - [ ] One based on PKC + HMAC w/ SHA1 (see [RFC2104](https://datatracker.ietf.org/doc/html/rfc2104))

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


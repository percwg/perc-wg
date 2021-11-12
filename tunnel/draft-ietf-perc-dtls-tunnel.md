%%%

    #
    # DTLS Tunnel for PERC
    #
    # Generation tool chain:
    #   mmark (https://github.com/mmarkdown/mmark)
    #   xml2rfc (https://xml2rfc.tools.ietf.org/)
    #

    title = "DTLS Tunnel between a Media Distributor and Key Distributor to Facilitate Key Exchange"
    abbrev = "DTLS Tunnel for PERC"
    category = "std"
    ipr= "trust200902"
    area = "Internet"
    workgroup = ""
    keyword = ["PERC", "SRTP", "RTP", "DTLS", "DTLS-SRTP", "DTLS tunnel", "conferencing", "security"]

    [seriesInfo]
    status = "informational"
    name = "Internet-Draft"
    value = "draft-ietf-perc-dtls-tunnel-12"
    stream = "IETF"

    [pi]
    subcompact = "yes"

    [[author]]
    initials = "P."
    surname = "Jones"
    fullname = "Paul E. Jones"
    organization = "Cisco Systems, Inc."
    abbrev = "Cisco Systems"
      [author.address]
      email = "paulej@packetizer.com"
      phone = "+1 919 476 2048"
      [author.address.postal]
      street = "7025 Kit Creek Rd."
      city = "Research Triangle Park"
      region = "North Carolina"
      code = "27709"
      country = "USA"

    [[author]]
    initials = "P."
    surname = "Ellenbogen"
    fullname = "Paul M. Ellenbogen"
    organization = "Princeton University"
      [author.address]
      email = "pe5@cs.princeton.edu"
      phone = "+1 206 851 2069"

    [[author]]
    initials = "N."
    surname = "Ohlmeier"
    fullname = "Nils H. Ohlmeier"
    organization = "8x8, Inc."
      [author.address]
      email = "nils@ohlmeier.org"
      phone = "+1 408 659 6457"

    #
    # Revision History
    #   00 - Minor editorial corrections
    #        Draft re-named to be WG document
    #   01 - Changes based on discussion at IETF 98
    #          - Use tls-id and remove conf_id
    #          - Move version field to SupportedProfiles
    #          - Indicate highest supported version in UnsupportedVersion
    #          - Change the association ID to be a UUID
    #          - Insert a message length field after msg_type
    #          - Allow the Key Distributor to send EndpointDisconnect
    #        Editorial refinement
    #   02 - Changes based on agreements at IETF99
    #          - Removed editor's note about how Key Distributor gets
    #            The dtls-id from SDP
    #   03 - No change; rev to address expiration
    #   04 - Expiration refresh
    #   05 - Expiration refresh
    #   06 - Expiration refresh
    #   07 - Several changes:
    #          - Updated references
    #          - Change status to informational
    #          - Align terminology with newer UKS draft
    #   08 - Addressed WGLC review comments
    #   09 - Addressed IETF LC review comments
    #   10 - Addressed IESG review comments
    #   11 - Addressed additional IESG review comments
    #   12 - Addressed additional IESG review comments
    #

%%%

.# Abstract

This document defines a protocol for tunneling DTLS traffic in multimedia
conferences that enables a Media Distributor to facilitate key
exchange between an endpoint in a conference and the Key Distributor.
The protocol is designed to ensure that the keying material used for
hop-by-hop encryption and authentication is accessible to the Media
Distributor, while the keying material used for end-to-end encryption
and authentication is inaccessible to the Media Distributor.

{mainmatter}

# Introduction

An objective of Privacy-Enhanced RTP Conferencing (PERC) [@!RFC8871] is to
ensure that endpoints in a multimedia conference have access to the
end-to-end (E2E) and hop-by-hop (HBH) keying material used to encrypt
and authenticate Real-time Transport Protocol (RTP) [@RFC3550]
packets, while the Media Distributor has access only to the HBH
keying material for encryption and authentication.

This specification defines a tunneling protocol that enables the Media
Distributor to tunnel DTLS [@!I-D.ietf-tls-dtls13] messages between an endpoint
and a Key Distributor, thus allowing an endpoint to use DTLS-SRTP
[@!RFC5764] for establishing encryption and authentication keys with
the Key Distributor.

The tunnel established between the Media Distributor and Key
Distributor is a TLS [@!RFC8446] connection that is established before any
messages are forwarded by the Media Distributor on behalf of
endpoints.  DTLS packets received from an endpoint are encapsulated by
the Media Distributor inside this tunnel as data to be sent to the Key
Distributor.  Likewise, when the Media Distributor receives data from
the Key Distributor over the tunnel, it extracts the DTLS message
inside and forwards the DTLS message to the endpoint.  In this way,
the DTLS association for the DTLS-SRTP procedures is established
between an endpoint and the Key Distributor, with the Media
Distributor forwarding DTLS messages between the two entities via the
established tunnel to the Key Distributor and having no visibility into
the confidential information exchanged.

Following the existing DTLS-SRTP procedures, the endpoint and Key
Distributor will arrive at a selected cipher and keying material,
which are used for HBH encryption and authentication by both the
endpoint and the Media Distributor.  However, since the Media
Distributor would not have direct access to this information, the Key
Distributor explicitly shares the HBH key information with the Media
Distributor via the tunneling protocol defined in this document.
Additionally, the endpoint and Key Distributor will agree on a cipher
for E2E encryption and authentication.  The Key Distributor will
transmit keying material to the endpoint for E2E operations, but will
not share that information with the Media Distributor.

By establishing this TLS tunnel between the Media Distributor and Key
Distributor and implementing the protocol defined in this document, it
is possible for the Media Distributor to facilitate the establishment
of a secure DTLS association between an endpoint and the Key
Distributor in order for the endpoint to generate E2E and HBH keying
material.  At the same time, the Key Distributor can securely provide
the HBH keying material to the Media Distributor.

# Conventions Used In This Document

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**",
"**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**",
"**NOT RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document are
to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only
when, they appear in all capitals, as shown here.

This document uses the terms "endpoint", "Media Distributor", and
"Key Distributor" defined in [@!RFC8871].

# Tunneling Concept

A TLS connection (tunnel) is established between the Media Distributor
and the Key Distributor.  This tunnel is used to relay DTLS messages
between the endpoint and Key Distributor, as depicted in
(#fig-tunnel):

{#fig-tunnel align="center"}
~~~
                         +-------------+
                         |     Key     |
                         | Distributor |
                         +-------------+
                             # ^ ^ #
                             # | | # <-- TLS Tunnel
                             # | | #
+----------+             +-------------+             +----------+
|          |     DTLS    |             |    DTLS     |          |
| Endpoint |<------------|    Media    |------------>| Endpoint |
|          |    to Key   | Distributor |   to Key    |          |
|          | Distributor |             | Distributor |          |
+----------+             +-------------+             +----------+
~~~
Figure: TLS Tunnel to Key Distributor

The three entities involved in this communication flow are the
endpoint, the Media Distributor, and the Key Distributor.  The
behavior of each entity is described in (#tunneling-procedures).

The Key Distributor is a logical function that might be
co-resident with a key management server operated by an enterprise,
reside in one of the endpoints participating in the conference, or
elsewhere that is trusted with E2E keying material.

# Example Message Flows

This section provides an example message flow to help clarify the
procedures described later in this document.  It is necessary that the
Key Distributor and Media Distributor establish a mutually
authenticated TLS connection for the purpose of sending tunneled
messages, though the complete TLS handshake for the tunnel is not
shown in (#fig-message-flow) since there is nothing new this document
introduces with regard to those procedures.

Once the tunnel is established, it is possible for the Media
Distributor to relay the DTLS messages between the endpoint and the
Key Distributor.  (#fig-message-flow) shows a message flow wherein the
endpoint uses DTLS-SRTP to establish an association with the Key
Distributor.  In the process, the Media Distributor shares its
supported SRTP protection profile information (see [@!RFC5764]) and
the Key Distributor shares HBH keying material and selected cipher
with the Media Distributor.

{#fig-message-flow align="center"}
~~~
Endpoint              Media Distributor          Key Distributor
    |                         |                         |
    |                         |<=======================>|
    |                         |    TLS Connection Made  |
    |                         |                         |
    |                         |========================>|
    |                         | SupportedProfiles       |
    |                         |                         |
    |------------------------>|========================>|
    | DTLS handshake message  | TunneledDtls            |
    |                         |                         |
         .... may be multiple handshake messages ...
    |                         |                         |
    |<------------------------|<========================|
    | DTLS handshake message  |            TunneledDtls |
    |                         |                         |
    |                         |                         |
    |                         |<========================|
    |                         |               MediaKeys |
~~~
Figure: Sample DTLS-SRTP Exchange via the Tunnel

After the initial TLS connection has been established each of the
messages on the right-hand side of (#fig-message-flow) is a tunneling
protocol message as defined in (#tunneling-protocol).

SRTP protection profiles supported by the Media Distributor will be
sent in a `SupportedProfiles` message when the TLS tunnel is initially
established.  The Key Distributor will use that information to select
a common profile supported by both the endpoint and the Media
Distributor to ensure that HBH operations can be successfully
performed.

As DTLS messages are received from the endpoint by the Media
Distributor, they are forwarded to the Key Distributor encapsulated
inside a `TunneledDtls` message.  Likewise, as `TunneledDtls`
messages are received by the Media Distributor from the Key
Distributor, the encapsulated DTLS packet is forwarded to the
endpoint.

The Key Distributor will provide the SRTP [@RFC3711] keying material
to the Media Distributor for HBH operations via the `MediaKeys`
message.  The Media Distributor will extract this keying material from
the `MediaKeys` message when received and use it for HBH
encryption and authentication.

# Tunneling Procedures

The following sub-sections explain in detail the expected behavior of
the endpoint, the Media Distributor, and the Key Distributor.

It is important to note that the tunneling protocol described in this
document is not an extension to TLS or DTLS.  Rather, it is a protocol that
transports DTLS messages generated by an endpoint or Key Distributor as data
inside of the TLS connection established between the Media Distributor and
Key Distributor.

## Endpoint Procedures

The endpoint follows the procedures outlined for DTLS-SRTP [@!RFC5764]
in order to establish the cipher and keys used for encryption and
authentication, with the endpoint acting as the client and the Key
Distributor acting as the server.  The endpoint does not need to be
aware of the fact that DTLS messages it transmits toward the Media
Distributor are being tunneled to the Key Distributor.

The endpoint **MUST** include a unique identifier in the `tls-id`
SDP [@RFC8866] attribute in all offer and answer messages [@RFC3264]
that it generates as per [@!RFC8842]. Further, the
endpoint **MUST** include this same unique identifier in the
`external_session_id` extension [@!RFC8844] in the
`ClientHello` message when establishing a DTLS association.

When receiving a `external_session_id` value from the Key Distributor, the
client **MUST** check to ensure that value matches the `tls-id` value
received in SDP.  If the values do not match, the endpoint **MUST**
consider any received keying material to be invalid and terminate the
DTLS association.

## Tunnel Establishment Procedures

Either the Media Distributor or Key Distributor initiates the
establishment of a TLS tunnel.  Which entity acts as the TLS client
when establishing the tunnel and what event triggers the establishment
of the tunnel are outside the scope of this document.  Further, how
the trust relationships are established between the Key Distributor
and Media Distributor are also outside the scope of this document.

A tunnel **MUST** be a mutually authenticated TLS connection.

The Media Distributor or Key Distributor **MUST** establish a tunnel
prior to forwarding tunneled DTLS messages.  Given the time-sensitive
nature of DTLS-SRTP procedures, a tunnel **SHOULD** be established
prior to the Media Distributor receiving a DTLS message from an
endpoint.

A single tunnel **MAY** be used to relay DTLS messages between any
number of endpoints and the Key Distributor.

A Media Distributor **MAY** have more than one tunnel established
between itself and one or more Key Distributors.  When multiple
tunnels are established, which tunnel or tunnels to use to send
messages for a given conference is outside the scope of this document.

## Media Distributor Tunneling Procedures

The first message transmitted over the tunnel is the
`SupportedProfiles` (see (#tunneling-protocol)).  This message informs
the Key Distributor about which DTLS-SRTP profiles the Media
Distributor supports.  This message **MUST** be sent each time a new
tunnel connection is established or, in the case of connection loss,
when a connection is re-established.  The Media Distributor **MUST**
support the same list of protection profiles for the duration of any
endpoint-initiated DTLS association and tunnel connection.

The Media Distributor **MUST** assign a unique association identifier
for each endpoint-initiated DTLS association and include it in all
messages forwarded to the Key Distributor.  The Key Distributor will
subsequently include this identifier in all messages it sends so that
the Media Distributor can map messages received via a tunnel and
forward those messages to the correct endpoint.  The association
identifier **MUST** be randomly assigned UUID value as described
Section 4.4 of [@!RFC4122].

When a DTLS message is received by the Media Distributor from an
endpoint, it forwards the UDP payload portion of that message to the
Key Distributor encapsulated in a `TuneledDtls` message.
The Media Distributor is not required to forward all messages received
from an endpoint for a given DTLS association through the same tunnel
if more than one tunnel has been established between it and a Key
Distributor.

When a `MediaKeys` message is received, the Media Distributor **MUST**
extract the cipher and keying material conveyed in order to
subsequently perform HBH encryption and authentication operations for
RTP and RTCP packets sent between it and an endpoint.  Since the HBH
keying material will be different for each endpoint, the Media
Distributor uses the association identifier included by the Key
Distributor to ensure that the HBH keying material is used with the
correct endpoint.

The Media Distributor **MUST** forward all DTLS messages received from
either the endpoint or the Key Distributor (via the `TunneledDtls`
message) to ensure proper communication between those two entities.

When the Media Distributor detects an endpoint has disconnected or
when it receives conference control messages indicating the endpoint
is to be disconnected, the Media Distributors **MUST** send an
`EndpointDisconnect` message with the association identifier assigned
to the endpoint to the Key Distributor.  The Media Distributor
**SHOULD** take a loss of all RTP and RTCP packets as an indicator
that the endpoint has disconnected.  The particulars of how RTP and
RTCP are to be used to detect an endpoint disconnect, such as timeout
period, is not specified.  The Media Distributor **MAY** use
additional indicators to determine when an endpoint has disconnected.

## Key Distributor Tunneling Procedures

Each TLS tunnel established between the Media Distributor and the
Key Distributor **MUST** be mutually authenticated.

When the Media Distributor relays a DTLS message from an endpoint, the
Media Distributor will include an association identifier that is
unique per endpoint-originated DTLS association.  The association
identifier remains constant for the life of the DTLS association.  The
Key Distributor identifies each distinct endpoint-originated DTLS
association by the association identifier.

When processing an incoming endpoint association, the Key Distributor
**MUST** extract the `external_session_id` value transmitted in the
`ClientHello` message and match that against the `tls-id` value the endpoint
transmitted via SDP.  If the values in SDP and the `ClientHello` do not match,
the DTLS association **MUST** be rejected.

The process through which the `tls-id` in SDP is conveyed to
the Key Distributor is outside the scope of this document.

The Key Distributor **MUST** match the fingerprint of the certificate and
`external_session_id` [@!RFC8844] received from endpoint via DTLS with the
expected fingerprint [@!RFC8122] and `tls-id` [@!RFC8842] values received via
SDP.  It is through this process that the Key Distributor can be sure to
deliver the correct conference key to the endpoint.

The Key Distributor MUST report its own unique identifier in the
`external_session_id` extension.  This extension is sent in the
`EncryptedExtensions` message in DTLS 1.3, and the `ServerHello` in
previous DTLS versions.  This value **MUST** also be conveyed back to
the client via SDP as a `tls-id` attribute.

The Key Distributor **MUST** encapsulate any DTLS message it sends to
an endpoint inside a `TunneledDtls` message (see
(#tunneling-protocol)).  The Key Distributor is not required to transmit
all messages for a given DTLS association through the same tunnel if more
than one tunnel has been established between it and the Media Distributor.

The Key Distributor **MUST** use the same association identifier in
messages sent to an endpoint as was received in messages from that
endpoint.  This ensures the Media Distributor can forward the messages
to the correct endpoint.

The Key Distributor extracts tunneled DTLS messages from an endpoint
and acts on those messages as if that endpoint had established the
DTLS association directly with the Key Distributor.  The Key
Distributor is acting as the DTLS server and the endpoint is acting as
the DTLS client.  The handling of the messages and certificates is
exactly the same as normal DTLS-SRTP procedures between endpoints.

The Key Distributor **MUST** send a `MediaKeys` message to the Media
Distributor immediately after the DTLS handshake completes.  The `MediaKeys`
message includes the selected cipher (i.e. protection profile), MKI
[@!RFC3711] value (if any), HBH SRTP master keys, and SRTP master salt
values.  The Key Distributor **MUST** use the same association
identifier in the `MediaKeys` message as is used in the `TunneledDtls`
messages for the given endpoint.

There are presently two SRTP protection profiles defined for PERC,
namely `DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM` and
`DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM` [@!RFC8723].  As [@!RFC8723]
explains in Section 5.2, the Media Distributor is only given the SRTP
master key for HBH operations.  As such, the SRTP master key
length advertised in the `MediaKeys` message is half the length of the key
normally associated with selected "double" protection profile.

The Key Distributor uses the certificate fingerprint of the endpoint
along with the unique identifier received in the `external_session_id`
extension to determine which conference a given DTLS association is
associated.

The Key Distributor **MUST** select a cipher that is supported itself,
the endpoint, and the Media Distributor to ensure proper HBH
operations.

When the DTLS association between the endpoint and the Key Distributor
is terminated, regardless of which entity initiated the termination,
the Key Distributor **MUST** send an `EndpointDisconnect` message
with the association identifier assigned to the endpoint to the Media
Distributor.

## Versioning Considerations

Since the Media Distributor sends the first message over the tunnel,
it effectively establishes the version of the protocol to be used.  If
that version is not supported by the Key Distributor, the Key
Distributor **MUST** transmit an `UnsupportedVersion` message containing
the highest version number supported, and close the TLS connection.

The Media Distributor **MUST** take note of the version received in an
`UnsupportedVersion` message and use that version when attempting to
re-establish a failed tunnel connection.  Note that it is not
necessary for the Media Distributor to understand the newer version of
the protocol to understand that the first message received is
`UnsupportedVersion`.  The Media Distributor can determine from the
first four octets received what the version number is and that the
message is `UnsupportedVersion`.  The rest of the data received, if
any, would be discarded and the connection closed (if not already
closed).

# Tunneling Protocol

Tunneled messages are transported via the TLS tunnel as application
data between the Media Distributor and the Key Distributor.  Tunnel
messages are specified using the format described in [@!RFC8446]
section 3.  As in [@!RFC8446], all values are stored in network byte
(big endian) order; the uint32 represented by the hex bytes 01 02 03
04 is equivalent to the decimal value 16909060.

This protocol defines several different messages, each of which
contains the following information:

* Message type identifier
* Message body length
* The message body

Each of the tunnel messages is a `TunnelMessage` structure with the
message type indicating the actual content of the message body.

## TunnelMessage Structure

The `TunnelMessage` defines the structure of all messages sent via the tunnel
protocol.  That structure includes a field called `msg_type` that identifies the
specific type of message contained within `TunnelMessage`.

{align="left"}
```
enum {
    supported_profiles(1),
    unsupported_version(2),
    media_keys(3),
    tunneled_dtls(4),
    endpoint_disconnect(5),
    (255)
} MsgType;

opaque uuid[16];

struct {
    MsgType msg_type;
    uint16 length;
    select (MsgType) {
        case supported_profiles:  SupportedProfiles;
        case unsupported_version: UnsupportedVersion;
        case media_keys:          MediaKeys;
        case tunneled_dtls:       TunneledDtls;
        case endpoint_disconnect: EndpointDisconnect;
  } body;
} TunnelMessage;
```

The elements of `TunnelMessage` include:

* `msg_type`: the type of message contained within the structure `body`.

* `length`: the length in octets of the following `body` of the message.

* `body`: the actual message being conveyed within this `TunnelMessage` structure.

## SupportedProfiles Message

The `SupportedProfiles` message is defined as:

{align="left"}
```
uint8 SRTPProtectionProfile[2]; /* from RFC5764 */

struct {
    uint8 version;
    SRTPProtectionProfile protection_profiles<2..2^16-1>;
} SupportedProfiles;
```

This message contains this single element:

* `version`: This document specifies version 0x00.

* `protection_profiles`: The list of two-octet SRTP protection profile
  values as per [@!RFC5764] supported by the Media Distributor.

## UnsupportedVersion Message

The `UnsupportedVersion` message is defined as follows:

{align="left"}
```
struct {
    uint8 highest_version;
} UnsupportedVersion;
```

The elements of `UnsupportedVersion` include:

* `highest_version`: indicates the highest version of the protocol supported
by the Key Distributor.

## MediaKeys Message

The `MediaKeys` message is defined as:

{align="left"}
```
struct {
    uuid association_id;
    SRTPProtectionProfile protection_profile;
    opaque mki<0..255>;
    opaque client_write_SRTP_master_key<1..255>;
    opaque server_write_SRTP_master_key<1..255>;
    opaque client_write_SRTP_master_salt<1..255>;
    opaque server_write_SRTP_master_salt<1..255>;
} MediaKeys;
```

The fields are described as follows:

* `association_id`: A value that identifies a distinct DTLS association
  between an endpoint and the Key Distributor.

* `protection_profiles`: The value of the two-octet SRTP protection
  profile value as per [@!RFC5764] used for this DTLS association.

* `mki`: Master key identifier [@!RFC3711].  A zero-length field indicates that
  no MKI value is present.

* `client_write_SRTP_master_key`: The value of the SRTP master key used
  by the client (endpoint).

* `server_write_SRTP_master_key`: The value of the SRTP master key used
  by the server (Media Distributor).

* `client_write_SRTP_master_salt`: The value of the SRTP master salt
  used by the client (endpoint).

* `server_write_SRTP_master_salt`: The value of the SRTP master salt
  used by the server (Media Distributor).

## TunneledDtls Message

The `TunneledDtls` message is defined as:

{align="left"}
```
struct {
    uuid association_id;
    opaque dtls_message<1..2^16-1>;
} TunneledDtls;
```

The fields are described as follows:

* `association_id`: A value that identifies a distinct DTLS association
  between an endpoint and the Key Distributor.

* `dtls_message`: the content of the DTLS message received by the
  endpoint or to be sent to the endpoint.  This includes one or more complete
  DTLS records.

## EndpointDisconnect Message

The `EndpointDisconnect` message is defined as:

{align="left"}
```
struct {
    uuid association_id;
} EndpointDisconnect;
```

The fields are described as follows:

* `association_id`: An value that identifies a distinct DTLS association
  between an endpoint and the Key Distributor.

# Example Binary Encoding

The `TunnelMessage` is encoded in binary following the procedures
specified in [@!RFC8446].  This section provides an example of what
the bits on the wire would look like for the `SupportedProfiles`
message that advertises support for both
`DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM` and
`DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM` [@!RFC8723].

{align="left"}
```
TunnelMessage:
         message_type: 0x01
               length: 0x0007
    SupportedProfiles:
                   version:  0x00
       protection_profiles:  0x0004 (length)
                             0x0009000A (value)
```

Thus, the encoding on the wire presented here in network bytes order
would be this stream of octets:

{align="left"}
```
0x0100070000040009000A
```

# IANA Considerations

This document establishes a new registry to contain message type
values used in the DTLS Tunnel protocol.  These message type values are a
single octet in length.  This document defines the values shown in
(#message_types) below, leaving the balance of possible values reserved
for future specifications:

MsgType | Description
:------:|:----------------------------------------
0x01    | Supported SRTP Protection Profiles
0x02    | Unsupported Version
0x03    | Media Keys
0x04    | Tunneled DTLS
0x05    | Endpoint Disconnect
Table: Message Type Values for the DTLS Tunnel Protocol {#message_types}

The value 0x00 is reserved and all values in the range 0x06 to 0xFF are
available for allocation.  The procedures for updating this table are those
defined as "IETF Review" in section 4.8 of [@RFC8126].

The name for this registry is "Datagram Transport Layer Security
(DTLS) Tunnel Protocol Message Types for Privacy Enhanced Conferencing".

# Security Considerations

Since the procedures in this document relies on TLS [@!RFC8446] for transport
security, the security considerations for TLS should be reviewed when
implementing the protocol defined in this document.

While the tunneling protocol defined in this document does not use
DTLS-SRTP [@!RFC5764] directly, it does convey and negotiate some of the
same information (e.g., protection profile data).  As such, a review of the
security considerations found in that document may be useful.

This document describes a means of securely exchanging keying material and
cryptographic transforms for both E2E and HBH encryption and authentication of
media between an endpoint and a Key Distributor via a Media Distributor.
Additionally, the procedures result in delivering HBH information to the
intermediary Media Distributor.  The Key Distributor and endpoint are the only
two entities with access to both the E2E and HBH keys, while the Media
Distributor has access to only HBH information.  Section 8.2 of [@!RFC8871]
enumerates various attacks against which one must guard when implementing a
Media Distributor and are important to note.

A requirement in this document is that a TLS connection between the Media
Distributor and the Key Distributor be mutually authenticated.  The reason
for this requirement is to ensure that only an authorized Media Distributor
receives the HBH keying material.  If an unauthorized Media Distributor gains
access to the HBH keying material, it can easily cause service degradation or
denial by transmitting HBH-valid packets that ultimately fail E2E
authentication or replay protection checks (see Section 3.3.2 of [@!RFC3711]).
Even if service does not appear degraded in any way, transmitting and
processing bogus packets are a waste of both computational and network
resources.

The procedures defined in this document assume that the Media Distributor
will properly convey DTLS messages between the endpoint and Key Distributor.
Should it fail in that responsibility by forwarding DTLS messages from
endpoint A advertised as being from endpoint B, this will result in
a failure at the DTLS layer those DTLS sessions.  This could be an additional
attack vector that Key Distributor implementations should consider.

While E2E keying material passes through the Media Distributor via the protocol
defined in this document, the Media Distributor has no means of gaining access
to that information and therefore cannot affect the E2E media processing
function in the endpoint except to present it with invalid or replayed data.
That said, any entity along the path that interferes with the DTLS exchange
between the endpoint and the Key Distributor, including a malicious Media
Distributor that is not properly authorized, could prevent an endpoint from
properly communicating with the Key Distributor and, therefore, prevent
successful conference participation.

It is worth noting that a compromised Media Distributor can convey
information to an adversary such as participant IP addresses, negotiates
protection profiles, or other metadata.  While [@!RFC8871] explains that
a malicious or compromised Media Distributor can disrupt communications,
an additional attack vector introduced by this protocol is the potential
disruption of DTLS negotiation or premature removal of a participant from
a conference by sending an `EndpointDisconnect` disconnect message to the
Key Distributor.

The Key Distributor should be aware of the possibility that a malicious
Media Distributor might transmit an `EndpointDisconnect` message to the Key
Distributor  when the endpoint is, in fact, still connected.

While the Security Considerations section of [@!RFC8871] describes various
attacks one needs to consider with respect to the Key Distributor and
denial-of-service, use of this protocol introduces another possible
attack vector.  Consider the case where a malicious endpoint sends unsolicited
DTLS-SRTP messages to a Media Distributor.  The Media Distributor will normally
forward those messages to the Key Distributor and, if found invalid, such
messages only serve to consume resources on both the Media Distributor and
Key Distributor.

# Acknowledgments

The author would like to thank David Benham and Cullen Jennings for
reviewing this document and providing constructive comments.

{backmatter}

%%%

    #
    # DTLS Tunnel for PERC
    #
    # Generation tool chain:
    #   mmark (https://github.com/miekg/mmark)
    #   xml2rfc (http://xml2rfc.ietf.org/)
    #

    Title = "DTLS Tunnel between a Media Distributor and Key Distributor to Facilitate Key Exchange"
    abbrev = "DTLS Tunnel for PERC"
    category = "std"
    docName = "draft-jones-perc-dtls-tunnel-04"
    ipr= "trust200902"
    area = "Internet"
    keyword = ["PERC", "SRTP", "RTP", "DTLS", "DTLS-SRTP", "DTLS tunnel", "conferencing", "security"]

    [pi]
    subcompact = "yes"

    [[author]]
    initials = "P."
    surname = "Jones"
    fullname = "Paul E. Jones"
    organization = "Cisco Systems"
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

    #
    # Revision History
    #   00 - Initial draft.
    #   01 - Removed TLS-style syntax.
    #        MDD always sends its list of protection profiles.
    #        Removed EKT stuff; not relevant to the tunnel protocol.
    #        Added a visual representation of the tunneling protocol.
    #        Changed the message names to be simpler.
    #        Simplified message flows, because they were overly complex.
    #        Simplified the text overall.
    #        Removed the "conference identifier".
    #        Much editorial cleanup.
    #   02 - The protection profile was inadvertently left out of the Key
    #        Info message.
    #   03 - Modified the protocol to reduce the message sizes.
    #        Added text related to PMTU size considerations.
    #        Added instructions for an IANA registry.
    #        Changed KMF and MDD to Key Distributor and Media Distributor.
    #   04 - Minor title change
    #

%%%

.# Abstract

This document defines a TLS tunneling protocol for use in multimedia
conferences that enables a Media Distributor to facilitate
key exchange between an endpoint in a conference and the Key Distributor.
The protocol is designed to ensure that the keying material used for
hop-by-hop encryption and authentication is accessible to the media
distributor, while the keying material used for end-to-end encryption and
authentication is inaccessible to the media distributor.

{mainmatter}

# Introduction

An objective of the work in the Privacy-Enhanced RTP Conferencing (PERC)
working group is to ensure that endpoints in a multimedia conference
have access to the end-to-end (E2E) and hop-by-hop (HBH) keying material
used to encrypt and authenticate Real-time Transport Protocol (RTP)
[@!RFC3550] packets, while the Media Distributor has access only to the
hop-by-hop (HBH) keying material for encryption and authentication.

This specification defines a tunneling protocol that enables the media
distributor to tunnel DTLS [@!RFC6347] messages between an endpoint and
the key distributor, thus allowing an endpoint to use DTLS-SRTP
[@!RFC5764] for establishing encryption and authentication keys with the
key distributor.

The tunnel established between the media distributor and key distributor
is a TLS association that is established before any messages are
forwarded by the media distributor on behalf of the endpoint.  DTLS packets
received from the endpoint are encapsulated by the media distributor inside
this tunnel as data to be sent to the key distributor.  Likewise, when the
media distributor receives data from the key distributor over the tunnel,
it extracts the DTLS message inside and forwards that to the endpoint.
In this way, the DTLS association for the DTLS-SRTP procedures is
established between the endpoint and the key distributor, with the media
distributor simply forwarding packets between the two entities and having
no visibility into the confidential information exchanged.

Following the existing DTLS-SRTP procedures, the endpoint and key
distributor will arrive at a selected cipher and keying material, which
are used for HBH encryption and authentication by both the endpoint and
the media distributor.  However, since the media distributor would not
have direct access to this information, the key distributor explicitly
shares the HBH key information with the media distributor via the
tunneling protocol defined in this document.  Additionally, the
endpoint and key distributor will agree on a cipher for E2E encryption
and authentication.  The key distributor will transmit keying material
to the endpoint for E2E operations, but will not share that information
with the media distributor.

By establishing this TLS tunnel between the media distributor and key
distributor and implementing the protocol defined in this document, it
is possible for the media distributor to facilitate the establishment of
a secure DTLS association between an endpoint and the key distributor in
order for the endpoint to receive E2E and HBH keying material.  At the
same time, the key distributor can securely provide the HBH keying
material to the media distributor.

# Conventions Used In This Document

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**",
"**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**",
"**MAY**", and "**OPTIONAL**" in this document are to be interpreted as
described in [@!RFC2119] when they appear in ALL CAPS.  These words may
also appear in this document in lower case as plain English words,
absent their normative meanings.

# Tunneling Concept

A TLS association (tunnel) is established between the media distributor
and the key distributor.  This tunnel is used to relay DTLS messages
between the endpoint and key distributor, as depicted in (#fig-tunnel):

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

The three entities involved in this communication flow are the endpoint,
the media distributor, and the key distributor.  The behavior of each
entity is described in (#tunneling-procedures).

The key distributor is a logical function that might might be co-resident
with a key management server operated by an enterprise, reside in one of
the endpoints participating in the conference, or elsewhere that is
trusted with E2E keying material.  This document does not preclude any
location, only requiring that the key distributor not allow the media
distributor to gain access to the E2E keying material by following the
procedures defined in this document.

# Example Message Flows

This section provides an example message flow to help clarify the
procedures described later in this document. It is necessary
that the key distributor and media distributor establish a mutually
authenticated TLS association for the purpose of sending tunneled
messages, though the complete TLS handshake for the tunnel is not
shown in (#fig-message-flow) since there is nothing new this document
introduces with regard to those procedures.

Once the tunnel is established, it is possible for the media distributor
to relay the DTLS messages between the endpoint and the key distributor.
(#fig-message-flow) shows a message flow wherein the endpoint uses
DTLS-SRTP to establish an association with the key distributor.  In the
process, the media distributor shares its supported SRTP protection
profile information (see [@!RFC5764]) and the key distributor shares HBH
keying material and selected cipher with the media distributor.  The
message used to tunnel the DTLS messages is named "Tunnel" and can
include Profiles, Key Info data, or endpoint disconnection notifications.

{#fig-message-flow align="center"}
~~~
Endpoint              media distributor          key distributor
    |                         |                         |
    |                         |<========================|
    |                         |   TLS Association Made  |
    |                         |                         |
    |------------------------>|========================>|
    | DTLS handshake message  | Tunnel + Profiles       |
    |                         |                         |
    |<------------------------|<========================|
    | DTLS handshake message  |                  Tunnel |
    |                         |                         |
         .... may be multiple handshake messages ...
    |------------------------>|========================>|
    | DTLS handshake message  | Tunnel + Profiles       |
    |                         |                         |
    |<------------------------|<========================|
    |  DTLS handshake message |       Tunnel + Key Info |
    |    (including Finished) |                         |
    |                         |                         |
~~~
Figure: Sample DTLS-SRTP Exchange via the Tunnel

Each of these tunneled messages on the right-hand side of
(#fig-message-flow) is a message of type "Tunnel" (see
(#tunneling-protocol)).  Each message contains the following
information:

* Protocol version
* Message type

SRTP protection profiles supported by the media distributor will be
sent in a supported profiles message.  The key distributor will select
a common profile supported by both the endpoint and the media
distributor to ensure that hop-by-hop operations can be successfully
performed.

Further, the key distributor will provide the SRTP [@!RFC3711] keying
material to the media distributor for HBH operations at the time it
sends a DTLS Finished message to the endpoint via the tunnel.  The
media distributor would extract this Key Info when received and use
it for hop-by-hop encryption and authentication.  The delivery of the
keying information along with the completion of the DTLS handshake
ensures the delivery of the keying information is fate shared with
completion of the DTLS handshake.  This guarantees that the media
distributor will have the HBH keying information before it receives
any media that is encrypted or authenticated with that key.

# Tunneling Procedures

The following sub-sections explain in detail the expected behavior of
the endpoint, the media distributor, and the key distributor.

It is important to note that the tunneling protocol described in this
document is not an extension to TLS [@!RFC5246] or DTLS [@!RFC6347].
Rather, it is a protocol that transports DTLS messages generated by an
endpoint or key distributor as data inside of the TLS association
established between the media distributor and key distributor.

## Endpoint Procedures

The endpoint follows the procedures outlined for DTLS-SRTP [@!RFC5764]
in order to establish the cipher and keys used for encryption and
authentication, with the endpoint acting as the client and the
key distributor acting as the server.  The endpoint does not need
to be aware of the fact that DTLS messages it transmits toward the
media distributor are being tunneled to the key distributor.

## Tunnel Establishment Procedures

Either the media distributor or key distributor initiates the
establishment of a TLS tunnel.  Which entity acts as the TLS client
when establishing the tunnel and what event triggers the establishment
of the tunnel are outside the scope of this document.  Further, how the
trust relationships are established between the key distributor and
media distributor are also outside the scope of this document.

A tunnel **MUST** be a mutually authenticated TLS association.  It is
used to relay DTLS messages between any number of endpoints and the key
distributor.

The media distributor or key distributor **MUST** establish a tunnel in
advance of, or no later than the point, when an endpoint attempts to
establish a DTLS association with the key distributor.

A media distributor **MAY** have more than one tunnel established
between itself and one or more key distributors.  When multiple tunnels
are established, which tunnel or tunnels to use to send messages for a
given conference is outside the scope of this document.

## Media Distributor Tunneling Procedures

The media distributor **MUST** forward all messages received from an
endpoint for a given DTLS association through the same tunnel if more
than one tunnel has been established between it and a key distributor.
A media distributor is not precluded from establishing more than one
tunnel to a given key distributor.

>Editor's Note: Do we want to have the above requirement or would we
prefer to allow the media distributor to send messages over more
than one tunnel to more than one key distributor?  The latter would
provide for higher availability, but at the cost of key distributor
complexity.

The media distributor **MUST** assign a unique "association identifier"
for each endpoint-initiated DTLS association and include it in all
messages forwarded to the key distributor.  The key distributor will
subsequently include in this identifier in all messages it sends so
that the media distributor can map messages received via a tunnel and
forward those messages to the correct endpoint.  The association
identifier **SHOULD** be randomly assigned and values not re-used for a
period of time sufficient to ensure no late-arriving messages might be
delivered to the wrong endpoint.  It is **RECOMMENDED** that the
association identifier not be re-used for at least 24 hours.

>Editor's Note: do we want to recommend a time and is 24 hours sufficient?

The tunnel protocol enables the key distributor to separately provide
HBH keying material to the media distributor for each of the individual
endpoint DTLS associations, though the media distributor cannot decrypt
messages between the key distributor and endpoints.

When a DTLS message is received by the media distributor from an
endpoint, it forwards the UDP payload portion of that message to the key
distributor encapsulated in a Tunnel + Profiles message (see
(#tunneling-protocol)).  The Tunnel + Profiles message allows the media
distributor to signal which SRTP protection profiles it supports for HBH
operations.

The media distributor **MUST** support the same list of protection
profiles for the life of a given endpoint's DTLS association, which is
represented by the association identifier.

When a message from the key distributor includes "Key Info," the media
distributor **MUST** extract the cipher and keying material conveyed in
order to subsequently perform HBH encryption and authentication
operations for RTP and RTCP packets sent between it and an endpoint.
Since the HBH keying material will be different for each endpoint, the
media distributor uses the association identifier included by the key
distributor to ensure that the HBH keying material is used with the
correct endpoint.

The media distributor **MUST** forward all messages received from
either the endpoint or the key distributor to ensure proper
communication between those two entities.

When the media distributor detects an endpoint has disconnected, the
media distributors **SHOULD** send a Endpoint Disconnect message with
the association identifier assigned to the endpoint. The media
distributor **SHOULD** use RTCP behavior to detect disconnected
endpoints. The particulars of how RTCP is to be used to detect endpoint , such as timeout period, is not specified.

## Key Distributor Tunneling Procedures

When the media distributor relays a DTLS message from an endpoint, the
media distributor will include an association identifier that is unique
per endpoint-originated DTLS association.  The association identifier
remains constant for the life of the DTLS association.  The key
distributor identifies each distinct endpoint-originated DTLS
association by the association identifier.

The key distributor **MUST** encapsulate the DTLS message inside a
Tunnel message (see (#tunneling-protocol)) when sending a message to an
endpoint.

The key distributor **MUST** use the same association identifier in
messages sent to an endpoint as was received in messages from that
endpoint.  This ensures the media distributor can forward the messages
to the correct endpoint.

The key distributor extracts tunneled DTLS messages from an endpoint and
acts on those messages as if that endpoint had established the DTLS
association directly with the key distributor.  The key distributor is
acting as the server and the endpoint is acting as the client.  The
handling of the messages and certificates is exactly the same as normal
DTLS-SRTP procedures between endpoints.

The key distributor **MUST** send a DTLS Finished message to the endpoint
at the point the DTLS handshake completes using the Tunnel + Key Info
message.  The Key Info includes the selected cipher (i.e. protection
profile), MKI [@!RFC3711] value (if any), SRTP master keys, and SRTP
master salt values.

The key distributor **MUST** select a cipher that is supported by both the
endpoint and the media distributor to ensure proper HBH operations.

# Tunneling Protocol

Tunneled messages are transported via the TLS tunnel as application
data between the media distributor and the key distributor. Tunnel
messages are specified using the format described in [@!rfc5246]
section 4. As in [@!rfc5246], all values are stored in network byte
(big-endian) order; the uint32 represented by the hex bytes 01 02 03 04 is equivalent to the decimal value 16909060.

## Tunnel Message Format

`TunnelMessage` is the only message sent, and there are four message types, defined by the `MsgType` enum.

```
enum {
  invalid(0),
  supported_profiles(1),
  media_keys(2),
  tunneled_dtls(3),
  endpoint_disconnect(4),
  (255)
} MsgType;

struct {
  uint8 version;
  MsgType msg_type;
  select (MsgType) {
    case supported_profiles: SupportedProfiles;
    case media_keys:         MediaKeys;
    case tunneled_dtls:      TunneledDtls;
	case endpoint_disconnect: EndpointDisconnect;
  } body;
} TunnelMessage;
```

version indicates the version of this protocol.
>Editor's Note: Do we start with version 0 or version 1?

MsgType is represented by a single octet value.

The four possible message types are defined as following.
```
uint8 SRTPProtectionProfile[2]; // from RFC5764

struct {
  SRTPProtectionProfile suites<0..2^16-1>;
} SupportedProfiles;

struct {
  uint32 associationID;
  SRTPProtectionProfile profile;
  opaque mki<0..255>;
  opaque clientWriteKey<0..255>;
  opaque serverWriteKey<0..255>;
  opaque clientWriteSalt<0..255>;
  opaque serverWriteSalt<0..255>;
} MediaKeys;

struct {
  uint32 associationID;
  opaque dtlsMessage<0..2^16-1>;
} TunneledDtls;

struct {
  uint32 associationID;
} EndpointDisconnect;
```
The fields are described as follows:
*  associationID: The value of the association identifier used to uniquely identify each endpoint in a conference
* SRTPProtectionProfile: The value of the two-octet SRTP protection profile value as per [@!RFC5764].
* mki: Master key identifier [@!RFC3711].
* clientWriteKey: The value of the SRTP master key used by the client (endpoint).
* serverWriteKey: The value of the SRTP master key used by the server (media distributor).
* clientWriteSalt: The value of the SRTP master salt used by the client (endpoint).
* serverWriteSalt: The value of the SRTP master salt used by the server (media distributor).

# To-Do List

Given what is presently defined in this draft, it is not possible for
the key distributor to determine which conference to which a given
DTLS-SRTP association belongs, making it impossible for the key
distributor to ensure it is providing the endpoint with the correct
conference key.  Observing the client certificate might be insufficient
if the same client is participating in more than one conference in
parallel.  The media distributor and key distributor may need to
coordinate or exchange a "conference identifier" common to the endpoints
a media distributor is bridging together.  Alternatively, information the
key distributor needs to know about conference-to-endpoint correlations might
be satisfied by getting info directly from the endpoints, or some trusted
entity on their behalf, via some other means.  Need to revisit this
design choice in the context of all the alternatives.

# IANA Considerations

This document establishes a new registry to contain "data type" values
used in the DTLS Tunnel protocol.  These data type values are a single
octet in length.  This document defines the values shown in (#data_types)
below, leaving the balance of possible values reserved for future
specifications:

Data Type | Description
----------|:----------------------------------------
0x01      | Supported SRTP Protection Profiles
0x02      | Key Information
Table: Data Type Values for the DTLS Tunnel Protocol {#data_types}

The name for this registry is "Datagram Transport Layer Security
(DTLS) Tunnel Protocol Data Types for Privacy Enhanced Conferencing."

# Security Considerations

TODO - Much more needed.

The encapsulated data is protected by the DTLS session from the endpoint
to key distributor and the media distributor is merely an on path entity.
This does not introduce any additional security concerns beyond a normal
DTLS-SRTP session.

The HBH keying material is protected by the mutual authenticated DTLS
session between the media distributor and key distributor.  The key
distributor MUST ensure that it only forms associations with authorized
media distributors or it could hand HBH keying information to untrusted
parties.

The supported profile information send from the media distributor to the
key distributor is not particularly sensitive as it only provides the
crypt algorithms supported by the media distributor but it is still
protected by the DTLS session from the media distributor to key
distributor.

# Acknowledgments

The author would like to thank David Benham and Cullen Jennings for
reviewing this document and providing constructive comments.

{backmatter}

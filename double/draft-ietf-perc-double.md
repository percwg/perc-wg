%%%

    #
    # SRTP Double Encryption Procedures
    #
    # Generation tool chain:
    #   mmark (https://github.com/miekg/mmark)
    #   xml2rfc (http://xml2rfc.ietf.org/)
    #

    Title = "SRTP Double Encryption Procedures"
    abbrev = "Double SRTP"
    category = "std"
    docName = "draft-ietf-perc-double-05"
    ipr= "trust200902"
    area = "Internet"
    keyword = ["PERC", "SRTP", "RTP", "conferencing", "encryption"]

    [pi]
    symrefs = "yes"
    sortrefs = "yes"
    compact = "yes"

    [[author]]
    initials = "C."
    surname = "Jennings"
    fullname = "Cullen Jennings"
    organization = "Cisco Systems"
      [author.address]
      email = "fluffy@iii.ca"

    [[author]]
    initials = "P."
    surname = "Jones"
    fullname = "Paul E. Jones"
    organization = "Cisco Systems"
      [author.address]
      email = "paulej@packetizer.com"

    [[author]]
    initials = "A.B."
    surname = "Roach"
    fullname = "Adam Roach"
    organization = "Mozilla"
      [author.address]
      email = "adam@nostrum.com"

%%%

.# Abstract

In some conferencing scenarios, it is desirable for an intermediary to
be able to manipulate some RTP parameters, while still providing
strong end-to-end security guarantees.  This document defines SRTP
procedures that use two separate but related cryptographic operations to
provide hop-by-hop and end-to-end security guarantees.  Both the
end-to-end and hop-by-hop cryptographic algorithms can utilize an
authenticated encryption with associated data scheme or take advantage
of future SRTP transforms with different properties.


{mainmatter}

# Introduction

Cloud conferencing systems that are based on switched conferencing
have a central Media Distributor device that receives media from
endpoints and distributes it to other endpoints, but does not need to
interpret or change the media content.  For these systems, it is
desirable to have one cryptographic key from the sending endpoint
to the receiving endpoint that can encrypt and authenticate the media
end-to-end while still allowing certain RTP header information to be
changed by the Media Distributor.  At the same time, a separate
cryptographic key provides integrity and optional confidentiality
for the media flowing between the Media Distributor and the endpoints.
See the framework document that describes this concept in more detail
in more detail in [@I-D.ietf-perc-private-media-framework].

This specification defines an SRTP transform that uses the AES-GCM
algorithm [@!RFC7714] to provide encryption and integrity for an RTP
packet for the end-to-end cryptographic key as well as a hop-by-hop
cryptographic encryption and integrity between the endpoint and the
Media Distributor.  The Media Distributor decrypts and checks
integrity of the hop-by-hop security.  The Media Distributor MAY
change some of the RTP header information that would impact the
end-to-end integrity.  The original value of any RTP header field that
is changed is included in a new RTP header extension called the
Original Header Block.  The new RTP packet is encrypted with the
hop-by-hop cryptographic algorithm before it is sent.  The receiving
endpoint decrypts and checks integrity using the hop-by-hop
cryptographic algorithm and then replaces any parameters the Media
Distributor changed using the information in the Original Header Block
before decrypting and checking the end-to-end integrity.

One can think of the double as a normal SRTP transform for encrypting
the RTP in a way where things that only know half of the key, can
decrypt and modify part of the RTP packet but not other parts of if
including the media payload.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [@!RFC2119].

Terms used throughout this document include:

* Media Distributor: media distribution device that routes media from
  one endpoint to other endpoints

* end-to-end: meaning the link from one endpoint through one or
  more Media Distributors to the endpoint at the other end.

* hop-by-hop: meaning the link from the endpoint to or from the
  Media Distributor.

* OHB: Original Header Block is an octet string that contains
  the original values from the RTP header that might have been changed
  by a Media Distributor.


# Cryptographic Context

This specification uses a cryptographic context with two parts: an inner
(end-to-end) part that is used by endpoints that originate and
consume media to ensure the integrity of media end-to-end, and an
outer (hop-by-hop) part that is used between endpoints and Media
Distributors to ensure the integrity of media over a single hop and to
enable a Media Distributor to modify certain RTP header fields.  RTCP
is also handled using the hop-by-hop cryptographic part.  The
RECOMMENDED cipher for the hop-by-hop and end-to-end algorithm is
AES-GCM.  Other combinations of SRTP ciphers that support the
procedures in this document can be added to the IANA registry.

The keys and salt for these algorithms are generated with the following
steps:

* Generate key and salt values of the length required for the combined
  inner (end-to-end) and outer (hop-by-hop) algorithms.

* Assign the key and salt values generated for the inner (end-to-end)
  algorithm to the first half of the key and salt for the double
  algorithm. 

* Assign the key and salt values for the outer (hop-by-hop) algorithm
  to the second half of the key and salt for the double algorithm. The
  first half of the key is referred to as the inner key while the
  second half is referred to as the outer key. When a key is used
  by a cryptographic algorithm, the salt used is the part of the salt
  generated with that key.
  
Obviously, if the Media Distributor is to be able to modify header
fields but not decrypt the payload, then it must have cryptographic
key for the outer algorithm, but not the inner (end-to-end) algorithm.  This
document does not define how the Media Distributor should be
provisioned with this information.  One possible way to provide keying
material for the outer (hop-by-hop) algorithm is to use
[@I-D.ietf-perc-dtls-tunnel].


# Original Header Block

The Original Header Block (OHB) contains the original values of any modified
header fields.  In the encryption process, the OHB is appended to the RTP
payload.  In the decryption process, the receiving endpoint uses it to
reconstruct the original RTP header, so that it can pass the proper AAD value
to the inner transform.

The OHB can reflect modifications to the following fields in an RTP header: the
payload type, the sequence number, and the marker bit.  All other fields in the
RTP header MUST remain unmodified; since the OHB cannot reflect their original
values, the receiver will be unable to verify the E2E integrity of the packet.

The OHB has the following syntax (in ABNF):

{align="left"}
~~~~~
BYTE = %x00-FF

PT = BYTE
SEQ = 2BYTE
Config = BYTE

OHB = ?PT ?SEQ Config
~~~~~

If present, the PT and SEQ parts of the OHB contain the original payload type
and sequence number fields, respectively. The final "config" octet of the OHB
specifies whether these fields are present, and the original value of the
marker bit (if necessary):

{align="left"}
~~~~~
+-+-+-+-+-+-+-+-+
|R R R R B M P Q|
+-+-+-+-+-+-+-+-+
~~~~~

* P: PT is present
* Q: SEQ is present
* M: Marker bit is present
* B: Value of marker bit
* R: Reserved, MUST be set to 0

In particular, an all-zero OHB config octet (0x00) indicates that there have
been no modifications from the original header.

# RTP Operations

~~~~~
       0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+<+
    |V=2|P|X|  CC   |M|     PT      |       sequence number         | I O
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ I O
    |                           timestamp                           | I O
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ I O
    |           synchronization source (SSRC) identifier            | I O
    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+ I O
    |            contributing source (CSRC) identifiers             | I O
    |                               ....                            | I O
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+ O
    |                    RTP extension (OPTIONAL) ...               | | O
+>+>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+ O
O I |                          payload  ...                         | I O
O I |                               +-------------------------------+ I O
O I |                               | RTP padding   | RTP pad count | I O
O +>+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<+ O
O | |                    E2E authentication tag                     | | O
O | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | O
O | |                            OHB ...                            | | O
+>| +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |<+
| | |                    HBH authentication tag                     | | | 
| | +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | |
| |                                                                   | |
| +- E2E Encrypted Portion               E2E Authenticated Portion ---+ |
|                                                                       |
+--- HBH Encrypted Portion               HBH Authenticated Portion -----+
~~~~~

## Encrypting a Packet

To encrypt a packet, the endpoint encrypts the packet using the inner (end-to-end)
cryptographic key and then encrypts using the outer (hop-by-hop) cryptographic
key.  The processes is as follows:

* Form an RTP packet.  If there are any header extensions, they MUST
  use [@!RFC5285].

* Form a synthetic RTP packet with the following contents:
  * Header: The RTP header of the original packet with the following
    modifications:
    * The X bit is set to zero
    * The header is truncated to remove any extensions (12 + 4 * CC bytes)
  * Payload: The RTP payload of the original packet

* Apply the inner cryptographic algorithm to the RTP packet.

* Replace the header of the protected RTP packet with the header of the
  original packet, and append to the payload of the packet (1) the
  authentication tag from the original transform, and (2) an empty OHB (0x00).
  
* Apply the outer cryptographic algorithm to the RTP packet.  If
  encrypting RTP header extensions hop-by-hop, then [@!RFC6904] MUST
  be used when encrypting the RTP packet using the outer cryptographic
  key.

When using EKT [@I-D.ietf-perc-srtp-ekt-diet], the EKT Field comes
after the SRTP packet exactly like using EKT with any other SRTP
transform.

## Relaying a Packet

The Media Distributor has the part of the key for the outer
(hop-by-hop), but it does not have the part of the key for the (end-to-end)
cryptographic algorithm.  The cryptographic algorithm and key used to
decrypt a packet and any encrypted RTP header extensions would be the
same as those used in the endpoint's outer algorithm and key.

In order to modify a packet, the Media Distributor decrypts the
packet, modifies the packet, updates the OHB with any modifications
not already present in the OHB, and re-encrypts the packet using the
cryptographic using the outer (hop-by-hop) key.

* Apply the outer (hop-by-hop) cryptographic algorithm to decrypt the
  packet.  If decrypting RTP header extensions hop-by-hop, then
  [@!RFC6904] MUST be used.  Note that the RTP payload produced by this
  decryption operation contains the original encrypted payload with the tag
  from the inner transofrm and the OHB appended.

* Change any parts of the RTP packet that the relay wishes to change
  and are allowed to be changed. 

* If a changed RTP header field is not already in the OHB, add it with
  its original value to the OHB.  A Media Distributor can add
  information to the OHB, but MUST NOT change existing information in
  the OHB.

* If the Media Distributor resets a parameter to its original value,
  it MAY drop it from the OHB. Note that this might result in a
  decrease in the size of the OHB.

* Apply the outer (hop-by-hop) cryptographic algorithm to the packet. If the RTP Sequence
  Number has been modified, SRTP processing happens as defined in SRTP
  and will end up using the new Sequence Number. If encrypting RTP
  header extensions hop-by-hop, then [@!RFC6904] MUST be used.

## Decrypting a Packet

To decrypt a packet, the endpoint first decrypts and verifies using
the outer (hop-by-hop) cryptographic key, then uses the OHB to
reconstruct the original packet, which it decrypts and verifies with
the inner (end-to-end) cryptographic key.

* Apply the outer cryptographic algorithm to the packet.  If the
  integrity check does not pass, discard the packet.  The result of
  this is referred to as the outer SRTP packet.  If decrypting RTP
  header extensions hop-by-hop, then [@!RFC6904] MUST be used when
  decrypting the RTP packet using the outer cryptographic key.

* Remove the inner authentication tag and the OHB from the end of the payload
  of the outer SRTP packet.

* Form a new synthetic SRTP packet with:

  * Header = Received header, with the following modifications:
    * Header fields replaced with values from OHB (if any)
    * The X bit is set to zero
    * The header is truncated to remove any extensions (12 + 4 * CC bytes) 

  * Payload is the encrypted payload from the outer SRTP packet (after the
    inner tag and OHB have been stripped).

  * Authentication tag is the inner authentication tag from the outer SRTP
    packet.

* Apply the inner cryptographic algorithm to this synthetic SRTP
  packet.  Note if the RTP Sequence Number was changed by the Media
  Distributor, the synthetic packet has the original Sequence
  Number. If the integrity check does not pass, discard the packet.

Once the packet has been successfully decrypted, the application needs
to be careful about which information it uses to get the correct
behaviour.  The application MUST use only the information found in the
synthetic SRTP packet and MUST NOT use the other data that was in the
outer SRTP packet with the following exceptions:

* The PT from the outer SRTP packet is used for normal matching to SDP
  and codec selection.

* The sequence number from the outer SRTP packet is used for normal
RTP ordering.

The PT and sequence number from the inner SRTP packet can be used for
collection of various statistics. 

If any of the following RTP headers extensions are found in the outer
SRTP packet, they MAY be used:

* Mixer-to-client audio level indicators (See [@RFC6465])

# RTCP Operations

Unlike RTP, which is encrypted both hop-by-hop and end-to-end using
two separate cryptographic key, RTCP is encrypted using only the
outer (hop-by-hop) cryptographic key.  The procedures for RTCP encryption
are specified in [@!RFC3711] and this document introduces no
additional steps.

# Use with Other RTP Mechanisms

There are some RTP related extensions that need special consideration
to be used by a relay when using the double transform due to the
end-to-end protection of the RTP.

## RTX

TODO - Add text to explain how to use RTX as described in Option A of
slides presented at IETF 99.

## RED

TODO - Add text to explain how to use RED as described in Option A of
slides presented at IETF 99.

## FEC

TODO - Add text to explain how to use FlexFEC
[@I-D.ietf-payload-flexible-fec-scheme] as described in Option A of
slides presented at IETF 99.

## DTMF

When DTMF is sent with [@RFC4733], it is end-to-end encrypted and the
relay can not read it so it can not be used to controll the
relay. Other out of band methods to controll the relay need to be used
instead.


# Recommended Inner and Outer Cryptographic Algorithms

This specification recommends and defines AES-GCM as both the inner
and outer cryptographic algorithms, identified as
DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM and
DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM.  These algorithm provide
for authenticated encryption and will consume additional processing
time double-encrypting for hop-by-hop and end-to-end.  However, the approach is
secure and simple, and is thus viewed as an acceptable trade-off in
processing efficiency.

Note that names for the cryptographic transforms are of the form
DOUBLE_(inner algorithm)_(outer algorithm).

While this document only defines a profile based on AES-GCM, it is
possible for future documents to define further profiles with
different inner and outer crypto in this same framework.  For
example, if a new SRTP transform was defined that encrypts some or all
of the RTP header, it would be reasonable for systems to have the
option of using that for the outer algorithm.  Similarly, if a new
transform was defined that provided only integrity, that would also be
reasonable to use for the hop-by-hop as the payload data is already encrypted
by the end-to-end.

The AES-GCM cryptographic algorithm introduces an additional 16 octets
to the length of the packet.  When using AES-GCM for both the inner
and outer cryptographic algorithms, the total additional length is 32
octets.  If no other header extensions are present in the packet and
the OHB is introduced, that will consume an additional 8 octets.  If
other extensions are already present, the OHB will consume up to 4
additional octets.


# Security Considerations

To summarize what is encrypted and authenticated, we will refer to all
the RTP fields and headers created by the sender and before the pay
load as the initial envelope and the RTP payload information with the
media as the payload. Any additional headers added by the Media
Distributor are referred to as the extra envelope. The sender uses the
end-to-end key to encrypts the payload and authenticate the payload + initial
envelope which using an AEAD cipher results in a slight longer new
payload.  Then the sender uses the hop-by-hop key to encrypt the new payload
and authenticate the initial envelope and new payload.

The Media Distributor has the hop-by-hop key so it can check the
authentication of the received packet across the initial envelope and
payload data but it can't decrypt the payload as it does not have the
end-to-end key. It can add extra envelope information. It then authenticates
the initial plus extra envelope information plus payload with a hop-by-hop
key. This hop-by-hop for the outgoing packet is typically different than the
hop-by-hop key for the incoming packet.

The receiver can check the authentication of the initial and extra
envelope information.  This, along with the OHB, is used to construct
a synthetic packet that is should be identical to one the sender
created and the receiver can check that it is identical and then
decrypt the original payload.

The end result is that if the authentications succeed, the receiver
knows exactly what the original sender sent, as well as exactly which
modifications were made by the Media Distributor.

It is obviously critical that the intermediary has only the outer
(hop-by-hop) algorithm key and not the half of the key for the the
inner (end-to-end) algorithm.  We rely on an external key management
protocol to assure this property.

Modifications by the intermediary result in the recipient getting two
values for changed parameters (original and modified).  The recipient
will have to choose which to use; there is risk in using either that
depends on the session setup.

The security properties for both the inner (end-to-end) and outer
(hop-by-hop) key holders are the same as the security properties of
classic SRTP.

# IANA Considerations

## RTP Header Extension

This document defines a new extension URI in the RTP Compact Header
Extensions part of the Real-Time Transport Protocol (RTP) Parameters
registry, according to the following data:

Extension URI: urn:ietf:params:rtp-hdrext:ohb

Description:   Original Header Block

Contact: Cullen Jennings <fluffy@iii.ca>

Reference:     RFCXXXX

Note to RFC Editor: Replace RFCXXXX with the RFC number of this
specification.
      

## DTLS-SRTP

We request IANA to add the following values to defines a DTLS-SRTP
"SRTP Protection Profile" defined in [@!RFC5764].

| Value  | Profile                                  | Reference |
|:-------|:-----------------------------------------|:----------|
|  {0x00, 0x09}  | DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM | RFCXXXX   |
|  {0x00, 0x0A}  | DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM | RFCXXXX   |

Note to IANA: Please assign value RFCXXXX and update table to point at
this RFC for these values.

The SRTP transform parameters for each of these protection are:

{align="left"}
~~~~
DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM
    cipher:                 AES_128_GCM then AES_128_GCM 
    cipher_key_length:      256 bits
    cipher_salt_length:     192 bits
    aead_auth_tag_length:   32 octets
    auth_function:          NULL
    auth_key_length:        N/A
    auth_tag_length:        N/A
    maximum lifetime:       at most 2^31 SRTCP packets and
                            at most 2^48 SRTP packets

DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM
    cipher:                 AES_256_GCM then AES_256_GCM 
    cipher_key_length:      512 bits
    cipher_salt_length:     192 bits
    aead_auth_tag_length:   32 octets
    auth_function:          NULL
    auth_key_length:        N/A
    auth_tag_length:        N/A
    maximum lifetime:       at most 2^31 SRTCP packets and
                            at most 2^48 SRTP packets
~~~~

The first half of the key and salt is used for the inner (end-to-end)
algorithm and the second half is used for the outer (hop-by-hop) algorithm.

# Acknowledgments

Many thanks to Richard Barnes for sending significant text for this
specification. Thank you for reviews and improvements from David
Benham, Paul Jones, Suhas Nandakumar, Nils Ohlmeier, and Magnus
Westerlund.

 
{backmatter}


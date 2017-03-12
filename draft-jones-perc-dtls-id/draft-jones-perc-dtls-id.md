%%%

    #
    # dtls-id Extension for TLS/DTLS in support of PERC
    #
    # Generation tool chain:
    #   mmark (https://github.com/miekg/mmark)
    #   xml2rfc (http://xml2rfc.ietf.org/)
    #

    Title = "Transporting the SDP attribute 'dtls-id' in TLS and DTLS"
    abbrev = "dtls-id in TLS and DTLS"
    category = "std"
    docName = "draft-jones-perc-dtls-id-00"
    ipr= "trust200902"
    area = "Internet"
    keyword = ["PERC", "SRTP", "RTP", "DTLS", "DTLS-SRTP", "DTLS tunnel", "conferencing", "security"]

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
    initials = "N."
    surname = "Ohlmeier"
    fullname = "Nils H. Ohlmeier"
    organization = "Mozilla"
      [author.address]
      email = "nils@ohlmeier.org"
      phone = "+1 408 659 6457"

    #
    # Revision History
    #   00 - Initial version
    #

%%%

.# Abstract

This draft defines a new extension to carry the `dtls-id` value defined
for use in the Session Description Protocol within TLS and DTLS.

{mainmatter}

# Introduction

The Privacy-Enhanced RTP Conferencing (PERC) working group specified a
DTLS [@!RFC6347] tunneling mechanism [@!I-D.perc-dtls-tunnel] that enables
a media distributor to forward DTLS messages between an endpoint
and a key distributor.  In the process, the media distributor
is able to securely receive only the hop-by-hop keying material,
while the endpoints are able to securely receive both end-to-end and
hob-by-hop keying material.

An open issue with the current design is how the key distributor
can determine which one of several conferences an endpoint is attempting to
join.  The only information that the key distributor receives via
the DTLS tunnel is the endpoint's certificate.  However, the same certificate
might be used to join several conferences in parallel, thus creating a
need for additional information.

[@!I-D.ietf-mmusic-dtls-sdp] defines an attribute in SDP [@!RFC4566] called
the `dlts-id`.  The `dtls-id` presented by the endpoint's in SDP will be
unique for each DTLS association established using the same certificate.
By signaling the certificate fingerprint and `dtls-id` in SDP, along with
including the same in the DTLS signaling sent to the key distributor, it would
be possible for the key distributor to unambiguously determine which
conference key the endpoint should receive.

# Conventions Used In This Document

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**",
"**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**",
"**MAY**", and "**OPTIONAL**" in this document are to be interpreted as
described in [@!RFC2119] when they appear in ALL CAPS.  These words may
also appear in this document in lower case as plain English words,
absent their normative meanings.

The terms key distributor, media distributor, endpoint,
conference, hop-by-hop keying material, and end-to-end keying material
used in this document are introduced in
[@!I-D.ietf-perc-private-media-framework].

# Endpoint procedures

The endpoint **MUST** include the `dtls_id` DTLS extension in the `ClientHello`
message when establishing a DTLS tunnel in a PERC conference.  Likewise,
the `dtls-id` SDP attribute **MUST** be included in SDP sent by the endpoint
in both the offer and answer [@!RFC3264] messages as per
[@!I-D.ietf-mmusic-dtls-sdp].

When receiving a `dtls_id` value from the key distributor, the
client **MUST** check to ensure that value matches the `dtls-id` value
received in SDP.  If the values do not match, the endpoint **MUST**
consider any received keying material to be invalid and terminate the
DTLS association.

# Media distributor procedures

The media distributor is not required to inspect the `dtls_id`
extension, as it merely forwards DTLS messages between the endpoint
and the key distributor.

# Key distributor procedures

This draft assumes that when the endpoint inserts the `dtls-id` into
SDP, the information will be conveyed in some way to the key distributor.
The process through which the `dtls-id` in SDP is conveyed to
the key distributor is outside the scope of this document.

The key distributor **MUST** extract the `dtls_id` value transmitted
in the `ClientHello` message and match that against `dtls-id` value the
endpoint transmitted via SDP.  If the values in SDP and the `ClientHello`
do not match, the DTLS association **MUST** be rejected.

The key distributor **MUST** correlate the certificate fingerprint and
`dtls_id` received from endpoint's `ClientHello` message with the
corresponding values received from the SDP transmitted by the endpoint.  It
is through this correlation that the key distributor can be sure to
deliver the correct conference key to the endpoint.

When sending the `ServerHello` message, the key distributor **MUST**
insert its own `dtls-id` value.  This value **MUST** also be conveyed back
to the client via SDP.

# The dtls_id TLS extension

The `dtls_id` TLS extension may be used either with TLS [@!RFC5246] or
DTLS.  It carries only `dtls-id` value defined in
[@!I-D.ietf-mmusic-dtls-sdp] in the field called `dtls_id`.  The syntax
for the `dtls_id` extension is shown below.

~~~
    struct {
        opaque dtls_id<20..255>;
    } SdpDtlsIdData;
~~~

# IANA Considerations

This document registers an extension in the TLS "ExtensionType
Values" registry established in [@!RFC5246].  The extension
is called `dtls_id` and is assigned the code point TBD.  The
following addition is made to the registry.

Extension | Recommended | TLS 1.3   | HelloRetryRequested
----------|-------------|-----------|---------------------
dlts_id   | Yes         | Encrypted | Yes

# Security Considerations

The `dtls-id` value is a random value that has no personal identifiable
information associated with it.  Thus, the value does not expose such
information.  It also has no particular security properties in and
of itself, so being in plaintext in the `ClientHello` or `ServerHello` is
not viewed as a security concern.

However, the value does have significance to the receiver, thus changes to
the `dtls-id` may result in unexpected behavior.  For example, if Alice
attempts to join a PERC-enabled conference and the `dtls_id` field is
modified in route to the key distributor, Alice may either fail
to receive the conference key or receive the wrong conference key.
However, since Alice will only be provided keys for conferences for which
she is authorized to join based on her client certificate, receiving the
wrong key will not compromise the security of the conference.  However,
receipt of the wrong key will deny Alice access to the plaintext of
media transmitted by other participants.  Additionally, if Alice transmits
media using the wrong conference key, the media will be undecipherable
by other conference participants.

As prescribed in these procedures, if the `dtls_id` field transmitted from
the key distributor to Alice is modified, Alice will tear down the DTLS
association and fail to join the conference.  The result is a denial of
service for Alice, but not worse than when any other part of the DTLS
message is modified.

# Acknowledgments

The authors would like to thank Martin Thomson for discussing the idea and
providing some initial feedback before the draft was written.  We also
want to express our appreciation to Cullen Jennings for reviewing the
text and providing constructive input.

{backmatter}

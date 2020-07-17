---
title: MultiPass Token Retriaval
abbrev: MultiPass Token Retriaval
docname: draft-waite-multipass-retrieval-00
date: 2020-07-11
category: exp

ipr: trust200902
area: General
workgroup: None
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: D. Waite
    name: David Waite
    organization: Ping Identity
    email: david@alkaline-solutions.com

normative:
  I-D.ietf-oauth-security-topics:
  W3C.REC-vc-data-model-20191119: # VC Data Model
    target: https://www.w3.org/TR/2019/CR-verifiable-claims-data-model-20190328
    title: Verifiable Credentials Data Model 1.0
    author:
      - ins: M. Sporny
      - ins: G. Noble
      - ins: D. Burnett
      - ins: D. Longley
    date: March 28 2019
  # OASIS Standard
  OASIS.saml-core-2.0-os:
    target: http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    title: Assertions and Protocols for the OASIS Security Assertion Markup Language (SAML) V2.0
    author:
      - ins: S. Cantor
      - ins: J. Kemp
      - ins: R. Philpott
      - ins: E. Maler
    date: March 2005
  RFC2119: # RFC Keywords
  RFC6749: # OAuth 2.0
  RFC3986: # URI Syntax
  RFC7159: # JSON
  RFC7519: # JWT
  RFC7518: # JWA

informative:
  RFC2818: # HTTP over TLS
  RFC3629: # UTF8
  RFC4949: # Internet Security Glossary
  RFC7231: # HTTP 1.1 Semantics and Content
  RFC7234: # HTTP 1.1 Caching
  RFC7595: # Guidelines, Registration Procedures for URI Schemes
  RFC8126: # Case ambiguity in RFC keywords
  RFC8252: # OAuth for Native Apps
  RFC8446: # TLS 1.3
  USASCII: # 7 bit ASCII
    title: "Coded Character Set -- 7-bit American Standard Code for Information Interchange, ANSI X3.4"
    author:
      name: "American National Standards Institute"
    date: 1986
  W3C.REC-html401-19991224: # HTML 4.01
  W3C.REC-xml-20081126: # XML 1.0 5th Ed
  OpenID: # Openid Connect Core 1.0
    title: "OpenID Connect Core 1.0"
    target: https://openiD.net/specs/openiD-connect-core-1_0.html
    date: November 8, 2014
    author:
      - ins: N. Sakimora
      - ins: J. Bradley
      - ins: M. Jones
      - ins: B. de Medeiros
      - ins: C. Mortimore
  OpenID.Messages: # Openid Connect Messages
    title: "OpenID Connect Messages 1.0"
    author:
      - ins: N. Sakimura
      - ins: J. Bradley
      - ins: M. Jones
      - ins: B. de Medeiros
      - ins: C. Mortimore
      - ins: E. Jay
    date: June 2012
    target: http://openid.net/specs/openid-connect-messages-1_0.html
  owasp_redir: # OWASP Cheet Sheet Series - Unvalidated Redirects
    title: "OWASP Cheat Sheet Series - Unvalidated Redirects and Forwards"
    target: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
    date: 2020
  RFC6265: # HTTP State Management
  RFC6819: # OAuth 2.0 Thread Model and Security Considerations
  RFC7230: # HTTP 1.1: Syntax and Routing
  RFC7235: # HTTP 1.1: Authentication
  RFC7591: # OAuth Dynamic Client Registration
  RFC7636: # OAUTH PKCE
  RFC7800: # PoP Key Semantics for JWTs
  RFC8414: # OAuth Server Metadata
  RFC8705: # OAuth MTLS client authentication/binding
  RFC8707: # Resource Indicators
  SAML.Core:
    title: Assertions and Protocols for the OASIS Security Assertion Markup Language
    target: http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    author:
      - name: Scott Cantor
      - name: John Kemp
      - name: Rob Philpott
      - name: Eve Maler
    date: March 15 2005
---
abstract

Most often user attributes are exchanged online between systems and organizations which have a local or bilateral business arrangement, with user consent and privaccy provided as desired by the organization(s) involved.

MultiPass is a Verifiable Credentials ({{W3C.REC-vc-data-model-20191119}}) system intended for an organization to supply attributes unilaterally, and for other organizations to rely upon those attributes without having a relationship to the supplier. This is accomplished by leveraging a local user agent (sometimes referred to as a wallet), which allows this exchange to be done in a manner which can respect user privacy and support informed decisions around disclosure. 

This specification provides a mechanism to retrieve single-use tickets which bundle cryptographically secure attributes in a non-correlatable, incrementally disclosable manner.

---
middle

# Introduction {#introduction}

In existing identity systems such as SAML ({{SAML.Core}}) and OpenID Connect ({{OpenID}}), two entities share identity information about the user with regard the entities' existing bilateral business relationship. The exchange of this authentication and claimed attribute information may more may not be something the user is informed of or consents to, depending on the policies and regulations that the entities operate under.

Verifiable Credential systems aim to introduce a new role into the system, that of a user agent which works to mediate this exchange of information and to decouple entities from needing a business relationship. This user agent, referred to from this point as a *Holder*, can implement a consistent level of informed consent onto the exchanged information.

This specification describes a system for fetching attribute credentials, known as *Multipass Tickets*, from an issuer. For compatibility with existing identity systems, this issuer acts as a protected resource under the OAuth 2.0 Authorization Framework described in ({{RFC6749}}). There may be other methods for retrieving multipass tickets outside of OAuth 2, which are out of scope of this specification.

This specification also describes the format of the ticket in the response, as well as how to process, send, and verify the response.

This specification does not define a profile for requesting or sending multipass tickets to recipients, which may operate in roles such as "Relying Parties" or "Verifiers" within such profiles.

## Roles

Multipass defines three roles beyond OAuth:

"Holder":
:   An application which acts as a client, requesting and holding onto multipass tickets on behalf of the resource owner. This may also be referred to sometimes as a "wallet."

"Issuer":
:   An application issuing multipass tokens to the holder. In the context of this specification, this entity is an OAuth 2 protected resource. These tokens may represent attributes about the resource owner, or of another party that has delegated access.

"Verifier":
:   An application requesting multipass tickets which meet certain requirements, and which can verify whether multipass tickets meet their requirements for action to be taken.

## Protocol Flow

~~~~~~~~~~
     +--------+                               +---------------+
     |        |<-(1a)- OAuth grant request -->| Authorization |
     |        |                               |     Server    |
     |        |<-(1b)- Access Token ----------|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(2)- Request ticket -------->|               |
     | Holder |                               |     Issuer    |
     |        |<-(3)- Multipass ticket -------|               |
     |        |                               +---------------+
    / /      / /
     |        |                               +---------------+
     |        |<-(4)- Presentation request ---|               |
     |        |                               |    Verifier   |
     |        |--(5)- Presentation response ->|               |
     +--------+                               +---------------+
~~~~~~~~~~
{: #fig-protocol-flow title="Abstract Protocol Flow"}

The abstract flow illustrated in {{fig-protocol-flow}} describes the interaction
Between the entities and includes the following steps:

1. The Holder seeks authorization from the Authorization Server as described in {{RFC6749}}. The scope for interacting with an issuer is "multipass".

2. The Holder requests a multipass ticket using the acquired access token. This request includes an ephemeral public key, which should be unique per request and be different from any cryptographic keys used for sender constrained token mechanisms (such as DPoP).

3. The holder returns a single-use multipass ticket, with confirmation set to the supplied ephemeral key.

4. A verifier requests a presentation with specific parameters which match the multipass ticket previously issued. If a valid ticket is not available at the holder (due to time-based expiry or all cached tickets being used) steps 2 and 3 may be repeeated here to fetch a new multipass ticket.

5. After the holder confirms the user wishes to share the information requested with the verifier, the presentation response is returned based on the multipass ticket.

## Multipass ticket format

A multipass ticket is single use cryptographic package used to form a presentation response. It consists of a collection of individually packaged attributes about the resource owner, which can be selectively disclosed to minimally meet the needs of the verifier.

~~~~~~~~~~
┌──────────────────────────────────────────┐
│                                          │
│                Multipass                 │
│                                          │
│ ┌──────────────────────────────────────┐ │
│ │                                      │ │
│ │           Issuer Statement           │ │
│ │                                      │ │
│ └──────────────────────────────────────┘ │
│ ┌──────────────────────────────────────┐ │
│ │                                      │ │
│ │          Holder Usage Data           │ │
│ │                                      │ │
│ └──────────────────────────────────────┘ │
│ ┌──────────────────────────────────┐     │
│ │                                  ├─┐   │
│ │            Attributes            │ ├─┐ │
│ │                                  │ │ │ │
│ └─┬────────────────────────────────┘ │ │ │
│   └─┬────────────────────────────────┘ │ │
│     └──────────────────────────────────┘ │
└──────────────────────────────────────────┘
~~~~~~~~~~
{: #fig-multipass-structure title="Multipass Structure"}

## Issuer Statement

The issuer statement is a signed JWT containing information which is both non-identifying and non-correlating of the user, which will be disclosed to all verifiers.

The JWT contains the following keys, defined by ({{RFC7519}}) and ({{RFC7800}})

"iss":
:    REQUIRED.  This value MUST uniquely identifies the issuer. It SHOULD be a "https" scheme URL usable for metadata discovery per ({{RFC8414}}).
"aud":
:    OPTIONAL. This value indicates recipient(s) that the JWT is intended for. If an audience is specified, the multipass MUST NOT be presented to a recipient that is not part of that audience.
"exp":
:    REQUIRED. The expiration time after which the multipass MUST NOT be presented to a verifier and MUST NOT be accepted by a verifier for processing.  A holder MAY use expiry to proactively acquire one or more new multipasses.
"jti":
:    REQUIRED. A unique identifier for the JWT. MAY be used for communicating out-of-band from a verifier to an issuer about this multipass and the associated resource owner, e.g. in abuse scenarios.
"cnf":
:    REQUIRED. Used to provide proof-of-possession of the holder to the verifier.
"atv":
:    OPTIONAL. Used to provide cryptographic verification of attributes.

### Attribute Verification

The Attribute Verification object within the issuer statement describes how to verify that any attributes presented alongside the issuer statement are valid.

Attribute verification consists of an ephemeral public key (as a "jwk" member), used to sign each attribute individually via JWS.

## Attribute format

A multipass contains multiple individually protected attributes, allowing for a statement about the resource owner previously to give only the information requested by a verifier. The attribute verification element specifies how to verify these individual attributes.

Attribues are represented as individual JWS-protected documents in a restricted JSON-LD format. These restrictions are meant to create an extensible format where:

- The document represented by each attribute is about the resource owner
- Properties from multiple attribute documents can be interpreted as a composition without needing to resolve conflicts
- Verifiers do not need a full JSON-LD and RDF toolset to understand attributes
- Attribute data is limited to a tree structure (rather than a directed cyclic graph structure)
- An issuer can not attempt to assert authoritative properties about entities other than the resource owner.

The restrictions are as follows:

1. Each document represents the resource owner as the base or root node.
2. The JSON-LD MUST be in compacted form and MUST be specified without any context. The document MUST limit the use of special keywords to "@id", "@type", "@list", "@json", "@language", "@value", and "@direction".  The use of "@direction" is DISCOURAGED due to compatibility with various RDF tools and formats. Use of "@value" is NOT RECOMMENDED except when neccessary to indicate a language and/or direction.
3. Two attributes MUST NOT contain conflicting properties. Multiple attributes containing the same property on the same node MUST be interpreted as an unordered set of values.
4. The document MUST NOT attempt to present authoritative information on any entity other than the resource owner. Each node within an attribute (other than the resource owner itself) MUST either be a node reference consisting of an IRI, be an unnamed node, or be a locally named node.
5. Node references to named nodes MAY be used to divide properties of a node among multiple attributes. Named nodes MUST only be referenced by one property of one node other than the named node itself, which will be its parent node in the document tree. A named node MUST NOT reference itself.
6. An attribute MAY indicate the "@id" of the resource owner to indicate a unique IRI for the resource owner in the context of the issuer. What information may be dereferenced at this location or what authorization might be required is out of scope of this specification.

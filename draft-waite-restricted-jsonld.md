---
title: MultiPass Restricted JSON-LD Attributes
abbrev: MultiPass attributes
docname: draft-waite-restricted-jsonld
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

NOTE: this document was originally an attempt to restrict JSON-LD to a sufficient subset to be usable for a wide variety of credentials, including by parsers which did not have JSON-LD capabilities, and to allow for selective disclosure. As the multipass ticket expanded to have different *formats* of credentials, the need for this went away.

As such, this is a text holding area until work begins defining an example credential format.

---
middle

# Introduction {#introduction}

Attributes within this specification are represented as multiple JWTs, each holding a subset of the attributes about the subject. These JWTs are signed by an ephemeral key in the issuer statement, indicated by the "atv" JWT value. By using an ephemeral key and having no correlatable information about the subject or holder in the issuer statement, the information presented to the verifier can range anywhere from the full set of attributes from the issuer, to a cryptographic proof of some unspecified relationship to the issuer.

## JSON-LD 1.1 Attribute format

Attributes are represented in a restricted JSON-LD format. For example, the following document might be representative of the information presented by an issuer of state driver's licenses:

~~~~~~~~~~
{
  "@type": [
    "https://schema.org/Person",
    "https://example.org/Licensee"
  ]
  "https://schema.org/name": "David Waite",
  "https://schema.org/familyName": "Waite",
  "https://schema.org/givenName": "David",
  "https://schema.org/homeLocation": {
    "@type": "https://schema.org/Place",
    "https://schema.org/address": {
      "@type": "https://schema.org/PostalAddress",
      "https://schema.org/addressCountry": "US",
      "https://schema.org/addressLocality": "Denver",
      "https://schema.org/addressRegion": "CO",
      "https://schema.org/streetAddress": "627 Incomplete Circle",
      "https://schema.org/postalCode": "80200"
    }
  },
  "https://schema.org/birthDate": "1900-01-01",
  "https://example.org/birthDate/over18": true,
  "https://example.org/birthDate/over21": true,
  "https://example.org/birthDate/over25": true
  "https://schema.org/image": "Base64EncodedImage=="
  "https://schema.org/height": "1.88 m",

  "https://example.org/hairColor": nil,
  "https://example.org/eyeColor": "brown",
  "https://example.org/issuedDate": 2020-01-01",
  "https://example.org/identifier": "01-154-0000",
  "https://example.org/correctiveLensesRequired": false,
  "https://example.org/veteran": false
}
~~~~~~~~~~
{: #fig-example-attributes title="Example Attributes"}

These attributes may be divided into individual attribute statements to enable selective disclosure. For example, in-person sale of restricted substances may require the release of proof that the person is over 21, and an image for visual verification. These might be represented as two seperate JSON-LD documents:

~~~~~~~~~~
{
  "https://example.org/birthDate/over18": true
}

{
  "https://schema.org/image": "Base64EncodedImage=="
}
~~~~~~~~~~

These indidual JSON-LD 1.1 documents are protected as JWS documents, signed with the ephemeral key indicated in the `atv` value of the issuer statement.

### JSON-LD 1.1 Restrictions

A set of restrictions on the JSON-LD 1.1 format are proposed to simplify tooling and usage in a secure, privacy-preserving context. These restrictions serve to provide the following properties:

- The document represented by each attribute is about the common subject
- Properties from multiple attribute documents are interpretable as a composition, without needing to resolve conflicting information
- Verifiers do not need a full JSON-LD and RDF toolset to understand attribute documents
- Attribute data is restricted to a hierarchal structure (instead of the directed cyclic graph structure of RDF)
- An issuer can not assert authoritative properties about entities other than the subject.

The restrictions are as follows:

1. Each document represents the subject as the base or root node.
2. The JSON-LD MUST be in compacted form and MUST be specified without any `@context` keyword.
3. The document MUST limit the use of special keywords to `@id`, `@type`, `@list`, `@set`, `@json`, `@language`, `@value`, and `@direction`.
4. The use of `@direction` is DISCOURAGED due to compatibility with various RDF tools and formats.
5. The `@value` and `@set` keywords MUST NOT be used when there is an equivalent compacted form.
6. The same node property MUST NOT be present in two attributes to represent conflicting information about a node.
7. Multiple properties MAY be used indicate an unordered set of values across multiple documents.
8. Each node within an attribute document MUST either be a node reference consisting of an IRI, be an unnamed node, or be a locally named node.
9. An attribute statement MUST NOT present authoritative information on any entity other than the subject, such as by having both an `@id` keyword and properties.
10. Named nodes MAY be used to divide properties of a node among multiple attributes.
11. A named node MUST NOT reference itself.
12. Named nodes MUST only be referenced by a single property on one node. This will be its parent node in the attribute hierarchy.

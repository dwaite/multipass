---
title: MultiPass Ticket Retriaval
abbrev: MultiPass Retriaval
docname: draft-waite-multipass-retrieval-00
date: 2020-07-22
category: exp

ipr: trust200902
area: General
workgroup: None
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs, comments]

author:
 -
    ins: D. Waite
    organization: Ping Identity
    email: david@alkaline-solutions.com

normative:
  # URI:        RFC3986
  OAUTH2:     RFC6749
  JSON:       RFC7159
  JWK:        RFC7517
  # JWA:        RFC7518
  JWT:        RFC7519
  # I-D.ietf-oauth-security-topics:
  W3C.REC-vc-data-model-20191119: # VC Data Model
    target: https://www.w3.org/TR/2019/REC-vc-data-model-20191119/
    title: Verifiable Credentials Data Model 1.0
    author:
      - ins: M. Sporny
      - ins: G. Noble
      - ins: D. Longley
      - ins: D. Burnett
      - ins: B. Zundel
    date: November 19 2019

informative:
  # HTTPTLS:        RFC2818 # HTTP over TLS
  # UTF8:           RFC3629 # UTF8
  SECURITY:  RFC4949 # Internet Security Glossary
  # COOKIES:        RFC6265 # HTTP State Management
  # OAUTHTHREAT:    RFC6819 # OAuth 2.0 Threat Model and Security Considerations
  # HTTPSYNTAX:     RFC7230 # HTTP 1.1: Syntax and Routing
  # HTTPSEMANTICS:  RFC7231 # HTTP 1.1 Semantics and Content
  # HTTPCACHING:    RFC7234 # HTTP 1.1 Caching
  # HTTPAUTH:       RFC7235 # HTTP 1.1: Authentication
  # OAUTHREG:       RFC7591 # OAuth Dynamic Client Registration
  # OAUTHPKCE:      RFC7636 # OAUTH PKCE
  JWTPOP:         RFC7800 # PoP Key Semantics for JWTs
  # APPAUTH:        RFC8252 # OAuth for Native Apps
  OAUTHMETA:      RFC8414 # OAuth Server Metadata
  # TLS13:          RFC8446
  # OAUTHMTLS:      RFC8705 # OAuth MTLS client authentication/binding
  # OAUTHRESOURCE:  RFC8707 # Resource Indicators
  OASIS.saml-core-2.0-os:
  # USASCII:                # 7 bit ASCII
  #   title: "Coded Character Set -- 7-bit American Standard Code for Information Interchange, ANSI X3.4"
  #   author:
  #     name: "American National Standards Institute"
  #   date: 1986
  # W3C.REC-html401-19991224: # HTML 4.01
  # W3C.REC-xml-20081126: # XML 1.0 5th Ed
  OpenID.Core: # Openid Connect Core 1.0
    title: "OpenID Connect Core 1.0"
    target: https://openiD.net/specs/openiD-connect-core-1_0.html
    date: November 8, 2014
    author:
      - ins: N. Sakimora
      - ins: J. Bradley
      - ins: M. Jones
      - ins: B. de Medeiros
      - ins: C. Mortimore
  # OpenID.Messages: # Openid Connect Messages
  #   title: "OpenID Connect Messages 1.0"
  #   author:
  #     - ins: N. Sakimura
  #     - ins: J. Bradley
  #     - ins: M. Jones
  #     - ins: B. de Medeiros
  #     - ins: C. Mortimore
  #     - ins: E. Jay
  #   date: June 2012
  #   target: http://openid.net/specs/openid-connect-messages-1_0.html
  # owasp_redir: # OWASP Cheet Sheet Series - Unvalidated Redirects
  #   title: "OWASP Cheat Sheet Series - Unvalidated Redirects and Forwards"
  #   target: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
  #   date: 2020
  ANONCRED:
    title: "An Efficient System for Non-trasferable Anonymous Credentials with Optional Anonymity Revocation"
    target: https://eprint.iacr.org/2001/019.pdf
    author:
      - ins: J. Camenisch
      - ins: A. Lysyanskaya
    date: 2001
  

---
abstract

User authentication and attributes are exchanged online today between organizations based on bilateral business arrangements, with user consent and privacy provided as desired by the organization(s) involved.

MultiPass is a system intended for an organization to issue credentials unilaterally, where other organizations can evaluate credentials without having a relationship to the issuing party. This is accomplished by leveraging a software agent, which allows this exchange to be done in a manner which can respect user privacy and support informed decisions around disclosure.

This specification provides a mechanism to retrieve single-use tickets, which bundle cryptographically secure credentials in a non-correlatable, selectively disclosable manner.

---
middle

# Introduction
{:#introduction}

Existing multi-organizatinal identity systems such as SAML ({{OASIS.saml-core-2.0-os}}) and OpenID Connect ({{OpenID.Core}}) are designed to share authentication information and claims about the user across organizations. The basis for this exchange is typically a bilateral business relationship and mutual trust between the organizations. The user may or may not have been informed of have consented to this disclosure, depending on the policies and the regulations that the entities operate under.

Verifiable Credential systems {{W3C.REC-vc-data-model-20191119}} aim to introduce a new role into the system, that of a software agent which mediates this exchange of information about the user. This agent decouples the entities from needing a business relationship, as well as takes responsibility for protecting privacy and providing the user with the opportunity for informed disclosure and consent.

This specification describes a container for retrieving a set of credentials from a single issuer, known as a *Multipass Ticket*. These tickets are single use, cryptographically verifiable statements by a particular issuer. For compatibility with existing identity systems, this issuer acts as a protected resource under the OAuth 2.0 Authorization Framework described in ({{OAUTH2}}). There may be other methods for retrieving multipass tickets, which are out of scope of this specification.

This specification also defines mechanisms to prove possession of a key associated with the ticket to the relying party, and one mechanism for verifying credentials were asserted by the issuer.

Finally, this specification describes the data expected in a request by a party for credentials, as well as the cryptographic format of the presentation of those credentials back to the requesting party. This specification does not define a profile for requesting or sending multipass tickets to recipients, which may operate in roles such as "Relying Parties" or "Verifiers" within such profiles.

## Notational Conventions

{::boilerplate bcp14+}

Certain security-related terms are to be understood in the sense defined in {{SECURITY}}.  These terms include, but are not limited to,
"air gap", "anonymity", "assymmetric cryptography", "attribute", "authentication", "authorization", "certificate", "challenge-response", "credential", "data integrity", "domain", "domain name", "enclave", "encryption", "ephemeral key", "expire", "fresh", "identifier", "identity", "identity proofing", "integrity", "privacy", "private key", "proof-of-possession", "protocol", "public key", "repudiation", "sign", "signature", "single sign-on", "steganography", "trust", "validate", "validity period", "verify", and "zero-knowledge proof"

Unless otherwise noted, all the protocol parameter names and values
are case sensitive.

This specification also defines or revises the following terms:

Credential:
: A data object representing some aspects of the identity of the subject. This includes (but is not limited to) attributes about the subject, an event associated with the subject, identifiers unique to the subject, a definition of how to authenticate a party as the subject, and authorizations of the subject. This specification places requirements on credentials but does not dictate a format for these data objects.

Selective Disclosure:
: In the context of set of credentials, or of an individual credential format which supports selective disclosure, the ability to release just a subset of the amount of information available when given to a verifier.

Ticket:
: In this context, a multipass ticket. A cryptographic message with a mechanism to verify proof of possession by the holder, and to define how to verify credentials are being asserted by the issuer. To prevent correlation between parties, this ticket is meant to be single-use.

## Roles

~~~ text/plain
               requests                  requests
+-----------+  multipass  +-----------+ credentials +-----------+
|           |<------------|           |<------------|           |
|  Issuer   |             |  Holder   |             | Verifier  |
|           |------------>|           |------------>|           |
+-----------+   issues    +-----------+             +-----------+
      ^        multipass                 presents
      |                                 credentials
      |
      |                   +-----------+
      |                   |           |
      +-------------------|  Subject  |
              authorizes  |           |
                Holder    +-----------+
~~~
{: #fig-roles title="Roles"}

Multipass defines four roles beyond OAuth:

Subject:
: An entity being described by the issue, such as the OAuth resource owner/end-user.

Holder:
: An application which acts as a client, requesting and holding onto multipass tickets on behalf of the subject. This may also be referred to sometimes as a "wallet." This application may be operated by a party other than the subject.

Issuer:
: An application issuing multipass tickets to the holder. In the context of this specification, this entity is an OAuth 2 protected resource. This party issues tickets containing credentials which other parties trust.

Verifier:
: An application requesting credentials which meet certain requirements, such as which issuers are supplying them, and which can verify the presented credentials.

## Protocol Flow

~~~~~~~~~~ text/plain
+--------------+  1. Discover Metadata        +---------------+
|              |  ------------------------>   |               |
|              |                              |Issuer Metadata|
|              |  2. Return Metadata          |   Endpoint    |
|              |  <------------------------   |               |
|              |                              +---------------+
|              |                                               
|              |  3. Authorize Holder         +---------------+
|              |  ------------------------>   |               |
|    Holder    |                              | Authorization |
|              |  4. Return OAuth tokens      |    Server     |
|              |  <------------------------   |               |
|              |                              +---------------+
|              |                                               
|              |  5. Request multipass        +---------------+
|              |  ------------------------>   |               |
|              |                              |   Multipass   |
|              |  6. Return generated ticket  |   Endpoint    |
|              |  <------------------------   |               |
+--------------+                              +---------------+
~~~~~~~~~~
{: #fig-retrieval-flow title="Retrieval Flow"}

The abstract flow illustrated in {{fig-retrieval-flow}} describes the interaction between the holder, authorization server and issuer to retrieve tickets.

1. The Holder retrieves metadata for the issuer to understand the requirements and capabilities of the Issuer.

2. The Metadata Endpoint returns the issuer metadata along with information on the appropriate Authorization Server.

3. The Holder requests authorization from the Authorization Server as described in ({{OAUTH2}}), by specifying a scope of `multipass`.

4. The Authorization Server returns an access token and optional refresh token to the holder.

5. The Holder requests a multipass ticket from the Multipass Endpoint, leveraging the previously discovered metadata. This request includes an ephemeral public key, which should be unique per request and be different from any cryptographic keys which might be used as part of client authorization to the Authorization or for access token usage.

6. The issuer returns a generated single-use ticket, with confirmation set to use the supplied ephemeral key.

Verifiers request credentials be presented to them, claimed by an Issuer with appropriate cryptographic proof. The presentation is constructed by the holder - based on statements from the issuer contained within the multipass ticket and for credentials the issuer asserts.

The multipass ticket may already have been retrieved and cached for later use (within the validity period of the ticket), or may be retrieved through the process of answering the issuer's request.

~~~~~~~ text/plain
+--------------+  1. Request presentation     +---------------+
|              |  ------------------------>   |               |
|              |                     +-----   |               |
|              |  2. Gather consent  |        |               |
|              |  and construct      |        |               |
|              |  presentation       |        |    Holder     |
|              |                     +---->   |               |
|              |                              |               |
|              |  3. Return presentation      |               |
|              |  <------------------------   |               |
|              |                              +---------------+
|   Verifier   |                                               
|              |                                               
|              |  4. Discover Metadata        +---------------+
|              |  ------------------------>   |               |
|              |                              |Issuer Metadata|
|              |  5. Return Metadata          |   Endpoint    |
|              |  <------------------------   |               |
|              |                              +---------------+
|              |  -----+                                       
|              |       |  6. Verify presentation               
|              |       |  and credentials                      
|              |  <----+                                       
+--------------+                                               
~~~~~~~
{: #fig-usage-flow title="Usage Flow"}

1. The Verifier requests a presentation of credentials, stating its requirements in terms of appropriate issuers, understood credential formats, and/or the attributes desired within those credentials.
2. The Holder interacts with the subject to make sure that the subject understands the information requested. If the user approved disclosure, the holder constructs the presentation of credentials.

3. The Holder returns the constructed presentation to the Verifier

4. If the verifier does not have appropriate information on the issuer, such as if a cached copy of the metadata has expired or if this issuer is one that the Verifier has not previously interacted with, the Issuer will fetch the metadata from the issuer.

5. The Issuer Metadata endpoint returns the current metadata

6. Using the presentation and issuer metadata, the verifier will verify the cryptographic message and make a determination of whether policy will allow it to trust the contained credentials.

## Multipass ticket format

A multipass ticket is single-use cryptographic package used to form a credential presentation to a verifier. It consists of a collection of individually packaged credentials about the resource owner, which may be selectively disclosed to minimally meet the needs of the verifier.

~~~~~~~~~~ text/plain
+------------------------------------------+
|                                          |
|             Multipass Ticket             |
|                                          |
| +--------------------------------------+ |
| |                                      | |
| |           Issuer Statement           | |
| |                                      | |
| +--------------------------------------+ |
|                                          |
| +----------------------------------+     |
| |                                  +-+   |
| |        Credential Statements     | +-+ |
| |                                  | | | |
| +-+--------------------------------+ | | |
|   +-+--------------------------------+ | |
|     +----------------------------------+ |
|                                          |
+------------------------------------------+
~~~~~~~~~~
{: #fig-multipass-structure title="Multipass Structure"}

### Issuer Statement
{: #issuer-statement}

The issuer statement is a signed JWT containing information which is both non-identifying and non-correlating of the user, which will be disclosed to all verifiers.

The JWT contains the following keys, defined by ({{JWT}}) and ({{JWTPOP}})

{: vspace="0"}
iss
:    REQUIRED.  This value MUST uniquely identifies the issuer. It SHOULD be a "https" scheme URL usable for metadata discovery per ({{OAUTHMETA}}).

aud
:    OPTIONAL. This value indicates recipient(s) that the JWT is intended for. If an audience is specified, the multipass MUST NOT be presented to a recipient that is not part of that audience.

exp
:    REQUIRED. The expiration time after which the multipass MUST NOT be presented to a verifier and MUST NOT be accepted by a verifier for processing.  A holder MAY use expiry to proactively acquire one or more new multipasses. The expiration SHOULD take into account the validity period of associated credentials. It is RECOMMENDED that expiry times have low precision or other mechanisms to prevent statistical correlation of multiple passes retrieved by the holder simultaneously.

jti
:    OPTIONAL. A unique identifier for the JWT. MAY be used for communicating out-of-band from a verifier to an issuer about this multipass and the associated resource owner.

cnf
:    REQUIRED. Used to provide proof-of-possession of the holder to the verifier. It is RECOMMENDED that this be a public key in the form of a point on the P-256 curve.

cdv
:    OPTIONAL. Used to provide cryptographic verification of credentials.

Issuer statements MAY provide additional information. This additional information MUST NOT contain identity information of the subject, or be usable to uniquely identify the subject or correlate the subject across multiple verifiers.

As a specific example, this information MUST NOT indicate the subject belong to a subset at a particular issuer who have access to a particular credential, such as by including an additional mechanism to verify that credential format. The `cdv` property is provided specifically so that that verification information can be included separately from the issuer statement, as part of the credential itself. The issuer statement MAY include such information if it does not distinguish the subject as belonging to a subset, but a requirement to do so might serve as a limitation of that credential format in other environments.

### Credential Verification

The Credential Verification object within the issuer statement describes how to verify that any credentials presented alongside the issuer statement are valid.

The Credential verification object of an ephemeral public key (as a `jwk` property) which can be leveraged by the issuer to sign credentials.

## Credentials

A multipass is a statement by the issuer of multiple credentials about the subject, which may be selectively disclosed by the holder to a verifier. Selective disclosure allows for presented credentials to be limited to the information requested by a verifier.

The format of a credential is out of scope of this specification, outside of providing the credential validation key (`cdv`) in the issuer statement.

The holder will typically only offer credentials to a relying party which it understands and can properly prompt the user to consent to release. Issuers offer credentials in the formats they supports, containing the attributes they offer. Validators indicate that they require a certain set of attributes, and the credential formats they support those attributes in.

### Credential Format Requirements

A specification which defines a credential format is RECOMMENDED to define:

- The mechanism for an issuer to create a credential, or to determine if it should assert a credential it acquired from another system or party
- The mechanism for proving the credential is associated with the ticket, such as a signature by the `cdv` key
- The mechanism for a verifier to validate the credential within a presentation
- The relationship of the credential with the subject
- The process for a holder creating a presentation of your credential, including leveraging any features your credential may support such as selective disclosure of data
- Recommendations on how a holder present your credential within a UX for informed consent

## Multipass Protocol

## Multipass ticket request

Given an appropriate access token, the holder requests a multipass ticket via POST to the multipass ticket endpoint.

The parameters of the request are:

{: vspace="0"}
jwk
:     REQUIRED. A JSON Web Key ({{JWK}}) describing the public key of a uniquely generated key pair by the client. A holder MUST NOT reuse this key pair for multiple passes or for other uses. For compatibility, is RECOMMENDED that this key be a point on the P-256 curve.

attribute_contexts
:     OPTIONAL. A list of one or more contexts supported by the issuer. An issuer MAY limit the attributes returned based on this list, if provided. If omitted, the issuer SHOULD determine appropriate attributes based on the subject and holder.

## Multipass ticket response

The multipass ticket response consists of a JSON {{JSON}} object body with keys representing the issuer statement, holder usage data, and attributes. These values are used by the holder to assemble a multipass presentation.

{: vspace="0"}
issuer_statement
:     REQUIRED. A JWT from the issuer to be sent with the presentation, as described in [Issuer Statement](#issuer-statement)

holder_usage
:     REQUIRED. A JSON object giving any information necessary for proving possession beyond the `cnf` value in the issuer statement.

attribute_contexts
:     REQUIRED. The contexts which were supplied by the issuer. The format of any supplied attributes are identified by these contexts. An issuer MUST NOT send attributes not represented by a specified context.

attributes:
:     REQUIRED. A collection of zero or more attributes defined by the supported attribute contexts.

## Multipass Presentation

The multipass presentation is the data model to be leveraged by profiles describing how the verifier interacts with the holder.

## Multipass Presentation Request

A presentation request is represented by an object with several keys:

## Future Considerations

A future system may support multi-use tickets by leveraging a different cryptographic protocol, such as anonymous credentials ({{ANONCRED}}). However, the difference in security is such that this likely should be a separate specification.

This system does not attempt to resolve the ability of the issuer and validator to collude to determine the identity of the subject.  In addition to a `jti` claim in the issuer statement, the issuer could use the uniqueness of the statement itself to correlate a statement to a particular issuance and the corresponding holder and user.

The ticket itself does not have a revocation mechanism, instead leveraging the expiry of the tickets themselves.
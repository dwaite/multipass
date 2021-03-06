---
title: Multipass Container Retrieval
abbrev: Multipass Retrieval
docname: draft-waite-multipass-retrieval-latest
date: 2020-07-30
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
 -
    ins: J. Miller
    organization: Ping Identity
    email: jmiller@pingidentity.com

normative:
  SECURITY:   RFC4949 # Internet Security Glossary
  OAUTH2:     RFC6749
  JSON:       RFC7159
  JWK:        RFC7517
  JWA:        RFC7518
  JWT:        RFC7519
  OAUTHMETA:  RFC8414 # OAuth Server Metadata
  # I-D.ietf-oauth-security-topics:

informative:
  # OAUTHREG:       RFC7591 # OAuth Dynamic Client Registration
  # OAUTHPKCE:      RFC7636 # OAUTH PKCE
  # APPAUTH:        RFC8252 # OAuth for Native Apps
  # OAUTHMTLS:      RFC8705 # OAuth MTLS client authentication/binding
  JWTPOP:         RFC7800 # PoP Key Semantics for JWTs
  # OAUTHRESOURCE:  RFC8707 # Resource Indicators
  OASIS.saml-core-2.0-os:
  # USASCII:                # 7 bit ASCII
  #   title: "Coded Character Set -- 7-bit American Standard Code for Information Interchange, ANSI X3.4"
  #   author:
  #     name: "American National Standards Institute"
  #   date: 1986
  # W3C.REC-html401-19991224: # HTML 4.01
  # W3C.REC-xml-20081126: # XML 1.0 5th Ed
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

Multipass is a system intended for an organization to issue credentials unilaterally, where other organizations can evaluate credentials without having a relationship to the issuing party. This is accomplished by leveraging a software agent, which allows this exchange to be done in a manner that is able to respect user privacy and support informed decisions around disclosure.

This specification provides a mechanism to retrieve single-use containers, which bundle cryptographically secure credentials in a non-correlatable, selectively disclosable manner.

---
middle

# Introduction
{:#introduction}

Existing multi-organizatinal identity systems such as SAML ({{OASIS.saml-core-2.0-os}}) and OpenID Connect ({{OpenID.Core}}) are designed to share authentication information and claims about the user across organizations. The basis for this exchange is typically a bilateral business relationship and mutual trust between the organizations. The user may or may not have been informed of have consented to this disclosure, depending on the policies and the regulations that the entities operate under.

Verifiable Credential systems {{W3C.REC-vc-data-model-20191119}} aim to introduce a new role into the system, that of a software agent which mediates this exchange of information about the user. This agent decouples the entities from needing a business relationship, as well as takes responsibility for protecting privacy and providing the user with the opportunity for informed disclosure and consent.

This specification describes the process for retrieving and handling a set of credentials from a single issuer, known as a *Multipass Container*. These containers are single use, cryptographically verifiable statements by a particular issuer. For compatibility with existing identity systems, this issuer acts as a protected resource under the OAuth 2.0 Authorization Framework described in ({{OAUTH2}}). There may be other methods for retrieving multipass containers, which are out of scope of this specification.

This specification also defines mechanisms to prove possession of a key associated with the container to the relying party, and for verifying the credentials were asserted by the issuer.

Finally, this specification describes the data expected in a request by a party for credentials, as well as the cryptographic format of the presentation of those credentials back to the requesting party. This specification does not define a profile for requesting or sending multipass containers to recipients, which may operate in roles such as "Relying Parties" or "Verifiers" within such profiles.

## Notational Conventions

{::boilerplate bcp14+}

Certain security-related terms are to be understood in the sense defined in {{SECURITY}}.  These terms include, but are not limited to,
"air gap", "anonymity", "assymmetric cryptography", "attribute", "authentication", "authorization", "certificate", "challenge-response", "credential", "data integrity", "domain", "domain name", "enclave", "encryption", "ephemeral key", "expire", "fresh", "identifier", "identity", "identity proofing", "integrity", "privacy", "private key", "proof-of-possession", "protocol", "public key", "repudiation", "sign", "signature", "single sign-on", "steganography", "trust", "validate", "validity period", "verify", and "zero-knowledge proof"

Unless otherwise noted, all the protocol parameter names and values are case sensitive.

This specification also defines or revises the following terms:

Credential:
: A data object representing some aspects of the identity of the subject. This includes (but is not limited to) attributes about the subject, an event associated with the subject, identifiers unique to the subject, a definition of how to authenticate a party as the subject, and authorizations of the subject. This specification places requirements on credentials but does not dictate a format for these data objects.

Selective Disclosure:
: In the context of set of credentials, or of an individual credential format which supports selective disclosure, the ability to release just a subset of the amount of information available when given to a verifier.

Container:
: In this context, a multipass container. A cryptographic message with a mechanism to verify proof of possession by the holder, and to define how to verify credentials are being asserted by the issuer. To prevent correlation between parties, this container is meant to be single-use.

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
: An application which acts as a client, requesting and holding onto multipass containers on behalf of the subject. This may also be referred to sometimes as a "wallet." This application may be operated by a party other than the subject.

Issuer:
: An application issuing multipass containers to the holder. In the context of this specification, this entity is an OAuth 2 protected resource. This party issues containers containing credentials which other parties trust.

Verifier:
: An application requesting credentials which meet certain requirements, such as which issuers are supplying them, and which can verify the presented credentials.

## Protocol Flow

~~~~~~~~~~ text/plain
+--------------+  1. Discover Metadata          +---------------+
|              |  -------------------------->   |               |
|              |                                |Issuer Metadata|
|              |  2. Return Metadata            |   Endpoint    |
|              |  <--------------------------   |               |
|              |                                +---------------+
|              |                                               
|              |  3. Authorize Holder           +---------------+
|              |  -------------------------->   |               |
|    Holder    |                                | Authorization |
|              |  4. Return OAuth tokens        |    Server     |
|              |  <--------------------------   |               |
|              |                                +---------------+
|              |                                               
|              |  5. Request multipass          +---------------+
|              |  -------------------------->   |               |
|              |                                |   Multipass   |
|              |  6. Return generated container |   Endpoint    |
|              |  <--------------------------   |               |
+--------------+                                +---------------+
~~~~~~~~~~
{: #fig-retrieval-flow title="Retrieval Flow"}

The abstract flow illustrated in {{fig-retrieval-flow}} describes the interaction between the holder, authorization server and issuer to retrieve containers.

1. The Holder retrieves metadata for the issuer to understand the requirements and capabilities of that issuer.

2. The Metadata Endpoint returns the issuer metadata along with information on the appropriate Authorization Server.

3. The Holder requests authorization from the Authorization Server as described in ({{OAUTH2}}), by specifying a scope of `multipass`.

4. The Authorization Server returns an access token and optional refresh token to the holder.

5. The Holder requests a multipass container from the Multipass Endpoint using the access token, leveraging the previously discovered metadata. This request includes an ephemeral public key, which should be unique per request and be different from any cryptographic keys which might be used as part of client authorization to the Authorization Server or for access token usage.

6. The issuer returns a generated single-use multipass container, bound to the supplied ephemeral key for proof of possession.

Verifiers request credentials be presented to them from a holder and asserted by an issuer with appropriate cryptographic proof. The presentation is constructed by the holder based on statements from the issuer contained within the multipass container and from the credentials asserted by the issuer.

The selected multipass container may already have been retrieved and cached for later use (within the validity period of the container), or may be retrieved on demand as part of the process of answering the validator's request.

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

3. The Holder returns the constructed presentation to the verifier.

4. If the verifier does not have appropriate information on the issuer, such as if a cached copy of the metadata has expired or if this issuer is one that the verifier has not previously interacted with, the verifier will fetch the metadata from the issuer.

5. The Issuer's metadata endpoint returns the current metadata.

6. Using the presentation and issuer metadata, the verifier is then able to verify the cryptographic message and make a determination of whether its policy will allow it to trust the presented credentials.

## Multipass Container Format

A multipass container is single-use cryptographic package used to form a credential presentation to a verifier from an issuer via a holder. It consists of a collection of individually packaged credentials about the subject, which may be selectively disclosed to minimally meet the needs of the verifier and protect the privacy of the subject.

~~~~~~~~~~ text/plain
+------------------------------------------+
|                                          |
|             Multipass Container          |
|                                          |
| +--------------------------------------+ |
| |                                      | |
| |           Issuer Statement           | |
| |                                      | |
| +--------------------------------------+ |
|                                          |
| +----------------------------------+     |
| |                                  +-+   |
| |           Credential Data        | +-+ |
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

The Issuer Statement is a signed JWT containing information which is both non-identifying and non-correlating of the user, which will be disclosed to all verifiers.

The JWT contains the following claims, defined by ({{JWT}}) and ({{JWTPOP}})

{: vspace="0"}
iss
:    REQUIRED.  This value MUST uniquely identifies the issuer. It SHOULD be a "https" scheme URL usable for metadata discovery per ({{OAUTHMETA}}).

aud
:    OPTIONAL. This value indicates recipient(s) that the JWT is intended for. If an audience is specified, the multipass MUST NOT be presented to a recipient that is not part of that audience.

exp
:    REQUIRED. The expiration time after which the multipass MUST NOT be presented to a verifier and MUST NOT be accepted by a verifier for processing.  A holder MAY use expiry to proactively acquire one or more new multipasses. The expiration SHOULD take into account the validity period of associated credentials. It is RECOMMENDED that expiry times have low precision or other mechanisms to prevent statistical correlation of multiple passes retrieved by the holder simultaneously.

jti
:    OPTIONAL. A unique identifier for the JWT. It MAY be used for communicating out-of-band from a verifier to an issuer about this multipass and the associated subject (such as in the case of abuse). It MUST NOT contain any information about the subject that could be used to correlate multiple containers.

cnf
:    REQUIRED. Used to provide proof-of-possession of the holder to the verifier. It is RECOMMENDED that this be a public key in the form of a point on the P-256 curve.

The JWT may also contain the following additional claim:

cdv
:    OPTIONAL. A key the issuer may have used for integrity and non-repudiation of credentials.

Issuer statements MAY provide additional information. This additional information MUST NOT contain identity information of the subject, or be usable to uniquely identify the subject or correlate the subject across multiple verifiers.

As a specific example, this information MUST NOT indicate the subject belong to a subset at a particular issuer who have access to a particular credential, such as by including an additional mechanism to verify that credential format. The `cdv` property is provided specifically so that that verification information can be included separately from the issuer statement, as part of the credential itself. The issuer statement MAY include such information if it does not distinguish the subject as belonging to a subset, but a requirement to do so might serve as a limitation of that credential format in other environments.

## Credentials

A multipass container is an assertion by the issuer of one or more credentials about the subject, which may be selectively disclosed by the holder to a verifier. Selective disclosure allows for presented credentials to be limited to only the information requested by a verifier. In addition to selecting which credentials are disclosed, some credential formats MAY also allow portions of the credential to be selectively disclosed.

The format of a credential data is out of scope of this specification, outside of providing the credential validation object (`cdv`) in the issued container. The credential validation object contains an ephemeral public key (as a `jwk` property) which is leveraged by some credential formats to verify that credential data is asserted by the issuer. The credential data MAY contain information only meant for the holder in order to properly present the credential to the issuer, and MAY define a verification method other than the `cdv` public key.

The holder will typically only offer credentials to a relying party which it understands and can properly prompt the user to consent to release. Issuers offer credentials in the formats they support, containing the attributes they can assert about the subject. Validators indicate that they require a certain set of attributes along with the credential formats they support to receive them.

### Credential Format Requirements

A specification which defines a credential format is RECOMMENDED to define:

1. The mechanism for an issuer to create a credential, or how to determine if it should assert a credential from another system or party
2. The mechanism for verifying the credential is associated with a presentation, such as a signature by the `cdv` key
3. The relationship of the credential with the subject
4. The process for a holder creating a presentation of the credential, including leveraging any features the credential may support such as selective disclosure of data
5. Recommendations on how a holder should present the credential within a UX for informed consent

A credential format MAY impact all stages of the multipass protocol described below, including:

1. Declare metadata on how it is meant to be used, such as supported cryptographic properties or potentially available attributes about subjects.
2. Support or require information on the multipass request from the holder to the issuer.
3. Provide information in the multipass container, such as credential data to include in a presentation or information the holder needs to properly present the credential.
4. Define parameters in a presentation request, such as the list of required attributes for service. Such a list could affect the UX of the holder, allow for selective disclosure, or result in a presentation request being rejected as being unable to be met.
5. Define the mechanism to present the credential to the verifier.

## Multipass Protocol

### Multipass Metadata Endpoint

The Multipass Metadata Endpoint builds upon the OAuth Authorization Server Metadata format ({{OAUTHMETA}}.) When using the OAuth Application Server metadata, the OAuth issuer and Multipass issuer have the same URI name.

It is RECOMMENDED that metadata be retrieved using the process detailed in Section 3 of {{OAUTHMETA}}, first attempting to resolve the URL suffix "oauth-authorization-server", then attempting to resolve the URL suffix "openid-configuration" using the same process. {{OpenID.Core}} describes a different, non-standard location for "openid-configuration" metadata when the issuer URL contains a path - Issuers SHOULD NOT assume that Holders or Verifiers will attempt to resolve this location, and SHOULD either move or duplicate their metadata to the location specified by {{OAUTHMETA}}.

### Multipass Metadata Values

Multipass Metadata values are grouped under a property with the `multipass` metadata name.

{: vspace="0"}
credentials_supported:
:  REQUIRED. An object with keys indicating the credential formats available. The value associated with this key MUST either be defined by the credential format, or be `true` to indicate support.

jwks_uri:
:  REQUIRED. The URI of the JWKS endpoint for the multipass issuer. The multipass issuer has a separate JWKS endpoint from the authorization server to support differing keys, rotated on a different schedule.

retrieval_endpoint:
:  REQUIRED. The `https` scheme URL of the multipass endpoint.

holder_cnf_alg_values_supported:
:  OPTIONAL. JSON array containing a list of JWS signing algorithms which can be supplied by the holder and used during presentation. Omitting this value is equivilant to specifying a single algorithm of `ES256` (ECDSA using P-256 and SHA-256). It is RECOMMENDED that `ES256` be supported for compatibility.

### Multipass Container Request

Given an appropriate access token, the holder requests a multipass container via POST to the multipass container endpoint.

The parameters of the request are:

{: vspace="0"}
holder_jwk:
:     REQUIRED. A JSON Web Key ({{JWK}}) describing the public key of a uniquely generated key pair by the client. A holder MUST NOT reuse this key pair for multiple passes or for other uses. For compatibility, is RECOMMENDED that this key use the ES256 algorithm specified by {{JWA}}.

credentials_requested:
:     OPTIONAL. A dictionary of credential formats. The value of this dictionary is defined by the credential format, but MAY support `true` as a default configuration and MUST use `true` if no configuration is defined for a given credential format. An issuer takes this as advice, and MAY return more credentials than requested or omit requested credential formats.

### Multipass Container Response

The multipass container response consists of a JSON {{JSON}} object body with keys representing the issuer statement and credentials. These values are used by the holder to assemble a multipass presentation.

{: vspace="0"}
issuer_statement:
:     REQUIRED. A JWT from the issuer to be sent with the presentation, as described in [Issuer Statement](#issuer-statement)

credentials:
:     REQUIRED. A dictionary of credentials, with keys indicating credential formats. The credential format describes both the structure of the credential and how to present it. For example, the value of a credential format may be a string holding a compact JWS message, signed using the key described by the `cdv` claim.

## Multipass Presentation

A relying party interacts with this system by requesting credentials from a holder, and being either presented back with those credentials or being given an error. This specification details the data format used for this request and the resulting presentation, while the semantics of the communication channel between the relying part and holder are considered out of scope.

### Presentation Request

A Presentation Request is represented by a JSON object with several keys.

{: vspace="0"}
rpid:
: REQUIRED. A valid domain string which identifies the relying party. Credentials are only meant for this relying party, and a credential format MAY restrict itself to only being readable by this relying party.

: The communications channel SHOULD guarantee the relying party initiating the request corresponds to the `rpid` parameter. For a relying party with a HTTPS identifier, this value should be the relying party's [effective domain](https://html.spec.whatwg.org/multipage/origin.html#concept-origin-effective-domain) or a registrable domain suffix of that effective domain.

issuers:
: REQUIRED. An array of acceptable issuer identifiers.

timeout:
: OPTIONAL. The time, in milliseconds, that the relying party is willing to wait for the call to complete. This is meant as a hint to software providing the transport or the holder functionality, which is given flexibility to select a default or alternative value.

challenge:
: REQUIRED. A binary challenge value to prevent replay attacks. This value MUST be randomly generated by the relying party in a trusted environment, and the value MUST be present in the resulting presentation.

required_credentials:
: REQUIRED. An object representing all required credentials. The keys of the object reference credential formats by name, while the corresponding values hold any configuration or data requests appropriate for that credential format. If a credential format does not specify additional request parameters, the corresponding value MUST be `true`.

optional_credentials:
: OPTIONAL.  An object representing all optional credentials. The keys of the object reference credential formats by name, while the corresponding value holds any configuration  or data requests appropriate for that credential format. If a credential format does not specify additional request parameters, the corresponding value MUST be `true`.

### Presentation

A presentation is the successful response to a relying party's presentation request. It is a signed {{JWT}}, protected by the ephemeral keypair represented within the issuer statement of a multipass container.

The JWT contains the following claims:

{: vspace="0"}
issuer_statement:
: REQUIRED. The JWT issuer statement within the multipass container

credentials:
: REQUIRED. An object representing all returned credentials. The keys of the object reference credential formats by name, while the corresponding values hold any mandated data.

: Credentials may be transmitted by value or by reference, and will have their own mechanism for validating they were correctly asserted by the issuer. One example would be a credential formatted as a JWS, with a signature verifiable using the `cdv` public key.

rpid:
: REQUIRED. The originally requested relying party identifier.

challenge:
: REQUIRED. The originally supplied challenge value, url-safe base64 encoded.

## Future Considerations

A future system may support multi-use containers by leveraging a different cryptographic protocol, such as anonymous credentials ({{ANONCRED}}). However, the difference in security is such that this likely will be a separate specification.

This system does not attempt to resolve the ability of the issuer and validator to collude to determine the identity of the subject.  In addition to a `jti` claim in the issuer statements, the issuer could use the uniqueness of the statements themselves to correlate any statement to a particular issuance and the corresponding holder and subject.

The container itself does not have a revocation mechanism, instead leveraging the expiry of the containers themselves. Accordingly, containers should have short expirations that properly accomodate potential offline or disconnected use cases.

In addition to requests against issuers, a brokered trust model (requesting an issuer within a network) will likely be desirable.

The current presentation response format limits the response to credentials from a single issuer. It should be possible to extend this presentation response to being from multiple issuers, although some scenarios may make it difficult to use a single ephemeral key.

The current issuer text is perhaps not flexible enough allow for other kinds of issuers, such as local (self-asserted) information or the use of a local authentication credential such as a client certificate or FIDO authenticator. The intention is that these would be possible within the framework described.

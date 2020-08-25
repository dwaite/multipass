---
title: Multipass Credential Type Template
abbrev: multicred template
docname: draft-template-credential-type-latest
date: 2020-08-20
category: exp

ipr: trust200902
area: General
workgroup: None
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs, comments]

author:
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
  draft-waite-multipass-retrieval:
    target: https://dwaite.github.io/multipass/
    title: Multipass Container Retrieval
    author:
       - ins: D. Waite
       - ins: J. Miller
    date: July 20, 2020
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

[//]: # "Add a description of the credential type and what the purpose is, e.g. describe how to use a web authentication credential"

This specification defines a credential type to DO STUFF.

---
middle

# Introduction
{:#introduction}

Multipass describes a process for retrieving and handling a set of credentials from a single issuer, known as a *Multipass Container*. These containers are single use, cryptographically verifiable statements by a particular issuer, containing or referencing credentials of various types - representing user attributes, authentication, and authorization. Multipass also defines mechanisms to prove possession of a key associated with the container to the relying party, and for verifying the credentials were asserted by the issuer.

This specification describes the data expected in a request by a party for a particular type of credential (CREDENTIAL NAME), as well as the cryptographic format of the presentation of this credential back to the requesting party.

## Notational Conventions

{::boilerplate bcp14+}

Certain security-related terms are to be understood in the sense defined in {{SECURITY}}.  These terms may include, but are not limited to,
"air gap", "anonymity", "assymmetric cryptography", "attribute", "authentication", "authorization", "certificate", "challenge-response", "credential", "data integrity", "domain", "domain name", "enclave", "encryption", "ephemeral key", "expire", "fresh", "identifier", "identity", "identity proofing", "integrity", "privacy", "private key", "proof-of-possession", "protocol", "public key", "repudiation", "sign", "signature", "single sign-on", "steganography", "trust", "validate", "validity period", "verify", and "zero-knowledge proof"

Unless otherwise noted, all the protocol parameter names and values are case sensitive.

This specification also leverages the terms and roles defined in {{draft-waite-multipass-retrieval}}

## Credential Type

### Overview

[//]: # "This section should describe the purpose of the credential, and the relationship of the credential to the subject. It should also define the credential type identifier, which will be the key used for the credential in metadata as well as all requests and responses"

Lorem ipsum dolor sit amet.

### Security and Privacy

[//]: # "This section should describe the security and privacy properties of the credential, expecially any exceptions to a default expectation of privacy (e.g. can be correlated across uses of multipass)"

Lorem ipsum dolor sit amet.

## Credential Metadata

[//]: # "This section should declare metadata advertising availability of the credential type, as well as information on how it is supported by the issuer (such as supported cryptographic properties, available attributes, etc)"

Lorem ipsum dolor sit amet.

## Holder Credential Request

[//]: # "This section should define the format of the request for a particular type of credential. This may be configuration, a reference to an externally available credential document, and/or a presentation of some proof credential information itself for the issuer to verify and then vouch for."

[//]: # "This section should should either include information on how the holder generates the request and the issuer creates the credential response from the request, or else these should be broken out into sections before and after this one (respectively)"

Lorem ipsum dolor sit amet.

## Container Credential Data

[//]: # "This should describe the information the holder gets back. More complex credentials may require processing by the holder in order to present them - this section should provide an overview of the data, while a later presentation section defines the operations required"

[//]: # "The `cdv` parameter may be leveraged to provide protection of credential data which may then be selectively disclosed to a verifier"

[//]: # "For more advanced credentials which require different verification than the `cdv` parameter, the `cdv` parameter can be indirectly as well. This parameter can be used to sign additional data for processing the credential type to a potential verifier."

Lorem ipsum dolor sit amet.

## Credential Presentation Request

[//]: # "This section describes the parameters a verifier can send when requesting a credential. Where it does not impact security, existing presentation values (such as the `challenge` and `rpid`) should be used rather than declaring new values."

[//]: # "This section can also describe the process of a verifier of processing metadata to determine how to send an appropriate request."

[//]: # "Especially for credentials that expose PII, it should be indicated whether a verifier should expect a partial credential or no credential should the user not hae the requested data or decide to not release said data. When creating a new credential, it is desirable to return no PII in the case where the full request cannot be met - the user privacy expectation is that their PII would not be released if the verifier is not going to accept what is presented and provide the requested service"

Lorem ipsum dolor sit amet.

## Holder Presentation Processing

[//]: # "The process of the holder to process the request with the existing credential data from the multipass container to create a presentable credential"

[//]: # "Instructions for user presentation for informed consent should go in this section."

[//]: # "The source of text is important - the verifier should ideally not affect presentation of the presentation request to the user except by selecting features. This text may be static to the implementation of the credential type with the holder, or may come from another source such as issuer metadata. Note that this text will often require localization, and the UX may be improved by knowing the appropriate text at implementation time rather than using dynamic text layout, etc."

[//]: # "The process for the holder creating a presentation of the credential should either be here or broken out into a following section. This may leverage information given above about how to present the request to the user, such as how to perform selective disclosure of a subset of attributes"

Lorem ipsum dolor sit amet.

## Credential Presentation Response

[//]: # "This section defines the resulting credential from processing, or an error response in the case where the request was not successful (due to processing or user consent issues)."

[//]: # "Steps for recovery from defined errors may belong in this or subsequent sections. For example, if the user indicated they would be willing to disclose a different set of attributes, an error might include information about what the user consented to return."

[//]: # "A credential definition might go as far as to include a single-use value to use to retry the presentation request, which would optimize the process (such as avoiding prompting the user again for consent)"

[//]: # "This section (or a separate following section) should describe how to verify the credential, such as via a signature by the `cdv` key"

Lorem ipsum dolor sit amet.

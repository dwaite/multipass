---
title: JWT Claim Credential Type
abbrev: JWT claim credential
docname: draft-waite-jwt-claim-credential
date: 2020-08-21
category: exp

ipr: trust200902
area: General
workgroup: None
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs, comments]

author:
  ins: D. Waite
  organization: Ping Identity
  email: david@alkaline-solutions.com

normative:
  SECURITY:   RFC4949 # Internet Security Glossary
  OAUTH2:     RFC6749
  JSON:       RFC7159
  JWK:        RFC7517
  JWA:        RFC7518
  JWT:        RFC7519
  OAUTHMETA:  RFC8414 # OAuth Server Metadata
  LANGTAG:    RFC5646
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

This specification defines a way to share a subset of attributes about a user stated by the credential issuer to a verifier. The process of selecting which attributes should be shared is performed by a holder in the user control, which can also provide informed consent options to the user.

---
middle

# Introduction
{:#introduction}

Multipass describes a process for retrieving and handling a set of credentials from a single issuer, known as a *Multipass Container*. These containers are single use, cryptographically verifiable statements by a particular issuer, containing or referencing credentials of various types - representing user attributes, authentication, and authorization. Multipass also defines mechanisms to prove possession of a key associated with the container to the relying party, and for verifying the credentials were asserted by the issuer.

This specification describes the data expected in a request by a party for a particular type of credential , as well as the cryptographic format of the presentation of this credential back to the requesting party.

## Notational Conventions

{::boilerplate bcp14+}

Certain security-related terms are to be understood in the sense defined in {{SECURITY}}.  These terms may include, but are not limited to,
"air gap", "anonymity", "assymmetric cryptography", "attribute", "authentication", "authorization", "certificate", "challenge-response", "credential", "data integrity", "domain", "domain name", "enclave", "encryption", "ephemeral key", "expire", "fresh", "identifier", "identity", "identity proofing", "integrity", "privacy", "private key", "proof-of-possession", "protocol", "public key", "repudiation", "sign", "signature", "single sign-on", "steganography", "trust", "validate", "validity period", "verify", and "zero-knowledge proof"

Unless otherwise noted, all the protocol parameter names and values are case sensitive.

This specification also leverages the terms and roles defined in {{draft-waite-multipass-retrieval}}

## Credential Type

### Overview

A JWT Claim credential shares attributes stated by some issuer to a verifier. The attributes within the credential are attributes about the subject, such as a contact email address or family name.

The credential is meant to only represent attributes of the subject, and does not represent other aspects the user identity. Other credential types should be used for authenticating the subject or for providing authorization scopes and policy decisions.

The credential consists of a series of JWS documents. This allows selective disclosure by the holder by choosing which JWS documents to share with a verifier.

The credential type identifier for JWS claim credentials is `jwt-claims`. This identifier serves as a key used in metadata as well as credential and presentation interactions.

### Security and Privacy

The credential consists of a series of JWS documents. This allows selective disclosure by the holder by choosing which JWS documents to share with a verifier.

The indivudal JWS documents are signed by the ephemeral multipass container key `cdv`. The existance of a particular claim for a user is hidden from verifiers until the JWS document associated with the claim is disclosed to the verifier.

The ability to partially or uniquely identify the subject is related to the claims released. A claim such as `gender` might separate a subject into one of two larger groups defined by traditional gender roles, or more specifically identify the subject if a non-traditional gender role is shared. The `sub` or `email` claims will likely uniquely identify the subject with that issuer.

## Supported JWT Claims

The JWT registry declares both claims which provide security properties (such as the expiry `exp`) and claims which indicate information about the subject (such as `sub` or `phone_number`). The majority of claims which provide information about a subject are declared as part of {{OpenID.Core}}.

This specification leverages and expands upon the OpenID process of creating specialized claims by suffixing the registered claim name with `#`.

In particular:

1. As described in {{OpenID.Core}} section 5.2, a string or reference may claim name may be suffixed with `#<language-tag>` (as defined in {{LANGTAG}}), to give the value appropriate for a particular locale or script. For human-readable/displayable text, this indicates an alternative displayable value. For a reference (such as a URL), this indicates the location of an alternative displayable value, such as a localized web page.
2. For numerical values, `#<predicate>:<value>` can be used to indicate the value holds the boolean value of the predicate evaluation against the claim.
3. For values which are objects, `#<key[.key]*>` indicates the object has been filtered to only include that key. For example, `address#postal_code` would only return the zip or postal code for the user's perferred phsyical mailing address.

If the claim name is a URL value, it is RECOMMENDED that the fragment identifier be usable in the same manner as declared above. It is NOT RECOMMENDED to use claim names which contain fragment identifiers.

For compatibility with OpenID Connect usage as well as URL formatting (which uses `#` as a delimiter for fragments), there is presently no way to indicate a combination of these values, such as a predicate applied to a value within an object claim.

## Claim Predicates

For numerical claim values, `#<predicate>:<value>` may be used to represent the boolean result of predicate evaluation. For example, a `power_level` claim might indicate the subject's fighting strength. To reduce the amount if information which may be shared with opponents, the issuer may give the option to only return whether the power level is over 8,000. This would be done by sharing a claim named `power_level#gt:8000`, which would have a value of `true` or `false`.

Predicate identifiers specified by this document are:

eq:
  :Equal to

gt:
  :Greater than

gte:
  :Greather than or equal

For simplicity, this list does not include the 'neq', 'lt', and 'lte' predicates. These can be determined by inverting the result of existing predicates.

This specification also does not declare more complex predicate relationships such as ranges. Instead, the attribute can be returned with two different predicates.

For exapmle, to determine appropriate opponents, both `power_level#gt:8000` and `power_level#gt:18000` might shared with a verifier. Note that this does provide more information to a verifier than if this was a single predicate.

## Claim Object Selection

For dictionary claim values, `#<key>` may be used to return the value of a particular key in the dictionary. This might be used, for example, to represent just the postal code or country of a subject's address.

If the key results in another dictionary, subkeys may also be supplied separated by a period, e.g. `#key.subkey`.

## Age Claim

The `age` claim indicates the non-negative integer number of years since a subject's recognized birth date, as evaluated at credential creation time. This value is usually represented in conjunction with the `gte` predicate, such as `age#gte:21` indicating whether a subject was 21 or over at the time of credential creation.

## Credential Metadata

Metadata under the `jwt-claims` key consists of a JSON object, where each key is a unique claim name which the holder MAY receive as part of a multipass, and be able to return to the verifier.

The value of each claim name key is a JSON object defining localized, displayable text for the holder to use in describing the claim. The value MAY be `true` if a holder is expected to already know the semantics of the claim. A holder MAY choose to not use the provided text for describing the claim to a user.

It is RECOMMENDED that a single base claim is used for values which may have language tags to specify multiple localizations/scripts.

It is RECOMMENDED that claims with predicates or object selection have each predicate/filter specified for verifiers to understand what they may request.

## Holder Credential Request

A holder requests a `jwt-claims` credential be included in the multipass container by specifying a `jwt-claims` credential request key with a value of `true`. The issuer SHOULD create a credential containing claims about the subject that the holder is allowed to disclose to issuers.

## Container Credential Data

Within a multipass container, the credential is represented as an array of compactly serialized JWS documents under the `jwt-claims` key.

The individual JWS documents have a media type of `application/jwt-claim`. The `typ` header parameter MUST indicate this, and SHOULD be set to `jwt-claim`.

The signature of the claim uses the key associated with the `cdv` public key value in the issuer statement. The `alg` header parameter MUST be present and MUST be set to the key type indicated by the `cdv` value. This parameter MUST NOT be `none`.

The contents of the JWS MUST be a JSON object, containing at least one JWT claim key/value pair. An issuer SHOULD create a JWS per distinct claim. For language-tagged claims, an issuer MAY choose to include multiple localizations of the claim within a single JWS.

An issuer MUST NOT include the same JWT claim within multiple returned JWS documents.

## Credential Presentation Request

A verifier requests a JWT claim credential via the `jwt-claims` key in the request JSON object.

The `jwt-claims` key is associated with a JSON object where each key represents a requested JWT claim name. These keys MAY also indicate aspects of the request for a particular JWT claim. This format is based on, but does not directly mirror, the Individual Claims Requests format in section 5.5.1 of {{OpenID.Core}}

The request for a particular claim may specify additional requirements by supplying a JWT object for the value of the claim name key. The value associated with the claim name key SHOULD be `null` if no requirements are necessary for the particular claim. The available requirements are specified via the following keys:

essential:
  :A value of `true` indicates the claim being requested is an essential claim for the verifier. An essential claim indicates that any presented credential cannot be successfully processed without the specified claim being returned.

values:
  :Specifies an array of at least one value expected for a claim. A claim request with required values indicates that a presented credential cannot be successfully processed without the specified claim indicating one of the specified values. Individual values MUST either be boolean, string, or numerical values.
  
  If "essential" is not indicated for the claim, the verifier is indicating that the claim should be omitted from the presented credential if it does not match one of the specified values.

predicates:
  :Indicates one or more predicates. A claim request with predicates indicates that the presented claim must meet the conditions of each predicate for a presented credential to be successfully processed. Predicate values are of the form `<predicate>:<value>`, with an additional optional prefix of '!' indicating the predicate is expected to evaluate to false.

  If "essential" is not indicated for the claim, the verifier is indicating that the claim should be omitted from the presented credential if it does not match all of the specified predicates.
  
## Holder Presentation Processing

The holder will process the presentation request against available credential data. The list of JWS documents within the credential data should be checked for available claims to be disclosed to the verifier. If the presentation request asks for essential claims which are not available, the holder MUST return an error, and SHOULD inform the user of the request and indicate the cause of the failure.

The holder MUST limit the returned claims to the set of requested claims. The user SHOULD be informed of the request, and MAY be given the option to control what data is returned. For example, the holder MAY display a list of the requested claims with checkboxes indicating which claims might be returned, with essential claims being unable to be unchecked and all other claims unchecked by default.

The metadata of the issuer MAY be used by the holder to determine appropriate localizable names to display to a user for a claim. A holder MAY use its own names for display, and MAY decide not to support claims which it cannot adequately convey to the user.

Once the holder determines the list of claims to return, it will create an array of JWS documents containing those claims. JWS documents containing other claims will not be shared and may be discarded.

## Predicate Processing

A claim request with required predicates may be met by returning a claim matching the predicate, a more specific predicate, or the non-predicated value of a claim.

For example, a request for:

``` json
{
  "jwt-claims": {
    "age": {
      "predicates": [ "gte:21" ]
    }
  }
}
```

Could be matched by returning any of the following claims.

- `"age#gte:21" : true`
- `"age#gt:21" : true`
- `"age#gte:25" : true`
- `"age": 27`

Holders are RECOMMENDED to return the most general form of claim by default. The holder SHOULD indicate to the user the information being disclosed (e.g. "Age over 25") rather than the requested predicate by the verifier ("Age over 21") if the two differ.

## Credential Presentation Response

The presentation of a `jws-claims` credential consists of a list of JWS documents, each holding one or more JWT claims.

A verifier MUST verify that the JWS header have a `typ` of either `application/jwt-claim` or the shortened `jwt-claim`. The `alg` header value MUST be set to the algorithm of the `cdv` key in the issuer statement, and MUST NOT be the value `none`. No other header values from the holder are valid.

The JWS documents must have their signatures verified against the `cdv` public key. If any documents cannot be verified, the entire credential MUST be rejected.

The JSON content of the JWS documents contain claims information. The same claim MUST NOT be made in multiple documents. A verifier MAY consider these individual JSON objects as slices of a single JSON object.

TODO: define errors and any recovery process.

[//]: # "Steps for recovery from defined errors may belong in this or subsequent sections. For example, if the user indicated they would be willing to disclose a different set of attributes, an error might include information about what the user consented to return."

[//]: # "A credential definition might go as far as to include a single-use value to use to retry the presentation request, which would optimize the process (such as avoiding prompting the user again for consent)"

## Alternatives Considered

Similar systems may allow the user to mix in self-asserted values, such as to change their given name to a different value. The preference would be to have this be a second credential, possibly protected by the ephemeral key of the holder indicated in the issuer statement.

A system leveraging merkle trees could eliminate the multiple signature validations necessary for processing individual attributes, but would require defining a system a format for encoding those values (rather than leveraging JWS).

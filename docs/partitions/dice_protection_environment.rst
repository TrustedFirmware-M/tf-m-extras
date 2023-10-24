###########################
DICE Protection Environment
###########################

The DICE Protection Environment (DPE) service makes it possible to execute DICE
commands within an isolated execution environment. It provides clients with an
interface to send DICE commands, encoded as CBOR objects, that act on opaque
context handles. The DPE service performs DICE derivations and certification on
its internal contexts, without exposing the DICE secrets (private keys and CDIs)
outside of the isolated execution environment.

For a full description of DPE, see the
`DPE Specification <https://trustedcomputinggroup.org/wp-content/uploads/TCG-DICE-Protection-Environment-Specification_14february2023-1.pdf>`_.

DPE consists of both a runtime service and boot time integration. The DPE
service is currently a work in progress.

*********
Boot time
*********

A platform integrating DPE must perform the following boot-time functions:

- Derive a RoT CDI from the UDS (HUK) provisioned in OTP, lifecycle state and
  measurement of the first firmware stage after ROM (BL1_2), and store it via a
  platform-specific mechanism to be retrieved at runtime.

- Store boot measurements and metadata for all images loaded by the bootloaders
  in the TF-M shared boot data area.

*******************
Runtime DPE service
*******************

The runtime DPE service provides the following functionality.

Initialization
==============

At initialization, DPE completes the following tasks:

- Retrieves and processes offline measurements and metadata from the TF-M shared
  boot data area.

- Retrieves the RoT CDI generated at boot time by calling the
  ``dpe_plat_get_rot_cdi()`` platform function.

- Derives DICE contexts for the RoT layer and platform layer, using the values
  processed from boot data and the RoT CDI.

- Shares the initial context handle, corresponding to the newly-created child
  context, with the first client (AP BL1), via a platform-specific mechanism.

Context management
==================

The internal DICE contexts are referred to by clients of the DPE service using
opaque context handles. Each DPE command generates a new context handle that is
returned to the client to refer to the new internal state. Each context handle
can only be used once, so clients must use the "retain context" parameter of the
DPE commands if they wish to obtain a fresh handle to the same context.

The context handles are 32-bit integers, where the lower 16-bits is the index of
the context within the service and the upper 16-bits is a random nonce.

The internal contexts are associated with the 32-bit ID of the owner of the
context. The DPE service only permits the owner to access the context through
its context handle. In the TF-M integration, the ID is bound to the PSA Client
ID of the sender of the DPE message.

Client APIs
===========

The DPE partition in TF-M wraps the DPE commands into PSA messages. The request
manager abstracts PSA message handling, and the remainder of the service avoids
coupling to TF-M partition specifics.

The DPE commands themselves are CBOR-encoded objects that the DPE decode layer
decodes into calls to one of the following supported DICE functions.

DeriveContext
-------------

Adds a component context to the layer, consisting of:

- Context handle
- Parent context handle
- Linked layer
- Is leaf
- Client ID
- DICE input values

  - Code hash
  - Config value
  - Authority hash
  - Operating mode

When a layer is finalized (create_certificate=true), it:

- Computes the Attestation CDI and Sealing CDI.

- Derives an attestation keypair from the Attestation CDI.

- Creates the corresponding certificate and signs it with the previous layer's
  attestation private key.

- Stores the finalized certificate in DPE partition SRAM.

Certificates are created in the CBOR Web Token (CWT) format, using the QCBOR
and t_cose libraries. CWT is specified in
`RFC 8392 <https://www.rfc-editor.org/rfc/rfc8392.html>`_,
with customization from
`Open DICE <https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md#CBOR-UDS-Certificates>`_.

CertifyKey
----------

Generates a leaf certificate and returns the full certificate chain leading to
it. If a public key is supplied, then it certifies the key.

- Adds label (if supplied) to list of measurements.

- Finalizes the layer (as for DeriveContext above).

- Returns the certificate chain (collection of individual certificates) as a
  CBOR array with format [+COSE_Sign1, COSE_Key]. The (pre-provisioned) root
  attestation public key is the first element in the CBOR array.

Seal
----

Encrypts and authenticates data using two keys derived from the Sealing CDI,
identifiers of the software components in the chain and a supplied label.

- Not currently implemented.

Unseal
------

Inverse of Seal.

- Not currently implemented.

--------------

*Copyright (c) 2023, Arm Limited. All rights reserved.*

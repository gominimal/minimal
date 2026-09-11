Frozen fixtures from gominimal/arch `specs/authn-authz/vectors` (schema
gatehouse-vectors/1.3, fixed clock 1750000000): the ssh-certs cases and
expectations, the three CA *public* keys, and the KRL's expected revoked set.
Public material only — the vectors' private keys are deliberately not copied
(vectors README rule 5); certificates minted at test time come from the stub
CA in `src/stub.rs`, never from these CAs.

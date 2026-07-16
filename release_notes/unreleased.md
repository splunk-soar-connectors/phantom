**Unreleased**

* Validate artifact identifiers before using them in REST endpoint paths.
* Reject peer addresses that resolve to loopback, unspecified, link-local, or reserved networks.
* Prevent deflate passwords from being persisted in action-result parameters and outputs.
* Bound artifact pagination even when an upstream peer never signals completion.
* Import peer containers without trusting numeric owner IDs, enabling automation, or silently accepting incomplete artifact retrieval.

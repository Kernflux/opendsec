# Security policy

OpenDsec runs untrusted code, so isolation bugs matter. Please report a
vulnerability privately, not in a public issue: use GitHub's "Report a
vulnerability" (Security advisories) on this repository. Include the
version (`opendsecctl version`), the backend (microvm, container, fncall,
fullvm), and the steps to reproduce.

You will get an answer within a week. Fixes go into the latest release;
older releases are not patched.

In scope: escaping a sandbox, reaching another sandbox or the host network
against the network policy, getting around quotas or permissions, using
another principal's token, and attacks on the control plane's mTLS.
Out of scope: denial of service by a caller with a valid token within its
quota, and setups that leave the internal ports (everything but the
apiserver's 7100) reachable from untrusted networks.

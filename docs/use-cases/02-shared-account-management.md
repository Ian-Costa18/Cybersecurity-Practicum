# Use Case: Shared Account Management

## Problem

When multiple people share ownership of an account (bank account, credit card, collaborative tools, shared passwords), one owner can unilaterally access or modify the account without the other owners' knowledge or consent.

**Real-world example:** Separated parents jointly own a savings account for their child's education fund. Without multi-approval:
- Parent A can withdraw the entire balance without Parent B's consent
- Parent A can change the account holder's email or recovery phone number, locking Parent B out
- If Parent A's credentials are stolen, the attacker can drain the account

**The core issue:** Access to shared credentials/accounts is unilaterally controlled by one owner.

## Actors & Workflow

### Before Access

1. **Account owner** (Parent A) wants to access shared account credentials or make a change (e.g., withdraw funds, change email)
2. **Owner** authenticates to the proxy (password + 2FA)
3. Owner submits request to the proxy with: action (withdraw, view balance, change email), amount/details

### Approval Phase

4. Proxy creates approval request and notifies other **owners** (Parent B) with approval link
5. Other **owner** (Parent B) receives notification
6. Owner B clicks link, authenticates (password + 2FA), reviews the request:
   - What action? (e.g., "withdraw $5,000")
   - Is this expected?
   - Do I approve?
7. Owner B approves or denies

### After Approval

8. Once **quorum is reached** (Owner A requested, Owner B approved), the proxy:
   - **Option A:** Reveals the account credentials to Owner A (who then logs in directly)
   - **Option B:** Grants Owner A a temporary session token to perform the action (proxy logs all activity)
   - **Option C:** Executes the action itself (e.g., submits withdrawal) on behalf of both owners

9. Proxy records the approval, action taken, and timestamp in an audit log

## Threat Model

**Attack scenario A (unilateral action):** Parent A wants to withdraw funds without Parent B's knowledge. With multi-approval, Parent B must consent.

**Attack scenario B (credential theft):** Attacker steals Parent A's credentials. Without approval, attacker can drain the account. With multi-approval, attacker still needs Parent B's credentials or approval.

**Assumption:** Both owners are trustworthy and will not collude with an attacker. Either owner can block the other's requests.

## Configuration (YAML)

```yaml
services:
  shared-savings-account:
    approvers:
      - parent_a
      - parent_b
    quorum: 2  # Both must approve for any action
    type: one-time
    action: reveal-credentials
    metadata:
      account_type: joint_savings
      account_number: "****1234"
```

**Note:** The quorum (2-of-2) is configurable by the account owners. Different accounts may have different rules:
- Some might require unanimous approval (2-of-2)
- Some might allow one owner to act alone for routine transactions and require 2-of-2 only for large withdrawals
- Some might have a third-party approver (a trusted family member, lawyer, accountant) for tie-breaking

## Implementation Details

### Credential Storage

The server stores account credentials (username, password, API tokens) encrypted at rest. The encryption key is NOT stored in the server; instead:

- The credentials are encrypted and stored in a database
- To decrypt and access the credentials, the approvers must authenticate to the proxy
- Only after quorum approval does the proxy decrypt the credentials using a mechanism that requires multiple approvers' consent

### Post-Approval Actions

After approval, the proxy can:

1. **Reveal credentials:** Display username/password to the requester so they can log in directly to the account platform
2. **Session grant:** Generate a temporary session token (valid for 1 hour) that allows the requester to act on the account
3. **Proxy-mediated action:** The proxy itself performs the action (e.g., submits a withdrawal request) on behalf of both owners

### Audit Trail

Every action is logged:
- Who requested the action
- Who approved it
- What action was taken
- When it occurred
- If credentials were revealed or session was created
- If the action was executed, what was the result

## Security Properties

- **Unanimous consent required:** By default, both owners must approve any action. No unilateral access.
- **Approval tied to identity:** Each approval is tied to an owner's authentication (password + 2FA), preventing unauthorized approval.
- **Credential never exposed without approval:** The server holds the credentials; they are only revealed after quorum.
- **Audit trail:** Every access/change is logged and auditable.
- **Flexible threshold:** Owners can configure the quorum rule (both must approve, majority, third-party tie-breaker, etc.).

## Usability Considerations

- **Friction:** One owner cannot act alone; requires coordination with other owners. This is intentional but requires time/communication.
- **Slow operations:** Owners are distributed (different time zones, schedules); approvals may take time.
- **False positives:** Legitimate transactions might be rejected if one owner is unavailable.

**Mitigations:**
- Show approval status (waiting for Parent B)
- Notification reminders ("Action pending since 2 hours ago")
- Pre-approval for expected/recurring transactions (e.g., "auto-approve monthly rent payment up to $2,000")
- Emergency access (if one owner is incapacitated, a trusted third party can approve on their behalf)

## Real-World Applicability

This use case is implementable with the multi-approval system because:

1. **Simple workflow:** Request → approve/deny → execute. No complex domain-specific logic.
2. **Credential storage:** The server naturally holds the account credentials (unlike Package Publishing where the upload payload is separate).
3. **Clear threat model:** Prevents unilateral access to shared resources.
4. **Configurable threshold:** Owners choose their own rules (unanimous, majority, etc.).

## Evaluation Questions

- **Usability:** How much friction is acceptable for account security? (benchmark: how long does Parent B typically take to approve?)
- **Emergency access:** If Parent B is unreachable, can Parent A take emergency action with an audit trail?
- **Credential security:** Can the proxy safely store shared credentials without exposing them to attackers?
- **Integration:** Which account platforms can the proxy integrate with? (banks, credit cards, SaaS tools)

## Future Extensions

- **Partial approval:** Owner A requests withdrawal of $5,000; Owner B approves $3,000 as a counter-offer.
- **Time-based rules:** Action can proceed automatically if quorum is reached by deadline; otherwise denied.
- **Spending limits:** Owners define spending thresholds (Owner A can withdraw up to $500 alone; over $500 requires approval).
- **Recovery keys:** If one owner loses access, a trusted recovery contact can approve actions for a limited time.

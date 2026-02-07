# Security Policy

## Supported Versions

| Version | Supported          | Security Updates |
|---------|--------------------|------------------|
| 1.x.x   | :white_check_mark: | Yes              |
| < 1.0   | :x:                | No               |

## Reporting a Vulnerability

**IMPORTANT:** This application is designed **EXCLUSIVELY** for authorized security testing.

If you discover a security vulnerability in this tool itself (not a vulnerability it discovers):

1. **DO NOT** create a public issue
2. Email: security@btsec-research.local
3. Include "VULNERABILITY REPORT" in the subject line
4. Provide:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if known)

### Response Timeline

- **Initial Response:** Within 48 hours
- **Detailed Assessment:** Within 7 days
- **Fix Release:** Within 30 days (based on severity)
- **Public Disclosure:** After fix is deployed

## Vulnerability Scoring

We use CVSS v3.1 for severity assessment:

| Severity | Response Time |
|----------|---------------|
| Critical (9.0-10.0) | 48 hours |
| High (7.0-8.9) | 7 days |
| Medium (4.0-6.9) | 30 days |
| Low (0.1-3.9) | Next release |

## Authorization Requirements

This tool includes built-in authorization enforcement:

1. **Digital Signature Verification** - All authorization tokens are cryptographically signed
2. **Scope Enforcement** - Operations are limited to authorized targets and actions
3. **Consent Tracking** - All operations require explicit user consent
4. **Audit Logging** - All security operations are logged for compliance

### Authorization Token Format

```
BTSEC-YYYYMMDD-XXXXXXXX
```

Example: `BTSEC-20260207-A1B2C3D4`

### Required Authorization for Security Testing

Before using this tool for security testing, you MUST have:

- [ ] Written authorization from target system owner
- [ ] Defined scope of testing (systems, networks, activities)
- [ ] Legal compliance review (jurisdiction-specific requirements)
- [ ] Rules of engagement documented
- [ ] Incident response procedures in place

## Security Best Practices

### For Tool Users

1. **Never use without authorization**
2. **Keep authorization tokens secure**
3. **Review consent prompts carefully**
4. **Maintain audit logs**
5. **Report findings responsibly**
6. **Follow disclosure guidelines**

### For Developers

1. **Code review all changes**
2. **Run security tests** (`./gradlew securityCheck`)
3. **Update dependencies regularly**
4. **Follow secure coding practices**
5. **Document security assumptions**
6. **Test authorization enforcement**

## Known Security Considerations

### Tool-Specific Risks

1. **Bluetooth Stack Access**
   - Requires dangerous permissions (BLUETOOTH_CONNECT, BLUETOOTH_SCAN)
   - Must be explicitly granted by user
   - Scope limited to authorized testing

2. **Key Extraction Capabilities**
   - Requires explicit authorization
   - Only for bonded/paired devices
   - All operations logged

3. **Fuzzing Operations**
   - Can cause target device crashes
   - Rate-limited per authorization
   - Requires explicit consent

4. **Packet Capture**
   - Requires root access on most devices
   - Not available without proper setup
   - Captures stored securely

### Mitigations

- **Authorization Enforcement:** Every security operation checks authorization
- **Scope Validation:** Operations limited to authorized targets
- **Rate Limiting:** Prevents accidental damage
- **Audit Logging:** All operations logged with timestamp and device info
- **Consent UI:** Clear prompts before sensitive operations

## Dependency Security

We use automated dependency scanning:

- **Dependabot:** Automated dependency updates
- **CodeQL:** Static analysis security scanning
- **OWASP Dependency Check:** Vulnerability scanning

### Updating Dependencies

```bash
# Check for updates
./gradlew dependencyUpdates

# Run security scan
./gradlew dependencyCheckAnalyze

# Update dependencies
./gradlew build -DrefreshDependencies
```

## Security Testing

### Running Security Tests

```bash
# Unit tests with security checks
./gradlew test

# Android lint with security rules
./gradlew lint

# Dependency vulnerability scan
./gradlew dependencyCheckAnalyze

# CodeQL analysis (via GitHub Actions)
```

### Test Coverage

- **Unit Tests:** 100% coverage of critical security paths
- **Authorization Tests:** All use cases verify authorization
- **Consent Tests:** Audit logging verified
- **Input Validation:** All user inputs validated

## Compliance

This tool is designed to support compliance with:

- **OWASP Mobile Security Testing Guide**
- **NIST Mobile Security Guidelines**
- **ISO 27001** (security testing procedures)
- **GDPR** (data handling and consent)
- **CCPA** (privacy requirements)

### Data Retention

- **Authorization Records:** 7 years (audit compliance)
- **Consent Records:** 7 years
- **Operation Logs:** 7 years
- **Test Results:** User-defined, default 1 year

## Responsible Disclosure

If you discover a Bluetooth vulnerability using this tool:

1. **Report to Vendor First:** Follow vendor's disclosure policy
2. **Allow 90 Days:** Standard disclosure timeline
3. **Request CVE:** For tracking purposes
4. **Credit Maintained:** Acknowledge your contribution

### Vendor Contact Template

```
Subject: Security Vulnerability Report - [Product/Service]

Dear Security Team,

I have discovered a security vulnerability in [Product].
I am reporting this under responsible disclosure principles.

Vulnerability: [Brief description]
Impact: [Potential risk]
Affected Versions: [Version numbers]
PoC: [Available upon request]

Proposed Timeline: 90-day disclosure
Contact: [Your PGP key and contact info]

This discovery was made using BTSec Test Tool during authorized
security testing.

Best regards,
[Your Name/Organization]
```

## Security Contacts

- **Security Team:** security@btsec-research.local
- **PGP Key:** Available on request
- **Bug Bounty:** Not applicable (research tool only)

## Acknowledgments

This tool incorporates security research from:

- **CVE Details:** Vulnerability database
- **OWASP:** Security best practices
- **Android Security Team:** Bluetooth security guidelines
- **Security Research Community:** Vulnerability disclosures

---

*Last Updated: February 7, 2026*
*Version: 1.0.0*

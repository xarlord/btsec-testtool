## Pull Request Checklist

Please ensure your PR meets the following requirements:

- [ ] **Tests Added/Updated:** All new/updated code has tests
- [ ] **Test Coverage:** Coverage remains at 100% (or has improved)
- [ ] **Authorization:** Security operations check authorization
- [ ] **Consent:** Audit logging tracks consent for operations
- [ ] **Documentation:** README, docs, or comments updated
- [ ] **Legal:** Legal disclaimers included in new files
- [ ] **Breaking Changes:** Documented if applicable
- [ ] **Commits:** Follow conventional commit format

---

## Type of Change

Mark the relevant type with an `x`:

- [ ] **Bug fix:** Non-breaking change that fixes an issue
- [ ] **Feature:** Non-breaking change that adds functionality
- [ ] **Breaking change:** Fix or feature that breaks existing functionality
- [ ] **Refactoring:** Code improvement without behavior change
- [ ] **Documentation:** Documentation only changes
- [ ] **Security:** Security-related changes
- [ ] **Tests:** Test-only changes
- [ ] **CI/CD:** Build/CI configuration changes

---

## Description

<!-- Describe your changes in detail -->

## Related Issue

Fixes # (issue)
Related to # (issue)

---

## Changes Made

### Domain Layer

<!-- Changes to models, repository interfaces, use cases -->

- [ ] Models updated
- [ ] Repository interfaces changed
- [ ] Use cases added/modified

### Data Layer

<!-- Changes to repository implementations -->

- [ ] Repository implementations updated
- [ ] Database migrations added
- [ ] Network API changes

### Presentation Layer

<!-- UI/UX changes -->

- [ ] Screens/Composables updated
- [ ] ViewModels modified
- [ ] Navigation changed

### Tests

<!-- Test coverage -->

- [ ] Unit tests added/updated
- [ ] Integration tests added
- [ ] UI tests added
- [ ] Test coverage: **XX%** (aim for 100%)

---

## Security Considerations

### Authorization

- [ ] New operations check authorization via `requestActionAuthorization`
- [ ] Scope validation performed for target devices/actions
- [ ] Authorization documented in use case

### Consent & Audit

- [ ] User consent obtained before sensitive operations
- [ ] Operations logged via `logAuditEvent` or `logOperation`
- [ ] Audit trail includes: timestamp, device, action, result

### Input Validation

- [ ] All user inputs validated
- [ ] Edge cases handled
- [ ] Sanitization performed where needed

### Data Protection

- [ ] Sensitive data not logged
- [ ] Encryption used for storage
- [ ] Secure communication enforced

---

## Testing Performed

### Unit Tests

```bash
./gradlew test
```

**Result:** [Pass/Fail, with details]

### Integration Tests

```bash
./gradlew connectedAndroidTest
```

**Result:** [Pass/Fail, with details]

### Manual Testing

<!-- Describe manual testing performed -->

### Test Coverage

```
Domain Layer:     XX%
Data Layer:       XX%
Presentation:     XX%
Overall:          XX%
```

---

## Screenshots

<!-- If applicable, add screenshots to demonstrate your changes -->

### Before

<!-- Screenshot of before state -->

### After

<!-- Screenshot of after state -->

---

## Breaking Changes

<!-- If this PR introduces breaking changes, describe them here -->

### API Changes

- [ ] Models changed
- [ ] Repository interfaces changed
- [ ] Use case signatures changed

### Migration Required

- [ ] Data migration needed
- [ ] Configuration changes needed
- [ ] User action required

---

## Performance Impact

- [ ] No performance impact
- [ ] Improved performance
- [ ] Minor performance impact
- [ ] Significant performance impact (explain)

---

## Dependencies

### Added

- [ ] dependency-name: version

### Updated

- [ ] dependency-name: old-version → new-version

### Removed

- [ ] dependency-name

---

## Documentation

- [ ] README.md updated
- [ ] TEST_COVERAGE_REPORT.md updated
- [ ] API docs updated
- [ ] Comments added to code
- [ ] CHANGELOG.md updated

---

## Checklist for Merge

- [ ] All tests pass
- [ ] Code review approved
- [ ] No merge conflicts
- [ ] Documentation complete
- [ ] Breaking changes documented
- [ ] Security review passed
- [ ] Performance acceptable
- [ ] Ready for merge

---

## Additional Notes

<!-- Any additional information for reviewers -->

---

**Remember:** This tool is for AUTHORIZED SECURITY TESTING ONLY. All changes must maintain proper authorization enforcement and audit logging.

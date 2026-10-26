package com.github.mphi_rc.fido2;

import org.junit.Test;

/** Same synthetic protocol regressions run independently by JUnit and standalone. */
public class SilentAssertionTest {
    @Test public void missingCredentialReturnsNoCredentialsWithoutWriting() throws Exception {
        SilentAssertionRegression.missingCredentialReturnsNoCredentialsWithoutWriting();
    }
    @Test public void wrongRpCannotMatchKnownId() throws Exception {
        SilentAssertionRegression.wrongRpCannotMatchKnownId();
    }
    @Test public void knownLegacySilentAssertionHasUpZeroUvOne() throws Exception {
        SilentAssertionRegression.knownLegacySilentAssertionHasUpZeroUvOne();
    }
    @Test public void residentSilentAssertionHasValidSignedFlags() throws Exception {
        SilentAssertionRegression.residentSilentAssertionHasValidSignedFlags();
    }
    @Test public void silentWithoutPinNeverClaimsUvOrDisclosesNames() throws Exception {
        SilentAssertionRegression.silentWithoutPinNeverClaimsUvOrDisclosesNames();
    }
    @Test public void absentUpStillMeansTrue() throws Exception {
        SilentAssertionRegression.absentUpStillMeansTrue();
    }
    @Test public void explicitUpTrueStillWorks() throws Exception {
        SilentAssertionRegression.explicitUpTrueStillWorks();
    }
    @Test public void badPinAuthCannotSignOrWrite() throws Exception {
        SilentAssertionRegression.badPinAuthCannotSignOrWrite();
    }
    @Test public void badPinAuthForMissingIdIsNotIgnored() throws Exception {
        SilentAssertionRegression.badPinAuthForMissingIdIsNotIgnored();
    }
    @Test public void builtInUvIsStillUnsupported() throws Exception {
        SilentAssertionRegression.builtInUvIsStillUnsupported();
    }
    @Test public void dummySelectionDoesNotRejectRealPinOrConsumeAttempts() throws Exception {
        SilentAssertionRegression.dummySelectionDoesNotRejectRealPinOrConsumeAttempts();
    }
    @Test public void chromeShapedExcludeMissCanProceedToRegistration() throws Exception {
        SilentAssertionRegression.chromeShapedExcludeMissCanProceedToRegistration();
    }
    @Test public void knownExcludeCredentialIsNotRegisteredTwice() throws Exception {
        SilentAssertionRegression.knownExcludeCredentialIsNotRegisteredTwice();
    }
    @Test public void silentDiscoveryContinuationKeepsUpZero() throws Exception {
        SilentAssertionRegression.silentDiscoveryContinuationKeepsUpZero();
    }
    @Test public void subsequentNormalRequestDoesNotInheritSilentUp() throws Exception {
        SilentAssertionRegression.subsequentNormalRequestDoesNotInheritSilentUp();
    }
    @Test public void silentSignatureStorageFailureCannotReturnSuccess() throws Exception {
        SilentAssertionRegression.silentSignatureStorageFailureCannotReturnSuccess();
    }
    @Test public void allAuthenticatorFlagCombinationsSerialize() throws Exception {
        SilentAssertionRegression.allAuthenticatorFlagCombinationsSerialize();
    }
}

package com.github.mphi_rc.fido2.protocol.ctap2;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.immutables.value.Value;

import com.google.common.hash.Hashing;

@Value.Immutable
public abstract class AuthenticatorData {
	
	public abstract String relayingPartyId();
	public abstract int signatureCount();
	public abstract boolean isUserPresent();
	public abstract boolean isUserVerified();
	public abstract Optional<byte[]> attestedCredentialData(); 
	
	public byte[] asBytes() {
		byte[] rpIdHash = Hashing.sha256()
				.hashString(relayingPartyId(), StandardCharsets.UTF_8)
				.asBytes();
		
		int size = rpIdHash.length + 1 + 4 + attestedCredentialData()
				.map(bytes -> bytes.length)
				.orElse(0);
		byte[] bytes = new byte[size];
		System.arraycopy(rpIdHash, 0, bytes, 0, 32);
		
		// Silent assertions can legitimately have no flags set (UP=0, UV=0).
		// BitSet.toByteArray() is empty for zero, but this field is always one byte.
		int flags = (isUserPresent() ? 0x01 : 0)
				| (isUserVerified() ? 0x04 : 0)
				| (attestedCredentialData().isPresent() ? 0x40 : 0);
		bytes[32] = (byte) flags;
		bytes[33] = (byte) ((0xFF000000 & signatureCount()) >> 24);
		bytes[34] = (byte) ((0x00FF0000 & signatureCount()) >> 16);
		bytes[35] = (byte) ((0x0000FF00 & signatureCount()) >> 8);
		bytes[36] = (byte) (0x000000FF & signatureCount());
		attestedCredentialData().ifPresent(d -> {
			System.arraycopy(d, 0, bytes, 37, d.length);
		});
		return bytes;
	}
}

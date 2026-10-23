package com.github.mphi_rc.fido2.authenticator;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.immutables.gson.Gson;
import org.immutables.value.Value;

import com.github.mphi_rc.fido2.authenticator.crypto.AttestationKeyPair;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;

@Gson.TypeAdapters
@Value.Immutable
public interface Credential {

	@Value.Parameter
	String relayingPartyId();

	@Value.Parameter
	Instant creation();

	@Value.Parameter
	byte[] userId();

	@Value.Parameter
	AttestationKeyPair keyPair();


	@Value.Parameter
	int signatureCount();

	/**
	 * V7.1 state has no discoverable property. Old credentials must remain
	 * non-discoverable, including after deserialization and migration.
	 */
	@Value.Default
	default boolean discoverable() {
		return false;
	}

	/** Optional, user-supplied display metadata (never part of the credential ID). */
	@Value.Default
	default String userName() {
		return "";
	}

	@Value.Default
	default String userDisplayName() {
		return "";
	}

	@Value.Check
	default void checkUserMetadata() {
		if (userName().getBytes(StandardCharsets.UTF_8).length > 64
				|| userDisplayName().getBytes(StandardCharsets.UTF_8).length > 128) {
			throw new IllegalArgumentException("Credential user metadata exceeds size limits");
		}
		if (discoverable() && (userId().length == 0 || userId().length > 64)) {
			throw new IllegalArgumentException("Discoverable credential user ID must be 1..64 bytes");
		}
	}

	@Value.Derived
	default byte[] id() {
		HashFunction hf = Hashing.murmur3_128();
		HashCode code = hf.newHasher()
			.putString(relayingPartyId(), StandardCharsets.UTF_8)
			.putLong(creation().toEpochMilli())
			.putBytes(userId())
			.putBytes(keyPair().publicKey())
			.hash();
		return code.asBytes();
	}
}

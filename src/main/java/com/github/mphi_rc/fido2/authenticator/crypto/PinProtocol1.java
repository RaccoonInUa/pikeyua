package com.github.mphi_rc.fido2.authenticator.crypto;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import co.nstant.in.cbor.model.*;

/** CTAP 2.0 PIN protocol 1 only: P-256 ECDH, SHA-256, AES-256-CBC/zero IV, HMAC-16. */
public final class PinProtocol1 {
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
    private static final SecureRandom RANDOM = new SecureRandom();
    private PinProtocol1() { }

    public static KeyPair newKeyAgreement() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", PROVIDER);
            generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) { throw new IllegalStateException("PIN key generation failed", e); }
    }

    private static BigInteger integer(Map map, int key) {
        DataItem value = map.get(key < 0 ? new NegativeInteger(key) : new UnsignedInteger(key));
        if (!(value instanceof co.nstant.in.cbor.model.Number)) throw new IllegalArgumentException("Invalid COSE integer");
        return ((co.nstant.in.cbor.model.Number) value).getValue();
    }
    private static byte[] coordinate(Map map, int key) {
        DataItem value = map.get(new NegativeInteger(key));
        if (!(value instanceof ByteString) || ((ByteString) value).getBytes() == null
                || ((ByteString) value).getBytes().length != 32) throw new IllegalArgumentException("Invalid P-256 coordinate");
        return ((ByteString) value).getBytes();
    }

    /** Validate COSE parameters, coordinate sizes, field range and curve membership BEFORE ECDH. */
    public static PublicKey decodePublicKey(Map map) {
        if (map == null || !integer(map, 1).equals(BigInteger.valueOf(2))
                || !integer(map, 3).equals(BigInteger.valueOf(-25))
                || !integer(map, -1).equals(BigInteger.ONE)) throw new IllegalArgumentException("Unsupported PIN key agreement parameters");
        ECNamedCurveParameterSpec curve = ECNamedCurveTable.getParameterSpec("secp256r1");
        BigInteger x = new BigInteger(1, coordinate(map, -2));
        BigInteger y = new BigInteger(1, coordinate(map, -3));
        BigInteger prime = curve.getCurve().getField().getCharacteristic();
        if (x.compareTo(prime) >= 0 || y.compareTo(prime) >= 0) throw new IllegalArgumentException("Out-of-field point");
        ECPoint point = curve.getCurve().createPoint(x, y);
        if (point.isInfinity() || !point.isValid()) throw new IllegalArgumentException("Invalid key agreement point");
        try { return KeyFactory.getInstance("EC", PROVIDER).generatePublic(new ECPublicKeySpec(point, curve)); }
        catch (GeneralSecurityException e) { throw new IllegalArgumentException("Invalid key agreement key", e); }
    }

    public static Map encodePublicKey(PublicKey key) {
        ECPublicKey ec = (ECPublicKey) key;
        Map result = new Map();
        result.put(new UnsignedInteger(1), new UnsignedInteger(2));
        result.put(new UnsignedInteger(3), new NegativeInteger(-25));
        result.put(new NegativeInteger(-1), new UnsignedInteger(1));
        result.put(new NegativeInteger(-2), new ByteString(fixed(ec.getW().getAffineX())));
        result.put(new NegativeInteger(-3), new ByteString(fixed(ec.getW().getAffineY())));
        return result;
    }
    private static byte[] fixed(BigInteger value) {
        byte[] raw = value.toByteArray(), result = new byte[32];
        int n = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - n, result, 32 - n, n);
        return result;
    }

    public static byte[] sharedSecret(KeyPair own, PublicKey peer) {
        try {
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH", PROVIDER);
            agreement.init(own.getPrivate());
            agreement.doPhase(peer, true);
            byte[] raw = agreement.generateSecret();
            try { return sha256(raw); } finally { wipe(raw); }
        } catch (GeneralSecurityException e) { throw new IllegalArgumentException("Invalid ECDH peer", e); }
    }
    public static byte[] sha256(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
        catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
    public static byte[] hmac16(byte[] key, byte[]... chunks) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (byte[] chunk : chunks) mac.update(chunk);
            byte[] full = mac.doFinal();
            try { return Arrays.copyOf(full, 16); } finally { wipe(full); }
        } catch (GeneralSecurityException e) { throw new IllegalStateException("PIN authentication failed", e); }
    }
    public static byte[] crypt(int mode, byte[] key, byte[] bytes) {
        if (key.length != 32 || bytes.length == 0 || bytes.length % 16 != 0) throw new IllegalArgumentException("Invalid PIN cipher length");
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(new byte[16]));
            return cipher.doFinal(bytes);
        } catch (GeneralSecurityException e) { throw new IllegalStateException("PIN encryption/decryption failed", e); }
    }
    public static boolean validNewPinCipher(byte[] bytes) {
        return bytes != null && bytes.length >= 64 && bytes.length <= 256 && bytes.length % 16 == 0;
    }

    /** Validate terminator, all-zero padding, UTF-8 and 4-code-point / 63-byte local PIN policy. */
    public static byte[] pinHashFromPadded(byte[] padded) {
        if (!validNewPinCipher(padded)) return null;
        int length = 0;
        while (length < padded.length && padded[length] != 0) length++;
        if (length < 4 || length > 63) return null;
        for (int i = length; i < padded.length; i++) if (padded[i] != 0) return null;
        CharBuffer characters = null;
        byte[] pin = Arrays.copyOf(padded, length);
        try {
            characters = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(pin));
            if (Character.codePointCount(characters, 0, characters.length()) < 4) return null;
            byte[] full = sha256(pin);
            try { return Arrays.copyOf(full, 16); } finally { wipe(full); }
        } catch (CharacterCodingException e) { return null; }
        finally {
            wipe(pin);
            if (characters != null && !characters.isReadOnly()) {
                for (int i = 0; i < characters.limit(); i++) characters.put(i, '\0');
            }
        }
    }
    public static void wipe(byte[] bytes) { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
}

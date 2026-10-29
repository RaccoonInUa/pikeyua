package com.github.mphi_rc.fido2;

import static com.github.mphi_rc.fido2.PinUvProbe.*;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import com.github.mphi_rc.fido2.protocol.ctap2.AuthenticatorRequestHandler;
import com.github.mphi_rc.fido2.protocol.usbhid.ImmutableChannelId;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.*;
import co.nstant.in.cbor.model.Map;

/** Test-only independent host ClientPIN implementation, using the existing probe's crypto helpers. */
final class TokenCtapClient {
    final AuthenticatorRequestHandler handler;
    byte[] shared, token;
    Map publicKey;
    TokenCtapClient(AuthenticatorRequestHandler handler) { this.handler = handler; }
    Reply call(int command, Map params) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(command);
        if (params != null) new CborEncoder(out).encode(Collections.<DataItem>singletonList(params));
        return new Reply(handler.handleCborRequest(ImmutableChannelId.of(new byte[]{7, 3, 0, 1}), out.toByteArray()).payload());
    }
    Map pinRequest(int subcommand) {
        Map body = new Map();
        put(body, 1, new UnsignedInteger(1)); put(body, 2, new UnsignedInteger(subcommand));
        return body;
    }
    int retries() throws Exception { Reply r = call(6, pinRequest(1)); ok(r); return ((UnsignedInteger) field(r.body, 3)).getValue().intValue(); }
    boolean configured() throws Exception {
        Reply r = call(4, null); ok(r);
        Map options = (Map) field(r.body, 4);
        check(options.get(new UnicodeString("uv")) == null, "ClientPIN must not advertise built-in UV");
        return SimpleValue.TRUE.equals(options.get(new UnicodeString("clientPin")));
    }
    void agreement() throws Exception {
        Reply r = call(6, pinRequest(2)); ok(r);
        Map peer = (Map) field(r.body, 1);
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec curve = parameters.getParameterSpec(ECParameterSpec.class);
        BigInteger x = new BigInteger(1, ((ByteString) peer.get(new NegativeInteger(-2))).getBytes());
        BigInteger y = new BigInteger(1, ((ByteString) peer.get(new NegativeInteger(-3))).getBytes());
        PublicKey remote = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new java.security.spec.ECPoint(x, y), curve));
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair own = generator.generateKeyPair();
        KeyAgreement ka = KeyAgreement.getInstance("ECDH"); ka.init(own.getPrivate()); ka.doPhase(remote, true);
        shared = digest(ka.generateSecret());
        ECPublicKey pub = (ECPublicKey) own.getPublic();
        publicKey = new Map();
        put(publicKey, 1, new UnsignedInteger(2)); put(publicKey, 3, new NegativeInteger(-25));
        publicKey.put(new NegativeInteger(-1), new UnsignedInteger(1));
        publicKey.put(new NegativeInteger(-2), new ByteString(fixed(pub.getW().getAffineX())));
        publicKey.put(new NegativeInteger(-3), new ByteString(fixed(pub.getW().getAffineY())));
    }
    Map setRequest(byte[] padded) throws Exception {
        agreement();
        byte[] encrypted = crypt(Cipher.ENCRYPT_MODE, shared, padded);
        Map request = pinRequest(3); put(request, 3, publicKey);
        put(request, 4, new ByteString(mac(shared, encrypted))); put(request, 5, new ByteString(encrypted));
        return request;
    }
    Reply set(String pin) throws Exception { return call(6, setRequest(padded(pin))); }
    Reply getToken(String pin) throws Exception {
        agreement();
        Map request = pinRequest(5); put(request, 3, publicKey);
        byte[] hash = Arrays.copyOf(digest(pin.getBytes(StandardCharsets.UTF_8)), 16);
        put(request, 6, new ByteString(crypt(Cipher.ENCRYPT_MODE, shared, hash)));
        Reply result = call(6, request);
        if (result.status == 0) token = crypt(Cipher.DECRYPT_MODE, shared, bytes(result.body, 2));
        Arrays.fill(hash, (byte) 0);
        return result;
    }
    Map changeRequest(String oldPin, String newPin) throws Exception {
        agreement();
        byte[] encryptedNew = crypt(Cipher.ENCRYPT_MODE, shared, padded(newPin));
        byte[] encryptedHash = crypt(Cipher.ENCRYPT_MODE, shared, Arrays.copyOf(digest(oldPin.getBytes(StandardCharsets.UTF_8)), 16));
        Map request = pinRequest(4); put(request, 3, publicKey);
        put(request, 4, new ByteString(mac(shared, encryptedNew, encryptedHash)));
        put(request, 5, new ByteString(encryptedNew)); put(request, 6, new ByteString(encryptedHash));
        return request;
    }
    Reply change(String oldPin, String newPin) throws Exception { return call(6, changeRequest(oldPin, newPin)); }
    Map makeRequest(String rpId, int user, boolean rk, boolean useToken) throws Exception {
        Map request = new Map(); put(request, 1, new ByteString(HASH));
        Map rp = new Map(); rp.put(new UnicodeString("id"), new UnicodeString(rpId)); put(request, 2, rp);
        Map account = new Map(); account.put(new UnicodeString("id"), new ByteString(new byte[]{(byte) user}));
        account.put(new UnicodeString("name"), new UnicodeString("synthetic-" + user));
        account.put(new UnicodeString("displayName"), new UnicodeString("Synthetic Account " + user)); put(request, 3, account);
        Map algorithm = new Map(); algorithm.put(new UnicodeString("alg"), new NegativeInteger(-7));
        algorithm.put(new UnicodeString("type"), new UnicodeString("public-key"));
        Array algorithms = new Array(); algorithms.add(algorithm); put(request, 4, algorithms);
        Map options = new Map(); options.put(new UnicodeString("rk"), rk ? SimpleValue.TRUE : SimpleValue.FALSE); put(request, 7, options);
        if (useToken) { put(request, 8, new ByteString(mac(token, HASH))); put(request, 9, new UnsignedInteger(1)); }
        return request;
    }
    Reply make(String rpId, int user, boolean rk, boolean useToken) throws Exception { return call(1, makeRequest(rpId, user, rk, useToken)); }
    Map assertionRequest(String rpId, byte[] id, boolean useToken) throws Exception {
        Map request = new Map(); put(request, 1, new UnicodeString(rpId)); put(request, 2, new ByteString(HASH));
        if (id != null) {
            Map descriptor = new Map(); descriptor.put(new UnicodeString("id"), new ByteString(id));
            descriptor.put(new UnicodeString("type"), new UnicodeString("public-key"));
            Array allow = new Array(); allow.add(descriptor); put(request, 3, allow);
        }
        if (useToken) { put(request, 6, new ByteString(mac(token, HASH))); put(request, 7, new UnsignedInteger(1)); }
        return request;
    }
    Reply assertion(String rpId, byte[] id, boolean useToken) throws Exception { return call(2, assertionRequest(rpId, id, useToken)); }
}

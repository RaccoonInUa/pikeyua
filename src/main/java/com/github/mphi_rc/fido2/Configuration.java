package com.github.mphi_rc.fido2;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.immutables.gson.Gson;
import org.immutables.value.Value;
import com.github.mphi_rc.fido2.authenticator.Credential;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.usb.gadget.UsbDeviceController;
import com.google.common.collect.ImmutableList;

@Gson.TypeAdapters
@Value.Immutable
public interface Configuration {
    List<Credential> credentials();
    /** Missing version is legacy v1; RK uses v2; durable PIN retries use v3. */
    @Value.Default default int schemaVersion() { return 1; }
    @Value.Default default List<Algorithm> enabledAlgorithms() {
        return ImmutableList.of(Algorithm.P256_ECDSA, Algorithm.Ed25519);
    }
    @Value.Default default UUID id() { return UUID.randomUUID(); }
    @Value.Default default Optional<byte[]> pinHash() { return Optional.empty(); }
    /** Legacy files have no retry count. Never default a schema-v3 file on load. */
    @Value.Default default int pinRetries() { return 8; }
    @Value.Default default boolean enableBonnet() { return false; }
    @Value.Default default String usbGadgetDevicePath() { return "/dev/hidg0"; }
    @Value.Default default UsbDeviceController usbDeviceController() {
        return UsbDeviceController.raspberryPiZero();
    }
    @Value.Default default String usbGadgetName() { return "fido2"; }
}

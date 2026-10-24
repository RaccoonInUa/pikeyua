package com.github.mphi_rc.fido2;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import com.github.mphi_rc.fido2.authenticator.Authenticator;
import com.github.mphi_rc.fido2.authenticator.ConfigurationCredentialStore;
import com.github.mphi_rc.fido2.authenticator.PinState;
import com.github.mphi_rc.fido2.protocol.PacketInputStream;
import com.github.mphi_rc.fido2.protocol.PacketOutputStream;
import com.github.mphi_rc.fido2.protocol.RequestStream;
import com.github.mphi_rc.fido2.protocol.ResponseStream;
import com.github.mphi_rc.fido2.protocol.ctap2.AuthenticatorRequestHandler;
import com.github.mphi_rc.fido2.protocol.ctap2.pin.PinRequestHandler;
import com.github.mphi_rc.fido2.protocol.usbhid.RawMessage;
import com.github.mphi_rc.fido2.protocol.usbhid.UsbHidRequestHandler;

public class Fido2Authenticator {
    private final UsbHidRequestHandler usbHidHandler;
    private final ResponseStream responses;
    private final RequestStream requests;

    public Fido2Authenticator(ConfigurationFile config) throws FileNotFoundException {
        PinState pin = new PinState(config);
        Authenticator authenticator = new Authenticator(config, new ConfigurationCredentialStore(config), pin);
        usbHidHandler = new UsbHidRequestHandler(new AuthenticatorRequestHandler(authenticator,
                new PinRequestHandler(pin)));
        responses = new ResponseStream(new PacketOutputStream(new DataOutputStream(new BufferedOutputStream(
                new FileOutputStream(config.usbGadgetDevicePath())))));
        requests = new RequestStream(new PacketInputStream(new DataInputStream(new BufferedInputStream(
                new FileInputStream(config.usbGadgetDevicePath())))));
    }

    public void start() throws IOException {
        while (true) {
            RawMessage response = usbHidHandler.handle(requests.readMessage());
            if (response != null) responses.accept(response);
        }
    }
}

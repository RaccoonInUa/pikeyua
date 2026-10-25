package com.github.mphi_rc.fido2;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import org.junit.Test;

import com.github.mphi_rc.fido2.protocol.PacketBuffer;
import com.github.mphi_rc.fido2.protocol.PacketInputStream;
import com.github.mphi_rc.fido2.protocol.RequestStream;
import com.github.mphi_rc.fido2.protocol.ctap2.MakeCredentialRequest;
import com.github.mphi_rc.fido2.protocol.usbhid.HidCommand;
import com.github.mphi_rc.fido2.protocol.usbhid.ImmutablePacket;
import com.github.mphi_rc.fido2.protocol.usbhid.RawMessage;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

/** Actual HID report reassembly. Synthetic fixtures only, no hardware or state files. */
public class UsbHidBoundaryTest {
    private static final byte[] CID = {1, 2, 3, 4};
    private static final int FIRST = 57;
    private static final int NEXT = 59;
    private static final int MAX = FIRST + 128 * NEXT;

    private static byte[] payload(int length) {
        byte[] value = new byte[length];
        for (int i = 0; i < length; i++) value[i] = (byte) (i * 31 + 7);
        return value;
    }

    /** Independent framing fixture: 64-byte init and continuation reports, zero padded. */
    private static byte[] reports(byte[] value) {
        if (value.length > MAX) throw new IllegalArgumentException("Oversized test message");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] init = new byte[64];
        System.arraycopy(CID, 0, init, 0, 4);
        init[4] = (byte) 0x90; // CTAPHID_CBOR with initialization bit.
        init[5] = (byte) (value.length >>> 8);
        init[6] = (byte) value.length;
        int offset = Math.min(FIRST, value.length);
        System.arraycopy(value, 0, init, 7, offset);
        out.write(init, 0, init.length);
        int seq = 0;
        while (offset < value.length) {
            byte[] next = new byte[64];
            System.arraycopy(CID, 0, next, 0, 4);
            next[4] = (byte) seq++;
            int count = Math.min(NEXT, value.length - offset);
            System.arraycopy(value, offset, next, 5, count);
            out.write(next, 0, next.length);
            offset += count;
        }
        return out.toByteArray();
    }

    /** A real USB read would block here; fail immediately instead, with no flaky timeout. */
    private static final class NoOverread extends InputStream {
        private final byte[] data;
        private int offset;
        NoOverread(byte[] data) { this.data = data; }
        @Override public int read() {
            if (offset == data.length) throw new AssertionError("Read past final HID report: complete message was not delivered");
            return data[offset++] & 255;
        }
        @Override public int read(byte[] dst, int start, int length) {
            if (length == 0) return 0;
            if (offset == data.length) throw new AssertionError("Read past final HID report: complete message was not delivered");
            int count = Math.min(length, data.length - offset);
            System.arraycopy(data, offset, dst, start, count);
            offset += count;
            return count;
        }
    }

    private static RequestStream requests(InputStream in) {
        return new RequestStream(new PacketInputStream(new DataInputStream(in)));
    }

    private static RawMessage reassemble(byte[] value) throws IOException {
        try (RequestStream stream = requests(new NoOverread(reports(value)))) {
            RawMessage message = stream.readMessage();
            assertEquals(HidCommand.CBOR, message.command());
            assertArrayEquals(CID, message.channelId().id());
            assertArrayEquals("Payload length " + value.length, value, message.payload());
            return message;
        }
    }

    @Test public void everyExactContinuationBoundaryIsDeliveredWithoutAnotherRead() throws Exception {
        for (int n = 1; n <= 128; n++) reassemble(payload(FIRST + NEXT * n));
    }

    @Test public void lengthsEitherSideOfEveryBoundaryRemainCorrect() throws Exception {
        for (int n = 1; n <= 128; n++) {
            int boundary = FIRST + NEXT * n;
            reassemble(payload(boundary - 1));
            if (boundary < MAX) reassemble(payload(boundary + 1));
        }
    }

    @Test public void unfragmentedMessagesIncludingZeroAnd57BytesRemainCorrect() throws Exception {
        for (int n = 0; n <= FIRST; n++) reassemble(payload(n));
    }

    @Test public void partialMessageWaitsButExactlyCompleteMessageDoesNot() throws Exception {
        byte[] value = payload(293);
        byte[] encoded = reports(value);
        PacketBuffer buffer = new PacketBuffer(ImmutablePacket.of(Arrays.copyOfRange(encoded, 0, 64))
                .asInitializationPacket().get());
        assertFalse(buffer.constructIfPossible().isPresent());
        for (int i = 1; i <= 4; i++) {
            buffer.enqueueFragment(ImmutablePacket.of(Arrays.copyOfRange(encoded, i * 64, (i + 1) * 64))
                    .asContinuationPacket().get());
            assertEquals("continuation " + i, i == 4, buffer.constructIfPossible().isPresent());
        }
        assertArrayEquals(value, buffer.constructIfPossible().get().payload());
    }

    @Test public void completeRequestCannotConsumeOrBeOvertakenByFollowingCommand() throws Exception {
        byte[] first = payload(293);
        byte[] second = {(byte) 0x04}; // Independent following GetInfo command.
        ByteArrayOutputStream input = new ByteArrayOutputStream();
        input.write(reports(first));
        input.write(reports(second));
        ByteArrayInputStream source = new ByteArrayInputStream(input.toByteArray());
        try (RequestStream stream = requests(source)) {
            assertArrayEquals(first, stream.readMessage().payload());
            assertEquals("Following report must remain unread", 64, source.available());
            assertArrayEquals(second, stream.readMessage().payload());
            assertEquals(0, source.available());
        }
    }

    @Test public void syntheticChromeRkPinRegistrationAt293BytesReachesCtapParser() throws Exception {
        Map root = new Map();
        root.put(new UnsignedInteger(1), new ByteString(new byte[32]));
        Map rp = new Map();
        rp.put(new UnicodeString("id"), new UnicodeString("example.org"));
        rp.put(new UnicodeString("name"), new UnicodeString("example.org"));
        root.put(new UnsignedInteger(2), rp);
        char[] name = new char[29];
        Arrays.fill(name, 'x');
        Map user = new Map();
        user.put(new UnicodeString("id"), new ByteString(new byte[40]));
        user.put(new UnicodeString("name"), new UnicodeString(new String(name)));
        user.put(new UnicodeString("displayName"), new UnicodeString(new String(name)));
        root.put(new UnsignedInteger(3), user);
        Array algorithms = new Array();
        for (int alg : new int[]{-8, -7, -257}) {
            Map descriptor = new Map();
            descriptor.put(new UnicodeString("alg"), new NegativeInteger(alg));
            descriptor.put(new UnicodeString("type"), new UnicodeString("public-key"));
            algorithms.add(descriptor);
        }
        root.put(new UnsignedInteger(4), algorithms);
        Map options = new Map();
        options.put(new UnicodeString("rk"), SimpleValue.TRUE);
        root.put(new UnsignedInteger(7), options);
        root.put(new UnsignedInteger(8), new ByteString(new byte[16]));
        root.put(new UnsignedInteger(9), new UnsignedInteger(1));
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        bytes.write(0x01);
        new CborEncoder(bytes).encode(Collections.<DataItem>singletonList(root));
        byte[] value = bytes.toByteArray();
        assertEquals("One CTAP byte plus canonical CBOR-shaped request", 293, value.length);
        assertEquals(5 * 64, reports(value).length);
        RawMessage message = reassemble(value);
        MakeCredentialRequest parsed = MakeCredentialRequest.fromBytes(
                Arrays.copyOfRange(message.payload(), 1, message.payload().length));
        assertTrue(parsed.residentKeyRequested());
        assertEquals(40, parsed.userId().length);
        assertEquals(16, parsed.pinAuth().get().length);
        assertEquals(Integer.valueOf(1), parsed.pinProtocolVersion().get());
    }
}

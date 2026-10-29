package com.github.mphi_rc.fido2;

import static com.github.mphi_rc.fido2.PinUvProbe.*;
import com.github.mphi_rc.fido2.authenticator.*;
import com.github.mphi_rc.fido2.authenticator.keys.*;
import com.github.mphi_rc.fido2.authenticator.keys.token.*;
import com.github.mphi_rc.fido2.authenticator.keys.pkcs11.*;
import com.github.mphi_rc.fido2.protocol.ctap2.*;
import com.github.mphi_rc.fido2.protocol.ctap2.pin.PinRequestHandler;
import co.nstant.in.cbor.model.*;
import co.nstant.in.cbor.model.Map;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/** Real CBOR handlers + independently implemented ClientPIN client. Synthetic fixtures only. */
public final class TokenCtapProbe {
    private static final String TEST_RP="ctap-token.synthetic.invalid", PIN="246810", NEW_PIN="135790";
    private TokenCtapProbe() { }
    public static void main(String[] args) throws Exception {
        if(args.length!=6 || !args[0].equals("--software-token"))
            throw new IllegalArgumentException("--software-token <phase> <module-or-file-fixture> <slot> <synthetic-pin-file> <private-test-dir>");
        Path dir=Paths.get(args[5]).toAbsolutePath().normalize();
        if(!Files.isDirectory(dir) || !Files.getPosixFilePermissions(dir)
                .equals(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
            throw new IllegalArgumentException("Private synthetic test directory required");
        Pkcs11P256Signer signer=null;
        try {
            TokenKeyDriver driver;
            if(args[2].equals("file-fixture")) {
                Path token=dir.resolve("synthetic-token");
                if(!Files.exists(token))Files.createDirectory(token,java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                        java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
                driver=new SyntheticFileToken(token);
            } else {
                char[] pin=new String(Files.readAllBytes(Paths.get(args[4])),StandardCharsets.US_ASCII).trim().toCharArray();
                try {signer=Pkcs11P256Signer.open(Paths.get(args[2]),Long.parseLong(args[3]),pin);}
                finally{Arrays.fill(pin,'\0');}
                driver=new Pkcs11TokenKeyDriver(signer);
            }
            run(dir,args[1],driver);
        } finally {if(signer!=null)signer.close();}
    }
    private static void run(Path dir,String phase,TokenKeyDriver driver)throws Exception {
        try(DurableTokenCredentialBackend backend=new DurableTokenCredentialBackend(dir.resolve("token-credentials.json"),driver)){
            ConfigurationFile config=new ConfigurationFile(dir.resolve("synthetic-fido-config.json"));config.persistToDisk();
            PinState pin=new PinState(config);
            Authenticator auth=new Authenticator(config,backend,pin,true,System::nanoTime);
            TokenCtapClient client=new TokenCtapClient(new AuthenticatorRequestHandler(auth,new PinRequestHandler(pin)));
            if(phase.equals("create")){
                check(!client.configured(),"Fixture already configured");ok(client.set(PIN));ok(client.getToken(PIN));
                verifyRegistration(backend,client.make(TEST_RP,1,true,true));
                verifyRegistration(backend,client.make(TEST_RP,2,true,true));
                AtomicStateFile.write(dir.resolve("synthetic-old-token"),client.token);
                verifyAssertion(backend,client.assertion(TEST_RP,null,true),true,true);
                verifyAssertion(backend,client.call(8,null),true,true);
                check(client.getToken("not-the-synthetic-pin").status==0x31,"Negative PIN not rejected");
                check(client.retries()==7,"PIN retry count wrong");
            }else if(phase.equals("verify")){
                check(client.configured() && client.retries()==7,"PIN persistence failed");
                client.token=Files.readAllBytes(dir.resolve("synthetic-old-token"));
                check(client.assertion(TEST_RP,null,true).status==0x33,"Old PIN token survived process restart");
                ok(client.getToken(PIN));check(client.retries()==8,"Successful PIN did not reset retries");
                Reply first=client.assertion(TEST_RP,null,true);verifyAssertion(backend,first,true,true);
                check(((UnsignedInteger)field(first.body,5)).getValue().intValue()==2,"Two resident accounts not discovered");
                verifyAssertion(backend,client.call(8,null),true,true);
                Map silent=client.assertionRequest(TEST_RP,id(first),true);Map options=new Map();
                options.put(new UnicodeString("up"),SimpleValue.FALSE);put(silent,5,options);
                verifyAssertion(backend,client.call(2,silent),true,false);
                check(client.assertion("wrong.synthetic.invalid",id(first),true).status==0x2e,"RP isolation failed");
                byte[] old=client.token.clone();ok(client.change(PIN,NEW_PIN));client.token=old;
                check(client.assertion(TEST_RP,null,true).status==0x33,"PIN change did not revoke token");
            }else if(phase.equals("final")){
                ok(client.getToken(NEW_PIN));
                Reply first=client.assertion(TEST_RP,null,true);verifyAssertion(backend,first,true,true);
                Reply second=client.call(8,null);verifyAssertion(backend,second,true,true);
                CredentialDescriptor removed=matching(backend,id(first));
                backend.delete(removed.handle());
                check(client.assertion(TEST_RP,id(first),true).status==0x2e,"Deleted credential still authenticates");
                verifyAssertion(backend,client.assertion(TEST_RP,id(second),true),true,true);
            }else if(phase.equals("remaining")){
                ok(client.getToken(NEW_PIN));check(backend.find(TEST_RP).size()==1,"Deletion was not durable");
                verifyAssertion(backend,client.assertion(TEST_RP,null,true),true,true);
            }else throw new IllegalArgumentException("Unknown synthetic CTAP phase");
            check(config.credentials().isEmpty(),"Token private keys leaked into legacy FIDO store");
            System.out.println("PASS: token CTAP CBOR "+phase+" (PIN, RK, UV, independent signatures; simulated UP)");
        }
    }
    private static byte[] id(Reply reply){
        return ((ByteString)((Map)field(reply.body,1)).get(new UnicodeString("id"))).getBytes();
    }
    private static CredentialDescriptor matching(DurableTokenCredentialBackend backend,byte[] id){
        return backend.find(TEST_RP).stream().filter(c->Arrays.equals(c.id(),id)).findFirst()
                .orElseThrow(()->new AssertionError("Unknown response credential"));
    }
    private static void verifyRegistration(DurableTokenCredentialBackend backend,Reply reply)throws Exception {
        ok(reply);byte[] data=bytes(reply.body,2);
        check((data[32]&0x45)==0x45,"Registration did not set AT/UP/UV");
        int length=((data[53]&255)<<8)|(data[54]&255);
        CredentialDescriptor credential=matching(backend,Arrays.copyOfRange(data,55,55+length));
        check(credential.signatureCount()==0,"Registration count wrong");
        verify(credential,data,((ByteString)((Map)field(reply.body,3)).get(new UnicodeString("sig"))).getBytes());
    }
    private static void verifyAssertion(DurableTokenCredentialBackend backend,Reply reply,boolean uv,boolean up)throws Exception {
        ok(reply);byte[] data=bytes(reply.body,2);
        check(((data[32]&4)!=0)==uv && ((data[32]&1)!=0)==up,"Wrong signed UP/UV flags");
        CredentialDescriptor c=matching(backend,id(reply));verify(c,data,bytes(reply.body,3));
        int count=((data[33]&255)<<24)|((data[34]&255)<<16)|((data[35]&255)<<8)|(data[36]&255);
        check(c.signatureCount()==count && count>0,"Returned counter not durably committed");
    }
    private static void verify(CredentialDescriptor c,byte[] data,byte[] signature)throws Exception {
        Signature v=Signature.getInstance("SHA256withECDSA");
        v.initVerify(KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(c.publicKey())));
        v.update(data);v.update(HASH);check(v.verify(signature),"Invalid native FIDO signature");
    }
}

package org.bchateu.pskfactories;

import fi.iki.elonen.NanoHTTPD;
import okhttp3.*;
import org.bchateau.pskfactories.BcPskSSLServerSocketFactory;
import org.bchateau.pskfactories.BcPskSSLSocketFactory;
import org.bouncycastle.tls.BasicTlsPSKIdentity;
import org.bouncycastle.tls.TlsPSKIdentityManager;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class TestBcPskFactories {

    /**
     * Test secret key, real implementations should not hardcode keys in source code like this!
     */
    byte[] testPskKey = new byte[] { 0x1a, 0x2b, 0x3c, 0x4d };

    BasicTlsPSKIdentity testIdentity = new BasicTlsPSKIdentity("test", testPskKey);

    TlsPSKIdentityManager testIdentityMgr = new TlsPSKIdentityManager() {
        @Override
        public byte[] getHint() {
            // If multiple keys are supported this could signal which key to use
            return new byte[0];
        }

        @Override
        public byte[] getPSK(byte[] identity) {
            return testPskKey;
        }
    };

    interface HttpServerFinisher {
        void stop();
    }

    private static void testTlsPskClientWithOkHttpClientBackedByBc() throws IOException {
        log("Running OkHttp Client backed by BC");

        BasicTlsPSKIdentity identity = new BasicTlsPSKIdentity("test", new byte[] { 0x1a, 0x2b, 0x3c, 0x4d } );
        OkHttpClient client = new OkHttpClient.Builder()
                .callTimeout(3, TimeUnit.SECONDS)
                .sslSocketFactory(new BcPskSSLSocketFactory(identity), new BcPskSSLSocketFactory.EmptyX509TrustManager())
                .hostnameVerifier((hostname, session) -> true)
                .connectionSpecs(Collections.singletonList(new ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
                        // Must specify the CipherSuite, ConnectionSpec.RESTRICTED_TLS doesn't support PSK
                        .cipherSuites(CipherSuite.forJavaName("TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"))
                        .tlsVersions(TlsVersion.TLS_1_2)
                        .build()))
                .addInterceptor(new SSLHandshakeInterceptor())
                .build();

        Call call;
        for (int i = 0; i < 6; i++) {
            if (i % 2 == 0) {
                log("Making a GET request");
                call = client.newCall(new Request.Builder().
                        url("https://localhost:4433").build());

            } else {
                log("Making a PUT request");
                call = client.newCall(new Request.Builder()
                        .method("PUT", RequestBody.create(MediaType.get("text/plain"), "Hi"))
                        .url("https://localhost:4433").build());
            }

            try (Response resp = call.execute()) {
                log("Got: " + resp.code());
                if (resp.code() != 429) {
                    throw new AssertionError("Unexpected HTTP response code: " + resp.code());
                }
            }
        }
    }

    private static HttpServerFinisher testTlsPskNanoHttpdWithBcFactory() throws IOException {
        NanoHTTPD nano = new NanoHTTPD(4433) {
            @Override
            public Response serve(IHTTPSession session) {
                Map<String, String> parameters = new HashMap<>();
                try {
                    // Must consume the body
                    session.parseBody(parameters);
                } catch (IOException e) {
                    return newFixedLengthResponse(Response.Status.INTERNAL_ERROR, NanoHTTPD.MIME_PLAINTEXT,
                            "SERVER INTERNAL ERROR: IOException: " + e.getMessage());
                } catch (ResponseException e) {
                    return newFixedLengthResponse(e.getStatus(), NanoHTTPD.MIME_PLAINTEXT, e.getMessage());
                }
                return newFixedLengthResponse(Response.Status.TOO_MANY_REQUESTS, NanoHTTPD.MIME_PLAINTEXT,
                        "Too much");
            }
        };

        TlsPSKIdentityManager identityMgr = new TlsPSKIdentityManager() {
            @Override
            public byte[] getHint() {
                return new byte[0];
            }

            @Override
            public byte[] getPSK(byte[] identity) {
                return new byte[] { 0x1a, 0x2b, 0x3c, 0x4d };
            }
        };

        // Setting sslProtocols param to null tells NanoHTTPD to allow all protocols supported by the ServerSocketFactory
        nano.makeSecure(new BcPskSSLServerSocketFactory(identityMgr), null);

        log("Starting Nano HTTP server backed by BC");
        nano.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);

        return nano::stop;
    }

    public static void log(String s) {
        RuntimeMXBean rb = ManagementFactory.getRuntimeMXBean();
        System.out.println(String.format(Locale.US, "%08d", rb.getUptime()) + ": " + s + " (" + Thread.currentThread() + ")");
    }

    @Test
    public void testClientCreate() {
        new BcPskSSLSocketFactory(testIdentity);
    }

    @Test
    public void testServerCreate() {
        new BcPskSSLServerSocketFactory(testIdentityMgr);
    }

    @Test
    public void testServerClientConnect() throws Exception {
        HttpServerFinisher server = null;
        try {
            server = testTlsPskNanoHttpdWithBcFactory();
            testTlsPskClientWithOkHttpClientBackedByBc();
        } finally {
            if (server != null) {
                server.stop();
            }
        }
    }

}

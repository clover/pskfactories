package org.bchateau.pskfactories;

import fi.iki.elonen.NanoHTTPD;
import okhttp3.Call;
import okhttp3.ConnectionSpec;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import org.bouncycastle.tls.BasicTlsPSKIdentity;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsPSKIdentityManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class TestBcPskFactories {

    final int testPort = 4433;

    /**
     * Test secret key, real implementations should not hardcode keys in source code like this!
     */
    final byte[] testPskKey = new byte[] {
            0x1a, 0x2b, 0x3c, 0x4d, 0x1a, 0x2b, 0x3c, 0x4d,
            0x1a, 0x2b, 0x3c, 0x4d, 0x1a, 0x2b, 0x3c, 0x4d,
    };

    final String TEST_IDENTITY_KEY = "test";

    final BasicTlsPSKIdentity testIdentity = new BasicTlsPSKIdentity("test", testPskKey);

    final TlsPSKIdentityManager testIdentityMgr = new TlsPSKIdentityManager() {
        @Override
        public byte[] getHint() {
            // If multiple keys are supported this could signal which key to use
            return new byte[0];
        }

        @Override
        public byte[] getPSK(byte[] identity) {
            if (Arrays.equals(TEST_IDENTITY_KEY.getBytes(), identity)) {
                return testPskKey;
            } else {
                throw new IllegalArgumentException("Unrecognized identity rejected");
            }
        }
    };

    final BcPskTlsParams defaultParams = new BcPskTlsParams();;

    final BcPskTlsParams tls12Params = new BcPskTlsParams(new ProtocolVersion[] { ProtocolVersion.TLSv12 },
            new int[] { org.bouncycastle.tls.CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 });

    final BcPskTlsParams tls13Params = new BcPskTlsParams(new ProtocolVersion[] { ProtocolVersion.TLSv13 },
            new int[] { org.bouncycastle.tls.CipherSuite.TLS_AES_128_GCM_SHA256 });

    interface HttpServerFinisher {
        void stop();
    }

    private static void runPskClient(int port, BcPskTlsParams params, BasicTlsPSKIdentity identity) throws IOException {
        log("Running OkHttp Client backed by BC");

        OkHttpClient client = new OkHttpClient.Builder()
                .callTimeout(3, TimeUnit.SECONDS)
                // Empty trust manager is required, null is not allowed
                .sslSocketFactory(new BcPskSSLSocketFactory(params, identity), new BcPskSSLSocketFactory.EmptyX509TrustManager())
                .hostnameVerifier((hostname, session) -> true)
                .connectionSpecs(Collections.singletonList(new ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
                        // Must specify the CipherSuite, ConnectionSpec.RESTRICTED_TLS doesn't support PSK
                        .cipherSuites(params.getSupportedCipherSuites())
                        .tlsVersions(params.getSupportedProtocols())
                        .build()))
                .addInterceptor(new SSLHandshakeInterceptor())
                .build();

        Call call;
        for (int i = 0; i < 6; i++) {
            if (i % 2 == 0) {
                log("Making a GET request");
                call = client.newCall(new Request.Builder().
                        url("https://localhost:" + port).build());

            } else {
                log("Making a PUT request");
                call = client.newCall(new Request.Builder()
                        .method("PUT", RequestBody.create(MediaType.get("text/plain"), "Hi"))
                        .url("https://localhost:" + port).build());
            }

            try (Response resp = call.execute()) {
                log("Got: " + resp.code());
                if (resp.code() != 429) {
                    throw new AssertionError("Unexpected HTTP response code: " + resp.code());
                }
            }
        }
    }

    private static HttpServerFinisher startPskServer(int port, BcPskTlsParams params, TlsPSKIdentityManager identityMgr)
            throws IOException {
        NanoHTTPD nano = new NanoHTTPD(port) {
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

        // Setting sslProtocols param to null tells NanoHTTPD to allow all protocols supported by the factory
        nano.makeSecure(new BcPskSSLServerSocketFactory(params, identityMgr), null);

        log("Starting Nano HTTP server backed by BC");
        nano.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);

        return nano::stop;
    }

    public static void log(String s) {
        RuntimeMXBean rb = ManagementFactory.getRuntimeMXBean();
        System.out.println(String.format(Locale.US, "%08d", rb.getUptime()) + ": " + s +
                " (" + Thread.currentThread() + ")");
    }

    @Test
    public void testServerTlsDefaultClientTlsDefaultConnect() throws Exception {
        HttpServerFinisher server = null;
        try {
            server = startPskServer(testPort, defaultParams, testIdentityMgr);
            runPskClient(testPort, defaultParams, testIdentity);
        } finally {
            if (server != null) {
                server.stop();
            }
        }
    }

    @Test
    public void testServerTls12ClientTlsDefaultConnect() throws Exception {
        HttpServerFinisher server = null;
        try {
            server = startPskServer(testPort, tls12Params, testIdentityMgr);
            runPskClient(testPort, defaultParams, testIdentity);
        } finally {
            if (server != null) {
                server.stop();
            }
        }
    }

    @Test
    public void testServerTlsDefaultClientTls12Connect() throws Exception {
        HttpServerFinisher server = null;
        try {
            server = startPskServer(testPort, defaultParams, testIdentityMgr);
            runPskClient(testPort, tls12Params, testIdentity);
        } finally {
            if (server != null) {
                server.stop();
            }
        }
    }

    @Test
    public void testServerTlsDefaultClientTls13Connect() throws Exception {
        HttpServerFinisher server = null;
        try {
            server = startPskServer(testPort, defaultParams, testIdentityMgr);
            runPskClient(testPort, tls13Params, testIdentity);
        } finally {
            if (server != null) {
                server.stop();
            }
        }
    }

    @Test
    public void testServerTls13ClientTlsDefaultConnect() throws Exception {
        HttpServerFinisher server = null;
        try {
            server = startPskServer(testPort, tls13Params, testIdentityMgr);
            runPskClient(testPort, defaultParams, testIdentity);
        } finally {
            if (server != null) {
                server.stop();
            }
        }
    }

    @Test
    public void testServerTls13ClientTls12Reject() {
        // Incompatible versions
        Assertions.assertThrows(IOException.class, () -> {
            HttpServerFinisher server = null;
            try {
                server = startPskServer(testPort, tls13Params, testIdentityMgr);
                runPskClient(testPort, tls12Params, testIdentity);
            } finally {
                if (server != null) {
                    server.stop();
                }
            }
        });
    }

    @Test
    public void testServerTls12ClientTls13Reject() {
        // Incompatible versions
        Assertions.assertThrows(IOException.class, () -> {
            HttpServerFinisher server = null;
            try {
                server = startPskServer(testPort, tls12Params, testIdentityMgr);
                runPskClient(testPort, tls13Params, testIdentity);
            } finally {
                if (server != null) {
                    server.stop();
                }
            }
        });
    }

    @Test
    public void testServerClientKeyMismatch() {
        // Key mismatch
        Assertions.assertThrows(IOException.class, () -> {
            final byte[] testPskKey2 = new byte[] {
                    0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
                    0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
            };

            final BasicTlsPSKIdentity testIdentity2 = new BasicTlsPSKIdentity("test", testPskKey2);

            HttpServerFinisher server = null;
            try {
                server = startPskServer(testPort, defaultParams, testIdentityMgr);
                runPskClient(testPort, defaultParams, testIdentity2);
            } finally {
                if (server != null) {
                    server.stop();
                }
            }
        });
    }

    @Test
    public void testServerClientIdentityMismatch() {
        // Key mismatch
        Assertions.assertThrows(IOException.class, () -> {
            final BasicTlsPSKIdentity testIdentity2 = new BasicTlsPSKIdentity("other", testPskKey);

            HttpServerFinisher server = null;
            try {
                server = startPskServer(testPort, defaultParams, testIdentityMgr);
                runPskClient(testPort, defaultParams, testIdentity2);
            } finally {
                if (server != null) {
                    server.stop();
                }
            }
        });
    }

}

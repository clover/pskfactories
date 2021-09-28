/*
 * Copyright (C) 2021 Clover Network, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bchateau;

import fi.iki.elonen.NanoHTTPD;
import okhttp3.Call;
import okhttp3.CipherSuite;
import okhttp3.ConnectionSpec;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.TlsVersion;
import org.bchateau.pskfactories.BcPskSSLServerSocketFactory;
import org.bchateau.pskfactories.BcPskSSLSocketFactory;
import org.bouncycastle.tls.BasicTlsPSKIdentity;
import org.bouncycastle.tls.TlsPSKIdentityManager;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Example to test out the functionality of the PSK factories.
 * <p>
 * You may test the client and the server against a reference implementation provided by openssl as well.
 * <br>
 * Server:
 * <pre>{@code
 * openssl s_server -psk 1a2b3c4d -nocert -www
 * }</pre>
 * Client:
 * <pre>{@code
 * openssl s_client -connect 127.0.0.1:4433 -psk 1a2b3c4d
 * }</pre>
 */
public class Main {

    public static void main(String[] args) {
        new Thread(() -> {
            HttpServerFinisher server = null;
            try {
                server = testTlsPskNanoHttpdWithBcFactory();

                Thread.sleep(500);

                testTlsPskClientWithOkHttpClientBackedByBc();

                Thread.sleep(2000);
            } catch (Exception e) {
                log("Exception during test");
                e.printStackTrace();
            } finally {
                if (server != null) {
                    server.stop();
                }
            }
        }).start();
    }

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
                        .cipherSuites(CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256)
                        .tlsVersions(TlsVersion.TLS_1_2)
                        .build()))
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
                     return newFixedLengthResponse(Response.Status.INTERNAL_ERROR, NanoHTTPD.MIME_PLAINTEXT, "SERVER INTERNAL ERROR: IOException: " + e.getMessage());
                 } catch (ResponseException e) {
                     return newFixedLengthResponse(e.getStatus(), NanoHTTPD.MIME_PLAINTEXT, e.getMessage());
                 }
                 return newFixedLengthResponse(Response.Status.TOO_MANY_REQUESTS, NanoHTTPD.MIME_PLAINTEXT, "Too much");
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

}

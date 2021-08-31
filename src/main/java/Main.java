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

import fi.iki.elonen.NanoHTTPD;
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
import java.net.MulticastSocket;
import java.util.Collections;
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
        MulticastSocket x;
        x.joinGroup();

        new Thread(() -> {
            HttpServerFinisher server = null;
            try {
                //server = testTlsPskNanoHttpdWithBcFactory();

                Thread.sleep(500);

                testTlsPskClientWithOkHttpClientBackedByBc();

                Thread.sleep(500);
            } catch (Exception e) {
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
        System.out.println("Running OkHttp Client backed by BC");

        BasicTlsPSKIdentity identity = new BasicTlsPSKIdentity("test", "478F3B36F8598C15B0F68360FB1BD5E0".getBytes() );
        OkHttpClient client = new OkHttpClient.Builder()
                .callTimeout(3, TimeUnit.SECONDS)
                .sslSocketFactory(new BcPskSSLSocketFactory(identity), new BcPskSSLSocketFactory.EmptyX509TrustManager())
                .hostnameVerifier((hostname, session) -> true)
                .connectionSpecs(Collections.singletonList(new ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
                                .cipherSuites(CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256)
                                .tlsVersions(TlsVersion.TLS_1_2)
                                .build()))
                .build();

        String syncMsg = "{\"authorities\":[\"com.clover.orders\"],\"authoritySyncTokenMap\":{\"com.clover.orders\":1627416855000},\"authorityViewMap\":{}}";

        Response resp = client.newCall(new Request.Builder().url("https://192.168.1.148:49152/sync")
                .post(RequestBody.create(MediaType.parse("application/json"), syncMsg))
                        .build()).execute();
        System.out.println("Got: " + resp.code());
    }

    private static HttpServerFinisher testTlsPskNanoHttpdWithBcFactory() throws IOException {
        NanoHTTPD nano = new NanoHTTPD(4433) {
             @Override
             public Response serve(IHTTPSession session) {
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

        System.out.println("Starting Nano HTTP server backed by BC");
        nano.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);

        return nano::stop;
    }

}

package org.bchateau.pskfactories;

import okhttp3.CipherSuite;
import okhttp3.Handshake;
import okhttp3.Response;
import okhttp3.TlsVersion;

import java.io.IOException;

public class SSLHandshakeInterceptor implements okhttp3.Interceptor {

    @Override
    public Response intercept(Chain chain) throws IOException {
        final Response response = chain.proceed(chain.request());
        printTlsAndCipherSuiteInfo(response);
        return response;
    }

    private void printTlsAndCipherSuiteInfo(Response response) {
        if (response != null) {
            Handshake handshake = response.handshake();
            if (handshake != null) {
                final CipherSuite cipherSuite = handshake.cipherSuite();
                final TlsVersion tlsVersion = handshake.tlsVersion();
                System.out.println("TLS: " + tlsVersion + ", CipherSuite: " + cipherSuite);
            }
        }
    }
}
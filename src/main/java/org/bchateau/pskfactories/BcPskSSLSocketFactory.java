/*
 * Copyright (C) 2024 Clover Network, Inc.
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

package org.bchateau.pskfactories;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.tls.PSKTlsClient;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsPSKIdentity;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;


/**
 * This SSLSocketFactory provides TLS pre-shared key (PSK) ciphersuites via Bouncy Castle. The existing Bouncy Castle
 * JSSE provider as of version 1.69 does not offer PSK ciphersuites. This class has only been lightly tested against
 * OkHttpClient at this time. When using an instance of this class with OkHttp you should also provide and instance of
 * {@link EmptyX509TrustManager}.
 */
public class BcPskSSLSocketFactory extends SSLSocketFactory {

    private static final boolean DEBUG = false;

    private final TlsCrypto crypto;
    private final TlsPSKIdentity pskIdentity;

    public BcPskSSLSocketFactory(TlsPSKIdentity pskIdentity) {
        this.crypto = new BcTlsCrypto(new SecureRandom());
        this.pskIdentity = pskIdentity;
    }

    private static class BcPskTlsClientProtocol extends TlsClientProtocol {
        public BcPskTlsClientProtocol(InputStream input, OutputStream output) {
            super(input, output);
        }

        @Override
        public void close() throws IOException {
            // Avoid null pointer when "Unable to find acceptable protocols" occurs
            if (getPeer() == null) {
                cleanupHandshake();
            } else {
                super.close();
            }
        }

        @Override
        protected void raiseAlertFatal(short alertDescription, String message, Throwable cause) throws IOException {
            cause.printStackTrace();
        }

        @Override
        protected void raiseAlertWarning(short alertDescription, String message) throws IOException {
            if (DEBUG) {
                System.out.println(message);
            }
        }

        String getCipherSuite() {
            TlsContext context = getContext();
            if (context == null) {
                return null;
            }
            return BcPskTlsParams.toCipherSuiteString(context.getSecurityParameters().getCipherSuite());
        }

        String getProtocol() {
            TlsContext context = getContext();
            if (context == null) {
                return null;
            }
            return BcPskTlsParams.toJavaName(context.getSecurityParameters().getNegotiatedVersion());
        }

        byte[] getSessionId() {
            TlsContext context = getContext();
            if (context == null) {
                return null;
            }
            return context.getSession().getSessionID();
        }

        String getApplicationProtocol() {
            TlsContext context = getContext();
            if (context == null) {
                return null;
            }
            return getApplicationProtocol(context.getSecurityParametersConnection());
        }

        static String getApplicationProtocol(SecurityParameters securityParameters) {
            if (null == securityParameters || !securityParameters.isApplicationProtocolSet()) {
                return null;
            }

            ProtocolName applicationProtocol = securityParameters.getApplicationProtocol();
            if (null == applicationProtocol) {
                return "";
            }

            return applicationProtocol.getUtf8Decoding();
        }
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return BcPskTlsParams.getSupportedCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return BcPskTlsParams.getSupportedCipherSuites();
    }

    /**
     * Not supported.
     */
    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        throw new UnsupportedOperationException();
    }

    /**
     * Not supported.
     */
    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        throw new UnsupportedOperationException();
    }

    /**
     * Not supported.
     */
    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        throw new UnsupportedOperationException();
    }

    /**
     * Not supported.
     */
    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        throw new UnsupportedOperationException();
    }

    /**
     * This is the only createSocket method that is implemented, it must be used with autoClose set to true and it
     * requires that the given socket already be connected.
     */
    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        if (!autoClose) {
            throw new UnsupportedOperationException("Only auto-close sockets can be created");
        }

        if (!socket.isConnected()) {
            throw new UnsupportedOperationException("Socket must be connected prior to be used with this factory");
        }

        BcPskTlsClientProtocol tlsClientProtocol = new BcPskTlsClientProtocol(socket.getInputStream(), socket.getOutputStream());

        return new WrappedSSLSocket(socket) {
            private String[] enabledCipherSuites = BcPskTlsParams.getSupportedCipherSuites();
            private String[] enabledProtocols = BcPskTlsParams.getSupportedProtocols();

            private boolean enableSessionCreation = true;

            @Override
            public InputStream getInputStream() throws IOException {
                return tlsClientProtocol.getInputStream();
            }

            @Override
            public OutputStream getOutputStream() throws IOException {
                return tlsClientProtocol.getOutputStream();
            }

            @Override
            public synchronized void close() throws IOException {
                super.close();
                synchronized (tlsClientProtocol) {
                    tlsClientProtocol.close();
                }
            }

            @Override
            public String getApplicationProtocol() {
                return tlsClientProtocol.getApplicationProtocol();
            }

            @Override
            public boolean getEnableSessionCreation() {
                return enableSessionCreation;
            }

            @Override
            public String[] getEnabledCipherSuites() {
                return enabledCipherSuites.clone();
            }

            @Override
            public String[] getEnabledProtocols() {
                return enabledProtocols.clone();
            }

            @Override
            public boolean getNeedClientAuth() {
                return false;
            }

            @Override
            public String[] getSupportedProtocols() {
                return BcPskTlsParams.getSupportedProtocols();
            }

            @Override
            public boolean getUseClientMode() {
                return false;
            }

            @Override
            public boolean getWantClientAuth() {
                return false;
            }

            @Override
            public void setEnabledCipherSuites(String[] suites) {
                Set<String> supported = new HashSet<>();
                Collections.addAll(supported, getSupportedCipherSuites());

                List<String> enabled = new ArrayList<>();
                for (String s : suites) {
                    if (supported.contains(s)) {
                        enabled.add(s);
                    }
                }
                enabledCipherSuites = enabled.toArray(new String[0]);
            }

            @Override
            public void setEnableSessionCreation(boolean flag) {
                enableSessionCreation = flag;
            }

            @Override
            public void setEnabledProtocols(String[] protocols) {
                Set<String> supported = new HashSet<>();
                Collections.addAll(supported, getSupportedProtocols());

                List<String> enabled = new ArrayList<>();
                for (String s : protocols) {
                    if (supported.contains(s)) {
                        enabled.add(s);
                    }
                }
                enabledProtocols = enabled.toArray(new String[0]);
            }

            @Override
            public void setNeedClientAuth(boolean need) {
                // Ignored, PSK ensures mutual auth
            }

            @Override
            public void setUseClientMode(boolean mode) {
                // Ignored, PSK ensures mutual auth
            }

            @Override
            public void setWantClientAuth(boolean want) {
                // Ignored, PSK ensures mutual auth
            }

            @Override
            public String[] getSupportedCipherSuites() {
                return BcPskTlsParams.getSupportedCipherSuites();
            }

            @Override
            public void startHandshake() throws IOException {
                tlsClientProtocol.connect(new PSKTlsClient(crypto, pskIdentity) {
                    @Override
                    protected ProtocolVersion[] getSupportedVersions() {
                        return BcPskTlsParams.fromSupportedProtocolVersions(getEnabledProtocols());
                    }

                    @Override
                    protected int[] getSupportedCipherSuites() {
                        return BcPskTlsParams.fromSupportedCipherSuiteCodes(getEnabledCipherSuites());
                    }
                });
            }

            @Override
            public SSLSession getSession() {
                return new SSLSession() {
                    private boolean isValid = true;

                    /**
                     * Maximum length of allowed plain data fragment
                     * as specified by TLS specification.
                     */
                    protected static final int MAX_DATA_LENGTH = 16384; // 2^14
                    /**
                     * Maximum length of allowed compressed data fragment
                     * as specified by TLS specification.
                     */
                    protected static final int MAX_COMPRESSED_DATA_LENGTH
                            = MAX_DATA_LENGTH + 1024;
                    /**
                     * Maximum length of allowed ciphered data fragment
                     * as specified by TLS specification.
                     */
                    protected static final int MAX_CIPHERED_DATA_LENGTH
                            = MAX_COMPRESSED_DATA_LENGTH + 1024;
                    /**
                     * Maximum length of ssl record. It is counted as:
                     * type(1) + version(2) + length(2) + MAX_CIPHERED_DATA_LENGTH
                     */
                    protected static final int MAX_SSL_PACKET_SIZE
                            = MAX_CIPHERED_DATA_LENGTH + 5;

                    private final long creationTime = System.currentTimeMillis();
                    private final Map<String, Object> valueMap = Collections.synchronizedMap(new HashMap<>());

                    @Override
                    public int getApplicationBufferSize() {
                        return tlsClientProtocol.getApplicationDataLimit();
                    }

                    @Override
                    public String getCipherSuite() {
                        return tlsClientProtocol.getCipherSuite();
                    }

                    @Override
                    public long getCreationTime() {
                        return creationTime;
                    }

                    @Override
                    public byte[] getId() {
                        return tlsClientProtocol.getSessionId();
                    }

                    @Override
                    public long getLastAccessedTime() {
                        return getCreationTime();
                    }

                    @Override
                    public java.security.cert.Certificate[] getLocalCertificates() {
                        return null;
                    }

                    @Override
                    public Principal getLocalPrincipal() {
                        throw new UnsupportedOperationException();
                    }

                    @Override
                    public int getPacketBufferSize() {
                        return MAX_SSL_PACKET_SIZE;
                    }

                    @Override
                    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
                        return null;
                    }

                    @Override
                    public java.security.cert.Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
                        return null;
                    }

                    @Override
                    public String getPeerHost() {
                        return host;
                    }

                    @Override
                    public int getPeerPort() {
                        return port;
                    }

                    @Override
                    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
                        return null;
                    }

                    @Override
                    public String getProtocol() {
                        return tlsClientProtocol.getProtocol();
                    }

                    @Override
                    public SSLSessionContext getSessionContext() {
                        throw new UnsupportedOperationException();
                    }

                    public Object getValue(String name) {
                        return valueMap.get(name);
                    }

                    public String[] getValueNames() {
                        synchronized (valueMap) {
                            return valueMap.keySet().toArray(new String[valueMap.size()]);
                        }
                    }

                    @Override
                    public void invalidate() {
                        isValid = false;
                    }

                    @Override
                    public boolean isValid() {
                        // TODO: Check session time limit
                        return isValid && !socket.isClosed() && !tlsClientProtocol.isClosed();
                    }

                    @Override
                    public void putValue(String name, Object value) {
                        notifyUnbound(name, valueMap.put(name, value));
                        notifyBound(name, value);
                    }

                    @Override
                    public void removeValue(String name) {
                        notifyUnbound(name, valueMap.remove(name));
                    }

                    private void notifyBound(String name, Object value) {
                        if (value instanceof SSLSessionBindingListener) {
                            ((SSLSessionBindingListener) value).valueBound(new SSLSessionBindingEvent(this, name));
                        }
                    }

                    private void notifyUnbound(String name, Object value) {
                        if (value instanceof SSLSessionBindingListener) {
                            ((SSLSessionBindingListener) value).valueUnbound(new SSLSessionBindingEvent(this, name));
                        }
                    }
                };
            }
        };
    }

    /**
     * PSK TLS does not use certificates but clients may still require a non-null X509TrustManager so this one can
     * be used.
     */
    public static class EmptyX509TrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new UnsupportedOperationException();
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
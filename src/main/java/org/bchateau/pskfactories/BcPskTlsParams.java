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

package org.bchateau.pskfactories;

import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ProtocolVersion;

/**
 * Provides some basic conversion methods and specifies defaults for TLS functionality.
 * <p>
 * Values may be customized as needed so long as they are within the functionality provided by BouncyCastle.
 */
class BcPskTlsParams {

    // Customize as needed
    // Subset of org.bouncycastle.tls.PSKTlsClient cipher suites that are most secure
    private static final int[] supportCipherSuiteCodes = new int[] {
            CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
    };

    private static final String[] supportedCipherSuites;

    // Customize as needed
    // Specify just TLS v1.2 since as of 2021 it is well-supported and secure
    private static final ProtocolVersion[] supportedProtocolVersions = new ProtocolVersion[] {
            ProtocolVersion.TLSv12,
    };

    private BcPskTlsParams() { }

    public static String toJavaName(ProtocolVersion version) {
        switch (version.getFullVersion()) {
            case 0x0301:
                return "TLSv1.0";
            case 0x0302:
                return "TLSv1.1";
            case 0x0303:
                return "TLSv1.2";
            case 0x0304:
                return "TLSv1.3";
        }

        throw new IllegalArgumentException("Unable to get java name for: " + version);
    }

    public static ProtocolVersion fromJavaName(String version) {
        switch (version) {
            case "TLSv1.0":
                return ProtocolVersion.TLSv10;
            case "TLSv1.1":
                return ProtocolVersion.TLSv11;
            case "TLSv1.2":
                return ProtocolVersion.TLSv12;
            case "TLSv1.3":
                return ProtocolVersion.TLSv13;
        }

        throw new IllegalArgumentException("Unable to get protocol version for: " + version);
    }

    // See org/bouncycastle/tls/CipherSuite.java
    public static String toCipherSuiteString(int code) {
        switch (code) {
            case 0x0090:
                return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA";
            case 0x00AA:
                return "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256";
            case 0x00B2:
                return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256";
            case 0xC035:
                return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA";
            case 0xC037:
                return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256";
            case 0xCCAC:
                return "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256";
            case 0xCCAD:
                return "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256";
            case 0xD001:
                return "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256";
        }

        throw new IllegalArgumentException("Unknown TLS cipher code: " + code);
    }

    // Customize as needed
    // See org/bouncycastle/tls/CipherSuite.java
    public static int fromCipherSuiteString(String name) {
        switch (name) {
            case "TLS_DHE_PSK_WITH_AES_128_CBC_SHA":
                return 0x0090;
            case "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256":
                return 0x00AA;
            case "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256":
                return 0x00B2;
            case "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA":
                return 0xC035;
            case "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256":
                return 0xC037;
            case "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256":
                return 0xCCAC;
            case "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256":
                return 0xCCAD;
            case "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256":
                return 0xD001;
        }

        throw new IllegalArgumentException("Unknown TLS cipher: " + name);
    }

    private static final String[] supportedProtocols;

    static {
        supportedProtocols = new String[supportedProtocolVersions.length];
        for (int i = 0; i < supportedProtocolVersions.length; i++) {
            supportedProtocols[i] = toJavaName(supportedProtocolVersions[i]);
        }

        supportedCipherSuites = new String[supportCipherSuiteCodes.length];
        for (int i = 0; i < supportCipherSuiteCodes.length; i++) {
            supportedCipherSuites[i] = toCipherSuiteString(supportCipherSuiteCodes[i]);
        }
    }

    public static String[] getSupportedCipherSuites() {
        return supportedCipherSuites.clone();
    }

    public static String[] getSupportedProtocols() {
        return supportedProtocols.clone();
    }

    public static int[] getSupportedCipherSuiteCodes() {
        return supportCipherSuiteCodes.clone();
    }

    public static ProtocolVersion[] getSupportedProtocolVersions() {
        return supportedProtocolVersions.clone();
    }

    public static int[] fromSupportedCipherSuiteCodes(String[] jsseCipherSuites) {
        int[] cipherSuiteCodes = new int[jsseCipherSuites.length];
        for (int i = 0; i < jsseCipherSuites.length; i++) {
            cipherSuiteCodes[i] = fromCipherSuiteString(jsseCipherSuites[i]);
        }
        return cipherSuiteCodes;
    }

    public static ProtocolVersion[] fromSupportedProtocolVersions(String[] jsseProtocols) {
        ProtocolVersion[] protocolVersions = new ProtocolVersion[jsseProtocols.length];
        for (int i = 0; i < jsseProtocols.length; i++) {
            protocolVersions[i] = fromJavaName(jsseProtocols[i]);
        }
        return protocolVersions;
    }
}

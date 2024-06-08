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

import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ProtocolVersion;

import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

/**
 * Provides basic conversion methods and specifies supported cipher suites and TLS protocol
 * versions. If older/unusual cipher suites are to be used some internal methods here will need
 * to be expanded.
 */
public class BcPskTlsParams {

    // Currently this is a subset of org.bouncycastle.tls.PSKTlsClient cipher suites that are most secure
    private static final int[] defaultSupportedCipherSuiteCodes = new int[] {
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
    };

    private static final ProtocolVersion[] defaultSupportedProtocolVersions = new ProtocolVersion[] {
            ProtocolVersion.TLSv13,
            ProtocolVersion.TLSv12,
    };

    private static final Comparator<ProtocolVersion> protocolComparator = (o1, o2) -> {
        if (o1.equals(o2)) {
            return 0;
        } else if (o1.isEarlierVersionOf(o2)) {
            return 1;
        }
        return -1;
    };

    private final ProtocolVersion[] supportedProtocolVersions;
    private final int[] supportedCipherSuiteCodes;
    private final String[] supportedCipherSuites;
    private final String[] supportedProtocols;

    /**
     * Create an instance that supports TLSv1.2 and TLSv1.3 with the following cipher suites:
     * <pre>
     * TLS_AES_128_GCM_SHA256,
     * TLS_AES_256_GCM_SHA384,
     * TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
     * TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
     * TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
     * </pre>
     */
    public BcPskTlsParams() {
        this.supportedProtocolVersions = defaultSupportedProtocolVersions.clone();
        this.supportedCipherSuiteCodes = defaultSupportedCipherSuiteCodes.clone();
        this.supportedCipherSuites = cipherSuiteCodesToStrings(supportedCipherSuiteCodes);
        this.supportedProtocols = protocolVersionsToStrings(supportedProtocolVersions);
    }

    /**
     * Create an instance that supports the given protocol versions and cipher suites. It is up to
     * the caller to ensure the given cipher suites are compatible with the given protocol versions
     * (i.e.: if TLSv1.2 only is given then only TLSv1.2 cipher suites must be given).
     */
    public BcPskTlsParams(ProtocolVersion[] supportedProtocolVersions, int[] supportedCipherSuiteCodes) {
        this.supportedProtocolVersions = supportedProtocolVersions.clone();
        // As-is Bouncy Castle breaks if TLSv1.2 is listed earlier than TLSv1.3, this ensures the
        // protocols are ordered by highest version first
        Arrays.sort(this.supportedProtocolVersions, protocolComparator);
        this.supportedCipherSuiteCodes = supportedCipherSuiteCodes.clone();
        this.supportedCipherSuites = cipherSuiteCodesToStrings(supportedCipherSuiteCodes);
        this.supportedProtocols = protocolVersionsToStrings(supportedProtocolVersions);
    }

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

    private static final HashMap<String, Integer> suiteToCodeMap = new HashMap<>();
    private static final HashMap<Integer, String> codeToSuiteMap = new HashMap<>();

    static {
        // Update as needed, see org/bouncycastle/tls/CipherSuite.java
        suiteToCodeMap.put("TLS_DHE_PSK_WITH_AES_128_CBC_SHA", 0x0090);
        suiteToCodeMap.put("TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", 0x00AA);
        suiteToCodeMap.put("TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", 0x00AB);
        suiteToCodeMap.put("TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", 0x00B2);
        suiteToCodeMap.put("TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", 0x00B3);
        suiteToCodeMap.put("TLS_AES_128_GCM_SHA256", 0x1301);
        suiteToCodeMap.put("TLS_AES_256_GCM_SHA384", 0x1302);
        suiteToCodeMap.put("TLS_CHACHA20_POLY1305_SHA256", 0x1303);
        suiteToCodeMap.put("TLS_AES_128_CCM_SHA256", 0x1304);
        suiteToCodeMap.put("TLS_AES_128_CCM_8_SHA256", 0x1305);
        suiteToCodeMap.put("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", 0xC035);
        suiteToCodeMap.put("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", 0xC037);
        suiteToCodeMap.put("TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", 0xCCAC);
        suiteToCodeMap.put("TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256", 0xCCAD);
        suiteToCodeMap.put("TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", 0xD001);
        suiteToCodeMap.put("TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384", 0xD002);

        for (Map.Entry<String, Integer> entry : suiteToCodeMap.entrySet()) {
            codeToSuiteMap.put(entry.getValue(), entry.getKey());
        }
    }

    public static String toCipherSuiteString(int code) {
        String suite = codeToSuiteMap.get(code);
        if (suite == null) {
            throw new IllegalArgumentException("Unsupported TLS cipher code: " + code);
        } else {
            return suite;
        }
    }

    public static int fromCipherSuiteString(String name) {
        Integer code = suiteToCodeMap.get(name);
        if (code == null) {
            throw new IllegalArgumentException("Unsupported TLS cipher: " + name);
        } else {
            return code;
        }
    }

    private static String[] protocolVersionsToStrings(ProtocolVersion[] versions) {
        String[] protocolStrings = new String[versions.length];
        for (int i = 0; i < versions.length; i++) {
            protocolStrings[i] = toJavaName(versions[i]);
        }
        return protocolStrings;
    }

    private static String[] cipherSuiteCodesToStrings(int[] codes) {
        String[] suiteStrings = new String[codes.length];
        for (int i = 0; i < codes.length; i++) {
            suiteStrings[i] = toCipherSuiteString(codes[i]);
        }
        return suiteStrings;
    }

    public String[] getSupportedCipherSuites() {
        return supportedCipherSuites.clone();
    }

    public String[] getSupportedProtocols() {
        return supportedProtocols.clone();
    }

    public int[] getSupportedCipherSuiteCodes() {
        return supportedCipherSuiteCodes.clone();
    }

    public ProtocolVersion[] getSupportedProtocolVersions() {
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

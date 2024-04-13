# PSK JSSE Socket Factories powered by Bouncy Castle

As of version 1.78 the Bouncy Castle JSSE provider supplies only an SSLSocketFactory and SSLServerSocketFactory with support for authentication via certificates. There is, however, an alternative mode of authentication available in the TLS standard which is supplied through the use of pre-shared keys (see https://datatracker.ietf.org/doc/html/rfc4279).

Bouncy Castle supports TLS PSK client and server connections but only through a non-standardized API and not through its JSSE implementation. The classes in this project bridge the gap, offerring developers JSSE standard SSLSocketFactory and SSLServerSocketFactory classes that support PSK cipher suites powered by Bouncy Castle.

At this time only OkHttp (client) and NanoHTTPD (server) have been lightly tested with this implementation.

TLS v1.2 with PSK is working. TLS v1.3 with PSK is not yet supported by Bouncy Castle, keep an eye out when this comment in Bouncy Castle source code is addressed:

    TODO[tls13] Constrain selection when PSK selected

# Usage

To use one or both of these factories in your project do the following:

## Include Dependencies

Include the Bouncy Castle bctls library and transitive dependencies in your project. If you are using Gradle with and Android project for example you would add the following to your dependencies:

    implementation "org.bouncycastle:bctls-jdk18on:1.78"

See https://www.bouncycastle.org/latest_releases.html for other packaging options.

## Copy Implementation

This project is not distributed via Maven Central.

To use this implementation copy the org.bchateau.pskfactories source code from this repository into your project.

## Use

See the TestBcPskFactories#testServerClientConnect() method for example client and server use.

Note that the cipher suites to allow can be customized by modifying BcPskTlsParams#supportCipherSuiteCodes. The current implementation enables the following very secure suites but others could be added as needed:

    TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256

# License

Copyright (C) 2024 Clover Network, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

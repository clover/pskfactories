# PSK JSSE Socket Factories powered by Bouncy Castle

As of version 1.69 the Bouncy Castle JSSE provider supplies only an SSLSocketFactory and SSLServerSocketFactory with support for authentication via certificates. There is, however, an alternative mode of authentication available in the TLS standard which is supplied through the use of pre-shared keys (see https://datatracker.ietf.org/doc/html/rfc4279).

Bouncy Castle supports TLS PSK client and server connections but only through a non-standardized API and not through its JSSE implementation. The classes in this project bridge the gap, offerring developers JSSE standard SSLSocketFactory and SSLServerSocketFactory classes that support PSK cipher suites powered by Bouncy Castle.

At this time only OkHttp (client) and NanoHTTPD (server) have been lightly tested with this implementation.

# Usage

To use one or both of these factories in your project do the following:

## Include Dependencies

Include the Bouncy Castle bctls library and transitive dependencies in your project. If you are using Gradle with and Android project for example you would add the following to your dependencies:

    api "org.bouncycastle:bctls-jdk15to18:1.69"

See https://www.bouncycastle.org/latest_releases.html for other packaging options.

## Copy Implementation

Copy the org.bchateau.pskfactories classes from this repository into your project.
## Use

See the Main class for example client and server use.

# License

Copyright (C) 2021 Clover Network, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

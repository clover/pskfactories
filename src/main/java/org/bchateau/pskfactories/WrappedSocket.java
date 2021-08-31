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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;


class WrappedSocket extends Socket {

    private final Socket socket;
    private InputStream in;
    private OutputStream out;

    public WrappedSocket(Socket socket, InputStream in, OutputStream out) throws IOException {
        super((java.net.SocketImpl) null);
        this.socket = socket;
        this.in = in;
        this.out = out;
    }

    @Override
    public InetAddress getInetAddress() {
        return socket.getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return socket.getLocalAddress();
    }

    @Override
    public int getPort() {
        return socket.getPort();
    }

    @Override
    public int getLocalPort() {
        return socket.getLocalPort();
    }

    @Override
    public InputStream getInputStream() throws IOException {
        if (in == null)
            in = socket.getInputStream();
        return in;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        if (out == null)
            out = socket.getOutputStream();
        return out;
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        socket.setTcpNoDelay(on);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return socket.getTcpNoDelay();
    }

    @Override
    public void setSoLinger(boolean on, int val) throws SocketException {
        socket.setSoLinger(on, val);
    }

    @Override
    public int getSoLinger() throws SocketException {
        return socket.getSoLinger();
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        socket.setSoTimeout(timeout);
    }

    @Override
    public int getSoTimeout() throws SocketException {
        return socket.getSoTimeout();
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }

    @Override
    public String toString() {
        return "Wrapped" + socket.toString();
    }
}

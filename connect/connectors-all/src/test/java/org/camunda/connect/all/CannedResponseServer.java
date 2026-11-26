/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH
 * under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership. Camunda licenses this file to you under the Apache License,
 * Version 2.0; you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.camunda.connect.all;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Minimal loopback HTTP/1.1 server that answers every request it receives on a
 * (keep-alive) connection with the same raw, pre-built response.
 */
public class CannedResponseServer implements Closeable {

  private final ServerSocket serverSocket;
  private final byte[] response;
  private final List<Socket> sockets = new CopyOnWriteArrayList<>();

  public CannedResponseServer(String rawResponse) throws IOException {
    this.response = rawResponse.getBytes(StandardCharsets.ISO_8859_1);
    this.serverSocket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
    Thread acceptor = new Thread(this::acceptLoop, "canned-response-server");
    acceptor.setDaemon(true);
    acceptor.start();
  }

  public String getUrl() {
    return "http://127.0.0.1:" + serverSocket.getLocalPort() + "/";
  }

  private void acceptLoop() {
    while (!serverSocket.isClosed()) {
      try {
        final Socket socket = serverSocket.accept();
        sockets.add(socket);
        Thread handler = new Thread(() -> serve(socket), "canned-response-handler");
        handler.setDaemon(true);
        handler.start();
      } catch (IOException e) {
        return;
      }
    }
  }

  private void serve(Socket socket) {
    try (Socket s = socket) {
      InputStream in = s.getInputStream();
      OutputStream out = s.getOutputStream();
      while (readRequestHead(in)) {
        out.write(response);
        out.flush();
      }
    } catch (IOException e) {
      // client went away
    }
  }

  /**
   * Consumes a request head (bodiless request) up to and including the empty line.
   *
   * @return false if the connection was closed by the client
   */
  private static boolean readRequestHead(InputStream in) throws IOException {
    int state = 0;
    int b;
    while ((b = in.read()) != -1) {
      if (b == '\n' && (state == 1 || state == 3)) {
        if (++state == 4) {
          return true;
        }
      } else if (b == '\r') {
        state = state == 2 ? 3 : 1;
      } else {
        state = 0;
      }
    }
    return false;
  }

  @Override
  public void close() throws IOException {
    serverSocket.close();
    for (Socket socket : sockets) {
      try {
        socket.close();
      } catch (IOException e) {
        // ignore
      }
    }
  }

}

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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.HostnameVerificationPolicy;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.net.NamedEndpoint;
import org.apache.hc.core5.reactor.ssl.SSLSessionInitializer;
import org.apache.hc.core5.reactor.ssl.TransportSecurityLayer;
import org.apache.hc.core5.util.Timeout;
import org.junit.After;
import org.junit.Test;

/**
 * CVE-2026-71290: the async TLS upgrade of the shaded httpclient5 must hand the
 * endpoint identification algorithm to the {@link SSLEngine}, otherwise the built-in
 * (JSSE) hostname verification never runs and a server presenting a trusted
 * certificate issued for another host is accepted.
 */
public class TlsEndpointIdentificationTest {

  /** Self-signed certificate (EC P-256) issued for {@code localhost} only. */
  private static final String SERVER_CERTIFICATE =
      "-----BEGIN CERTIFICATE-----\n"
      + "MIIBuTCCAV+gAwIBAgIUcCbkJE5K+ShwiqpV+cwgr4W3IdswCgYIKoZIzj0EAwIw\n"
      + "FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTIwMDEwMTAwMDAwMFoYDzIxMjAwMTAx\n"
      + "MDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO\n"
      + "PQMBBwNCAATu2enn25dU/kRVJX9HzlokI/f8isKbM1BqC4BvQ5slFY5zGyFw7BgA\n"
      + "EBPzY3tg46ITNyma5Q/hhxqTUj+sMxUio4GMMIGJMB0GA1UdDgQWBBTCqg/ekKbg\n"
      + "nKJ/p6r07BIP8W5cRDAfBgNVHSMEGDAWgBTCqg/ekKbgnKJ/p6r07BIP8W5cRDAU\n"
      + "BgNVHREEDTALgglsb2NhbGhvc3QwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMC\n"
      + "B4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDSAAwRQIgIqnK+af/\n"
      + "Jbf6hEPLRkamDJvR6N6fS3SiYR2cIGnnkcMCIQDXIFdOuT2P8DRMFAf/yN/xRp6O\n"
      + "7wHAhIXUfJJ7yXYRKQ==\n"
      + "-----END CERTIFICATE-----\n";

  private static final String SERVER_PRIVATE_KEY =
      "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgs91za78hfRYosvHo"
      + "EAQe89XhUpLgpgOJ8xr/C2FrEa+hRANCAATu2enn25dU/kRVJX9HzlokI/f8isKb"
      + "M1BqC4BvQ5slFY5zGyFw7BgAEBPzY3tg46ITNyma5Q/hhxqTUj+sMxUi";

  private static final char[] KEY_PASSWORD = "changeit".toCharArray();

  private static final String OK_RESPONSE =
      "HTTP/1.1 200 OK\r\n"
      + "Content-Type: text/plain\r\n"
      + "Content-Length: 2\r\n"
      + "Connection: close\r\n"
      + "\r\n"
      + "ok";

  /**
   * Resolves every host name to the loopback address, i.e. simulates an attacker who
   * redirects the traffic for any host to the server under its control.
   */
  private static final DnsResolver LOOPBACK_RESOLVER = new DnsResolver() {

    @Override
    public InetAddress[] resolve(String host) {
      return new InetAddress[] { InetAddress.getLoopbackAddress() };
    }

    @Override
    public String resolveCanonicalHostname(String host) {
      return host;
    }
  };

  private TlsServer server;
  private CloseableHttpAsyncClient client;

  @After
  public void tearDown() throws IOException {
    if (client != null) {
      client.close();
    }
    if (server != null) {
      server.close();
    }
  }

  @Test
  public void shouldEnableEndpointIdentificationOnEngineForBuiltinVerification() throws Exception {
    assertEquals("https", endpointIdentificationAlgorithmAfterUpgrade(HostnameVerificationPolicy.BUILTIN));
    assertEquals("https", endpointIdentificationAlgorithmAfterUpgrade(HostnameVerificationPolicy.BOTH));
  }

  @Test
  public void shouldLeaveEndpointIdentificationDisabledForClientOnlyVerification() throws Exception {
    assertNull(endpointIdentificationAlgorithmAfterUpgrade(HostnameVerificationPolicy.CLIENT));
  }

  @Test
  public void shouldRejectCertificateForAnotherHostWithDefaultStrategyFromBuilder() throws Exception {
    // without a custom HostnameVerifier the builder relies on BUILTIN verification only
    TlsStrategy tlsStrategy = ClientTlsStrategyBuilder.create()
        .setSslContext(clientSslContext())
        .build();

    assertImpersonationRejected(tlsStrategy);
  }

  @Test
  public void shouldRejectCertificateForAnotherHostWithBuiltinVerification() throws Exception {
    TlsStrategy tlsStrategy = new DefaultClientTlsStrategy(clientSslContext(), HostnameVerificationPolicy.BUILTIN, null);

    assertImpersonationRejected(tlsStrategy);
  }

  @Test
  public void shouldAcceptCertificateForRequestedHostWithBuiltinVerification() throws Exception {
    TlsStrategy tlsStrategy = new DefaultClientTlsStrategy(clientSslContext(), HostnameVerificationPolicy.BUILTIN, null);
    server = new TlsServer(serverSslContext());

    SimpleHttpResponse response = execute(tlsStrategy, "https://localhost:" + server.getPort() + "/");

    assertEquals(200, response.getCode());
    assertEquals("ok", response.getBodyText());
  }

  private void assertImpersonationRejected(TlsStrategy tlsStrategy) throws Exception {
    server = new TlsServer(serverSslContext());

    // the server presents a trusted certificate that was issued for 'localhost' only
    ExecutionException exception = assertThrows(ExecutionException.class,
        () -> execute(tlsStrategy, "https://bank.example:" + server.getPort() + "/"));
    assertNotNull("expected a TLS handshake failure but got " + exception.getCause(),
        findCause(exception, SSLException.class));
  }

  private SimpleHttpResponse execute(TlsStrategy tlsStrategy, String uri) throws Exception {
    client = HttpAsyncClients.custom()
        .setConnectionManager(PoolingAsyncClientConnectionManagerBuilder.create()
            .setTlsStrategy(tlsStrategy)
            .setDnsResolver(LOOPBACK_RESOLVER)
            .build())
        .build();
    client.start();
    return client.execute(SimpleRequestBuilder.get(uri).build(), null).get(30, TimeUnit.SECONDS);
  }

  /**
   * Runs the async TLS upgrade of a strategy with the given policy against an in-memory
   * session and returns the endpoint identification algorithm that reached the engine.
   */
  private static String endpointIdentificationAlgorithmAfterUpgrade(HostnameVerificationPolicy policy) throws Exception {
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, null, null);
    TlsStrategy tlsStrategy = new DefaultClientTlsStrategy(sslContext, policy, null);

    SSLEngine sslEngine = sslContext.createSSLEngine("bank.example", 443);
    sslEngine.setUseClientMode(true);
    TransportSecurityLayer tlsSession = (TransportSecurityLayer) Proxy.newProxyInstance(
        TransportSecurityLayer.class.getClassLoader(),
        new Class<?>[] { TransportSecurityLayer.class },
        (proxy, method, args) -> {
          if ("startTls".equals(method.getName())) {
            SSLSessionInitializer initializer = (SSLSessionInitializer) args[3];
            initializer.initialize((NamedEndpoint) args[1], sslEngine);
            return null;
          }
          throw new UnsupportedOperationException(method.getName());
        });

    NamedEndpoint endpoint = new HttpHost("https", "bank.example", 443);
    tlsStrategy.upgrade(tlsSession, endpoint, null, Timeout.ofSeconds(5), null);

    return sslEngine.getSSLParameters().getEndpointIdentificationAlgorithm();
  }

  private static Certificate serverCertificate() throws Exception {
    return CertificateFactory.getInstance("X.509")
        .generateCertificate(new ByteArrayInputStream(SERVER_CERTIFICATE.getBytes(StandardCharsets.US_ASCII)));
  }

  private static SSLContext clientSslContext() throws Exception {
    KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    trustStore.setCertificateEntry("server", serverCertificate());
    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);

    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
    return sslContext;
  }

  private static SSLContext serverSslContext() throws Exception {
    PrivateKey privateKey = KeyFactory.getInstance("EC")
        .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(SERVER_PRIVATE_KEY)));
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    keyStore.setKeyEntry("server", privateKey, KEY_PASSWORD, new Certificate[] { serverCertificate() });
    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, KEY_PASSWORD);

    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
    return sslContext;
  }

  private static <T extends Throwable> T findCause(Throwable throwable, Class<T> type) {
    for (Throwable t = throwable; t != null; t = t.getCause()) {
      if (type.isInstance(t)) {
        return type.cast(t);
      }
    }
    return null;
  }

  /**
   * Minimal loopback HTTPS server that answers every request with {@link #OK_RESPONSE}.
   */
  private static class TlsServer implements Closeable {

    private final SSLServerSocket serverSocket;

    TlsServer(SSLContext sslContext) throws IOException {
      this.serverSocket = (SSLServerSocket) sslContext.getServerSocketFactory()
          .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
      Thread acceptor = new Thread(this::acceptLoop, "tls-server");
      acceptor.setDaemon(true);
      acceptor.start();
    }

    int getPort() {
      return serverSocket.getLocalPort();
    }

    private void acceptLoop() {
      while (!serverSocket.isClosed()) {
        try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
          socket.setSoTimeout(10000);
          socket.startHandshake();
          BufferedReader reader = new BufferedReader(
              new InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1));
          String line;
          while ((line = reader.readLine()) != null && !line.isEmpty()) {
            // consume the request head
          }
          OutputStream out = socket.getOutputStream();
          out.write(OK_RESPONSE.getBytes(StandardCharsets.ISO_8859_1));
          out.flush();
        } catch (IOException e) {
          // handshake rejected by the client, client went away or server closed
        }
      }
    }

    @Override
    public void close() throws IOException {
      serverSocket.close();
    }
  }

}

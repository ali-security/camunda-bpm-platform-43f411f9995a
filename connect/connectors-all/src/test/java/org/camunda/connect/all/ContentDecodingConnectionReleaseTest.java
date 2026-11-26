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
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.hc.client5.http.ClientProtocolException;
import org.apache.hc.client5.http.HttpRoute;
import org.apache.hc.client5.http.classic.ExecChain;
import org.apache.hc.client5.http.classic.ExecChainHandler;
import org.apache.hc.client5.http.classic.ExecRuntime;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.entity.EntityBuilder;
import org.apache.hc.client5.http.impl.ChainElement;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.ContentCompressionExec;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.ProtocolException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import org.apache.hc.core5.util.Timeout;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * CVE-2026-64607: a response whose content coding cannot be handled (or any other
 * failure of the classic execution chain after a connection has been leased) must not
 * leak the pooled connection, otherwise a malicious server can exhaust the pool.
 */
public class ContentDecodingConnectionReleaseTest {

  private static final String UNSUPPORTED_ENCODING_RESPONSE =
      "HTTP/1.1 200 OK\r\n"
      + "Content-Type: text/plain\r\n"
      + "Content-Encoding: x-unsupported\r\n"
      + "Content-Length: 5\r\n"
      + "\r\n"
      + "hello";

  private static final String OK_RESPONSE =
      "HTTP/1.1 200 OK\r\n"
      + "Content-Type: text/plain\r\n"
      + "Content-Length: 2\r\n"
      + "\r\n"
      + "ok";

  private static final int ATTEMPTS = 3;

  private CannedResponseServer maliciousServer;
  private CannedResponseServer server;
  private PoolingHttpClientConnectionManager connManager;

  @Before
  public void setUp() throws IOException {
    maliciousServer = new CannedResponseServer(UNSUPPORTED_ENCODING_RESPONSE);
    server = new CannedResponseServer(OK_RESPONSE);
    connManager = PoolingHttpClientConnectionManagerBuilder.create()
        .setMaxConnTotal(1)
        .setMaxConnPerRoute(1)
        .build();
  }

  @After
  public void tearDown() throws IOException {
    connManager.close();
    maliciousServer.close();
    server.close();
  }

  @Test
  public void shouldReleaseConnectionWhenContentEncodingIsUnsupported() throws Exception {
    try (CloseableHttpClient client = clientBuilder()
        .replaceExecInterceptor(ChainElement.COMPRESS.name(), new ContentCompressionExec(false))
        .build()) {

      for (int i = 0; i < ATTEMPTS; i++) {
        ClientProtocolException exception = assertThrows(ClientProtocolException.class,
            () -> client.execute(new HttpGet(maliciousServer.getUrl()), this::readBody));
        assertEquals("Unsupported Content-Encoding: x-unsupported", exception.getMessage());
        assertEquals(0, connManager.getTotalStats().getLeased());
      }

      // the only pooled connection is still available
      assertEquals("ok", client.execute(new HttpGet(server.getUrl()), this::readBody));
    }
  }

  @Test
  public void shouldReleaseConnectionWhenExecChainThrowsRuntimeException() throws Exception {
    assertConnectionReleasedOnFailure(new IllegalStateException("Ooopsie"), IllegalStateException.class);
  }

  @Test
  public void shouldReleaseConnectionWhenExecChainThrowsHttpException() throws Exception {
    assertConnectionReleasedOnFailure(new ProtocolException("Ooopsie"), ClientProtocolException.class);
  }

  @Test
  public void shouldReleaseConnectionWhenExecChainThrowsIOException() throws Exception {
    assertConnectionReleasedOnFailure(new IOException("Ooopsie"), IOException.class);
  }

  @Test
  public void shouldCloseResponseWhenContentEncodingIsUnsupported() throws Exception {
    TrackingResponse response = new TrackingResponse();
    response.setEntity(EntityBuilder.create().setText("encoded stuff").setContentEncoding("whatever").build());

    ContentCompressionExec exec = new ContentCompressionExec(false);
    HttpGet request = new HttpGet("http://localhost/");

    assertThrows(HttpException.class, () -> exec.execute(request, scope(request), (req, s) -> response));
    assertTrue(response.closed);
  }

  @Test
  public void shouldCloseResponseWhenContentDecodingSetupThrowsRuntimeException() throws Exception {
    TrackingResponse response = new TrackingResponse();
    response.setEntity((HttpEntity) Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[] { HttpEntity.class },
        (proxy, method, args) -> {
          if ("getContentLength".equals(method.getName())) {
            return -1L;
          }
          if ("getContentEncoding".equals(method.getName())) {
            throw new IllegalStateException("Boom");
          }
          return null;
        }));

    ContentCompressionExec exec = new ContentCompressionExec();
    HttpGet request = new HttpGet("http://localhost/");

    IllegalStateException exception = assertThrows(IllegalStateException.class,
        () -> exec.execute(request, scope(request), (req, s) -> response));
    assertEquals("Boom", exception.getMessage());
    assertTrue(response.closed);
  }

  /**
   * Installs an outermost exec chain handler that lets the exchange complete (so a pooled
   * connection is leased and still held by the streamed response) and then fails with the
   * given exception; every failed attempt must hand the connection back to the pool.
   */
  private void assertConnectionReleasedOnFailure(Exception failure,
                                                 Class<? extends Exception> expected) throws Exception {
    AtomicBoolean armed = new AtomicBoolean(true);
    ExecChainHandler failingHandler = (request, scope, chain) -> {
      ClassicHttpResponse response = chain.proceed(request, scope);
      if (!armed.get()) {
        return response;
      }
      if (failure instanceof IOException) {
        throw (IOException) failure;
      }
      if (failure instanceof HttpException) {
        throw (HttpException) failure;
      }
      throw (RuntimeException) failure;
    };

    try (CloseableHttpClient client = clientBuilder()
        .addExecInterceptorFirst("failing-handler", failingHandler)
        .build()) {

      for (int i = 0; i < ATTEMPTS; i++) {
        Exception exception = assertThrows(expected,
            () -> client.execute(new HttpGet(server.getUrl()), this::readBody));
        if (expected == ClientProtocolException.class) {
          assertSame(failure, exception.getCause());
        } else {
          assertSame(failure, exception);
        }
        assertEquals(0, connManager.getTotalStats().getLeased());
      }

      armed.set(false);
      // the only pooled connection is still available
      assertEquals("ok", client.execute(new HttpGet(server.getUrl()), this::readBody));
    }
  }

  private HttpClientBuilder clientBuilder() {
    return HttpClients.custom()
        .setConnectionManager(connManager)
        .setConnectionManagerShared(true)
        .setDefaultRequestConfig(RequestConfig.custom()
            .setConnectionRequestTimeout(Timeout.ofSeconds(2))
            .build());
  }

  private String readBody(ClassicHttpResponse response) throws IOException, HttpException {
    return EntityUtils.toString(response.getEntity());
  }

  private static ExecChain.Scope scope(HttpGet request) {
    ExecRuntime execRuntime = (ExecRuntime) Proxy.newProxyInstance(
        ContentDecodingConnectionReleaseTest.class.getClassLoader(),
        new Class<?>[] { ExecRuntime.class },
        (proxy, method, args) -> {
          throw new UnsupportedOperationException(method.getName());
        });
    return new ExecChain.Scope("ex-test", new HttpRoute(new HttpHost("localhost", 80)), request,
        execRuntime, HttpClientContext.create());
  }

  private static final class TrackingResponse extends BasicClassicHttpResponse {

    private boolean closed;

    TrackingResponse() {
      super(200, "OK");
    }

    @Override
    public void close() {
      closed = true;
    }
  }

}

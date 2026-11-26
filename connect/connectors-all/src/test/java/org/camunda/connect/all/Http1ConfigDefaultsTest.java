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
import static org.junit.Assert.assertThrows;

import java.io.IOException;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.ManagedHttpClientConnectionFactory;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.MessageConstraintException;
import org.apache.hc.core5.http.config.Http1Config;
import org.camunda.connect.ConnectorRequestException;
import org.camunda.connect.httpclient.impl.HttpConnectorImpl;
import org.junit.After;
import org.junit.Test;

/**
 * CVE-2026-54399: the HTTP/1.1 message parser of the shaded httpcore5 must not accept
 * an unlimited number of response headers or unbounded header lines by default.
 */
public class Http1ConfigDefaultsTest {

  private static final int EXCESSIVE_HEADER_COUNT = 2000;
  private static final int EXCESSIVE_LINE_LENGTH = 10000;

  private CannedResponseServer server;

  @After
  public void tearDown() throws IOException {
    if (server != null) {
      server.close();
    }
  }

  @Test
  public void shouldLimitHeaderCountAndLineLengthByDefault() {
    assertEquals(1024, Http1Config.DEFAULT.getMaxHeaderCount());
    assertEquals(8192, Http1Config.DEFAULT.getMaxLineLength());

    Http1Config config = Http1Config.custom().build();
    assertEquals(1024, config.getMaxHeaderCount());
    assertEquals(8192, config.getMaxLineLength());

    Http1Config copy = Http1Config.copy(config).build();
    assertEquals(1024, copy.getMaxHeaderCount());
    assertEquals(8192, copy.getMaxLineLength());
  }

  @Test
  public void shouldRejectResponseWithExcessiveHeaderCount() throws Exception {
    server = new CannedResponseServer(responseWithHeaders(EXCESSIVE_HEADER_COUNT, 10));

    try (CloseableHttpClient client = HttpClients.createSystem()) {
      MessageConstraintException exception = assertThrows(MessageConstraintException.class,
          () -> client.execute(new HttpGet(server.getUrl()), response -> response.getHeaders().length));
      assertEquals("Maximum header count exceeded", exception.getMessage());
    }
  }

  @Test
  public void shouldRejectResponseWithOverlongHeaderLine() throws Exception {
    server = new CannedResponseServer(responseWithHeaders(1, EXCESSIVE_LINE_LENGTH));

    try (CloseableHttpClient client = HttpClients.createSystem()) {
      MessageConstraintException exception = assertThrows(MessageConstraintException.class,
          () -> client.execute(new HttpGet(server.getUrl()), response -> response.getHeaders().length));
      assertEquals("Maximum line length limit exceeded", exception.getMessage());
    }
  }

  @Test
  public void shouldRejectExcessiveHeadersInHttpConnector() throws Exception {
    server = new CannedResponseServer(responseWithHeaders(EXCESSIVE_HEADER_COUNT, 10));

    HttpConnectorImpl connector = new HttpConnectorImpl();
    try {
      ConnectorRequestException exception = assertThrows(ConnectorRequestException.class,
          () -> connector.createRequest().get().url(server.getUrl()).execute());
      assertNotNull(findCause(exception, MessageConstraintException.class));
    } finally {
      connector.getHttpClient().close();
    }
  }

  @Test
  public void shouldAcceptResponseWithinLimits() throws Exception {
    server = new CannedResponseServer(responseWithHeaders(100, 4096));

    try (CloseableHttpClient client = HttpClients.createSystem()) {
      int headerCount = client.execute(new HttpGet(server.getUrl()), response -> response.getHeaders().length);
      assertEquals(100 + 2, headerCount);
    }
  }

  @Test
  public void shouldStillAllowLimitsToBeLiftedExplicitly() throws Exception {
    server = new CannedResponseServer(responseWithHeaders(EXCESSIVE_HEADER_COUNT, EXCESSIVE_LINE_LENGTH));

    Http1Config unlimited = Http1Config.custom()
        .setMaxHeaderCount(-1)
        .setMaxLineLength(-1)
        .build();
    try (CloseableHttpClient client = HttpClients.custom()
        .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
            .setConnectionFactory(ManagedHttpClientConnectionFactory.builder().http1Config(unlimited).build())
            .build())
        .build()) {
      int headerCount = client.execute(new HttpGet(server.getUrl()), response -> response.getHeaders().length);
      assertEquals(EXCESSIVE_HEADER_COUNT + 2, headerCount);
    }
  }

  /**
   * Builds a 200 response carrying {@code count} custom headers (plus Content-Type and
   * Content-Length), each with a value of {@code valueLength} characters.
   */
  private static String responseWithHeaders(int count, int valueLength) {
    StringBuilder value = new StringBuilder(valueLength);
    for (int i = 0; i < valueLength; i++) {
      value.append('a');
    }
    StringBuilder response = new StringBuilder("HTTP/1.1 200 OK\r\n");
    for (int i = 0; i < count; i++) {
      response.append("X-Header-").append(i).append(": ").append(value).append("\r\n");
    }
    response.append("Content-Type: text/plain\r\n");
    response.append("Content-Length: 2\r\n");
    response.append("\r\n");
    response.append("ok");
    return response.toString();
  }

  private static <T extends Throwable> T findCause(Throwable throwable, Class<T> type) {
    for (Throwable t = throwable; t != null; t = t.getCause()) {
      if (type.isInstance(t)) {
        return type.cast(t);
      }
    }
    return null;
  }

}

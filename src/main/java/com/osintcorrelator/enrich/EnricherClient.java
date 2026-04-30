package com.osintcorrelator.enrich;

import com.osintcorrelator.json.Json;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

public final class EnricherClient {
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(120);

    private final HttpClient client = HttpClient.newHttpClient();
    private final URI uri;

    public EnricherClient(String enricherUrl) {
        this.uri = URI.create(enricherUrl);
    }

    public Map<String, Object> enrich(String seed) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(Json.stringify(Map.of("seed", seed))))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("enrichment failed with HTTP " + response.statusCode());
        }
        return Json.expectObject(Json.parse(response.body()));
    }
}

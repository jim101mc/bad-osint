package com.osintcorrelator.api;

import com.osintcorrelator.db.Database;
import com.osintcorrelator.enrich.EnricherClient;
import com.osintcorrelator.json.Json;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

public final class ApiServer {
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final int PROFILE_TOOL_COVERAGE_LIMIT = 3;

    private final int port;
    private final Database database;
    private final EnricherClient enricherClient;

    public ApiServer(int port, Database database, EnricherClient enricherClient) {
        this.port = port;
        this.database = database;
        this.enricherClient = enricherClient;
    }

    public void start() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/health", this::health);
        server.createContext("/", this::staticFiles);
        server.createContext("/assets", this::staticFiles);
        server.createContext("/api/database", this::databaseSummary);
        server.createContext("/api/profiles", this::profiles);
        server.createContext("/api/connections", this::connections);
        server.createContext("/api/tools", this::tools);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        System.out.printf("OSINT Profile Correlator API listening on http://127.0.0.1:%d%n", port);
    }

    private void health(HttpExchange exchange) throws IOException {
        try {
            database.ping();
            send(exchange, 200, Map.of("status", "ok", "database", "ok"));
        } catch (Exception exception) {
            send(exchange, 500, Map.of("status", "error", "database", errorMessage(exception)));
        }
    }

    private void profiles(HttpExchange exchange) throws IOException {
        try {
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();
            if ("POST".equals(method) && "/api/profiles".equals(path)) {
                createProfile(exchange);
                return;
            }
            if ("GET".equals(method) && "/api/profiles".equals(path)) {
                Map<String, String> query = queryParams(exchange);
                int limit = Math.max(1, Math.min(500, parseInt(query.get("limit"), 100)));
                send(exchange, 200, Map.of("profiles", database.listProfiles(limit)));
                return;
            }
            if ("GET".equals(method) && path.startsWith("/api/profiles/")) {
                String id = path.substring("/api/profiles/".length());
                send(exchange, 200, database.getProfile(parseUuid(id, "profile id")));
                return;
            }
            send(exchange, 404, Map.of("error", "route not found"));
        } catch (IllegalArgumentException exception) {
            sendError(exchange, 400, exception);
        } catch (Exception exception) {
            sendError(exchange, 500, exception);
        }
    }

    private void createProfile(HttpExchange exchange) throws Exception {
        Map<String, Object> request = Json.expectObject(Json.parse(readBody(exchange)));
        String seed = Json.string(request, "seed").trim();
        if (seed.isBlank()) {
            throw new IllegalArgumentException("seed is required");
        }

        Map<String, Object> enrichment = enricherClient.enrich(seed);
        UUID profileId = database.createProfile(seed, enrichment);
        database.recordSearch(profileId, seed, "completed", Json.array(enrichment, "evidence").size());
        for (Object item : Json.array(enrichment, "suggestedSearches")) {
            Map<String, Object> search = Json.expectObject(item);
            database.recordSearch(
                    profileId,
                    Json.string(search, "query"),
                    Json.string(search, "status", "suggested"),
                    (int) Json.decimal(search, "resultCount", 0.0));
        }
        database.queueCategoryCoverage(profileId);
        database.queueToolCoverage(profileId, PROFILE_TOOL_COVERAGE_LIMIT);
        try {
            database.correlateProfile(profileId, enrichment);
        } catch (Exception exception) {
            System.err.printf("Auto-correlation skipped for profile %s: %s%n", profileId, errorMessage(exception));
        }
        send(exchange, 201, database.getProfile(profileId));
    }

    private void connections(HttpExchange exchange) throws IOException {
        try {
            if (!"POST".equals(exchange.getRequestMethod())) {
                send(exchange, 405, Map.of("error", "method not allowed"));
                return;
            }
            Map<String, Object> request = Json.expectObject(Json.parse(readBody(exchange)));
            UUID id = database.addConnection(
                    parseUuid(Json.string(request, "fromProfileId"), "fromProfileId"),
                    parseUuid(Json.string(request, "toProfileId"), "toProfileId"),
                    Json.string(request, "relationshipType"),
                    Json.decimal(request, "confidence", 0.0),
                    Json.string(request, "source", "manual review"));
            send(exchange, 201, Map.of("id", id.toString()));
        } catch (IllegalArgumentException exception) {
            sendError(exchange, 400, exception);
        } catch (Exception exception) {
            sendError(exchange, 500, exception);
        }
    }

    private void databaseSummary(HttpExchange exchange) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                send(exchange, 405, Map.of("error", "method not allowed"));
                return;
            }
            Map<String, String> query = queryParams(exchange);
            int limit = Math.max(1, Math.min(500, parseInt(query.get("limit"), 100)));
            Map<String, Object> summary = new LinkedHashMap<>();
            summary.put("counts", database.databaseSummary());
            summary.put("profiles", database.listProfiles(limit));
            send(exchange, 200, summary);
        } catch (IllegalArgumentException exception) {
            sendError(exchange, 400, exception);
        } catch (Exception exception) {
            sendError(exchange, 500, exception);
        }
    }

    private void tools(HttpExchange exchange) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                send(exchange, 405, Map.of("error", "method not allowed"));
                return;
            }
            Map<String, String> query = queryParams(exchange);
            int limit = Math.max(1, Math.min(200, parseInt(query.get("limit"), 50)));
            send(exchange, 200, Map.of("tools", database.searchTools(query, limit)));
        } catch (IllegalArgumentException exception) {
            sendError(exchange, 400, exception);
        } catch (Exception exception) {
            sendError(exchange, 500, exception);
        }
    }

    private void staticFiles(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            send(exchange, 405, Map.of("error", "method not allowed"));
            return;
        }
        String path = exchange.getRequestURI().getPath();
        if (path.startsWith("/api/") || "/health".equals(path)) {
            send(exchange, 404, Map.of("error", "route not found"));
            return;
        }

        String relative = "/".equals(path) ? "index.html" : path.substring(1);
        if (relative.startsWith("assets/")) {
            relative = relative.substring("assets/".length());
        }

        Path webRoot = Path.of("web").toAbsolutePath().normalize();
        Path target = webRoot.resolve(relative).normalize();
        if (!target.startsWith(webRoot) || !Files.exists(target) || Files.isDirectory(target)) {
            target = webRoot.resolve("index.html").normalize();
        }

        byte[] body = Files.readAllBytes(target);
        exchange.getResponseHeaders().put("Content-Type", List.of(contentType(target)));
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(body);
        }
    }

    private String contentType(Path path) {
        String name = path.getFileName().toString().toLowerCase();
        if (name.endsWith(".html")) return "text/html; charset=utf-8";
        if (name.endsWith(".css")) return "text/css; charset=utf-8";
        if (name.endsWith(".js")) return "application/javascript; charset=utf-8";
        if (name.endsWith(".json")) return "application/json; charset=utf-8";
        if (name.endsWith(".svg")) return "image/svg+xml";
        return "application/octet-stream";
    }

    private Map<String, String> queryParams(HttpExchange exchange) {
        Map<String, String> params = new LinkedHashMap<>();
        String query = exchange.getRequestURI().getRawQuery();
        if (query == null || query.isBlank()) {
            return params;
        }
        for (String pair : query.split("&")) {
            int split = pair.indexOf('=');
            String key = decode(split >= 0 ? pair.substring(0, split) : pair);
            String value = decode(split >= 0 ? pair.substring(split + 1) : "");
            params.put(key, value);
        }
        return params;
    }

    private String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private int parseInt(String value, int fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("invalid integer value: " + value);
        }
    }

    private UUID parseUuid(String raw, String label) {
        if (raw == null || !UUID_PATTERN.matcher(raw).matches()) {
            throw new IllegalArgumentException("invalid " + label);
        }
        return UUID.fromString(raw);
    }

    private String readBody(HttpExchange exchange) throws IOException {
        try (InputStream input = exchange.getRequestBody()) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private void sendError(HttpExchange exchange, int status, Exception exception) throws IOException {
        exception.printStackTrace(System.err);
        send(exchange, status, Map.of("error", errorMessage(exception)));
    }

    private String errorMessage(Exception exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank() ? exception.getClass().getSimpleName() : message;
    }

    private void send(HttpExchange exchange, int status, Object payload) throws IOException {
        byte[] body = Json.stringify(payload).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().put("Content-Type", List.of("application/json; charset=utf-8"));
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(body);
        }
    }
}

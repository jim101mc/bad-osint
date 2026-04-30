package com.osintcorrelator.db;

import com.osintcorrelator.config.AppConfig;
import com.osintcorrelator.json.Json;

import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class Database {
    private final AppConfig config;

    public Database(AppConfig config) {
        this.config = config;
    }

    public void ping() throws SQLException {
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement("SELECT 1");
             ResultSet ignored = statement.executeQuery()) {
            // Opening the result set is enough to prove the credentials and DB are usable.
        }
    }

    public UUID createProfile(String seed, Map<String, Object> enrichment) throws SQLException {
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            try {
                UUID profileId = insertProfile(connection, seed, enrichment);
                for (Object item : Json.array(enrichment, "identifiers")) {
                    insertIdentifier(connection, profileId, Json.expectObject(item));
                }
                for (Object item : Json.array(enrichment, "evidence")) {
                    insertEvidence(connection, profileId, Json.expectObject(item));
                }
                connection.commit();
                return profileId;
            } catch (SQLException | RuntimeException exc) {
                connection.rollback();
                throw exc;
            }
        }
    }

    public Map<String, Object> getProfile(UUID profileId) throws SQLException {
        try (Connection connection = connect()) {
            Map<String, Object> profile = one(connection,
                    "SELECT id, seed, display_name, summary, confidence, created_at, updated_at FROM profiles WHERE id = ?",
                    profileId);
            if (profile.isEmpty()) {
                throw new IllegalArgumentException("profile not found");
            }
            profile.put("identifiers", many(connection,
                    "SELECT id, kind, value, confidence, source, created_at FROM identifiers WHERE profile_id = ? ORDER BY created_at",
                    profileId));
            profile.put("evidence", many(connection,
                    "SELECT id, source_type, source_uri, title, snippet, observed_at, confidence FROM evidence WHERE profile_id = ? ORDER BY observed_at DESC",
                    profileId));
            profile.put("searches", many(connection,
                    "SELECT id, query, status, result_count, created_at FROM searches WHERE profile_id = ? ORDER BY created_at DESC",
                    profileId));
            profile.put("connections", connections(connection, profileId));
            return profile;
        }
    }

    public List<Map<String, Object>> listProfiles(int limit) throws SQLException {
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT
                         p.id,
                         p.seed,
                         p.display_name,
                         p.summary,
                         p.confidence,
                         p.created_at,
                         p.updated_at,
                         count(DISTINCT i.id) AS identifier_count,
                         count(DISTINCT e.id) AS evidence_count,
                         count(DISTINCT c.id) AS connection_count
                     FROM profiles p
                     LEFT JOIN identifiers i ON i.profile_id = p.id
                     LEFT JOIN evidence e ON e.profile_id = p.id
                     LEFT JOIN connections c
                         ON c.from_profile_id = p.id OR c.to_profile_id = p.id
                     GROUP BY p.id
                     ORDER BY p.created_at DESC
                     LIMIT ?
                     """)) {
            statement.setInt(1, limit);
            try (ResultSet rs = statement.executeQuery()) {
                return rows(rs);
            }
        }
    }

    public Map<String, Object> databaseSummary() throws SQLException {
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT
                         (SELECT count(*) FROM profiles) AS profiles,
                         (SELECT count(*) FROM identifiers) AS identifiers,
                         (SELECT count(*) FROM evidence) AS evidence,
                         (SELECT count(*) FROM searches) AS searches,
                         (SELECT count(*) FROM connections) AS connections,
                         (SELECT count(*) FROM osint_tools) AS osint_tools,
                         (SELECT count(DISTINCT COALESCE(NULLIF(split_part(framework_path, ' / ', 2), ''), 'Uncategorized'))
                          FROM osint_tools) AS osint_categories
                     """);
             ResultSet rs = statement.executeQuery()) {
            rs.next();
            Map<String, Object> summary = new LinkedHashMap<>();
            summary.put("profiles", normalize(rs.getObject("profiles")));
            summary.put("identifiers", normalize(rs.getObject("identifiers")));
            summary.put("evidence", normalize(rs.getObject("evidence")));
            summary.put("searches", normalize(rs.getObject("searches")));
            summary.put("connections", normalize(rs.getObject("connections")));
            summary.put("osintTools", normalize(rs.getObject("osint_tools")));
            summary.put("osintCategories", normalize(rs.getObject("osint_categories")));
            return summary;
        }
    }

    public void recordSearch(UUID profileId, String query, String status, int resultCount) throws SQLException {
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement(
                     "INSERT INTO searches (profile_id, query, status, result_count) VALUES (?, ?, ?, ?)")) {
            statement.setObject(1, profileId);
            statement.setString(2, query);
            statement.setString(3, status);
            statement.setInt(4, resultCount);
            statement.executeUpdate();
        }
    }

    public int queueCategoryCoverage(UUID profileId) throws SQLException {
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement("""
                     WITH categories AS (
                         SELECT
                             COALESCE(NULLIF(split_part(framework_path, ' / ', 2), ''), 'Uncategorized') AS category,
                             count(*)::int AS tool_count
                         FROM osint_tools
                         GROUP BY 1
                     )
                     INSERT INTO searches (profile_id, query, status, result_count)
                     SELECT
                         ?,
                         'category:' || category,
                         'category_queued',
                         tool_count
                     FROM categories
                     ORDER BY category
                     """)) {
            statement.setObject(1, profileId);
            return statement.executeUpdate();
        }
    }

    public int queueToolCoverage(UUID profileId, int perCategoryLimit) throws SQLException {
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement("""
                     WITH ranked AS (
                         SELECT
                             COALESCE(NULLIF(split_part(framework_path, ' / ', 2), ''), 'Uncategorized') AS category,
                             name,
                             COALESCE(url, '') AS url,
                             row_number() OVER (
                                 PARTITION BY COALESCE(NULLIF(split_part(framework_path, ' / ', 2), ''), 'Uncategorized')
                                 ORDER BY
                                     CASE WHEN status = 'live' THEN 0 ELSE 1 END,
                                     deprecated ASC,
                                     name
                             ) AS rn
                         FROM osint_tools
                     )
                     INSERT INTO searches (profile_id, query, status, result_count)
                     SELECT
                         ?,
                         'tool:' || category || ' | ' || name || ' | ' || url,
                         'tool_queued',
                         1
                     FROM ranked
                     WHERE rn <= ?
                     ORDER BY category, rn
                     """)) {
            statement.setObject(1, profileId);
            statement.setInt(2, Math.max(1, perCategoryLimit));
            return statement.executeUpdate();
        }
    }

    public UUID addConnection(UUID fromProfileId, UUID toProfileId, String relationshipType, double confidence, String source)
            throws SQLException {
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement("""
                     INSERT INTO connections (from_profile_id, to_profile_id, relationship_type, confidence, source)
                     VALUES (?, ?, ?, ?, ?)
                     RETURNING id
                     """)) {
            statement.setObject(1, fromProfileId);
            statement.setObject(2, toProfileId);
            statement.setString(3, relationshipType);
            statement.setBigDecimal(4, BigDecimal.valueOf(confidence));
            statement.setString(5, source);
            try (ResultSet rs = statement.executeQuery()) {
                rs.next();
                return (UUID) rs.getObject("id");
            }
        }
    }

    public void correlateProfile(UUID profileId, Map<String, Object> enrichment) throws SQLException {
        try (Connection connection = connect()) {
            connection.setAutoCommit(false);
            try {
                upsertCorrelationKeys(connection, profileId, enrichment);
                List<CorrelationMatch> matches = findCorrelationMatches(connection, profileId);
                for (CorrelationMatch match : matches) {
                    if ("domain".equals(match.keyType())) {
                        insertCorrelationEvidenceIfMissing(
                                connection,
                                profileId,
                                match.otherProfileId(),
                                "domain",
                                match.keyValue(),
                                0.40);
                        insertCorrelationEvidenceIfMissing(
                                connection,
                                match.otherProfileId(),
                                profileId,
                                "domain",
                                match.keyValue(),
                                0.40);
                        continue;
                    }

                    String relationshipType = "email".equals(match.keyType()) ? "shared_email" : "shared_username";
                    double confidence = "email".equals(match.keyType()) ? 0.92 : 0.78;
                    insertAutoConnectionIfMissing(
                            connection,
                            profileId,
                            match.otherProfileId(),
                            relationshipType,
                            confidence,
                            "auto-correlation");
                    insertCorrelationEvidenceIfMissing(
                            connection,
                            profileId,
                            match.otherProfileId(),
                            match.keyType(),
                            match.keyValue(),
                            confidence);
                    insertCorrelationEvidenceIfMissing(
                            connection,
                            match.otherProfileId(),
                            profileId,
                            match.keyType(),
                            match.keyValue(),
                            confidence);
                }
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                connection.rollback();
                throw exception;
            }
        }
    }

    public List<Map<String, Object>> searchTools(Map<String, String> filters, int limit) throws SQLException {
        StringBuilder sql = new StringBuilder("""
                SELECT id, framework_path, name, type, url, description, status, pricing, best_for,
                       input_type, output_type, opsec, opsec_note, local_install, google_dork,
                       registration, edit_url, api, invitation_only, deprecated,
                       source_name, source_url, source_license, imported_at
                FROM osint_tools
                WHERE 1 = 1
                """);
        List<Object> params = new ArrayList<>();

        String input = filters.get("input");
        if (hasText(input)) {
            sql.append("""
                    AND (
                        input_type ILIKE ?
                        OR best_for ILIKE ?
                        OR description ILIKE ?
                        OR framework_path ILIKE ?
                    )
                    """);
            addLike(params, input, 4);
        }

        String query = filters.get("q");
        if (hasText(query)) {
            sql.append("""
                    AND (
                        name ILIKE ?
                        OR url ILIKE ?
                        OR description ILIKE ?
                        OR framework_path ILIKE ?
                    )
                    """);
            addLike(params, query, 4);
        }

        addBooleanFilter(sql, params, "api", filters.get("api"));
        addBooleanFilter(sql, params, "registration", filters.get("registration"));
        addBooleanFilter(sql, params, "local_install", filters.get("localInstall"));
        addBooleanFilter(sql, params, "google_dork", filters.get("googleDork"));
        addBooleanFilter(sql, params, "deprecated", filters.get("deprecated"));

        String opsec = filters.get("opsec");
        if (hasText(opsec)) {
            sql.append("AND lower(opsec) = ?\n");
            params.add(opsec.toLowerCase(Locale.ROOT));
        }

        sql.append("""
                ORDER BY
                    CASE WHEN status = 'live' THEN 0 ELSE 1 END,
                    deprecated ASC,
                    framework_path,
                    name
                LIMIT ?
                """);
        params.add(limit);

        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement(sql.toString())) {
            bind(statement, params);
            try (ResultSet rs = statement.executeQuery()) {
                return rows(rs);
            }
        }
    }

    private UUID insertProfile(Connection connection, String seed, Map<String, Object> enrichment) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO profiles (seed, display_name, summary, confidence)
                VALUES (?, ?, ?, ?)
                RETURNING id
                """)) {
            statement.setString(1, seed);
            statement.setString(2, Json.string(enrichment, "displayName", seed));
            statement.setString(3, Json.string(enrichment, "summary", ""));
            statement.setBigDecimal(4, BigDecimal.valueOf(Json.decimal(enrichment, "confidence", 0.0)));
            try (ResultSet rs = statement.executeQuery()) {
                rs.next();
                return (UUID) rs.getObject("id");
            }
        }
    }

    private void insertIdentifier(Connection connection, UUID profileId, Map<String, Object> identifier) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO identifiers (profile_id, kind, value, confidence, source)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (profile_id, kind, value) DO NOTHING
                """)) {
            statement.setObject(1, profileId);
            statement.setString(2, Json.string(identifier, "kind"));
            statement.setString(3, Json.string(identifier, "value"));
            statement.setBigDecimal(4, BigDecimal.valueOf(Json.decimal(identifier, "confidence", 0.0)));
            statement.setString(5, Json.string(identifier, "source", "unknown"));
            statement.executeUpdate();
        }
    }

    private void insertEvidence(Connection connection, UUID profileId, Map<String, Object> evidence) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO evidence (profile_id, source_type, source_uri, title, snippet, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, profileId);
            statement.setString(2, Json.string(evidence, "source_type", "unknown"));
            statement.setString(3, Json.string(evidence, "source_uri", ""));
            statement.setString(4, Json.string(evidence, "title", ""));
            statement.setString(5, Json.string(evidence, "snippet", ""));
            statement.setBigDecimal(6, BigDecimal.valueOf(Json.decimal(evidence, "confidence", 0.0)));
            statement.executeUpdate();
        }
    }

    private void upsertCorrelationKeys(Connection connection, UUID profileId, Map<String, Object> enrichment) throws SQLException {
        Object raw = enrichment.get("correlationKeys");
        if (!(raw instanceof Map<?, ?>)) {
            return;
        }
        Map<String, Object> keys = Json.expectObject(raw);
        upsertCorrelationKeyGroup(connection, profileId, "email", Json.array(keys, "email"));
        upsertCorrelationKeyGroup(connection, profileId, "username", Json.array(keys, "username"));
        upsertCorrelationKeyGroup(connection, profileId, "domain", Json.array(keys, "domain"));
    }

    private void upsertCorrelationKeyGroup(
            Connection connection,
            UUID profileId,
            String keyType,
            List<Object> values) throws SQLException {
        Set<String> seen = new HashSet<>();
        for (Object item : values) {
            String normalized = normalizeCorrelationValue(keyType, String.valueOf(item));
            if (normalized == null || !seen.add(normalized)) {
                continue;
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO profile_correlation_keys (profile_id, key_type, key_value, source)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT (profile_id, key_type, key_value) DO NOTHING
                    """)) {
                statement.setObject(1, profileId);
                statement.setString(2, keyType);
                statement.setString(3, normalized);
                statement.setString(4, "enricher");
                statement.executeUpdate();
            }
        }
    }

    private String normalizeCorrelationValue(String keyType, String raw) {
        String value = raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT);
        if (value.isBlank()) {
            return null;
        }
        return switch (keyType) {
            case "email" -> value.contains("@") ? value : null;
            case "username" -> {
                String candidate = value.startsWith("@") ? value.substring(1) : value;
                if (candidate.length() < 2 || candidate.length() > 64) {
                    yield null;
                }
                if (!candidate.matches("[a-z0-9._-]+")) {
                    yield null;
                }
                yield candidate;
            }
            case "domain" -> {
                String candidate = value;
                while (candidate.endsWith(".")) {
                    candidate = candidate.substring(0, candidate.length() - 1);
                }
                if (candidate.isBlank() || !candidate.contains(".")) {
                    yield null;
                }
                yield candidate;
            }
            default -> null;
        };
    }

    private List<CorrelationMatch> findCorrelationMatches(Connection connection, UUID profileId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT self.key_type, self.key_value, other.profile_id AS other_profile_id
                FROM profile_correlation_keys self
                INNER JOIN profile_correlation_keys other
                    ON other.key_type = self.key_type
                    AND other.key_value = self.key_value
                    AND other.profile_id <> self.profile_id
                WHERE self.profile_id = ?
                    AND self.key_type IN ('email', 'username', 'domain')
                ORDER BY self.key_type, self.key_value
                """)) {
            statement.setObject(1, profileId);
            List<CorrelationMatch> matches = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            try (ResultSet rs = statement.executeQuery()) {
                while (rs.next()) {
                    String keyType = String.valueOf(rs.getObject("key_type"));
                    String keyValue = String.valueOf(rs.getObject("key_value"));
                    UUID otherProfileId = (UUID) rs.getObject("other_profile_id");
                    String dedupeKey = keyType + "|" + keyValue + "|" + otherProfileId;
                    if (!seen.add(dedupeKey)) {
                        continue;
                    }
                    matches.add(new CorrelationMatch(otherProfileId, keyType, keyValue));
                }
            }
            return matches;
        }
    }

    private void insertAutoConnectionIfMissing(
            Connection connection,
            UUID firstProfileId,
            UUID secondProfileId,
            String relationshipType,
            double confidence,
            String source) throws SQLException {
        if (firstProfileId.equals(secondProfileId)) {
            return;
        }

        UUID from = firstProfileId;
        UUID to = secondProfileId;
        if (firstProfileId.toString().compareTo(secondProfileId.toString()) > 0) {
            from = secondProfileId;
            to = firstProfileId;
        }

        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO connections (from_profile_id, to_profile_id, relationship_type, confidence, source)
                SELECT ?, ?, ?, ?, ?
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM connections
                    WHERE (
                            (from_profile_id = ? AND to_profile_id = ?)
                            OR (from_profile_id = ? AND to_profile_id = ?)
                        )
                        AND relationship_type = ?
                        AND source = ?
                )
                """)) {
            statement.setObject(1, from);
            statement.setObject(2, to);
            statement.setString(3, relationshipType);
            statement.setBigDecimal(4, BigDecimal.valueOf(confidence));
            statement.setString(5, source);
            statement.setObject(6, from);
            statement.setObject(7, to);
            statement.setObject(8, to);
            statement.setObject(9, from);
            statement.setString(10, relationshipType);
            statement.setString(11, source);
            statement.executeUpdate();
        }
    }

    private void insertCorrelationEvidenceIfMissing(
            Connection connection,
            UUID profileId,
            UUID matchedProfileId,
            String keyType,
            String keyValue,
            double confidence) throws SQLException {
        String title;
        if ("email".equals(keyType)) {
            title = "Shared email correlation";
        } else if ("username".equals(keyType)) {
            title = "Shared username correlation";
        } else {
            title = "Shared domain observation";
        }
        String snippet = "Matched profile " + matchedProfileId + " on " + keyType + " key '" + keyValue + "'.";
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO evidence (profile_id, source_type, source_uri, title, snippet, confidence)
                SELECT ?, ?, ?, ?, ?, ?
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM evidence
                    WHERE profile_id = ?
                        AND source_type = ?
                        AND title = ?
                        AND snippet = ?
                )
                """)) {
            statement.setObject(1, profileId);
            statement.setString(2, "auto_correlation");
            statement.setString(3, "");
            statement.setString(4, title);
            statement.setString(5, snippet);
            statement.setBigDecimal(6, BigDecimal.valueOf(confidence));
            statement.setObject(7, profileId);
            statement.setString(8, "auto_correlation");
            statement.setString(9, title);
            statement.setString(10, snippet);
            statement.executeUpdate();
        }
    }

    private Connection connect() throws SQLException {
        return DriverManager.getConnection(config.dbUrl(), config.dbUser(), config.dbPassword());
    }

    private Map<String, Object> one(Connection connection, String sql, UUID id) throws SQLException {
        List<Map<String, Object>> rows = many(connection, sql, id);
        return rows.isEmpty() ? new LinkedHashMap<>() : rows.get(0);
    }

    private List<Map<String, Object>> many(Connection connection, String sql, UUID id) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, id);
            try (ResultSet rs = statement.executeQuery()) {
                return rows(rs);
            }
        }
    }

    private List<Map<String, Object>> connections(Connection connection, UUID profileId) throws SQLException {
        return many(connection, """
                SELECT id, from_profile_id, to_profile_id, relationship_type, confidence, source, created_at
                FROM connections
                WHERE from_profile_id = ? OR to_profile_id = ?
                ORDER BY created_at DESC
                """, profileId, profileId);
    }

    private List<Map<String, Object>> many(Connection connection, String sql, UUID firstId, UUID secondId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, firstId);
            statement.setObject(2, secondId);
            try (ResultSet rs = statement.executeQuery()) {
                return rows(rs);
            }
        }
    }

    private List<Map<String, Object>> rows(ResultSet rs) throws SQLException {
        List<Map<String, Object>> rows = new ArrayList<>();
        int columns = rs.getMetaData().getColumnCount();
        while (rs.next()) {
            Map<String, Object> row = new LinkedHashMap<>();
            for (int index = 1; index <= columns; index++) {
                row.put(rs.getMetaData().getColumnLabel(index), normalize(rs.getObject(index)));
            }
            rows.add(row);
        }
        return rows;
    }

    private void bind(PreparedStatement statement, List<Object> params) throws SQLException {
        for (int index = 0; index < params.size(); index++) {
            statement.setObject(index + 1, params.get(index));
        }
    }

    private void addLike(List<Object> params, String value, int times) {
        String pattern = "%" + value.trim() + "%";
        for (int index = 0; index < times; index++) {
            params.add(pattern);
        }
    }

    private void addBooleanFilter(StringBuilder sql, List<Object> params, String column, String value) {
        if (!hasText(value)) {
            return;
        }
        sql.append("AND ").append(column).append(" = ?\n");
        params.add(Boolean.parseBoolean(value));
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private Object normalize(Object value) {
        if (value instanceof UUID uuid) {
            return uuid.toString();
        }
        if (value instanceof BigDecimal decimal) {
            return decimal.doubleValue();
        }
        if (value instanceof Number || value instanceof Boolean) {
            return value;
        }
        return value == null ? "" : value.toString();
    }

    private record CorrelationMatch(UUID otherProfileId, String keyType, String keyValue) {
    }
}

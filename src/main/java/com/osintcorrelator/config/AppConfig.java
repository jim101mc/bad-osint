package com.osintcorrelator.config;

public record AppConfig(
        String dbUrl,
        String dbUser,
        String dbPassword,
        String enricherUrl,
        int apiPort) {

    public static AppConfig fromEnv() {
        return new AppConfig(
                env("OSINT_DB_URL", "jdbc:postgresql://localhost:5432/osint"),
                env("OSINT_DB_USER", "postgres"),
                env("OSINT_DB_PASSWORD", "postgres"),
                env("OSINT_ENRICHER_URL", "http://127.0.0.1:8091/enrich"),
                Integer.parseInt(env("OSINT_API_PORT", "8080")));
    }

    private static String env(String key, String fallback) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? fallback : value;
    }
}

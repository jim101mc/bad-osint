package com.osintcorrelator;

import com.osintcorrelator.api.ApiServer;
import com.osintcorrelator.config.AppConfig;
import com.osintcorrelator.db.Database;
import com.osintcorrelator.enrich.EnricherClient;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) throws Exception {
        AppConfig config = AppConfig.fromEnv();
        Database database = new Database(config);
        EnricherClient enricherClient = new EnricherClient(config.enricherUrl());
        ApiServer server = new ApiServer(config.apiPort(), database, enricherClient);
        server.start();
    }
}

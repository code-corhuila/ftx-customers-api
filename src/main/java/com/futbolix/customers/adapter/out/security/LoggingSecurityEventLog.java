package com.futbolix.customers.adapter.out.security;

import com.futbolix.customers.application.port.out.SecurityEventLog;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Writes each security event as one structured log line (ECS JSON, see application.yml) on the
 * "security" logger, with the event name, administrator id and client address as fields.
 */
public class LoggingSecurityEventLog implements SecurityEventLog {

    private static final Logger log = LoggerFactory.getLogger("security");

    @Override
    public void record(Event event, UUID administratorId, String clientAddress, String reason) {
        Level level = event == Event.AUTH_LOGIN_SUCCESS || event == Event.AUTH_TOKEN_REVOKED ? Level.INFO : Level.WARN;
        log.atLevel(level)
                .addKeyValue("securityEvent", event.name())
                .addKeyValue("administratorId", administratorId == null ? "-" : administratorId.toString())
                .addKeyValue("clientAddress", clientAddress == null ? "-" : clientAddress)
                .log(reason == null ? event.name() : event.name() + ": " + reason);
    }
}

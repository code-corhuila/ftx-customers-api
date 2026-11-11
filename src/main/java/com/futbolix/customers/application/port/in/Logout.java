package com.futbolix.customers.application.port.in;

import java.util.UUID;

/** POST /auth/logout for the administrator of the access token. */
public interface Logout {

    /**
     * Revokes {@code refreshToken} when it belongs to {@code administratorId}. With
     * {@code allDevices}, or without a token, revokes every active token of that administrator.
     * A token of another administrator is left untouched and nothing reveals that it exists.
     */
    void logout(UUID administratorId, String refreshToken, boolean allDevices, String clientAddress);
}

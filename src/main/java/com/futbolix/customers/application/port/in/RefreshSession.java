package com.futbolix.customers.application.port.in;

import com.futbolix.customers.application.AuthResult;

/** POST /auth/refresh: one use per refresh token, rotated within its family. */
public interface RefreshSession {

    AuthResult refresh(String refreshToken, String clientAddress);
}

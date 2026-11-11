package com.futbolix.customers.application.port.in;

import com.futbolix.customers.application.AuthResult;

/** POST /auth/login (HU-ADM-002 AC1, AC3). */
public interface Login {

    AuthResult login(String email, String password, String clientAddress);
}

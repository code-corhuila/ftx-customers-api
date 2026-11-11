package com.futbolix.customers.adapter.config;

import com.futbolix.customers.application.AuthResult;
import com.futbolix.customers.application.AuthService;
import com.futbolix.customers.application.InvalidCredentialsException;
import com.futbolix.customers.application.InvalidRefreshTokenException;
import com.futbolix.customers.application.TooManyLoginAttemptsException;
import com.futbolix.customers.application.port.in.Login;
import com.futbolix.customers.application.port.in.Logout;
import com.futbolix.customers.application.port.in.RefreshSession;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Runs each use case in one transaction. The expected refusals (wrong password, spent token, rate
 * limit) still COMMIT: the failure counter, the lock and the family revocation they wrote must
 * survive the refusal. Any other exception rolls everything back.
 */
public class TransactionalAuthService implements Login, RefreshSession, Logout {

    private final AuthService delegate;
    private final TransactionTemplate transactions;

    public TransactionalAuthService(AuthService delegate, TransactionTemplate transactions) {
        this.delegate = delegate;
        this.transactions = transactions;
    }

    @Override
    public AuthResult login(String email, String password, String clientAddress) {
        return inTransaction(() -> delegate.login(email, password, clientAddress));
    }

    @Override
    public AuthResult refresh(String refreshToken, String clientAddress) {
        return inTransaction(() -> delegate.refresh(refreshToken, clientAddress));
    }

    @Override
    public void logout(UUID administratorId, String refreshToken, boolean allDevices, String clientAddress) {
        inTransaction(() -> {
            delegate.logout(administratorId, refreshToken, allDevices, clientAddress);
            return null;
        });
    }

    private <T> T inTransaction(Supplier<T> work) {
        RuntimeException[] refusal = new RuntimeException[1];
        T result = transactions.execute(status -> {
            try {
                return work.get();
            } catch (InvalidCredentialsException | InvalidRefreshTokenException | TooManyLoginAttemptsException e) {
                refusal[0] = e;
                return null;
            }
        });
        if (refusal[0] != null) {
            throw refusal[0];
        }
        return result;
    }
}

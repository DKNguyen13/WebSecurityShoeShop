package hcmute.com.ShoeShop.component;

import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class LoginAttemptService {
    private static final int MAX_ATTEMPTS = 5;
    private static final int BLOCK_TIME_MINUTES = 10;

    private record AttemptInfo(int attempts, LocalDateTime lastFailedTime) {}

    private final Map<String, AttemptInfo> attemptsCache = new ConcurrentHashMap<>();

    public void loginFailed(String username) {
        AttemptInfo current = attemptsCache.getOrDefault(username, new AttemptInfo(0, LocalDateTime.now()));
        int newAttempts = current.attempts() + 1;
        attemptsCache.put(username, new AttemptInfo(newAttempts, LocalDateTime.now()));
    }

    public void loginSucceeded(String username) {
        attemptsCache.remove(username);
    }

    public boolean isBlocked(String username) {
        AttemptInfo attempt = attemptsCache.get(username);
        if (attempt == null) return false;

        if (attempt.attempts() >= MAX_ATTEMPTS) {
            LocalDateTime unlockTime = attempt.lastFailedTime().plusMinutes(BLOCK_TIME_MINUTES);
            if (LocalDateTime.now().isBefore(unlockTime)) {
                return true;
            } else {
                attemptsCache.remove(username);
            }
        }
        return false;
    }
}

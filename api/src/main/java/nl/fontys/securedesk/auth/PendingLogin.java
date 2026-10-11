package nl.fontys.securedesk.auth;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * What a session holds between the password and the last stage: the user's id and the stages
 * still to pass. Never an authenticated principal and never an authority; every protected URL
 * still turns such a session away (test case 3 of BoK 6.1).
 */
public final class PendingLogin implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final UUID userId;
    private final String throttleKey;
    private final List<AuthStage> remaining;
    private int factors = 1;
    private boolean enrolmentStarted;

    PendingLogin(UUID userId, String throttleKey, List<AuthStage> stages) {
        this.userId = userId;
        this.throttleKey = throttleKey;
        this.remaining = new ArrayList<>(stages);
    }

    public UUID userId() {
        return userId;
    }

    public String throttleKey() {
        return throttleKey;
    }

    public AuthStage current() {
        return remaining.isEmpty() ? null : remaining.get(0);
    }

    public boolean isAt(AuthStage stage) {
        return stage == current();
    }

    /** Marks the current stage as passed; a passed MFA or ENROL stage counts as a second factor. */
    void pass(AuthStage stage) {
        if (!isAt(stage)) {
            throw new IllegalStateException("not at stage " + stage);
        }
        remaining.remove(0);
        if (stage == AuthStage.MFA || stage == AuthStage.ENROL) {
            factors = 2;
        }
    }

    public boolean done() {
        return remaining.isEmpty();
    }

    public int factors() {
        return factors;
    }

    boolean enrolmentStarted() {
        return enrolmentStarted;
    }

    void markEnrolmentStarted() {
        this.enrolmentStarted = true;
    }
}

package nl.fontys.securedesk.support;

import nl.fontys.securedesk.auth.Sleeper;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Records the progressive delay instead of waiting for it. */
public class RecordingSleeper implements Sleeper {

    private final List<Duration> delays = new ArrayList<>();

    @Override
    public synchronized void sleep(Duration duration) {
        delays.add(duration);
    }

    public synchronized List<Duration> delays() {
        return List.copyOf(delays);
    }

    public synchronized void clear() {
        delays.clear();
    }
}

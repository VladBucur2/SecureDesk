package nl.fontys.securedesk.admin;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.springframework.data.domain.Persistable;

import java.time.Instant;

/** One configuration value that administrators change at run time. */
@Entity
@Table(name = "app_setting")
public class AppSetting implements Persistable<String> {

    @Id
    @Column(name = "setting_key", length = 64)
    private String key;

    @Column(name = "setting_value", nullable = false, length = 255)
    private String value;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @jakarta.persistence.Transient
    private boolean fresh;

    protected AppSetting() {
    }

    AppSetting(String key, String value, Instant now) {
        this.key = key;
        this.value = value;
        this.updatedAt = now;
        this.fresh = true;
    }

    String getValue() {
        return value;
    }

    void setValue(String value, Instant now) {
        this.value = value;
        this.updatedAt = now;
    }

    @Override
    public String getId() {
        return key;
    }

    @Override
    public boolean isNew() {
        return fresh;
    }
}

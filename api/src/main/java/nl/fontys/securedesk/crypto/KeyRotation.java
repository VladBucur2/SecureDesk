package nl.fontys.securedesk.crypto;

import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.audit.Outcome;
import nl.fontys.securedesk.auth.RecoveryCode;
import nl.fontys.securedesk.auth.RecoveryCodeRepository;
import nl.fontys.securedesk.user.AppUser;
import nl.fontys.securedesk.user.AppUserRepository;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;

/**
 * Key rotation without anyone's password (BoK 6.3.7). The procedure:
 *
 * <ol>
 *   <li>add a new key file (k2) next to the old one and make it current;</li>
 *   <li>restart the API: this pass re-seals every password record, recovery code and TOTP secret
 *       that is not yet under the current key, and records the counts;</li>
 *   <li>remove the old key file and restart again. A backup sealed with the old key no longer
 *       opens, which is the point.</li>
 * </ol>
 *
 * A record that cannot be opened at all is reported as tampered and left alone.
 */
@Component
class KeyRotation {

    private static final int PAGE = 200;

    private final AppUserRepository users;
    private final RecoveryCodeRepository recoveryCodes;
    private final Pepper pepper;
    private final TotpSecretCipher totpCipher;
    private final AuditLog audit;

    KeyRotation(AppUserRepository users, RecoveryCodeRepository recoveryCodes, Pepper pepper,
                TotpSecretCipher totpCipher, AuditLog audit) {
        this.users = users;
        this.recoveryCodes = recoveryCodes;
        this.pepper = pepper;
        this.totpCipher = totpCipher;
        this.audit = audit;
    }

    @EventListener(ApplicationReadyEvent.class)
    void resealOutdatedRecords() {
        int passwords = 0;
        int secrets = 0;
        int codes = 0;
        int unreadable = 0;

        for (int page = 0; ; page++) {
            Page<AppUser> batch = users.findAll(PageRequest.of(page, PAGE, Sort.by("id")));
            for (AppUser user : batch) {
                boolean changed = false;
                try {
                    if (user.getPasswordRecord() != null && !pepper.isCurrent(user.getPasswordRecord())) {
                        user.setPasswordRecord(pepper.resealPassword(user.getId(), user.getPasswordRecord()));
                        passwords++;
                        changed = true;
                    }
                    if (user.getTotpSecret() != null && !totpCipher.isCurrent(user.getTotpSecret())) {
                        user.setTotpSecret(totpCipher.reseal(user.getId(), user.getTotpSecret()));
                        secrets++;
                        changed = true;
                    }
                } catch (GeneralSecurityException e) {
                    unreadable++;
                    audit.event(AuditType.CREDENTIAL_TAMPERED).system().outcome(Outcome.FAILURE)
                            .target("user", user.getId()).detail("during", "key_rotation").write();
                }
                if (changed) {
                    users.save(user);
                }
            }
            if (!batch.hasNext()) {
                break;
            }
        }

        for (int page = 0; ; page++) {
            Page<RecoveryCode> batch = recoveryCodes.findAll(PageRequest.of(page, PAGE, Sort.by("id")));
            for (RecoveryCode code : batch) {
                if (!pepper.isCurrent(code.getCodeRecord())) {
                    try {
                        code.setCodeRecord(pepper.resealRecoveryCode(code.getId(), code.getCodeRecord()));
                        recoveryCodes.save(code);
                        codes++;
                    } catch (GeneralSecurityException e) {
                        unreadable++;
                        audit.event(AuditType.CREDENTIAL_TAMPERED).system().outcome(Outcome.FAILURE)
                                .target("recovery_code", code.getId()).detail("during", "key_rotation").write();
                    }
                }
            }
            if (!batch.hasNext()) {
                break;
            }
        }

        if (passwords + secrets + codes + unreadable > 0) {
            audit.event(AuditType.KEYS_ROTATED).system()
                    .detail("pepper_key", pepper.currentKeyId())
                    .detail("password_records", passwords)
                    .detail("totp_records", secrets)
                    .detail("recovery_records", codes)
                    .detail("unreadable", unreadable).write();
        }
    }
}

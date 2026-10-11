package nl.fontys.securedesk.user;

/** The three application roles of BoK 2.2. One role per account. */
public enum Role {
    REQUESTER,
    AGENT,
    ADMIN;

    public String authority() {
        return "ROLE_" + name();
    }

    /** SR-01: a second factor is mandatory for agents and administrators, whatever the account says. */
    public boolean alwaysRequiresMfa() {
        return this != REQUESTER;
    }
}

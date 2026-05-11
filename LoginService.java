import java.sql.*;
import org.mindrot.jbcrypt.BCrypt;

public class LoginService {

    private static final int MAX_ATTEMPTS = 3;

    public static String login(String username, String password) throws Exception {

        // Input validation: null check, max length, whitelist format
        if (username == null || password == null || username.isBlank() || password.isBlank()
                || username.length() > 50 || password.length() > 50
                || !username.matches("^[a-zA-Z0-9_.]{3,50}$"))
            return "Invalid input.";

        // Parameterized query — prevents SQL injection
        String sql = "SELECT password_hash, role, failed_attempts, is_locked FROM users WHERE username = ?";
        try (Connection c = DriverManager.getConnection(System.getenv("DB_URL"),
                System.getenv("DB_USER"), System.getenv("DB_PASS"));
             PreparedStatement ps = c.prepareStatement(sql)) {

            ps.setString(1, username);
            ResultSet rs = ps.executeQuery();

            if (!rs.next())                 return "Invalid username or password.";
            if (rs.getBoolean("is_locked")) return "Account locked. Contact admin.";

            int attempts = rs.getInt("failed_attempts") + 1;

            // BCrypt password verification — never compare plaintext
            if (BCrypt.checkpw(password, rs.getString("password_hash"))) {
                update(c, username, 0, false);   // reset counter on success
                return "Login successful. Welcome, " + rs.getString("role") + ": " + username;
            }

            update(c, username, attempts, attempts >= MAX_ATTEMPTS);   // increment / lock
            return attempts >= MAX_ATTEMPTS
                    ? "Account locked after " + MAX_ATTEMPTS + " failed attempts."
                    : "Invalid username or password. Attempt " + attempts + "/" + MAX_ATTEMPTS + ".";
        }
    }

    // Update failed_attempts and is_locked using a parameterized query
    private static void update(Connection c, String username, int attempts, boolean lock) throws Exception {
        PreparedStatement ps = c.prepareStatement(
                "UPDATE users SET failed_attempts = ?, is_locked = ? WHERE username = ?");
        ps.setInt(1, attempts);
        ps.setBoolean(2, lock);
        ps.setString(3, username);
        ps.executeUpdate();
    }
}

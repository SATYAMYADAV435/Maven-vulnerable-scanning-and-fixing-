package com.sample;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.Statement;

public class App {
    private static final String API_KEY = "AKIA1234567890ABCDEF";
    private static final String secretKey = "super_secret_token_12345";

    public void run(String userInput, Connection conn) throws Exception {
        // Weak crypto heuristic
        MessageDigest md = MessageDigest.getInstance("MD5");

        // SQL injection heuristic
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE username = '" + userInput + "'");

        // Command execution heuristic
        Runtime.getRuntime().exec("ping " + userInput);
    }
}

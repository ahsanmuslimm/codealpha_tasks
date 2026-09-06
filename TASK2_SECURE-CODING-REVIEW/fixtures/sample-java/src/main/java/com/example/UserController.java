package com.example;

import java.sql.*;
import javax.servlet.http.*;

public class UserController extends HttpServlet {
    private static final String DB_PASSWORD = "admin123";

    protected void doGet(HttpServletRequest req, HttpServletResponse res) {
        String id = req.getParameter("id");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", DB_PASSWORD);
            // SQL Injection (CWE-89)
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

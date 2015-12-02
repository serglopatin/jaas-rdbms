// $Id: DBLogin.java,v 1.5 2003/02/17 20:13:23 andy Exp $
package com.tagish.auth;

import java.util.Map;
import java.util.*;
import java.sql.*;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;

import java.io.*;
import javax.xml.bind.DatatypeConverter;


/**
 * Simple database based authentication module.
 *
 * @author Andy Armstrong, <A HREF="mailto:andy@tagish.com">andy@tagish.com</A>
 * @version 1.0.3
 */
public class DBLogin extends SimpleLogin
{
    	protected String                dbDriver;
    	protected String                dbUrl;
    	protected String                dbUser;
    	protected String                dbPassword;
    	protected String                dbTable;
	protected String                dbColumnPw;
	protected String                dbColumnLogin;
    	protected String                hashAlgorithm;
	protected String                pyPath;
	protected String                pyModulePath;


	protected synchronized Vector validateUser(String username, char password[]) throws LoginException
	{
		ResultSet rsu = null;
		Connection con = null;
		PreparedStatement psu = null;

		try
		{
			Class.forName(dbDriver);
			if (dbUser != null)
			   con = DriverManager.getConnection(dbUrl, dbUser, dbPassword);
			else
			   con = DriverManager.getConnection(dbUrl);

			psu = con.prepareStatement("SELECT " + dbColumnPw + " FROM " + dbTable + " WHERE " + dbColumnLogin + "=?");

			/* Set the username to the statement */
			psu.setString(1, username);
			rsu = psu.executeQuery();
			if (!rsu.next()) throw new FailedLoginException("Credentials not recognized.");

			String password_hash = rsu.getString(1);
			
			
			if (hashAlgorithm.equals("pbkdf2_sha512")) {
				if (!verify_pbkdf2_sha512(new String(password), password_hash)) {
                                	throw new FailedLoginException("Credentials not recognized1.");
				}
                        }
			else {
				throw new LoginException("Not implemented.");
			}

			Vector p = new Vector();
			p.add(new TypedPrincipal(username, TypedPrincipal.USER));
			return p;
		}
		catch (ClassNotFoundException e)
		{
			throw new LoginException("Error reading user database (" + e.getMessage() + ")");
		}
		catch (SQLException e)
		{
			throw new LoginException("Error reading user database (" + e.getMessage() + ")");
		}
		finally
		{
			try {
				if (rsu != null) rsu.close();
				if (psu != null) psu.close();
				if (con != null) con.close();
			} catch (Exception e) { }
		}
	}

        private Boolean verify_pbkdf2_sha512(String pw, String hash)
        {
                try {
                        String pw1 = new String(DatatypeConverter.printBase64Binary(pw.getBytes()));
                        String hash1 = new String(DatatypeConverter.printBase64Binary(hash.getBytes()));

                        Process p = Runtime.getRuntime().exec(pyPath + " " + pyModulePath + " " + pw1 + " " + hash1);

                        BufferedReader stdInput = new BufferedReader(new
                        InputStreamReader(p.getInputStream()));

                        String s = stdInput.readLine();
                        if (s.equals("1")) {
                                return true;
                        }
                        return false;
                 } catch (IOException e) {
                        return false;
                }
        }


	public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options)
	{
		super.initialize(subject, callbackHandler, sharedState, options);

		dbDriver = getOption("dbDriver", null);
		if (dbDriver == null) throw new Error("No database driver named (dbDriver=?)");

		dbUrl = getOption("dbUrl", null);
		if (dbUrl == null) throw new Error("No database URL specified (dbUrl=?)");

		dbUser = getOption("dbUser", null);
		dbPassword = getOption("dbPassword", null);
		if ((dbUser == null && dbPassword != null) || (dbUser != null && dbPassword == null))
		   throw new Error("Either provide dbUser and dbPassword or encode both in dbURL");

		dbTable = getOption("dbTable", "");
		dbColumnLogin = getOption("dbColumnLogin", "");
		dbColumnPw = getOption("dbColumnPw", "");

		hashAlgorithm = getOption("hashAlgorithm", "");

		pyPath = getOption("pyPath", "");
		pyModulePath = getOption("pyModulePath", "");
	}
}

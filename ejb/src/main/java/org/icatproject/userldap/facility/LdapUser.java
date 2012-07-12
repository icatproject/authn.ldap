package org.icatproject.userldap.facility;

import java.io.File;
import java.io.FileInputStream;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.icatproject.core.IcatException;
import org.icatproject.core.authentication.Authenticator;

public class LdapUser implements Authenticator {

	private LdapAuthenticator ldapAuthenticator;
	private static final Logger log = Logger.getLogger(LdapUser.class);
	private IcatException icatException;

	public LdapUser() throws IcatException {
		File f = new File("icat.properties");
		try {
			Properties props = new Properties();
			props.load(new FileInputStream(f));
			String providerUrl = props.getProperty("auth.ldap.provider_url");
			if (providerUrl == null) {
				throw new IcatException(IcatException.IcatExceptionType.INTERNAL,
						"auth.ldap.provider_url not defined");
			}
			String securityPrincipal = props.getProperty("auth.ldap.security_principal");
			if (securityPrincipal == null) {
				throw new IcatException(IcatException.IcatExceptionType.INTERNAL,
						"auth.ldap.security_principal not defined");
			}
			if (securityPrincipal.indexOf('%') < 0) {
				throw new IcatException(IcatException.IcatExceptionType.INTERNAL,
						"auth.ldap.security_principal value must include a % to be substituted by the user name");
			}
			ldapAuthenticator = new LdapAuthenticator(providerUrl, securityPrincipal);
		} catch (Exception e) {
			String msg = "Problem with " + f.getAbsolutePath() + "  " + e.getMessage();
			log.fatal(msg);
			icatException = new IcatException(IcatException.IcatExceptionType.INTERNAL, msg);
			throw icatException;
		}
		log.trace("Created LdapUser");
	}

	@Override
	public Authentication login(Map<String, String> credentials) throws IcatException {
		String username = credentials.get("username");
		log.trace("login:" + username);

		if (username == null || username.equals("")) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Username cannot be null or empty.");
		}
		String password = credentials.get("password");
		if (password == null || password.equals("")) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Password cannot be null or empty.");
		}

		log.info("Checking password against database");

		if (!ldapAuthenticator.authenticate(username, password)) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Username and password do not match");
		}

		return new Authentication(username, LdapUser.class.getName());
	}

}

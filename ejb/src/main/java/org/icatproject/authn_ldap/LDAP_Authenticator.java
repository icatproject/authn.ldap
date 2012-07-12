package org.icatproject.authn_ldap;

import java.io.File;
import java.io.FileInputStream;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;

import javax.ejb.Remote;
import javax.ejb.Stateless;
import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;

import org.apache.log4j.Logger;
import org.icatproject.core.IcatException;
import org.icatproject.core.authentication.Authenticator;

@Stateless()
@Remote(Authenticator.class)
public class LDAP_Authenticator implements Authenticator {

	private static final Logger log = Logger.getLogger(LDAP_Authenticator.class);
	private IcatException icatException;
	private String securityPrincipal;
	private String providerUrl;

	public LDAP_Authenticator() throws IcatException {
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
			this.providerUrl = providerUrl;
			this.securityPrincipal = securityPrincipal;
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

		log.info("Checking username/password with ldap server");

		Hashtable<Object, Object> authEnv = new Hashtable<Object, Object>();
		authEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		authEnv.put(Context.PROVIDER_URL, providerUrl);
		authEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
		authEnv.put(Context.SECURITY_PRINCIPAL, securityPrincipal.replace("%", username));
		authEnv.put(Context.SECURITY_CREDENTIALS, password);

		try {
			new InitialDirContext(authEnv);
			log.info("Authentication successful");
			return new Authentication(username, LDAP_Authenticator.class.getName());
		} catch (AuthenticationException e) {
			log.debug("Authentication exception thrown:" + e.getMessage());
			throw new IcatException(IcatException.IcatExceptionType.SESSION, e.getMessage());
		} catch (NamingException e) {
			log.debug("Naming exception thrown" + e.getMessage());
			throw new IcatException(IcatException.IcatExceptionType.SESSION, e.getMessage());
		}

	}

}

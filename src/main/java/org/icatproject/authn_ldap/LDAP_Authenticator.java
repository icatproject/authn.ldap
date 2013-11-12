package org.icatproject.authn_ldap;

import java.io.File;
import java.io.FileInputStream;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.ejb.Remote;
import javax.ejb.Stateless;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;

import org.apache.log4j.Logger;
import org.icatproject.authentication.AddressChecker;
import org.icatproject.authentication.Authentication;
import org.icatproject.authentication.Authenticator;
import org.icatproject.core.IcatException;

/* Mapped name is to avoid name clashes */
@Stateless(mappedName = "org.icatproject.authn_ldap.LDAP_Authenticator")
@Remote
public class LDAP_Authenticator implements Authenticator {

	private static final Logger log = Logger.getLogger(LDAP_Authenticator.class);
	private String securityPrincipal;
	private String providerUrl;
	private org.icatproject.authentication.AddressChecker addressChecker;
	private String mechanism;

	@SuppressWarnings("unused")
	@PostConstruct
	private void init() {
		File f = new File("authn_ldap.properties");
		Properties props = null;
		try {
			props = new Properties();
			props.load(new FileInputStream(f));
		} catch (Exception e) {
			String msg = "Unable to read property file " + f.getAbsolutePath() + "  "
					+ e.getMessage();
			log.fatal(msg);
			throw new IllegalStateException(msg);

		}
		String authips = props.getProperty("ip");
		if (authips != null) {
			try {
				addressChecker = new AddressChecker(authips);
			} catch (IcatException e) {
				String msg = "Problem creating AddressChecker with information from "
						+ f.getAbsolutePath() + "  " + e.getMessage();
				log.fatal(msg);
				throw new IllegalStateException(msg);
			}
		}

		String providerUrl = props.getProperty("provider_url");
		if (providerUrl == null) {
			String msg = "provider_url not defined in " + f.getAbsolutePath();
			log.fatal(msg);
			throw new IllegalStateException(msg);
		}
		String securityPrincipal = props.getProperty("security_principal");
		if (securityPrincipal == null) {
			String msg = "security_principal not defined in " + f.getAbsolutePath();
			log.fatal(msg);
			throw new IllegalStateException(msg);
		}
		if (securityPrincipal.indexOf('%') < 0) {
			String msg = "security_principal value must include a % to be substituted by the user name "
					+ f.getAbsolutePath();
			log.fatal(msg);
			throw new IllegalStateException(msg);
		}
		this.providerUrl = providerUrl;
		this.securityPrincipal = securityPrincipal;

		// Note that the mechanism is optional
		mechanism = props.getProperty("mechanism");

		log.debug("Initialised LDAP_Authenticator");
	}

	@Override
	public Authentication authenticate(Map<String, String> credentials, String remoteAddr)
			throws IcatException {

		if (addressChecker != null) {
			if (!addressChecker.check(remoteAddr)) {
				throw new IcatException(IcatException.IcatExceptionType.SESSION,
						"authn_db does not allow log in from your IP address " + remoteAddr);
			}
		}

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
		} catch (NamingException e) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"The username and password do not match");
		}
		log.info(username + " logged in succesfully");
		return new Authentication(username, mechanism);

	}

}

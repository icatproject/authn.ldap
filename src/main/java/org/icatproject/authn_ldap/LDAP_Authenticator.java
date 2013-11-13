package org.icatproject.authn_ldap;

import java.util.Hashtable;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.Stateless;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.apache.log4j.Logger;
import org.icatproject.authentication.AddressChecker;
import org.icatproject.authentication.Authentication;
import org.icatproject.authentication.Authenticator;
import org.icatproject.core.IcatException;
import org.icatproject.utils.CheckedProperties;
import org.icatproject.utils.CheckedProperties.CheckedPropertyException;

/* Mapped name is to avoid name clashes */
@Stateless(mappedName = "org.icatproject.authn_ldap.LDAP_Authenticator")
public class LDAP_Authenticator implements Authenticator {

	public enum Case {
		UPPER, LOWER
	}

	private static final Logger logger = Logger.getLogger(LDAP_Authenticator.class);
	private String securityPrincipal;
	private String providerUrl;
	private org.icatproject.authentication.AddressChecker addressChecker;
	private String mechanism;
	private Hashtable<Object, Object> authEnv;
	private String ldapBase;
	private String ldapFilter;
	private String ldapAttribute;
	private Case userNameCase;

	@PostConstruct
	private void init() {

		String propsName = "authn_ldap.properties";
		CheckedProperties props = new CheckedProperties();
		try {
			props.loadFromFile(propsName);

			String authips = props.getProperty("ip");
			if (authips != null) {
				try {
					addressChecker = new AddressChecker(authips);
				} catch (IcatException e) {
					String msg = "Problem creating AddressChecker with information from "
							+ propsName + " " + e.getMessage();
					logger.fatal(msg);
					throw new IllegalStateException(msg);
				}
			}

			this.providerUrl = props.getString("provider_url");

			this.securityPrincipal = props.getString("security_principal");
			if (securityPrincipal.indexOf('%') < 0) {
				String msg = "security_principal value must include a % to be substituted by the user name "
						+ propsName;
				logger.fatal(msg);
				throw new IllegalStateException(msg);
			}

			authEnv = new Hashtable<>();
			authEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
			authEnv.put(Context.PROVIDER_URL, providerUrl);
			authEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
			if (props.has("context.props")) {
				for (String prop : props.getString("context.props").trim().split("\\s+")) {
					String value = props.getString("context.props." + prop);
					authEnv.put(prop, value);
				}
			}

			if (props.has("ldap.base") || props.has("ldap.filter") || props.has("ldap.attribute")) {
				ldapBase = props.getString("ldap.base");
				ldapFilter = props.getString("ldap.filter");
				ldapAttribute = props.getString("ldap.attribute");
			}

			if (props.has("case")) {
				String nameCase = props.getString("case");
				if (nameCase.equals("upper")) {
					userNameCase = Case.UPPER;
				} else if (nameCase.equals("lower")) {
					userNameCase = Case.LOWER;
				} else {
					String msg = "The \"case\" property, if present, must be \"upper\" or \"lower\"";
					logger.fatal(msg);
					throw new IllegalStateException(msg);
				}
			}

			// Note that the mechanism is optional
			mechanism = props.getProperty("mechanism");
		} catch (CheckedPropertyException e) {
			logger.fatal(e.getMessage());
			throw new IllegalStateException(e.getMessage());
		}

		logger.debug("Initialised LDAP_Authenticator");
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
		logger.trace("login:" + username);

		if (username == null || username.equals("")) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Username cannot be null or empty.");
		}
		String password = credentials.get("password");
		if (password == null || password.equals("")) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Password cannot be null or empty.");
		}

		logger.info("Checking username/password with ldap server");

		authEnv.put(Context.SECURITY_PRINCIPAL, securityPrincipal.replace("%", username));
		authEnv.put(Context.SECURITY_CREDENTIALS, password);

		try {
			LdapContext m_ctx = new InitialLdapContext(authEnv, null);
			if (ldapBase != null) {
				SearchControls ctls = new SearchControls();
				ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
				ctls.setCountLimit(0);
				ctls.setTimeLimit(0);
				NamingEnumeration<SearchResult> results = m_ctx.search(ldapBase,
						ldapFilter.replace("%", username), ctls);
				if (!results.hasMoreElements()) {
					throw new IcatException(IcatException.IcatExceptionType.SESSION,
							"Unable to locate user in LDAP directory");
				}
				username = (String) results.nextElement().getAttributes().get(ldapAttribute).get();
				logger.debug("username changed to " + username + " from ldap search");
			}
		} catch (NamingException e) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"The username and password do not match");
		}

		if (userNameCase == Case.UPPER) {
			username = username.toUpperCase();
			logger.debug("username changed to " + username + " from upper request");
		} else if (userNameCase == Case.LOWER) {
			username = username.toLowerCase();
			logger.debug("username changed to " + username + " from lower request");
		}

		logger.info(username + " logged in succesfully");
		return new Authentication(username, mechanism);

	}

}

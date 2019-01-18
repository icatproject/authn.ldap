package org.icatproject.authn_ldap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;
import java.util.Hashtable;

import javax.annotation.PostConstruct;
import javax.ejb.Stateless;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;
import javax.json.stream.JsonGenerator;
import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.icatproject.authentication.AuthnException;
import org.icatproject.utils.AddressChecker;
import org.icatproject.utils.AddressCheckerException;
import org.icatproject.utils.CheckedProperties;
import org.icatproject.utils.CheckedProperties.CheckedPropertyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

@Path("/")
@Stateless
public class LDAP_Authenticator {

	public enum Case {
		UPPER, LOWER
	}

	private static final Logger logger = LoggerFactory.getLogger(LDAP_Authenticator.class);
	private static final Marker fatal = MarkerFactory.getMarker("FATAL");

	private String securityPrincipal;
	private String providerUrl;
	private AddressChecker addressChecker;

	private String mechanism;
	private Hashtable<Object, Object> authEnv;
	private String ldapBase;
	private String ldapFilter;
	private String ldapAttribute;
	private Case userNameCase;

	@PostConstruct
	private void init() {

		CheckedProperties props = new CheckedProperties();
		try {
			props.loadFromResource("run.properties");

			if (props.has("ip")) {
				String authips = props.getString("ip");
				try {
					addressChecker = new AddressChecker(authips);
				} catch (Exception e) {
					String msg = "Problem creating AddressChecker with information from run.properties."
							+ e.getMessage();
					logger.error(fatal, msg);
					throw new IllegalStateException(msg);
				}
			}

			this.providerUrl = props.getString("provider_url");

			this.securityPrincipal = props.getString("security_principal");
			if (securityPrincipal.indexOf('%') < 0) {
				String msg = "security_principal value must include a % to be substituted by the user name ";
				logger.error(fatal, msg);
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
					logger.error(fatal, msg);
					throw new IllegalStateException(msg);
				}
			}

			if (props.has("mechanism")) {
				mechanism = props.getString("mechanism");
			}
		} catch (CheckedPropertyException e) {
			logger.error(fatal, e.getMessage());
			throw new IllegalStateException(e.getMessage());
		}

		logger.debug("Initialised LDAP_Authenticator");
	}

	@GET
	@Path("version")
	@Produces(MediaType.APPLICATION_JSON)
	public String getVersion() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		JsonGenerator gen = Json.createGenerator(baos);
		gen.writeStartObject().write("version", Constants.API_VERSION).writeEnd();
		gen.close();
		return baos.toString();
	}

	@POST
	@Path("authenticate")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public String authenticate(@FormParam("json") String jsonString) throws AuthnException {

		ByteArrayInputStream s = new ByteArrayInputStream(jsonString.getBytes());

		String username = null;
		String password = null;
		String ip = null;
		try (JsonReader r = Json.createReader(s)) {
			JsonObject o = r.readObject();
			for (JsonValue c : o.getJsonArray("credentials")) {
				JsonObject credential = (JsonObject) c;
				if (credential.containsKey("username")) {
					username = credential.getString("username");
				} else if (credential.containsKey("password")) {
					password = credential.getString("password");
				}
			}
			if (o.containsKey("ip")) {
				ip = o.getString("ip");
			}

		}

		logger.debug("Login request by: {} from {}", username, (ip != null ? ip : "?"));

		if (username == null || username.isEmpty()) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "username cannot be null or empty.");
		}

		if (password == null || password.isEmpty()) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "password cannot be null or empty.");
		}

		if (addressChecker != null) {
			try {
				if (!addressChecker.check(ip)) {
					throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN,
							"authn_ldap does not allow log in from your IP address " + ip);
				}
			} catch (AddressCheckerException e) {
				throw new AuthnException(HttpURLConnection.HTTP_INTERNAL_ERROR, e.getClass() + " " + e.getMessage());
			}
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
				NamingEnumeration<SearchResult> results = m_ctx.search(ldapBase, ldapFilter.replace("%", username),
						ctls);
				if (!results.hasMoreElements()) {
					throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN,
							"Unable to locate user in LDAP directory.");
				}
				username = (String) results.nextElement().getAttributes().get(ldapAttribute).get();
				logger.debug("username changed to " + username + " from ldap search");
			}
		} catch (AuthenticationException e) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The username and password do not match ");
		} catch (NamingException e) {
			String msg = e.getClass() + ": " + e.getMessage();
			logger.error(msg);
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, msg);
		}

		if (userNameCase == Case.UPPER) {
			username = username.toUpperCase();
			logger.debug("username changed to " + username + " from upper request");
		} else if (userNameCase == Case.LOWER) {
			username = username.toLowerCase();
			logger.debug("username changed to " + username + " from lower request");
		}

		logger.info(username + " logged in succesfully" + (mechanism != null ? " by " + mechanism : ""));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (JsonGenerator gen = Json.createGenerator(baos)) {
			gen.writeStartObject().write("username", username);
			if (mechanism != null) {
				gen.write("mechanism", mechanism);
			}
			gen.writeEnd();
		}
		return baos.toString();

	}

	@GET
	@Path("description")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public String getDescription() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (JsonGenerator gen = Json.createGenerator(baos)) {
			gen.writeStartObject().writeStartArray("keys");
			gen.writeStartObject().write("name", "username").writeEnd();
			gen.writeStartObject().write("name", "password").write("hide", true).writeEnd();
			gen.writeEnd().writeEnd();
		}
		return baos.toString();
	}

}

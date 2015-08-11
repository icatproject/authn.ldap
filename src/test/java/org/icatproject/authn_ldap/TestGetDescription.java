package org.icatproject.authn_ldap;

import static org.junit.Assert.assertEquals;

import org.icatproject.authentication.Authenticator;
import org.junit.Test;

public class TestGetDescription {
	@Test
	public void t4() throws Exception {
		Authenticator a = new LDAP_Authenticator();
		assertEquals("{\"keys\":[{\"name\":\"username\"},{\"name\":\"password\",\"hide\":true}]}", a.getDescription());
	}
}
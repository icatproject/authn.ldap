package org.icatproject.authn_ldap;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class Tests {
	@Test
	public void getDescription() throws Exception {
		LDAP_Authenticator a = new LDAP_Authenticator();
		assertEquals("{\"keys\":[{\"name\":\"username\"},{\"name\":\"password\",\"hide\":true}]}", a.getDescription());
	}
}
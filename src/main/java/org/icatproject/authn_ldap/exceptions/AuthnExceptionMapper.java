package org.icatproject.authn_ldap.exceptions;

import java.io.ByteArrayOutputStream;

import jakarta.json.Json;
import jakarta.json.stream.JsonGenerator;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

import org.icatproject.authentication.AuthnException;

@Provider
public class AuthnExceptionMapper implements ExceptionMapper<AuthnException> {

	@Override
	public Response toResponse(AuthnException e) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		JsonGenerator gen = Json.createGenerator(baos);
		gen.writeStartObject().write("code", e.getClass().getSimpleName()).write("message", e.getShortMessage());
		gen.writeEnd().close();
		return Response.status(e.getHttpStatusCode()).entity(baos.toString()).build();
	}
}
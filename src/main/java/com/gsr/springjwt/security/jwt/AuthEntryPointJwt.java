package com.gsr.springjwt.security.jwt;

import java.io.IOException;
import java.time.LocalDateTime;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint{

	private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);
	
	@SuppressWarnings("unchecked")
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		logger.error("Unauthorized error: {}", authException.getMessage());
		response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        JSONObject object = new JSONObject();
        object.put("timestamp", LocalDateTime.now());
        object.put("message", "Access Denied");
		response.getWriter().write(object.toString());
	}
}

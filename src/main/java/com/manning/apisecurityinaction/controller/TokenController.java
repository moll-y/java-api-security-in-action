package com.manning.apisecurityinaction.controller;

import com.manning.apisecurityinaction.token.TokenStore;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

public class TokenController {
  private final TokenStore tokenStore;

  public TokenController(TokenStore tokenStore) {
    this.tokenStore = tokenStore;
  }

  public JSONObject login(Request request, Response response) {
    String subject = request.attribute("subject");
    var expiry = Instant.now().plus(10, ChronoUnit.MINUTES);

    var token = new TokenStore.Token(expiry, subject);
    var tokenId = tokenStore.create(request, token);

    response.status(201);
    return new JSONObject().put("token", tokenId);
  }

  public JSONObject logout(Request request, Response response) {
    // Get the token ID from the X-CSRF-Token header.
    var tokenId = request.headers("X-CSRF-Token");
    if (tokenId == null) {
      throw new IllegalArgumentException("missing token header");
    }

    tokenStore.revoke(request, tokenId);

    response.status(200);
    return new JSONObject();
  }

  public void validateToken(Request request, Response response) {
    // Read the CSRF token from the X-CSRF-Token header.
    var tokenId = request.headers("X-CSRF-Token");
    if (tokenId == null) {
      return;
    }

    // WARNING: csrf attack possible.
    tokenStore
        .read(request, tokenId)
        // Check if a token is present and not expired.
        .ifPresent(
            token -> {
              if (Instant.now().isBefore(token.expiry)) {
                request.attribute("subject", token.username);
                token.attributes.forEach(request::attribute);
              }
            });
  }
}

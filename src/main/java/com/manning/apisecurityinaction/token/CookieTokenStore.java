package com.manning.apisecurityinaction.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import spark.Request;

public class CookieTokenStore implements TokenStore {

  @Override
  public String create(Request request, Token token) {
    // WARNING: session fixation vulnerability.
    // var session = request.session(true);

    var session = request.session(false);
    if (session != null) {
      session.invalidate();
    }

    session = request.session(true);
    session.attribute("username", token.username);
    session.attribute("expiry", token.expiry);
    session.attribute("attrs", token.attributes);

    // Return the SHA-256 hash of the session cookie, Base64url-encoded.
    return Base64url.encode(sha256(session.id()));
  }

  @Override
  public Optional<Token> read(Request request, String tokenId) {
    // Pass false to check if a valid session is present.
    var session = request.session(false);
    if (session == null) {
      return Optional.empty();
    }

    // Decode the suplied token ID and compare it to the SHA-256 of the
    // session.
    var provided = Base64url.decode(tokenId);
    var computed = sha256(session.id());

    // If the CSRF token doesn't match the session hash, then reject the
    // request.
    if (!MessageDigest.isEqual(computed, provided)) {
      return Optional.empty();
    }

    var token = new Token(session.attribute("expiry"), session.attribute("username"));
    token.attributes.putAll(session.attribute("attrs"));
    return Optional.of(token);
  }

  @Override
  public void revoke(Request request, String tokenId) {
    var session = request.session(false);
    if (session == null) {
      return;
    }

    var provided = Base64url.decode(tokenId);
    var computed = sha256(session.id());

    if (!MessageDigest.isEqual(computed, provided)) {
      return;
    }

    session.invalidate();
  }

  static byte[] sha256(String tokenId) {
    try {
      var sha256 = MessageDigest.getInstance("SHA-256");
      return sha256.digest(tokenId.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}

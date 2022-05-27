package com.manning.apisecurityinaction.controller;

import static spark.Spark.*;

import com.lambdaworks.crypto.SCryptUtil;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.dalesbred.Database;
import org.json.JSONObject;
import spark.Filter;
import spark.Request;
import spark.Response;

public class UserController {
  private static final String USERNAME_PATTERN = "[a-zA-Z][a-zA-Z0-9]{1,29}";

  private final Database database;

  public UserController(Database database) {
    this.database = database;
  }

  public JSONObject register(Request request, Response response) throws Exception {
    var json = new JSONObject(request.body());
    var username = json.getString("username");
    var password = json.getString("password");

    if (!username.matches(USERNAME_PATTERN)) {
      throw new IllegalArgumentException("invalid username");
    }

    if (password.length() < 8) {
      throw new IllegalArgumentException("password must be at least 8 characters");
    }

    // The latest NIST guidance on secure passwords storage recommends using
    // strong memory-hard hash functions such as Scrypt. Recommended parameters
    // as of 2019, which should take around 100ms on a single CPU and 32MiB of
    // memory.
    var hash = SCryptUtil.scrypt(password, 32768, 8, 1);
    database.updateUnique("INSERT INTO users(user_id, pw_hash) VALUES(?, ?)", username, hash);

    response.status(201);
    response.header("Location", "/users/" + username);
    return new JSONObject().put("username", username);
  }

  public void authenticate(Request request, Response response) {
    // Check to see if there is an HTTP Basic Authorization header.
    var authHeader = request.headers("Authorization");
    if (authHeader == null || !authHeader.startsWith("Basic ")) {
      return;
    }

    var offset = "Basic ".length();
    // Decode the credentials using Base64 and UTF-8.
    var credentials =
        new String(
            Base64.getDecoder().decode(authHeader.substring(offset)), StandardCharsets.UTF_8);

    // Split the credentials into username and password.
    var components = credentials.split(":", 2);
    if (components.length != 2) {
      throw new IllegalArgumentException("invalid auth header");
    }

    var username = components[0];
    var password = components[1];

    if (!username.matches(USERNAME_PATTERN)) {
      throw new IllegalArgumentException("invalid username");
    }

    var hash =
        database.findOptional(
            String.class, "SELECT pw_hash FROM users WHERE user_id = ?", username);

    if (hash.isPresent() && SCryptUtil.check(password, hash.get())) {
      request.attribute("subject", username);
    }
  }

  public Filter requirePermission(String method, String permission) {
    return (request, response) -> {
      // Ignore requests that don't match the request method.
      if (!method.equalsIgnoreCase(request.requestMethod())) {
        return;
      }

      // Check if the user is authenticated.
      requireAuthentication(request, response);
      var spaceId = Long.parseLong(request.params(":spaceId"));
      var username = (String) request.attribute("subject").toString();

      // Look up permissions for the current user in the given space,
      // defaulting to no permissions.
      var perms =
          database
              .findOptional(
                  String.class,
                  "SELECT perms FROM permissions WHERE space_id = ? AND user_id = ?",
                  spaceId,
                  username)
              .orElse("");

      // If the user doesn't have permission, then halt with a 403 Forbidden
      // status.
      if (!perms.contains(permission)) {
        halt(403);
      }
    };
  }

  public void requireAuthentication(Request request, Response response) {
    if (request.attribute("subject") == null) {
      response.header("WWW-Authenticate", "Basic realm=\"/\", charset=\"UTF-8\"");
      halt(401);
    }
  }
}

package com.manning.apisecurityinaction;

import static spark.Spark.*;

import com.google.common.util.concurrent.RateLimiter;
import com.manning.apisecurityinaction.controller.AuditController;
import com.manning.apisecurityinaction.controller.SpaceController;
import com.manning.apisecurityinaction.controller.TokenController;
import com.manning.apisecurityinaction.controller.UserController;
import com.manning.apisecurityinaction.token.CookieTokenStore;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.dalesbred.Database;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONException;
import org.json.JSONObject;
import spark.Request;
import spark.Response;
import spark.Spark;

/** Hello world! */
public class App {
  public static void main(String[] args) throws Exception {
    Spark.staticFiles.location("/public");

    // Enable HTTPS support.
    secure("localhost.p12", "changeit", null, null);

    var datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter", "password");
    var database = Database.forDataSource(datasource);
    createTables(database);

    datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter_api_user", "password");
    database = Database.forDataSource(datasource);

    var spaceController = new SpaceController(database);
    var userController = new UserController(database);
    var auditController = new AuditController(database);

    var tokenStore = new CookieTokenStore();
    var tokenController = new TokenController(tokenStore);

    // Rate-Limiting
    var rateLimiter = RateLimiter.create(2.0d);
    before(
        (request, response) -> {
          if (!rateLimiter.tryAcquire()) {
            // Indicate when the client should try again.
            response.header("Retry-After", "2");
            // Too Many Requests status.
            halt(429);
          }
        });

    before(
        (request, response) -> {
          if (request.requestMethod().equals("POST")
              && !"application/json".equals(request.contentType())) {
            halt(415, new JSONObject().put("error", "only application/json supported").toString());
          }
        });

    afterAfter(
        (request, response) -> {
          // Indicate UTF-8 character-encoding to avoid tricks for stealing
          // JSON data by specifying a different encoding such as UTF-16BE.
          response.type("application/json;charset=utf-8");

          // Prevent the browser guessing the Content-Type.
          response.header("X-Content-Type-Options", "nosniff");

          // Prevent responses being loaded in a frame or iframe.
          response.header("X-Frame-Options", "DENY");

          // Tells the browser whether to block/ignore suspected XSS attacks.
          // The current guidance is to set to "0" on API responses to
          // completely disable these protections due to security issues they
          // can introduce.
          response.header("X-XSS-Protection", "0");

          // Controls whether browsers and proxies can cache content in the
          // response and for how long.
          response.header("Cache-Control", "no-store");

          // "default-src 'none': prevents the response from loading any
          // scripts or resources. frame-ancestors 'none': replacement for
          // X-Frame-Options. sandbox: disables scripts and other potentially
          // dangerous content from being executed.
          response.header(
              "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox");

          // Instructs the browser to always use the HTTPS version in future.
          // response.header("Strict-Transport-Security", "max-age=31536000");

          response.header("Server", "");
        });

    // Authentication.
    before(userController::authenticate);
    before(tokenController::validateToken);
    // Audit log.
    before(auditController::auditRequestStart);
    afterAfter(auditController::auditRequestEnd);

    // Reject unauthenticated requests before the login endpoint can be
    // accessed.
    before("/sessions", userController::requireAuthentication);
    post("/sessions", tokenController::login);
    delete("/sessions", tokenController::logout);

    before("/spaces", userController::requireAuthentication);
    post("/spaces", spaceController::create);

    before("/spaces/:spaceId/members", userController.requirePermission("POST", "rwd"));
    post("/spaces/:spaceId/members", spaceController::addMember);

    // before("/spaces/:spaceId/messages", userController.requirePermission("POST", "w"));
    // post("/spaces/:spaceId/messages", spaceController::postMessage);
    //
    // before("/spaces/:spaceId/messages/*", userController.requirePermission("GET", "r"));
    // get("/spaces/:spaceId/messages/:msgId", spaceController::readMessage);
    //
    // before("/spaces/:spaceId/messages", userController.requirePermission("GET", "r"));
    // get("/spaces/:spaceId/messages", spaceController::findMessages);
    //
    // before("/spaces/:spaceId/messages/*", userController.requirePermission("DELETE", "d"));
    // delete("/spaces/:spaceId/messages/:msgId", spaceController::deleteMessagea)

    post("/users", userController::register);
    // Insecured on purpose.
    get("/logs", auditController::readAuditLog);

    internalServerError(new JSONObject().put("error", "internal server error").toString());
    notFound(new JSONObject().put("error", "not found").toString());

    exception(IllegalArgumentException.class, App::badRequest);
    exception(JSONException.class, App::badRequest);
    exception(EmptyResultException.class, (e, request, response) -> response.status(404));
  }

  private static void createTables(Database database) throws Exception {
    var path = Paths.get(App.class.getResource("/schema.sql").toURI());
    database.update(Files.readString(path));
  }

  private static void badRequest(Exception ex, Request request, Response response) {
    response.status(400);
    response.body(new JSONObject().put("error", ex.getMessage()).toString());
  }
}

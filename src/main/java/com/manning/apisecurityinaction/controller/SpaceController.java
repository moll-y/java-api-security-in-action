package com.manning.apisecurityinaction.controller;

import java.sql.SQLException;
import org.dalesbred.Database;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

public class SpaceController {
  private final Database database;

  public SpaceController(Database database) {
    this.database = database;
  }

  public JSONObject create(Request request, Response response) throws SQLException {
    var json = new JSONObject(request.body());
    var spaceName = json.getString("name");
    if (spaceName.length() > 255) {
      throw new IllegalArgumentException("space name too long");
    }
    var owner = json.getString("owner");
    var subject = request.attribute("subject");
    if (!owner.equals(subject)) {
      throw new IllegalArgumentException("owner must match authenticated user");
    }

    if (!owner.matches("[a-zA-Z][a-zA-Z0-9]{1,29}")) {
      throw new IllegalArgumentException("invalid username");
    }

    return database.withTransaction(
        tx -> {
          var spaceId = database.findUniqueLong("SELECT NEXT VALUE FOR space_id_seq;");

          database.updateUnique(
              "INSERT INTO spaces(space_id, name, owner) VALUES(?, ?, ?);",
              spaceId,
              spaceName,
              owner);

          database.updateUnique(
              "INSERT INTO permissions(space_id, user_id, perms) VALUES(?, ?, ?);",
              spaceId,
              owner,
              "rwd");

          response.status(201);
          response.header("location", "/spaces" + spaceId);
          return new JSONObject().put("name", spaceName).put("uri", "/spaces/" + spaceId);
        });
  }

  public JSONObject addMember(Request request, Response response) {
    var json = new JSONObject(request.body());
    var spaceId = Long.parseLong(request.params(":spaceId"));
    var userToAdd = json.getString("username");
    var perms = json.getString("permissions");

    if (!perms.matches("r?w?d?")) {
      throw new IllegalArgumentException("invalid permissions");
    }

    database.updateUnique(
        "INSERT INTO permissions(space_id, user_id, perms) VALUES(?, ?, ?);",
        spaceId,
        userToAdd,
        perms);

    response.status(200);
    return new JSONObject().put("username", userToAdd).put("permissions", perms);
  }
}

const express = require('express');
const router = express.Router();
const Roles = require("../db/models/Roles")
const RolePrivileges = require("../db/models/RolePrivileges")
const Response = require("../lib/Response");
const CustomError = require('../lib/Error');
const Enum = require('../config/Enum');
const role_privileges = require("../config/role_privileges")
const auth = require("../lib/auth")();

router.all("*", auth.authenticate(), (res, req, next) => {
  next();
})

router.get("/", async (req, res) => {
  try {
    let roles = await Roles.find({});

    res.json(Response.succesResponse(roles));
  } catch (err) {
    let errorResponse = Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
  }
})

router.post("/add", async (req, res) => {
  let body = req.body;
  try {

    if (!body.role_name) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation error!", "role_name field must be filled")
    if (!body.permissions || !Array.isArray(body.permissions || body.permissions.length == 0)) {
      throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation error!", "permissions field must be an array")
    }
    let role = new Roles({
      role_name: body.role_name,
      is_active: true,
      created_by: req.user?.id
    })
    await role.save();

    for (let index = 0; index < body.permissions.length; index++) {
      let priv = new RolePrivileges({
        role_id: role._id,
        permission: body.permissions[index],
        created_by: req.user?.id
      })
      await priv.save();
    }

    res.json(Response.succesResponse({ success: true }));
  } catch (err) {
    let errorResponse = Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
  }
})

router.post("/update", async (req, res) => {
  let body = req.body;
  try {

    if (!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation error!", "role_name field must be filled")

    let updates = {}

    if (body.role_name) updates.role_name = body.role_name;
    if (typeof body.is_active === "boolean") updates.is_active = body.is_active;

    if (body.permissions && !Array.isArray(body.permissions && body.permissions.length > 0)) {
      let permissions = await RolePrivileges.find({ role_id: body._id })

      let removedPermissions = permissions.filter(x => !body.permissions.includes(x.permissions));
      let newPermissons = body.permissions.filter(x => !permissions.map(p => p.permissions).includes(x));

      if (removedPermissions.length > 0) {
        await RolePrivileges.deleteMany({ _id: { $in: removedPermissions.map(x => x._id) } });
      }

      if (newPermissons.length > 0) {
        for (let index = 0; index < newPermissons.length; index++) {
          let priv = new RolePrivileges({
            role_id: body._id,
            permission: newPermissons[index],
            created_by: req.user?.id
          });

          await priv.save();
        }
      }
    }


    await Roles.updateOne({ _id: body._id }, updates);

    res.json(Response.succesResponse({ success: true }));
  } catch (err) {
    let errorResponse = Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
  }
})

router.post("/delete", async (req, res) => {
  let body = req.body;
  try {

    if (!body._id) throw new CustomError(Enum.HTTP_CODES.BAD_REQUEST, "Validation error!", "role_name field must be filled")

    await Roles.deleteMany({ _id: body._id });

    res.json(Response.succesResponse({ success: true }));
  } catch (err) {
    let errorResponse = Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
  }
})

router.get("/role_privileges", async (req, res) => {
  res.json(role_privileges);
})

module.exports = router
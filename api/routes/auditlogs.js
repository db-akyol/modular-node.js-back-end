const express = require("express");
const AuditLogs = require("../db/models/AuditLogs");
const router = express.Router();
const Response = require("../lib/Response");
const moment = require("moment");
const auth = require("../lib/auth")();

router.all("*", auth.authenticate(), (res, req, next) => {
  next();
})

router.post("/", async (req, res) => {

  try {

    let body = req.body
    let query = {};
    let skip = body.skip;
    let limit = body.limit;

    if (typeof body.skip !== "number") {
      skip = 0;
    }

    if (typeof body.limit !== "number") {
      limit = 500;
    }

    if (body.begin_date && body.end_date) {
      query.created_at = {
        $gte: moment(body.begin_date),
        $lte: moment(body.end_date)
      }
    } else {
      query.created_at = {
        $gte: moment().subtract(1, "day").startOf("day"),
        $lte: moment()
      }
    }

    let auditLogs = await AuditLogs.find(query).sort({ created_at: -1 }).skip(skip).limit(limit);

    res.json(Response.succesResponse(auditLogs))

  } catch (err) {
    let errorResponse = Response.errorResponse(err);
    res.status(errorResponse.code).json(errorResponse);
  }
})

module.exports = router;
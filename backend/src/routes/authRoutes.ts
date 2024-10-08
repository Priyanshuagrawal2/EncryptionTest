import express from "express";
import {
  getCredentials,
  setCredentials,
  verifySignature,
} from "../controllers/authController";

const router = express.Router();

router.post("/get-credentials", getCredentials);
router.post("/set-credentials", setCredentials);
router.post("/verify-signature", verifySignature);

export default router;

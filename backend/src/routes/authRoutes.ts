import express from "express";
import {
  getCreds,
  setCreds,
  verifySignature,
} from "../controllers/authController";

const router = express.Router();

router.post("/get-creds", getCreds);
router.post("/set-creds", setCreds);
router.post("/verify-signature", verifySignature);

export default router;

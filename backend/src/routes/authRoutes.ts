import express from "express";
import * as authController from "../controllers/authController";

const router = express.Router();

// Existing routes
router.post("/get-credentials", authController.getCredentials);
router.post("/set-credentials", authController.setCredentials);
router.post("/verify-signature", authController.verifySignature);
router.post("/get-register-options", authController.getRegisterOptions);

// New OTP routes
router.post("/request-otp", authController.requestOTP);
router.post("/verify-otp", authController.verifyOTPAndCreateCredential);

export default router;

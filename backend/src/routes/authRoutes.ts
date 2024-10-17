import express from "express";
import * as authController from "../controllers/authController";

const router = express.Router();

// Existing routes
router.post("/register-credentials", authController.registerCredentials);
router.post("/verify-signature", authController.verifySignature);
router.post("/get-register-options", authController.getRegisterOptions);
router.post("/get-auth-options", authController.getAuthOptions);

// New OTP routes
router.post("/request-otp", authController.requestOTP);
router.post("/verify-otp", authController.verifyOTPAndCreateCredential);

export default router;

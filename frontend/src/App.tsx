import { arrayBufferToBase64, base64ToArrayBuffer } from "./util/util";
import { useEffect, useState } from "react";
import axios from "axios";
import OTPModal from "./components/OTPModal";
import urlJoin from "url-join";

export type UserCreds = {
  credentialId: string;
  publicKey: string;
  algorithm: string;
  transports: AuthenticatorTransport[];
};

const baseUrl = "http://localhost:3002";

function App() {
  const [status, setStatus] = useState<string>("");
  const [username, setUsername] = useState<string>("");
  const [email, setEmail] = useState<string>("");
  const [isOTPModalOpen, setIsOTPModalOpen] = useState(false);
  const [otpSent, setOtpSent] = useState(false);

  async function handleCreateCredential(challenge: string) {
    setStatus("Creating credential...");
    const publicKeyOptions: PublicKeyCredentialCreationOptions = {
      challenge: base64ToArrayBuffer(challenge),
      rp: { name: "Codilytics" },
      user: {
        id: Uint8Array.from(username, (c) => c.charCodeAt(0)),
        name: email,
        displayName: username,
      },

      pubKeyCredParams: [
        { alg: -7, type: "public-key" }, // ES256
        { alg: -257, type: "public-key" }, // RS256
      ],
      authenticatorSelection: {
        userVerification: "preferred",
        residentKey: "required",
        // authenticatorAttachment: "cross-platform",
      },
      attestation: "direct",
      timeout: 30000,
    };

    try {
      const credential = (await navigator.credentials.create({
        publicKey: publicKeyOptions,
      })) as any;
      const attestationResponse =
        credential.response as AuthenticatorAttestationResponse;
      const attestationAlgorithm = attestationResponse.getPublicKeyAlgorithm();
      const transports = (attestationResponse as any).getTransports?.() ?? [];
      const encodedCredentialId = arrayBufferToBase64(credential.rawId);
      const encodedPublicKey = arrayBufferToBase64(
        (
          credential.response as AuthenticatorAttestationResponse
        ).getPublicKey()!
      );

      const response = await fetch(urlJoin(baseUrl, "/auth/set-credentials"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userId: email,
          creds: {
            credentialId: encodedCredentialId,
            publicKey: encodedPublicKey,
            algorithm: attestationAlgorithm,
            transports: transports,
          },
        }),
      });

      setStatus(
        response.ok
          ? "Credential data sent to backend successfully"
          : "Failed to send credential data to backend"
      );
    } catch (error) {
      setStatus(`Error creating credential: ${error}`);
    }
  }

  async function handleGetCredential() {
    try {
      const response = await axios.post<{
        credentials: UserCreds[];
        challenge: string;
      }>(urlJoin(baseUrl, "/auth/get-credentials"), {
        userId: email,
      });

      const { credentials, challenge } = response.data;

      if (!credentials || !challenge) {
        handleRequestOTP();
        return;
      }
      const reorderTransports = (
        transports: AuthenticatorTransport[] = []
      ): AuthenticatorTransport[] => {
        if (transports.includes("internal")) {
          return ["internal", ...transports.filter((t) => t !== "internal")];
        }
        return transports;
      };

      const publicKeyOptions: PublicKeyCredentialRequestOptions = {
        challenge: base64ToArrayBuffer(challenge),
        allowCredentials: credentials.map((cred) => ({
          id: base64ToArrayBuffer(cred.credentialId),
          type: "public-key",
          transports: reorderTransports(cred.transports) ?? [
            "internal",
            "hybrid",
            "usb",
            "nfc",
            "ble",
          ],
        })),
        userVerification: "preferred",
      };
      const assertion = (await navigator.credentials.get({
        publicKey: publicKeyOptions,
      })) as PublicKeyCredential;
      const verificationResponse = await fetch(
        urlJoin(baseUrl, "/auth/verify-signature"),
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            userId: email,
            credentialId: assertion.id,
            clientDataJSON: arrayBufferToBase64(
              assertion.response.clientDataJSON
            ),
            authenticatorData: arrayBufferToBase64(
              (assertion.response as AuthenticatorAssertionResponse)
                .authenticatorData
            ),
            signature: arrayBufferToBase64(
              (assertion.response as AuthenticatorAssertionResponse).signature
            ),
          }),
        }
      );

      setStatus(
        verificationResponse.ok
          ? "Signature verified successfully"
          : "Failed to verify signature"
      );
    } catch (error: any) {
      console.log(error);
      setStatus(`Error: ${error.message}`);
      handleRequestOTP();
    }
  }

  async function handleRequestOTP() {
    try {
      const response = await axios.post(urlJoin(baseUrl, "/auth/request-otp"), {
        email,
      });
      if (response.data.success) {
        setStatus("OTP sent successfully. Please check your email.");
        setOtpSent(true);
        setIsOTPModalOpen(true);
      } else {
        setStatus("Failed to send OTP. Please try again.");
      }
    } catch (error: any) {
      setStatus(`Error: ${error.message}`);
    }
  }

  const handleOTPSubmit = async (otp: string) => {
    try {
      const response = await axios.post(urlJoin(baseUrl, "/auth/verify-otp"), {
        email,
        otp,
      });

      if (response.data.success) {
        setIsOTPModalOpen(false);
        setStatus("OTP verified successfully. Creating credential...");
        handleCreateCredential(response.data.challenge);
      } else {
        setStatus("Invalid OTP. Please try again.");
      }
    } catch (error: any) {
      setStatus(`Error: ${error.message}`);
    }
  };

  return (
    <div className="App">
      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <br />
      <input
        type="email"
        placeholder="Email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
      />
      <br />
      <button onClick={handleGetCredential}>Get Credential</button>
      <br />
      {otpSent && (
        <button onClick={() => setIsOTPModalOpen(true)}>Enter OTP</button>
      )}
      <p>{status}</p>
      <OTPModal
        isOpen={isOTPModalOpen}
        onClose={() => setIsOTPModalOpen(false)}
        onSubmit={handleOTPSubmit}
      />
    </div>
  );
}

export default App;

import { useState } from "react";
import axios from "axios";
import OTPModal from "./components/OTPModal";
import urlJoin from "url-join";
import { base64url } from "./util/base64url";
import {
  RegistrationCredential,
  RegistrationResponseJSON,
  AuthenticationCredential,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentialRequestOptions,
} from "@simplewebauthn/types";
import { getBrowserInfo, parseAuthenticationCredential } from "./util/util";

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

  async function handleCreateCredential() {
    setStatus("Creating credential...");
    const response = await axios.post(
      urlJoin(baseUrl, "/auth/get-register-options"),
      {
        username,
        userId: email,
      }
    );
    const { options } = response.data;

    const user = {
      ...options.user,
      id: base64url.decode(options.user.id),
    } as PublicKeyCredentialUserEntity;
    const challenge = base64url.decode(options.challenge);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(
        (cred: any) => ({
          id: base64url.decode(cred.id),
          type: "public-key",
          transports: cred.transports,
        })
      );
    }
    const decodedOptions = {
      ...options,
      user,
      challenge,
    } as PublicKeyCredentialCreationOptions;

    try {
      // Create a new attestation.
      const credential = (await navigator.credentials.create({
        publicKey: decodedOptions,
      })) as RegistrationCredential;
      const attestationResponse =
        credential.response as AuthenticatorAttestationResponse;
      const transports = (attestationResponse as any).getTransports?.() ?? [];
      const rawId = base64url.encode(credential.rawId);
      const clientDataJSON = base64url.encode(
        credential.response.clientDataJSON
      );
      const attestationObject = base64url.encode(
        credential.response.attestationObject
      );
      const clientExtensionResults: AuthenticationExtensionsClientOutputs = {};

      // if `getClientExtensionResults()` is supported, serialize the result.
      if (credential.getClientExtensionResults) {
        const extensions: AuthenticationExtensionsClientOutputs =
          credential.getClientExtensionResults();
        if (extensions.credProps) {
          clientExtensionResults.credProps = extensions.credProps;
        }
      }

      const encodedCredential = {
        id: credential.id,
        rawId,
        response: {
          clientDataJSON,
          attestationObject,
          transports,
        },
        type: credential.type,
        clientExtensionResults,
      } as RegistrationResponseJSON;

      const response = await fetch(urlJoin(baseUrl, "/auth/set-credentials"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: encodedCredential, userId: email }),
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
      const res = await axios.post(urlJoin(baseUrl, "/auth/get-auth-options"), {
        userId: email,
      });
      const { options } = res.data;

      options.challenge = base64url.decode(options.challenge);
      if (options.allowCredentials?.length) {
        // const browserInfo = getBrowserInfo(navigator.userAgent);
        options.allowCredentials = options.allowCredentials.map((cred: any) => {
          // if (
          //   browserInfo.browser == cred.browser &&
          //   browserInfo.os == cred.os
          // ) {
          return {
            id: base64url.decode(cred.id),
            type: "public-key",
            transports: cred.transports,
          };
          // }
        });
      } else {
        handleRequestOTP();
        return;
      }

      const decodedOptions = options as PublicKeyCredentialRequestOptions;

      const credential = (await navigator.credentials.get({
        publicKey: decodedOptions,
      })) as AuthenticationCredential;

      const rawId = base64url.encode(credential.rawId);
      const authenticatorData = base64url.encode(
        credential.response.authenticatorData
      );
      const clientDataJSON = base64url.encode(
        credential.response.clientDataJSON
      );
      const signature = base64url.encode(credential.response.signature);
      const userHandle = credential.response.userHandle
        ? base64url.encode(credential.response.userHandle)
        : undefined;
      const clientExtensionResults: AuthenticationExtensionsClientOutputs = {};

      if (credential.getClientExtensionResults) {
        const extensions: AuthenticationExtensionsClientOutputs =
          credential.getClientExtensionResults();
        if (extensions.credProps) {
          clientExtensionResults.credProps = extensions.credProps;
        }
      }

      const encodedCredential = {
        id: credential.id,
        rawId,
        response: {
          authenticatorData,
          clientDataJSON,
          signature,
          userHandle,
        },
        type: credential.type,
        clientExtensionResults,
      } as AuthenticationResponseJSON;

      const parsedCredential = await parseAuthenticationCredential(credential);

      // Verify and store the credential.
      const verificationResponse = await fetch(
        urlJoin(baseUrl, "/auth/verify-signature"),
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            credential: encodedCredential,
            userId: email,
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
        handleCreateCredential();
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

import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  WebAuthnAuthenticationObject,
  WebAuthnRegistrationObject,
  $,
} from "./util/util";
import { useEffect, useState } from "react";
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
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptions,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/types";

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
      urlJoin(baseUrl, "/auth/get-register-options")
    );
    const { options } = response.data;

    const user = {
      ...options.user,
      id: base64url.decode(options.user.id),
    } as PublicKeyCredentialUserEntity;
    const challenge = base64url.decode(options.challenge);

    const decodedOptions = {
      ...options,
      user,
      challenge,
    } as PublicKeyCredentialCreationOptions;

    console.log("[CredentialCreationOptions]", decodedOptions);
    // const publicKeyOptions: PublicKeyCredentialCreationOptions = {
    //   challenge: base64ToArrayBuffer(challenge),
    //   rp: { name: "Codilytics" },
    //   user: {
    //     id: Uint8Array.from(username, (c) => c.charCodeAt(0)),
    //     name: email,
    //     displayName: username,
    //   },

    //   pubKeyCredParams: [
    //     { alg: -7, type: "public-key" }, // ES256
    //     { alg: -257, type: "public-key" }, // RS256
    //   ],
    //   authenticatorSelection: {
    //     userVerification: "preferred",
    //     residentKey: "required",
    //     // authenticatorAttachment: "cross-platform",
    //   },
    //   attestation: "direct",
    //   timeout: 30000,
    // };

    try {
      // Create a new attestation.
      const credential = (await navigator.credentials.create({
        publicKey: decodedOptions,
      })) as RegistrationCredential;
      console.log(credential);
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
        body: JSON.stringify({ credential, userId: email }),
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
      // const response = await axios.post<{
      //   credentials: UserCreds[];
      //   challenge: string;
      // }>(urlJoin(baseUrl, "/auth/get-credentials"), {
      //   userId: email,
      // });

      // const { credentials } = response.data;
      // console.log(credentials);
      // if (!credentials) {
      //   handleRequestOTP();
      //   return;
      // }
      const reorderTransports = (
        transports: AuthenticatorTransport[] = []
      ): AuthenticatorTransport[] => {
        if (transports.includes("internal")) {
          return ["internal", ...transports.filter((t) => t !== "internal")];
        }
        return transports;
      };

      const res = await axios.post(urlJoin(baseUrl, "/auth/get-auth-options"), {
        userId: email,
      });
      const { options } = res.data;
      // const publicKeyOptions: PublicKeyCredentialRequestOptions = {
      //   challenge: base64ToArrayBuffer(challenge),
      //   allowCredentials: credentials.map((cred) => ({
      //     id: base64ToArrayBuffer(cred.credentialId),
      //     type: "public-key",
      //     transports: reorderTransports(cred.transports) ?? [
      //       "internal",
      //       "hybrid",
      //       "usb",
      //       "nfc",
      //       "ble",
      //     ],
      //   })),
      //   userVerification: "preferred",
      // };
      console.log({ options });
      const challenge = base64url.decode(options.challenge);
      if (options.allowCredentials?.length) {
        options.allowCredentials = options.allowCredentials.map(
          (cred: any) => ({
            id: base64url.decode(cred.id),
            type: "public-key",
            transports: cred.transports,
          })
        );
      }
      const decodedOptions = {
        ...options,

        // hints: opts.hints,
        challenge,
      } as PublicKeyCredentialRequestOptions;

      const credential = (await navigator.credentials.get({
        publicKey: decodedOptions,
      })) as AuthenticationCredential;
      // Encode the credential.
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
          authenticatorData,
          clientDataJSON,
          signature,
          userHandle,
        },
        type: credential.type,
        clientExtensionResults,
      } as AuthenticationResponseJSON;

      const parsedCredential = await parseAuthenticationCredential(credential);

      console.log("[AuthenticationResponseJSON]", parsedCredential);

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
      // const verificationResponse = await fetch(
      //   urlJoin(baseUrl, "/auth/verify-signature"),
      //   {
      //     method: "POST",
      //     headers: { "Content-Type": "application/json" },
      //     body: JSON.stringify({
      //       userId: email,
      //       credentialId: assertion.id,
      //       clientDataJSON: arrayBufferToBase64(
      //         assertion.response.clientDataJSON
      //       ),
      //       authenticatorData: arrayBufferToBase64(
      //         (assertion.response as AuthenticatorAssertionResponse)
      //           .authenticatorData
      //       ),
      //       signature: arrayBufferToBase64(
      //         (assertion.response as AuthenticatorAssertionResponse).signature
      //       ),
      //     }),
      //   }
      // );

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

  async function parseAuthenticationCredential(
    cred: AuthenticationCredential
  ): Promise<any> {
    const userHandle = cred.response.userHandle
      ? base64url.encode(cred.response.userHandle)
      : undefined;

    const credJSON = {
      id: cred.id,
      rawId: cred.id,
      type: cred.type,
      response: {
        clientDataJSON: {},
        authenticatorData: {},
        signature: base64url.encode(cred.response.signature),
        userHandle,
      },
      clientExtensionResults: {},
    };

    const decoder = new TextDecoder("utf-8");
    credJSON.response.clientDataJSON = JSON.parse(
      decoder.decode(cred.response.clientDataJSON)
    );
    credJSON.response.authenticatorData = await parseAuthenticatorData(
      new Uint8Array(cred.response.authenticatorData)
    );

    credJSON.clientExtensionResults = parseClientExtensionResults(cred);

    return credJSON;
  }

  async function parseAuthenticatorData(buffer: any): Promise<any> {
    const authData = {
      rpIdHash: "",
      flags: {
        up: false,
        uv: false,
        be: false,
        bs: false,
        at: false,
        ed: false,
      },
    };

    const rpIdHash = buffer.slice(0, 32);
    buffer = buffer.slice(32);
    authData.rpIdHash = [...rpIdHash]
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");

    const flags = buffer.slice(0, 1)[0];
    buffer = buffer.slice(1);
    authData.flags = {
      up: !!(flags & (1 << 0)),
      uv: !!(flags & (1 << 2)),
      be: !!(flags & (1 << 3)),
      bs: !!(flags & (1 << 4)),
      at: !!(flags & (1 << 6)),
      ed: !!(flags & (1 << 7)),
    };

    return authData;
  }

  function parseClientExtensionResults(
    credential: RegistrationCredential | AuthenticationCredential
  ): AuthenticationExtensionsClientOutputs {
    const clientExtensionResults: AuthenticationExtensionsClientOutputs = {};
    if (credential.getClientExtensionResults) {
      const extensions: AuthenticationExtensionsClientOutputs =
        credential.getClientExtensionResults();
      if (extensions.credProps) {
        clientExtensionResults.credProps = extensions.credProps;
      }
    }
    return clientExtensionResults;
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

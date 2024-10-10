import { arrayBufferToBase64, base64ToArrayBuffer } from "./util/util";
import { useEffect, useState } from "react";
import axios from "axios";

export type UserCreds = {
  credentialId: string;
  publicKey: string;
  algorithm: string;
  deviceName: string;
  transports: AuthenticatorTransport[];
};

function App() {
  const [status, setStatus] = useState<string>("");
  const [username, setUsername] = useState<string>("");
  const [email, setEmail] = useState<string>("");
  const [deviceName, setDeviceName] = useState<string>("");

  useEffect(() => {
    setDeviceName(localStorage.getItem("deviceName") || "");
  }, []);

  async function handleCreateCredential() {
    setStatus("Creating credential...");
    localStorage.setItem("deviceName", deviceName);
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));
    const publicKeyOptions: PublicKeyCredentialCreationOptions = {
      challenge,
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
      },
      attestation: "direct",
      timeout: 60000,
    };

    try {
      const credential = (await navigator.credentials.create({
        publicKey: publicKeyOptions,
      })) as any;
      const credentialJSON = credential.toJSON();
      const encodedCredentialId = arrayBufferToBase64(credential.rawId);
      const encodedPublicKey = arrayBufferToBase64(
        (
          credential.response as AuthenticatorAttestationResponse
        ).getPublicKey()!
      );
      console.log(credentialJSON);

      const response = await fetch(
        "https://76ae-103-176-134-214.ngrok-free.app/auth/set-credentials",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            userId: email,
            creds: {
              deviceName: deviceName,
              credentialId: encodedCredentialId,
              publicKey: encodedPublicKey,
              algorithm: credentialJSON.response.publicKeyAlgorithm,
              transports: credentialJSON.response.transports,
            },
          }),
        }
      );

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
      }>(
        "https://76ae-103-176-134-214.ngrok-free.app/auth/get-credentials",

        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          userId: email,
        }
      );

      const { credentials, challenge } = response.data;
      const credential = credentials.find(
        (cred: UserCreds) =>
          cred.deviceName === localStorage.getItem("deviceName")
      );

      if (!credential || !challenge) {
        return handleCreateCredential();
      }

      const publicKeyOptions: PublicKeyCredentialRequestOptions = {
        challenge: base64ToArrayBuffer(challenge),
        allowCredentials: [
          {
            id: base64ToArrayBuffer(credential.credentialId),
            type: "public-key",
            transports: credential.transports,
          },
        ],
        userVerification: "preferred",
      };
      const assertion = (await navigator.credentials.get({
        publicKey: publicKeyOptions,
      })) as PublicKeyCredential;

      const verificationResponse = await fetch(
        "https://76ae-103-176-134-214.ngrok-free.app/auth/verify-signature",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            userId: email,
            credentialId: credential.credentialId,
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
      return handleCreateCredential();
    }
  }
  return (
    <div className="App">
      <input
        type="text"
        placeholder="Device Name"
        value={deviceName}
        onChange={(e) => setDeviceName(e.target.value)}
      />
      <br />{" "}
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
      <p>{status}</p>
    </div>
  );
}

export default App;

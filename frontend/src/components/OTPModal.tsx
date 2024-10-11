import React, { useState } from "react";

interface OTPModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (otp: string) => void;
}

const OTPModal: React.FC<OTPModalProps> = ({ isOpen, onClose, onSubmit }) => {
  const [otp, setOtp] = useState("");

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(otp);
    setOtp("");
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <h2>Enter OTP</h2>
        <form onSubmit={handleSubmit}>
          <input
            type="text"
            value={otp}
            onChange={(e) => setOtp(e.target.value)}
            placeholder="Enter OTP"
            required
          />
          <button type="submit">Submit</button>
        </form>
        <button onClick={onClose}>Close</button>
      </div>
    </div>
  );
};

export default OTPModal;

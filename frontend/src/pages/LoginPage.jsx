// ========================
// frontend/src/pages/LoginPage.jsx (RSA Encrypted Login)
// ========================

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import JSEncrypt from 'jsencrypt';
import api, { authAPI } from '../services/api';

const SHIELD_ICON = '🛡️';

export default function LoginPage({ onLoginSuccess }) {
  const [step, setStep]         = useState(1);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp]           = useState('');
  const [email, setEmail]       = useState('');
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState('');

  const navigate = useNavigate();

  // Tự động xóa thông báo lỗi sau 5 giây
  useEffect(() => {
    if (error) {
      const timer = setTimeout(() => setError(''), 5000);
      return () => clearTimeout(timer);
    }
  }, [error]);

  // ======== Bước 1: Đăng nhập & Gửi OTP (Có mã hóa RSA) ========
  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    if (loading) return;

    setError('');
    setLoading(true);

    try {
      // 1. Lấy Public Key từ Backend
      const pubKeyRes = await api.get('/auth/public-key');
      const publicKey = pubKeyRes.data.public_key;

      if (!publicKey) {
        throw new Error("Không lấy được khóa bảo mật từ máy chủ");
      }

      // 2. Mã hóa mật khẩu bằng JSEncrypt (Chuẩn PKCS1v15 tương thích với Python)
      const encryptor = new JSEncrypt();
      encryptor.setPublicKey(publicKey);
      const encryptedPassword = encryptor.encrypt(password);

      if (!encryptedPassword) {
        throw new Error("Mã hóa mật khẩu thất bại");
      }

      // 3. Gửi mật khẩu đã mã hóa lên API login
      const res = await authAPI.login(
        { username, password: encryptedPassword },
        { timeout: 60000 }
      );

      if (res.data && res.data.email) {
        setEmail(res.data.email);
        setStep(2);
      }
    } catch (err) {
      console.error("Login Error:", err.response?.data || err.message);
      if (err.code === 'ECONNABORTED') {
        setError('Hệ thống gửi OTP hơi chậm, vui lòng thử lại sau giây lát');
      } else {
        setError(err.response?.data?.detail || err.message || 'Tên đăng nhập hoặc mật khẩu không đúng');
      }
    } finally {
      setLoading(false);
    }
  };

  // ======== Bước 2: Xác minh OTP ========
  const handleVerifyOTP = async (e) => {
    e.preventDefault();
    if (loading) return;

    setError('');
    setLoading(true);
    try {
      const res = await api.post('/auth/verify-otp', {
        email: email,
        otp_code: otp
      });

      const token = res.data.access_token;

      localStorage.setItem('access_token', token);
      localStorage.setItem('user', JSON.stringify({
        id: res.data.user_id,
        username: res.data.username
      }));

      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;

      onLoginSuccess();

    } catch (err) {
      console.error("OTP Error:", err.response?.data);
      setError(err.response?.data?.detail || 'Mã OTP không đúng hoặc đã hết hạn');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.bgOverlay} />

      <div style={styles.card}>
        <div style={styles.logoArea}>
          <div style={styles.logoIcon}>{SHIELD_ICON}</div>
          <h1 style={styles.logoText}>CyberMail Shield</h1>
          <p style={styles.logoSub}>Hệ thống Bảo mật AI 2026</p>
        </div>

        <div style={styles.stepIndicator}>
          <div style={{ ...styles.step, ...(step >= 1 ? styles.stepActive : {}) }}>
            <span style={{ ...styles.stepNum, ...(step >= 1 ? styles.stepNumActive : {}) }}>1</span>
            <span style={styles.stepLabel}>Xác thực</span>
          </div>
          <div style={styles.stepLine} />
          <div style={{ ...styles.step, ...(step >= 2 ? styles.stepActive : {}) }}>
            <span style={{ ...styles.stepNum, ...(step >= 2 ? styles.stepNumActive : {}) }}>2</span>
            <span style={styles.stepLabel}>Mã OTP</span>
          </div>
        </div>

        {error && <div style={styles.errorBox}>⚠️️ {error}</div>}

        {step === 1 ? (
          <>
            <form onSubmit={handleLogin} style={styles.form}>
              <div style={styles.inputGroup}>
                <label style={styles.label}>Tên đăng nhập</label>
                <input
                  style={styles.input}
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  required
                  autoFocus
                />
              </div>
              <div style={styles.inputGroup}>
                <label style={styles.label}>Mật khẩu (Bảo mật RSA)</label>
                <input
                  style={styles.input}
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                />
              </div>
              <button type="submit" style={styles.btn} disabled={loading}>
                {loading ? '⏳ Đang mã hóa & Gửi...' : '🔐 Đăng nhập & Gửi OTP'}
              </button>
            </form>

            <div style={styles.registerPrompt}>
              Chưa có tài khoản?{' '}
              <span style={styles.link} onClick={() => navigate('/register')}>
                Đăng ký ngay
              </span>
            </div>
          </>
        ) : (
          <form onSubmit={handleVerifyOTP} style={styles.form}>
            <div style={styles.otpInfo}>
              Gửi đến: <strong>{email}</strong>
            </div>
            <div style={styles.inputGroup}>
              <label style={styles.label}>Mã OTP 6 số</label>
              <input
                style={{...styles.input, ...styles.otpInput}}
                type="text"
                placeholder="000000"
                value={otp}
                onChange={e => setOtp(e.target.value.replace(/\D/g,'').slice(0,6))}
                required
                autoFocus
              />
            </div>
            <button type="submit" style={styles.btn} disabled={loading || otp.length < 6}>
              {loading ? '⏳ Đang xác minh...' : '✅ Xác nhận OTP'}
            </button>
            <button type="button" style={styles.btnSecondary} onClick={() => setStep(1)}>
              ← Quay lại
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

// ==========================================
// CSS STYLESHEET (LIGHT THEME LIKE IMAGE 2)
// ==========================================
const styles = {
  container: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#f8fafc',
    backgroundImage: `
      linear-gradient(to right, rgba(226, 232, 240, 0.6) 1px, transparent 1px),
      linear-gradient(to bottom, rgba(226, 232, 240, 0.6) 1px, transparent 1px)
    `,
    backgroundSize: '24px 24px',
    fontFamily: "'Segoe UI', Roboto, sans-serif",
    position: 'relative',
    overflow: 'hidden'
  },
  bgOverlay: {
    position: 'absolute',
    inset: 0,
    pointerEvents: 'none'
  },
  card: {
    background: '#ffffff',
    border: '1.5px solid #2563eb',
    borderRadius: '16px',
    padding: '40px 48px',
    width: '420px',
    position: 'relative',
    zIndex: 1,
    boxShadow: '0 10px 25px -5px rgba(37, 99, 235, 0.08), 0 8px 10px -6px rgba(0, 0, 0, 0.04)'
  },
  logoArea: {
    textAlign: 'center',
    marginBottom: '24px'
  },
  logoIcon: {
    fontSize: '48px',
    marginBottom: '8px'
  },
  logoText: {
    color: '#0f172a',
    fontSize: '24px',
    fontWeight: '800',
    margin: '0 0 4px',
    letterSpacing: '-0.5px'
  },
  logoSub: {
    color: '#64748b',
    fontSize: '13px',
    margin: 0
  },
  stepIndicator: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: '24px',
    gap: '12px'
  },
  step: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    opacity: 0.5,
    transition: '0.3s'
  },
  stepActive: {
    opacity: 1
  },
  stepNum: {
    width: '28px',
    height: '28px',
    borderRadius: '50%',
    background: '#e2e8f0',
    color: '#64748b',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '13px',
    fontWeight: 700,
    marginBottom: '4px'
  },
  stepNumActive: {
    background: '#2563eb',
    color: '#ffffff'
  },
  stepLabel: {
    color: '#2563eb',
    fontSize: '12px',
    fontWeight: '600'
  },
  stepLine: {
    width: '50px',
    height: '1px',
    background: '#e2e8f0',
    marginTop: '-16px'
  },
  errorBox: {
    background: '#fef2f2',
    border: '1px solid #fecaca',
    borderRadius: '8px',
    padding: '10px 14px',
    color: '#dc2626',
    fontSize: '13px',
    marginBottom: '16px',
    textAlign: 'center'
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px'
  },
  inputGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '6px'
  },
  label: {
    color: '#334155',
    fontSize: '13px',
    fontWeight: '600'
  },
  input: {
    background: '#eff6ff',
    border: '1px solid #dbeafe',
    borderRadius: '8px',
    padding: '12px 16px',
    color: '#1e293b',
    fontSize: '14px',
    outline: 'none',
    transition: 'all 0.2s',
  },
  otpInput: {
    fontSize: '24px',
    letterSpacing: '12px',
    textAlign: 'center',
    fontWeight: '700'
  },
  otpInfo: {
    background: '#f0fdf4',
    border: '1px solid #bbf7d0',
    borderRadius: '8px',
    padding: '12px 14px',
    color: '#166534',
    fontSize: '13px',
    textAlign: 'center',
    lineHeight: 1.6
  },
  btn: {
    background: '#2563eb',
    color: '#ffffff',
    border: 'none',
    borderRadius: '8px',
    padding: '13px',
    fontSize: '14px',
    fontWeight: '700',
    cursor: 'pointer',
    transition: 'background 0.2s, transform 0.1s',
    marginTop: '4px'
  },
  btnSecondary: {
    background: '#ffffff',
    color: '#64748b',
    border: '1px solid #cbd5e1',
    borderRadius: '8px',
    padding: '10px',
    fontSize: '13px',
    fontWeight: '600',
    cursor: 'pointer'
  },
  registerPrompt: {
    marginTop: '20px',
    textAlign: 'center',
    fontSize: '13px',
    color: '#64748b'
  },
  link: {
    color: '#2563eb',
    fontWeight: '700',
    cursor: 'pointer',
    textDecoration: 'none',
    marginLeft: '4px'
  }
};
import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { authAPI } from '../services/api';

const Register = () => {
    const [formData, setFormData] = useState({
        username: '',
        email: '',
        password: '',
        confirmPassword: ''
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        // Validate cơ bản
        if (formData.password !== formData.confirmPassword) {
            return setError("Mật khẩu xác nhận không khớp!");
        }

        setLoading(true);
        try {
            await authAPI.register({
                username: formData.username,
                email: formData.email,
                password: formData.password,
                role: 'staff' // Mặc định là staff
            });
            // Đăng ký xong thì nhảy sang trang Login
            alert("Đăng ký thành công! Vui lòng đăng nhập.");
            navigate('/login');
        } catch (err) {
            setError(err.response?.data?.detail || "Đăng ký thất bại, vui lòng thử lại.");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={styles.container}>
            <div style={styles.card}>
                <h2 style={styles.title}>🛡️ CyberMail - Register</h2>
                <p style={styles.subtitle}>Tạo tài khoản để bảo vệ Email của bạn</p>

                {error && <div style={styles.error}>{error}</div>}

                <form onSubmit={handleSubmit}>
                    <div style={styles.inputGroup}>
                        <label style={styles.label}>Username</label>
                        <input
                            type="text"
                            name="username"
                            value={formData.username}
                            onChange={handleChange}
                            style={styles.input}
                            required
                        />
                    </div>

                    <div style={styles.inputGroup}>
                        <label style={styles.label}>Email</label>
                        <input
                            type="email"
                            name="email"
                            value={formData.email}
                            onChange={handleChange}
                            style={styles.input}
                            required
                        />
                    </div>

                    <div style={styles.inputGroup}>
                        <label style={styles.label}>Password</label>
                        <input
                            type="password"
                            name="password"
                            value={formData.password}
                            onChange={handleChange}
                            style={styles.input}
                            required
                        />
                    </div>

                    <div style={styles.inputGroup}>
                        <label style={styles.label}>Confirm Password</label>
                        <input
                            type="password"
                            name="confirmPassword"
                            value={formData.confirmPassword}
                            onChange={handleChange}
                            style={styles.input}
                            required
                        />
                    </div>

                    <button type="submit" disabled={loading} style={styles.button}>
                        {loading ? 'Đang xử lý...' : 'Đăng ký tài khoản'}
                    </button>
                </form>

                <div style={styles.footer}>
                    Đã có tài khoản? <Link to="/login" style={styles.link}>Đăng nhập ngay</Link>
                </div>
            </div>
        </div>
    );
};

const styles = {
    container: { height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: '#f8fafc', color: '#1e293b', fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif' },
    card: { width: '400px', padding: '40px', backgroundColor: '#ffffff', borderRadius: '12px', border: '1px solid #e2e8f0', boxShadow: '0 8px 24px rgba(0,0,0,0.06)' },
    title: { textAlign: 'center', marginBottom: '10px', color: '#2563eb', fontWeight: 800 },
    subtitle: { textAlign: 'center', color: '#64748b', marginBottom: '30px', fontSize: '14px' },
    inputGroup: { marginBottom: '20px' },
    label: { display: 'block', marginBottom: '8px', fontSize: '14px', color: '#334155', fontWeight: 600 },
    input: { width: '100%', padding: '12px', borderRadius: '6px', border: '1px solid #cbd5e1', backgroundColor: '#ffffff', color: '#0f172a', boxSizing: 'border-box', outline: 'none' },
    button: { width: '100%', padding: '12px', borderRadius: '6px', border: 'none', backgroundColor: '#16a34a', color: 'white', fontWeight: 'bold', cursor: 'pointer', marginTop: '10px', transition: '0.2s' },
    error: { backgroundColor: '#fef2f2', color: '#dc2626', padding: '10px', borderRadius: '6px', marginBottom: '20px', border: '1px solid #fecaca', fontSize: '13px' },
    footer: { textAlign: 'center', marginTop: '20px', fontSize: '14px', color: '#64748b' },
    link: { color: '#2563eb', textDecoration: 'none', marginLeft: '5px', fontWeight: 600 }
};

export default Register;
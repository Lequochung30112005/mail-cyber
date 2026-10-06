import React, { useState } from 'react';
import { emailAPI } from '../services/api';

export default function EmailTester() {
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleTest = async () => {
    if (!body.trim()) return alert("Vui lòng nhập nội dung email!");

    setLoading(true);
    try {
      const res = await emailAPI.predictSpam({ subject, body });

      // Xử lý linh hoạt dữ liệu trả về từ API (phòng hờ axios bọc hay không bọc .data)
      const raw = res.data ? res.data : res;

      // Chuẩn hóa dữ liệu số, mảng và giữ lại url_details từ backend
      const resultData = {
        spam_score: Number(raw.spam_score || 0),
        phishing_score: Number(raw.phishing_score || 0),
        risk_level: raw.risk_level || 'safe',
        top_keywords: raw.top_keywords || [],
        url_details: raw.url_details || []
      };

      setResult(resultData);

    } catch (err) {
      console.error(err);
      alert("Lỗi kết nối đến máy chủ phân tích!");
    } finally {
      setLoading(false);
    }
  };

  // Logic hiển thị nhãn cảnh báo dựa trên Risk Level từ Backend
  const getRiskColor = (level) => {
    if (level === 'dangerous') return '#ff4d4f';
    if (level === 'suspicious') return '#faad14';
    return '#52c41a';
  };

  return (
    <div style={styles.container}>
      <h2 style={{ color: '#58a6ff', display: 'flex', alignItems: 'center', gap: '10px' }}>
        🧪 Email Safety Lab (AI Edition)
      </h2>
      <p style={{ color: '#8b949e' }}>
        Phân tích sâu nội dung bằng mô hình SVM-HHO để phát hiện Spam và Phishing.
      </p>

      <div style={styles.inputGroup}>
        <input
          placeholder="Tiêu đề email (không bắt buộc)..."
          style={styles.input}
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
        />
        <textarea
          placeholder="Dán nội dung email hoặc mã HTML vào đây..."
          style={{ ...styles.input, height: '220px', resize: 'none' }}
          value={body}
          onChange={(e) => setBody(e.target.value)}
        />
        <button
          style={{ ...styles.testBtn, opacity: loading ? 0.7 : 1 }}
          onClick={handleTest}
          disabled={loading}
        >
          {loading ? '⏳ AI ĐANG BÓC TÁCH DỮ LIỆU...' : '🚀 BẮT ĐẦU PHÂN TÍCH'}
        </button>
      </div>

      {result && (
        <div style={{ ...styles.resultBox, borderColor: getRiskColor(result.risk_level) }}>
          <h3 style={{ margin: '0 0 20px 0', color: '#fff' }}>🛡️ Kết quả phân tích AI:</h3>

          {/* Thanh tỉ lệ SPAM */}
          <div style={styles.resItem}>
            <span style={styles.label}>Tỉ lệ Spam:</span>
            <div style={styles.progressBg}>
              <div style={{
                ...styles.progressFill,
                width: `${result.spam_score}%`,
                background: result.spam_score > 50 ? '#ff4d4f' : '#faad14'
              }}></div>
            </div>
            <span style={styles.percentText}>{result.spam_score.toFixed(1)}%</span>
          </div>

          {/* Thanh tỉ lệ PHISHING */}
          <div style={styles.resItem}>
            <span style={styles.label}>Tỉ lệ Phishing:</span>
            <div style={styles.progressBg}>
              <div style={{
                ...styles.progressFill,
                width: `${result.phishing_score}%`,
                background: result.phishing_score > 50 ? '#ff4d4f' : '#faad14'
              }}></div>
            </div>
            <span style={styles.percentText}>{result.phishing_score.toFixed(1)}%</span>
          </div>

          <div style={{ ...styles.badge, backgroundColor: getRiskColor(result.risk_level) }}>
             Mức độ rủi ro: {result.risk_level?.toUpperCase()}
          </div>

          <div style={styles.keywordSection}>
            <p style={{ fontSize: '14px', color: '#8b949e', marginBottom: '8px' }}>Từ khóa đáng ngờ:</p>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {result.top_keywords.length > 0 ? (
                result.top_keywords.map((kw, i) => (
                  <span key={i} style={styles.tag}>{kw}</span>
                ))
              ) : (
                <span style={{ fontSize: '13px', color: '#8b949e', fontStyle: 'italic' }}>Không phát hiện từ khóa đáng ngờ cụ thể.</span>
              )}
            </div>
          </div>

          {/* HIỂN THỊ CHI TIẾT URL & VIRUSTOTAL */}
          {result.url_details && result.url_details.length > 0 && (
            <div style={{ marginTop: '20px', borderTop: '1px solid #30363d', paddingTop: '15px' }}>
              <p style={{ fontSize: '14px', color: '#8b949e', marginBottom: '10px' }}>🔗 Phân tích Liên kết (URL) & Bảo mật:</p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {result.url_details.map((item, idx) => {
                  const vt = item.details?.virustotal;
                  const features = item.details?.features;
                  return (
                    <div key={idx} style={{ background: '#161b22', border: '1px solid #30363d', padding: '12px', borderRadius: '8px', fontSize: '13px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <a href={item.url} target="_blank" rel="noreferrer" style={{ color: '#58a6ff', textDecoration: 'none', fontWeight: '600', wordBreak: 'break-all' }}>
                          🌐 {item.url}
                        </a>
                        <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold', background: item.is_malicious ? 'rgba(255, 77, 79, 0.2)' : 'rgba(82, 196, 26, 0.2)', color: item.is_malicious ? '#ff4d4f' : '#52c41a' }}>
                          {item.is_malicious ? `Nguy hiểm (${item.threat_source || 'Phát hiện'})` : 'An toàn'}
                        </span>
                      </div>

                      {features && features.suspicious_score > 0 && (
                        <div style={{ marginTop: '6px', fontSize: '12px', color: '#faad14', background: 'rgba(250, 173, 20, 0.1)', padding: '4px 8px', borderRadius: '4px' }}>
                          ⚠️ Heuristic Score: <b>{features.suspicious_score} điểm</b> nghi ngờ
                        </div>
                      )}

                      {vt && vt.vt_checked && (
                        <div style={{ marginTop: '6px', fontSize: '12px', color: '#8b949e', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#0d1117', padding: '6px 8px', borderRadius: '4px', border: '1px solid #30363d' }}>
                          <span>🛡️ VirusTotal: <b style={{ color: vt.vt_malicious > 0 ? '#ff4d4f' : '#52c41a' }}>{vt.vt_malicious} / {vt.vt_total}</b> cờ độc hại</span>
                          {vt.vt_permalink && (
                            <a href={vt.vt_permalink} target="_blank" rel="noreferrer" style={{ color: '#58a6ff', textDecoration: 'underline', fontSize: '11px' }}>
                              Xem chi tiết ↗
                            </a>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <p style={{
            marginTop: '20px',
            color: getRiskColor(result.risk_level),
            fontWeight: 'bold',
            padding: '10px',
            borderLeft: `4px solid ${getRiskColor(result.risk_level)}`,
            background: 'rgba(255,255,255,0.05)'
          }}>
            {result.risk_level === 'dangerous'
              ? '⚠️ CẢNH BÁO: Email chứa dấu hiệu lừa đảo chiếm đoạt tài sản hoặc mã độc!'
              : result.risk_level === 'suspicious'
              ? '🧐 CHÚ Ý: Nội dung có dấu hiệu quảng cáo rác hoặc chưa rõ nguồn gốc.'
              : '✅ AN TOÀN: Email có vẻ hợp lệ để gửi đi.'}
          </p>
        </div>
      )}
    </div>
  );
}

const styles = {
  container: { padding: '40px', background: '#0d1117', minHeight: '100vh', color: '#fff', fontFamily: 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif' },
  inputGroup: { display: 'flex', flexDirection: 'column', gap: '15px', maxWidth: '850px', marginTop: '20px' },
  input: { background: '#161b22', border: '1px solid #30363d', borderRadius: '8px', padding: '15px', color: '#fff', fontSize: '15px', outline: 'none', transition: '0.3s' },
  testBtn: { background: '#238636', color: '#fff', border: 'none', padding: '15px', borderRadius: '8px', cursor: 'pointer', fontWeight: 'bold', fontSize: '16px', transition: '0.3s' },
  resultBox: { marginTop: '30px', background: '#1c2128', padding: '25px', borderRadius: '12px', border: '2px solid #30363d', maxWidth: '850px' },
  resItem: { display: 'flex', alignItems: 'center', gap: '15px', marginBottom: '15px' },
  label: { width: '120px', color: '#8b949e', fontSize: '14px' },
  percentText: { width: '65px', textAlign: 'right', fontWeight: 'bold' },
  progressBg: { flex: 1, background: '#30363d', height: '10px', borderRadius: '10px', overflow: 'hidden' },
  progressFill: { height: '100%', transition: '1s ease-in-out' },
  badge: { display: 'inline-block', padding: '4px 12px', borderRadius: '20px', fontSize: '12px', fontWeight: 'bold', marginBottom: '15px' },
  keywordSection: { marginTop: '15px', borderTop: '1px solid #30363d', paddingTop: '15px' },
  tag: { background: '#30363d', padding: '4px 10px', borderRadius: '4px', fontSize: '12px', color: '#58a6ff' }
};
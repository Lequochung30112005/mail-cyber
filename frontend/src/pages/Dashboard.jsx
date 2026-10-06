import React, { useState, useEffect, useCallback } from 'react';
import { emailAPI, reportAPI, downloadFile } from '../services/api';
import BlacklistPage from './BlacklistPage'; // <--- IMPORT TRANG QUẢN LÝ BLACKLIST/WHITELIST

// --- HỆ THỐNG BIỂU ĐỒ ---
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend,
  CategoryScale, LinearScale, BarElement, Title,
} from 'chart.js';
import ChartDataLabels from 'chartjs-plugin-datalabels'; // <--- 1. IMPORT PLUGIN DATALABELS
import { Pie } from 'react-chartjs-2';

// Đăng ký plugin với ChartJS
ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title, ChartDataLabels);

const RISK_CONFIG = {
  safe: { label: 'An toàn', color: '#28a745', icon: '✅' },
  suspicious: { label: 'Nghi ngờ', color: '#ffc107', icon: '⚠️' },
  dangerous: { label: 'Nguy hiểm', color: '#dc3545', icon: '🔴' },
};

// Danh sách từ khóa dự phòng nếu email không trả về mảng top_keywords riêng
const FALLBACK_KEYWORDS = [
  'urgent', 'compromised', 'action required', 'password', 'verify',
  'account', 'security', 'login', 'click here', 'suspended', 'immediately',
  'mật khẩu', 'tài khoản', 'khẩn cấp', 'xác thực', 'cảnh báo', 'bảo mật'
];

export default function Dashboard() {
  // --- STATES HỆ THỐNG ---
  const [stats, setStats] = useState({ total: 0, safe: 0, suspicious: 0, dangerous: 0 });
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard'); // Có thể là: 'dashboard', 'history', 'tester', 'lists'
  const [page, setPage] = useState(1);
  const [totalItems, setTotalItems] = useState(0);
  const [filterRisk, setFilterRisk] = useState('');

  // --- STATES LAB TEST ---
  const [testSubject, setTestSubject] = useState('');
  const [testBody, setTestBody] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [isTesting, setIsTesting] = useState(false);

  // --- STATES MODALS & CONFIG ---
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [appPassword, setAppPassword] = useState('');
  const [configLoading, setConfigLoading] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [scanning, setScanning] = useState(false);

  // --- STATES XUẤT BÁO CÁO & DATASET ---
  const [showPreview, setShowPreview] = useState(false);
  const [previewData, setPreviewData] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [excelLoading, setExcelLoading] = useState(false);

  // --- TẢI DỮ LIỆU ---
  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const [statsRes, emailRes] = await Promise.all([
        emailAPI.getStats(),
        emailAPI.getHistory(page, '', filterRisk)
      ]);

      const rawStats = statsRes.data;
      const parsedStats = rawStats.summary || rawStats;
      setStats(parsedStats);

      setEmails(emailRes.data.data || []);
      setTotalItems(emailRes.data.total || 0);
    } catch (err) {
      console.error('Lỗi tải dữ liệu:', err);
    } finally { setLoading(false); }
  }, [page, filterRisk]);

  useEffect(() => { loadData(); }, [loadData]);

  // --- XỬ LÝ CHI TIẾT EMAIL ---
  const handleViewDetail = async (id) => {
    try {
      const res = await emailAPI.getDetail(id);
      setSelectedEmail(res.data);
      setShowModal(true);
    } catch (err) { alert("Không lấy được nội dung email!"); }
  };

  // --- HÀM HIGHLIGHT TỪ KHÓA MÔ HÌNH PHÁT HIỆN TRONG NỘI DUNG ---
  const renderHighlightedBody = (text, keywordsList) => {
    if (!text) return "Nội dung email không có dữ liệu.";

    const activeKeywords = (keywordsList && keywordsList.length > 0) ? keywordsList : FALLBACK_KEYWORDS;
    const escapedKeywords = activeKeywords.map(kw => kw.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&'));
    if (escapedKeywords.length === 0) return text;

    const regex = new RegExp(`(${escapedKeywords.join('|')})`, 'gi');
    const parts = text.split(regex);

    return parts.map((part, index) => {
      const isMatch = activeKeywords.some(kw => kw.toLowerCase() === part.toLowerCase());
      if (isMatch) {
        return (
          <mark key={index} style={{ backgroundColor: '#fee2e2', color: '#dc3545', padding: '2px 4px', borderRadius: '4px', fontWeight: 'bold' }} title="Từ khóa rủi ro phát hiện bởi AI Model">
            {part}
          </mark>
        );
      }
      return part;
    });
  };

  // --- QUÉT GMAIL ---
  const handleFetchAndScan = async () => {
    setScanning(true);
    try {
      await emailAPI.fetchAndAnalyze(20);
      alert("Hệ thống đang kết nối và quét Gmail...");
      setTimeout(() => loadData(), 5000);
    } catch (err) {
      if (err.response?.status === 400) setShowConfigModal(true);
      else alert("Lỗi khi quét email mới!");
    } finally { setScanning(false); }
  };

  // --- LAB TEST ---
  const handleManualTest = async () => {
    if (!testBody.trim()) return alert("Vui lòng nhập nội dung!");
    setIsTesting(true);
    try {
      const res = await emailAPI.predictSpam({ subject: testSubject, body: testBody });
      const resultData = res.data ? res.data : res;
      setTestResult(resultData);
    } catch (err) {
      console.error(err);
      alert("Lỗi kết nối AI Engine!");
    } finally { setIsTesting(false); }
  };

  // --- LƯU CẤU HÌNH IMAP ---
  const handleSaveConfig = async () => {
    if (appPassword.length < 16) return alert("App Password phải đủ 16 ký tự!");
    setConfigLoading(true);
    try {
      await emailAPI.configImap(appPassword);
      setShowConfigModal(false);
      handleFetchAndScan();
    } catch (err) { alert("Lỗi cấu hình mật khẩu ứng dụng!"); }
    finally { setConfigLoading(false); }
  };

  // --- XỬ LÝ BÁO CÁO PDF ---
  const handleOpenReportPreview = async () => {
    setReportLoading(true);
    try {
      const res = await reportAPI.getPreview();
      setPreviewData(res.data);
      setShowPreview(true);
    } catch (err) {
      alert("Không thể tải bản xem trước báo cáo!");
    } finally { setReportLoading(false); }
  };

  const handleDownloadPDF = async () => {
    try {
      const response = await reportAPI.downloadPDF();
      downloadFile(response, `CyberReport_${new Date().getTime()}.pdf`);
      setShowPreview(false);
    } catch (err) { alert("Lỗi khi tải PDF!"); }
  };

  const handleDownloadExcel = async () => {
    setExcelLoading(true);
    try {
      const response = await reportAPI.downloadExcel();
      if (response && response.data) {
        downloadFile(response, `CyberDataset_${new Date().getTime()}.xlsx`);
      } else {
        alert("Dữ liệu trả về không hợp lệ!");
      }
    } catch (err) {
      console.error("Excel Download Error:", err);
      alert("Lỗi khi trích xuất Dataset Excel!");
    } finally { setExcelLoading(false); }
  };

  // --- CẤU HÌNH BIỂU ĐỒ TRÒN & TỶ LỆ % ---
  const pieData = {
    labels: ['An toàn', 'Nghi ngờ', 'Nguy hiểm'],
    datasets: [{
      data: stats && stats.total > 0 ? [
        ((stats.safe / stats.total) * 100).toFixed(1),
        ((stats.suspicious / stats.total) * 100).toFixed(1),
        ((stats.dangerous / stats.total) * 100).toFixed(1)
      ] : [0, 0, 0],
      backgroundColor: ['#28a745', '#ffc107', '#dc3545'],
      borderWidth: 0
    }]
  };

  const pieOptions = {
    plugins: {
      legend: {
        position: 'bottom',
      },
      datalabels: {
        color: '#ffffff',
        font: {
          weight: 'bold',
          size: 13,
        },
        formatter: (value) => {
          if (value == 0) return '';
          return value + '%';
        },
      },
    },
  };

  return (
    <div style={styles.layout}>
      {/* SIDEBAR */}
      <aside style={styles.sidebar}>
        <div style={styles.sidebarLogo}>🛡️ CyberMail AI</div>
        <nav style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
          <button style={{ ...styles.navBtn, ...(activeTab === 'dashboard' ? styles.navBtnActive : {}) }} onClick={() => setActiveTab('dashboard')}>📊 Thống kê</button>
          <button style={{ ...styles.navBtn, ...(activeTab === 'history' ? styles.navBtnActive : {}) }} onClick={() => { setActiveTab('history'); setPage(1); }}>📋 Nhật ký quét</button>

          {/* NÚT TRUY CẬP TRANG QUẢN LÝ BLACK/WHITELIST */}
          <button style={{ ...styles.navBtn, ...(activeTab === 'lists' ? styles.navBtnActive : {}), color: '#38bdf8' }} onClick={() => setActiveTab('lists')}>
            🛡️ Quản lý Danh Sách
          </button>

          <button style={{ ...styles.navBtn, ...(activeTab === 'tester' ? styles.navBtnActive : {}), color: '#a371f7' }} onClick={() => setActiveTab('tester')}>🧪 Lab Phân Tích</button>
        </nav>
        <div style={{ marginTop: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <button style={{ ...styles.navBtn, color: '#475569' }} onClick={() => setShowConfigModal(true)}>⚙️ Cấu hình IMAP</button>
          <button style={{ ...styles.navBtn, color: '#475569' }} onClick={handleOpenReportPreview} disabled={reportLoading}>📄 {reportLoading ? 'Đang phân tích...' : 'Xuất Báo Cáo PDF'}</button>
          <button style={{ ...styles.navBtn, color: '#475569' }} onClick={handleDownloadExcel} disabled={excelLoading}>📊 {excelLoading ? 'Đang xuất...' : 'Xuất Excel (Dataset)'}</button>
          <button style={{ ...styles.navBtn, color: '#475569' }} onClick={() => { localStorage.clear(); window.location.reload(); }}>🚪 Đăng xuất</button>
        </div>
      </aside>

      {/* MAIN CONTENT */}
      <main style={styles.main}>
        <header style={styles.topBar}>
          <h2 style={styles.pageTitle}>
            {activeTab === 'dashboard' ? '📊 Tổng quan hệ thống' : activeTab === 'history' ? '📋 Danh sách email đã quét' : activeTab === 'lists' ? '🛡️ Quản lý Blacklist & Whitelist' : '🧪 Thử nghiệm mô hình AI'}
          </h2>
          <button style={styles.scanBtn} onClick={handleFetchAndScan} disabled={scanning}>
            {scanning ? '⏳ AI đang làm việc...' : '🔄 Quét Gmail Mới'}
          </button>
        </header>

        {activeTab === 'dashboard' && (
          <>
            <div style={styles.statsGrid}>
              <div style={styles.statCard}>
                <div style={styles.statHeader}>
                  <span style={styles.statLabel}>Tổng quét</span>
                  <div style={styles.iconBadge('#eff6ff', '#2563eb')}>📊</div>
                </div>
                <div style={styles.statValue}>{stats.total || 0}</div>
              </div>

              <div style={styles.statCard}>
                <div style={styles.statHeader}>
                  <span style={styles.statLabel}>An toàn</span>
                  <div style={styles.iconBadge('#ecfdf5', '#10b981')}>🛡️</div>
                </div>
                <div style={styles.statValue}>{stats.safe || 0}</div>
              </div>

              <div style={styles.statCard}>
                <div style={styles.statHeader}>
                  <span style={styles.statLabel}>Nghi ngờ</span>
                  <div style={styles.iconBadge('#fffbeb', '#f59e0b')}>⚠️</div>
                </div>
                <div style={styles.statValue}>{stats.suspicious || 0}</div>
              </div>

              <div style={styles.statCard}>
                <div style={styles.statHeader}>
                  <span style={styles.statLabel}>Nguy hiểm</span>
                  <div style={styles.iconBadge('#fef2f2', '#ef4444')}>🚨</div>
                </div>
                <div style={styles.statValue}>{stats.dangerous || 0}</div>
              </div>
            </div>

            {/* KHỐI LỐI TẮT NHANH ĐẾN BLACK/WHITELIST */}
            <div style={{ ...styles.chartCard, marginTop: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h4 style={{ margin: '0 0 5px 0', color: '#1e293b' }}>🛡️ Quy tắc Chặn & Tin Cậy (Black/Whitelist)</h4>
                <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>Chủ động chặn hoặc ưu tiên các nguồn gửi email ở tầng database trước khi phân tích AI.</p>
              </div>
              <button
                style={{ ...styles.scanBtn, background: '#2563eb', whiteSpace: 'nowrap' }}
                onClick={() => setActiveTab('lists')}
              >
                Quản lý ngay →
              </button>
            </div>

            <div style={styles.chartSection}>
              <div style={styles.chartCard}>
                <h4>Phân bổ rủi ro (%)</h4>
                <div style={{ height: '300px', display: 'flex', justifyContent: 'center' }}>
                  <Pie data={pieData} options={pieOptions} />
                </div>
              </div>
              <div style={styles.chartCard}>
                <h4>Hướng dẫn Dashboard</h4>
                <ul style={{ color: '#8b949e', fontSize: '14px', lineHeight: '2.2' }}>
                  <li>Lọc email theo mức độ rủi ro tại tab <b>Nhật ký quét</b>.</li>
                  <li>Nhấp vào một hàng email để xem chi tiết % Spam, % Phishing và từ khóa highlight.</li>
                  <li>Sử dụng <b>Lab Phân Tích</b> để kiểm tra văn bản lạ trực tiếp.</li>
                  <li>Chủ động thêm email độc hại vào <b>Blacklist</b> để hệ thống tự động loại bỏ.</li>
                </ul>
              </div>
            </div>
          </>
        )}

        {/* HIỂN THỊ TRANG QUẢN LÝ BLACK/WHITELIST */}
        {activeTab === 'lists' && <BlacklistPage />}

        {activeTab === 'history' && (
          <>
            <div style={{ marginBottom: '20px', display: 'flex', gap: '15px', alignItems: 'center', justifyContent: 'flex-end' }}>
              <span style={{ fontSize: '14px', color: '#8b949e' }}>🔍 Lọc theo đánh giá:</span>
              <select
                style={{ ...styles.configInput, width: '220px', padding: '8px' }}
                value={filterRisk}
                onChange={(e) => { setFilterRisk(e.target.value); setPage(1); }}
              >
                <option value="">📂 Tất cả email</option>
                <option value="safe">✅ Chỉ email An toàn</option>
                <option value="suspicious">⚠️ Chỉ email Nghi ngờ</option>
                <option value="dangerous">🔴 Chỉ email Nguy hiểm</option>
              </select>
            </div>

            <div style={styles.tableContainer}>
              <table style={styles.table}>
                <thead>
                  <tr style={styles.tableHead}>
                    <th style={{ ...styles.th, width: '60px' }}>STT</th>
                    <th style={styles.th}>Người gửi</th>
                    <th style={styles.th}>Nội dung / Tiêu đề & Link phát hiện</th>
                    <th style={{ ...styles.th, width: '180px' }}>Score Tổng kết </th>
                    <th style={{ ...styles.th, width: '120px' }}>Đánh giá</th>
                  </tr>
                </thead>
                <tbody>
                  {emails.map((email, idx) => {
                    const rawSpam = email.spam_score ?? 0;
                    const rawPhish = email.phishing_score ?? 0;

                    const spamVal = Math.round(rawSpam <= 1 ? rawSpam * 100 : rawSpam);
                    const phishVal = Math.round(rawPhish <= 1 ? rawPhish * 100 : rawPhish);

                    const totalScore = Math.round((spamVal * 0.3) + (phishVal * 0.7));
                    const getScoreColor = (val) => (val > 50 ? '#dc3545' : val > 20 ? '#f59e0b' : '#10b981');
                    const stt = (page - 1) * 12 + idx + 1;

                    return (
                      <tr key={email.id || idx} style={styles.tableRow} onClick={() => handleViewDetail(email.id)}>
                        <td style={{ ...styles.td, fontWeight: '600', color: '#64748b' }}>{stt}</td>
                        <td style={{ ...styles.td, color: '#2563eb', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {email.sender}
                        </td>
                        <td style={{ ...styles.td, maxWidth: '300px' }}>
                          <div style={{ fontWeight: '600', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {email.subject || "(Không có tiêu đề)"}
                          </div>
                          {email.urls && email.urls.length > 0 && (
                            <div style={{ fontSize: '11px', color: '#dc2626', marginTop: '3px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              🔗 Link: {email.urls[0]}
                            </div>
                          )}
                        </td>

                        <td style={styles.td}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', fontWeight: '700', marginBottom: '4px' }}>
                            <span style={{ color: getScoreColor(totalScore) }}>{totalScore}%</span>
                            <span style={{ fontSize: '10px', color: '#64748b' }}>(S:{spamVal}% / P:{phishVal}%)</span>
                          </div>
                          <div style={styles.progressBg}>
                            <div style={{
                              ...styles.progressFill,
                              width: `${Math.min(totalScore, 100)}%`,
                              background: getScoreColor(totalScore)
                            }}></div>
                          </div>
                        </td>

                        <td style={styles.td}>
                          <span style={{ color: RISK_CONFIG[email.risk_level]?.color, fontWeight: 'bold' }}>
                            {RISK_CONFIG[email.risk_level]?.label || email.risk_level}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div style={styles.pagination}>
              <button disabled={page === 1} onClick={() => setPage(p => p - 1)} style={styles.pageBtn}>◀ Trước</button>
              <span style={styles.pageInfo}>Trang {page} / {Math.ceil(totalItems / 12) || 1}</span>
              <button disabled={emails.length < 12} onClick={() => setPage(p => p + 1)} style={styles.pageBtn}>Sau ▶</button>
            </div>
          </>
        )}

        {activeTab === 'tester' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
            <div style={styles.chartCard}>
              <h3 style={{ marginBottom: '15px', color: '#1e293b' }}>📝 Nhập nội dung email cần kiểm tra</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div>
                  <label style={{ fontSize: '13px', fontWeight: '600', color: '#475569', display: 'block', marginBottom: '5px' }}>Tiêu đề email (Subject):</label>
                  <input
                    type="text"
                    style={styles.configInput}
                    placeholder="Ví dụ: Tài khoản của bạn đã bị khóa..."
                    value={testSubject}
                    onChange={(e) => setTestSubject(e.target.value)}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '13px', fontWeight: '600', color: '#475569', display: 'block', marginBottom: '5px' }}>Nội dung chi tiết (Body):</label>
                  <textarea
                    style={{ ...styles.configInput, height: '150px', resize: 'vertical' }}
                    placeholder="Dán nội dung email vào đây để AI phân tích..."
                    value={testBody}
                    onChange={(e) => setTestBody(e.target.value)}
                  />
                </div>
                <button
                  style={{ ...styles.scanBtn, background: '#7c3aed', justifyContent: 'center', marginTop: '5px' }}
                  onClick={handleManualTest}
                  disabled={isTesting}
                >
                  {isTesting ? '⏳ AI đang phân tích...' : '🚀 Phân tích ngay'}
                </button>
              </div>
            </div>

            <div>
              {testResult ? (
                <div style={styles.labResultCard}>
                  <h3 style={{ color: '#2563eb', marginBottom: '15px' }}>📊 Kết quả phân tích AI</h3>

                  <div style={styles.labScoreBox}>
                    <div style={styles.labScoreHeader}>
                      <span>Tỉ lệ Spam</span>
                      <span>{Number(testResult.spam_score || 0).toFixed(1)}%</span>
                    </div>
                    <div style={styles.progressBg}>
                      <div style={{
                        ...styles.progressFill,
                        width: `${testResult.spam_score || 0}%`,
                        background: (testResult.spam_score || 0) > 50 ? '#dc3545' : '#ffc107'
                      }}></div>
                    </div>
                  </div>

                  <div style={styles.labScoreBox}>
                    <div style={styles.labScoreHeader}>
                      <span>Tỉ lệ Phishing</span>
                      <span>{Number(testResult.phishing_score || 0).toFixed(1)}%</span>
                    </div>
                    <div style={styles.progressBg}>
                      <div style={{
                        ...styles.progressFill,
                        width: `${testResult.phishing_score || 0}%`,
                        background: (testResult.phishing_score || 0) > 50 ? '#dc3545' : '#ffc107'
                      }}></div>
                    </div>
                  </div>

                  <div style={{ ...styles.finalRisk, borderColor: RISK_CONFIG[testResult.risk_level]?.color || '#dc3545', marginTop: '15px', textAlign: 'center', padding: '10px', borderWidth: '2px', borderStyle: 'solid', borderRadius: '6px' }}>
                    <div style={{ color: RISK_CONFIG[testResult.risk_level]?.color || '#dc3545', fontSize: '16px', fontWeight: 800 }}>
                      {RISK_CONFIG[testResult.risk_level]?.label?.toUpperCase() || testResult.risk_level?.toUpperCase()}
                    </div>
                    {testResult.email_category && (
                      <div style={{ fontSize: '12px', color: '#64748b', marginTop: '4px' }}>
                        Loại hình: <b>{testResult.email_category}</b>
                      </div>
                    )}
                  </div>

                  {testResult.explanation && (
                    <div style={{ marginTop: '20px', background: '#fffbeb', border: '1px solid #fde68a', padding: '12px 15px', borderRadius: '8px' }}>
                      <div style={{ fontSize: '13px', fontWeight: '700', color: '#d97706', marginBottom: '6px' }}>
                        🛡️ Báo cáo giải thích chi tiết từ AI:
                      </div>
                      <p style={{ fontSize: '13px', color: '#92400e', margin: '0 0 8px 0' }}>
                        <b>Kết luận:</b> {testResult.explanation.summary}
                      </p>
                      <ul style={{ margin: '0', paddingLeft: '18px', fontSize: '12px', color: '#b45309', lineHeight: '1.6' }}>
                        {testResult.explanation.reasons.map((reason, idx) => (
                          <li key={idx}>{reason}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {testResult.url_details && Array.isArray(testResult.url_details) && testResult.url_details.length > 0 && (
                    <div style={{ marginTop: '20px' }}>
                      <span style={{ fontSize: '13px', color: '#475569', fontWeight: '700' }}>🔗 Phân tích Liên kết (URL) & Bảo mật:</span>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '8px' }}>
                        {testResult.url_details.map((item, idx) => (
                          <div key={idx} style={{ background: '#f8fafc', border: '1px solid #e2e8f0', padding: '10px', borderRadius: '6px', fontSize: '13px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <a href={item.url} target="_blank" rel="noreferrer" style={{ color: '#2563eb', textDecoration: 'none', fontWeight: '600', wordBreak: 'break-all' }}>
                                🌐 {item.url}
                              </a>
                              <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold', background: item.is_malicious ? '#fee2e2' : '#ecfdf5', color: item.is_malicious ? '#dc3545' : '#10b981' }}>
                                {item.is_malicious ? 'Nguy hiểm' : 'An toàn'}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ ...styles.chartCard, textAlign: 'center', color: '#64748b', padding: '60px 20px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
                  <div style={{ fontSize: '40px', marginBottom: '10px' }}>🔍</div>
                  <p>Nhập nội dung vào form bên trái và nhấn <b>Phân tích ngay</b> để xem kết quả từ AI Engine.</p>
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* MODAL PREVIEW BÁO CÁO */}
      {showPreview && previewData && (
        <div style={styles.modalOverlay} onClick={() => setShowPreview(false)}>
          <div style={{ ...styles.modalContent, width: '550px' }} onClick={e => e.stopPropagation()}>
            <div style={styles.modalHeader}>
              <h3 style={{ color: '#2563ff' }}>📑 Xem trước báo cáo hệ thống</h3>
              <button onClick={() => setShowPreview(false)} style={styles.closeBtn}>&times;</button>
            </div>
            <div style={styles.modalBody}>
              <div style={styles.previewBox}>
                <p>📊 Tổng số email đã quét: <b>{previewData.total_scanned}</b></p>
                <p>📈 Tăng trưởng:
                  <span style={{ color: previewData.growth_percent >= 0 ? '#28a745' : '#dc3545', fontWeight: 'bold', marginLeft: '5px' }}>
                    {previewData.growth_percent >= 0 ? '+' : ''}{previewData.growth_percent}%
                  </span>
                </p>
                <p>🎯 Điểm Spam TB: <b>{(previewData.average_spam * 100).toFixed(1)}%</b></p>
                <hr style={styles.hr} />
                <p style={{ marginBottom: '10px' }}>🧠 <b>Từ khóa nguy hiểm tiêu biểu:</b></p>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {previewData.top_keywords.map((kw, i) => (
                    <span key={i} style={styles.tag}>{kw}</span>
                  ))}
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
              <button style={{ ...styles.scanBtn, flex: 1 }} onClick={handleDownloadPDF}>✅ Tải Báo Cáo PDF</button>
              <button style={{ ...styles.pageBtn, flex: 1 }} onClick={() => setShowPreview(false)}>Hủy</button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL CHI TIẾT EMAIL */}
      {showModal && selectedEmail && (
        <div style={styles.modalOverlay} onClick={() => setShowModal(false)}>
          <div style={{ ...styles.modalContent, width: '700px', maxHeight: '90vh', overflowY: 'auto' }} onClick={e => e.stopPropagation()}>
            <div style={styles.modalHeader}>
              <h3 style={{ color: '#2563eb' }}>📧 Chi tiết Phân tích Email & Bảo mật URL</h3>
              <button onClick={() => setShowModal(false)} style={styles.closeBtn}>&times;</button>
            </div>
            <div style={styles.modalBody}>
              <p><b>Người gửi:</b> {selectedEmail.sender}</p>
              <p><b>Tiêu đề:</b> {selectedEmail.subject || "(Không có tiêu đề)"}</p>
              <p style={{ marginTop: '5px' }}>
                <b>Đánh giá tổng quan:</b> <span style={{ color: RISK_CONFIG[selectedEmail.risk_level]?.color, fontWeight: 'bold' }}>{RISK_CONFIG[selectedEmail.risk_level]?.label}</span>
              </p>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', margin: '15px 0', background: '#f1f5f9', padding: '12px', borderRadius: '8px' }}>
                <div>
                  <span style={{ fontSize: '12px', color: '#64748b', fontWeight: '600' }}>TỈ LỆ SPAM SCORE:</span>
                  <div style={{ fontSize: '18px', fontWeight: '700', color: '#dc3545' }}>
                    {Math.round((selectedEmail.spam_score ?? 0) <= 1 ? (selectedEmail.spam_score ?? 0) * 100 : (selectedEmail.spam_score ?? 0))}%
                  </div>
                </div>
                <div>
                  <span style={{ fontSize: '12px', color: '#64748b', fontWeight: '600' }}>TỈ LỆ PHISHING SCORE:</span>
                  <div style={{ fontSize: '18px', fontWeight: '700', color: '#dc3545' }}>
                    {Math.round((selectedEmail.phishing_score ?? 0) <= 1 ? (selectedEmail.phishing_score ?? 0) * 100 : (selectedEmail.phishing_score ?? 0))}%
                  </div>
                </div>
              </div>

              <div style={{ marginBottom: '15px', background: '#fffbeb', border: '1px solid #fde68a', padding: '10px 12px', borderRadius: '6px' }}>
                <span style={{ fontSize: '13px', fontWeight: '700', color: '#d97706' }}>⚠️ Nhận định từ hệ thống:</span>
                <p style={{ fontSize: '13px', color: '#92400e', margin: '4px 0 0 0' }}>
                  {selectedEmail.reason || selectedEmail.description || "Phát hiện cấu trúc nội dung hoặc liên kết có dấu hiệu bất thường, đáng ngờ."}
                </p>
              </div>

              <div style={{ marginBottom: '15px' }}>
                <span style={{ fontSize: '13px', color: '#475569', fontWeight: '700' }}>🔗 Liên kết (URL) & Báo cáo VirusTotal:</span>
                {selectedEmail.url_details && selectedEmail.url_details.length > 0 ? (
                  <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {selectedEmail.url_details.map((item, idx) => {
                      const vt = item.details?.virustotal;
                      return (
                        <div key={idx} style={{ background: '#f8fafc', border: '1px solid #e2e8f0', padding: '10px', borderRadius: '6px', fontSize: '13px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <a href={item.url} target="_blank" rel="noreferrer" style={{ color: '#2563eb', textDecoration: 'none', fontWeight: '600', wordBreak: 'break-all' }}>
                              🌐 {item.url}
                            </a>
                            <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold', background: item.is_malicious ? '#fee2e2' : '#ecfdf5', color: item.is_malicious ? '#dc3545' : '#10b981' }}>
                              {item.is_malicious ? `Nguy hiểm (${item.threat_source})` : 'An toàn'}
                            </span>
                          </div>

                          {vt && vt.vt_checked && (
                            <div style={{ marginTop: '6px', fontSize: '12px', color: '#64748b', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#fff', padding: '6px 8px', borderRadius: '4px', border: '1px solid #f1f5f9' }}>
                              <span>🛡️ VirusTotal Check: <b style={{ color: vt.vt_malicious > 0 ? '#dc3545' : '#10b981' }}>{vt.vt_malicious} / {vt.vt_total}</b> cờ độc hại</span>
                              {vt.vt_permalink && (
                                <a href={vt.vt_permalink} target="_blank" rel="noreferrer" style={{ color: '#2563eb', textDecoration: 'underline', fontSize: '11px' }}>
                                  Xem báo cáo gốc ↗
                                </a>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p style={{ fontSize: '13px', color: '#64748b', marginTop: '5px', fontStyle: 'italic' }}>Không tìm thấy đường dẫn URL nào trong nội dung email này.</p>
                )}
              </div>

              <hr style={styles.hr} />
              <p style={{ fontSize: '13px', color: '#64748b', marginBottom: '8px' }}>
                🔍 <b>Nội dung chi tiết (Các từ khóa nguy hiểm được highlight):</b>
              </p>
              <div style={styles.emailBodyContainer}>
                {renderHighlightedBody(selectedEmail.body, selectedEmail.top_keywords)}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MODAL CẤU HÌNH IMAP */}
      {showConfigModal && (
        <div style={styles.modalOverlay}>
          <div style={{ ...styles.modalContent, width: '420px' }}>
            <div style={styles.modalHeader}>
              <h3 style={{ color: '#2563eb' }}>⚙️ Cấu hình Mật khẩu Ứng dụng</h3>
              <button onClick={() => setShowConfigModal(false)} style={styles.closeBtn}>&times;</button>
            </div>
            <div style={styles.modalBody}>
              <p style={{ fontSize: '13px', color: '#64748b', marginBottom: '12px' }}>
                Nhập <b>App Password (16 ký tự)</b> từ tài khoản Gmail của bạn để hệ thống kết nối và quét hòm thư:
              </p>
              <input
                type="password"
                style={styles.configInput}
                placeholder="xxxx xxxx xxxx xxxx"
                value={appPassword}
                onChange={(e) => setAppPassword(e.target.value)}
                maxLength={20}
              />
            </div>
            <div style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
              <button style={{ ...styles.scanBtn, flex: 1, justifyContent: 'center' }} onClick={handleSaveConfig} disabled={configLoading}>
                {configLoading ? '⏳ Đang lưu...' : '💾 Lưu & Quét ngay'}
              </button>
              <button style={{ ...styles.pageBtn, flex: 1 }} onClick={() => setShowConfigModal(false)}>Hủy</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// --- CSS STYLES INLINE (Giữ nguyên giao diện chuẩn sáng) ---
const styles = {
  layout: { display: 'flex', height: '100vh', backgroundColor: '#f8fafc', fontFamily: 'Inter, sans-serif', color: '#1e293b', overflow: 'hidden' },
  sidebar: { width: '260px', backgroundColor: '#ffffff', borderRight: '1px solid #e2e8f0', display: 'flex', flexDirection: 'column', padding: '20px', boxSizing: 'border-box' },
  sidebarLogo: { fontSize: '20px', fontWeight: '800', color: '#2563eb', marginBottom: '30px', display: 'flex', alignItems: 'center', gap: '10px' },
  navBtn: { display: 'flex', alignItems: 'center', gap: '10px', padding: '12px 15px', borderRadius: '8px', border: 'none', background: 'transparent', color: '#64748b', fontSize: '14px', fontWeight: '600', cursor: 'pointer', textAlign: 'left', transition: 'all 0.2s' },
  navBtnActive: { backgroundColor: '#eff6ff', color: '#2563eb' },
  main: { flex: 1, display: 'flex', flexDirection: 'column', overflowY: 'auto', padding: '24px 32px' },
  topBar: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' },
  pageTitle: { fontSize: '22px', fontWeight: '700', color: '#0f172a', margin: 0 },
  scanBtn: { backgroundColor: '#2563eb', border: 'none', padding: '10px 18px', borderRadius: '8px', fontWeight: '600', fontSize: '13px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px', color: '#fff' },
  statsGrid: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px', marginBottom: '24px' },
  statCard: { backgroundColor: '#ffffff', padding: '20px', borderRadius: '12px', border: '1px solid #e2e8f0', boxShadow: '0 1px 3px rgba(0,0,0,0.05)' },
  statHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' },
  statLabel: { fontSize: '13px', fontWeight: '600', color: '#64748b' },
  iconBadge: (bg, color) => ({ width: '32px', height: '32px', borderRadius: '8px', backgroundColor: bg, color: color, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '15px' }),
  statValue: { fontSize: '26px', fontWeight: '800', color: '#0f172a' },
  chartSection: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' },
  chartCard: { backgroundColor: '#ffffff', padding: '20px', borderRadius: '12px', border: '1px solid #e2e8f0' },
  tableContainer: { backgroundColor: '#ffffff', borderRadius: '12px', border: '1px solid #e2e8f0', overflow: 'hidden', boxShadow: '0 1px 3px rgba(0,0,0,0.05)' },
  table: { width: '100%', borderCollapse: 'collapse', textAlign: 'left' },
  tableHead: { backgroundColor: '#f8fafc', borderBottom: '1px solid #e2e8f0' },
  th: { padding: '12px 16px', fontSize: '12px', fontWeight: '700', color: '#475569', textTransform: 'uppercase' },
  tableRow: { borderBottom: '1px solid #f1f5f9', cursor: 'pointer', transition: 'background 0.1s' },
  td: { padding: '14px 16px', fontSize: '13px', color: '#334155', verticalAlign: 'middle' },
  progressBg: { width: '100%', height: '6px', backgroundColor: '#e2e8f0', borderRadius: '3px', overflow: 'hidden' },
  progressFill: { height: '100%', borderRadius: '3px' },
  pagination: { display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '15px', marginTop: '20px' },
  pageBtn: { padding: '8px 14px', borderRadius: '6px', border: '1px solid #cbd5e1', background: '#fff', color: '#334155', fontWeight: '600', fontSize: '13px', cursor: 'pointer' },
  pageInfo: { fontSize: '13px', fontWeight: '600', color: '#64748b' },
  modalOverlay: { position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 },
  modalContent: { backgroundColor: '#ffffff', borderRadius: '12px', padding: '24px', boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)' },
  modalHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' },
  closeBtn: { background: 'none', border: 'none', fontSize: '20px', cursor: 'pointer', color: '#64748b' },
  modalBody: { fontSize: '14px', color: '#334155', lineHeight: '1.6' },
  configInput: { width: '100%', padding: '10px 12px', borderRadius: '8px', border: '1px solid #cbd5e1', fontSize: '14px', boxSizing: 'border-box', outline: 'none' },
  emailBodyContainer: { backgroundColor: '#f8fafc', border: '1px solid #e2e8f0', padding: '15px', borderRadius: '8px', maxHeight: '200px', overflowY: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: '13px', lineHeight: '1.5' },
  previewBox: { backgroundColor: '#f8fafc', padding: '15px', borderRadius: '8px', border: '1px solid #e2e8f0', display: 'flex', flexDirection: 'column', gap: '8px' },
  hr: { border: 'none', borderTop: '1px solid #e2e8f0', margin: '12px 0' },
  tag: { backgroundColor: '#fee2e2', color: '#dc3545', padding: '3px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: '600' },
  labResultCard: { backgroundColor: '#ffffff', padding: '20px', borderRadius: '12px', border: '1px solid #e2e8f0', boxShadow: '0 1px 3px rgba(0,0,0,0.05)' },
  labScoreBox: { marginBottom: '12px' },
  labScoreHeader: { display: 'flex', justifyContent: 'space-between', fontSize: '12px', fontWeight: '700', color: '#475569', marginBottom: '4px' }
};
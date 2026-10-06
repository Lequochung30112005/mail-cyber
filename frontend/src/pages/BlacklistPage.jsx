// ========================
// frontend/src/pages/BlacklistPage.jsx
// CRUD Blacklist và Whitelist - BẢN HOÀN CHỈNH
// ========================

import React, { useState, useEffect, useCallback } from 'react';
import { listAPI } from '../services/api';

const TABS = ['blacklist', 'whitelist'];
const TYPE_OPTIONS = ['domain', 'ip', 'email'];

export default function BlacklistPage() {
  const [activeTab, setActiveTab]   = useState('blacklist');
  const [items, setItems]           = useState([]);
  const [loading, setLoading]       = useState(false);
  const [search, setSearch]         = useState('');
  const [page, setPage]             = useState(1);
  const [total, setTotal]           = useState(0);
  const [showModal, setShowModal]   = useState(false);
  const [editItem, setEditItem]     = useState(null);
  const [form, setForm]             = useState({ value: '', type: 'domain', reason: '' });
  const [saving, setSaving]         = useState(false);
  const [msg, setMsg]               = useState('');

  // Tải dữ liệu từ API
  const loadItems = useCallback(async () => {
    setLoading(true);
    try {
      // Chọn API tương ứng với Tab đang đứng
      const fn = activeTab === 'blacklist' ? listAPI.getBlacklist : listAPI.getWhitelist;
      const res = await fn(page, search);

      setItems(res.data.data || []);
      setTotal(res.data.total || 0);
    } catch (err) {
      console.error("Lỗi load danh sách:", err);
      if (err.response?.status === 401) {
          setMsg('❌ Phiên đăng nhập hết hạn, vui lòng đăng nhập lại.');
      }
    } finally {
      setLoading(false);
    }
  }, [activeTab, page, search]);

  // Reset trang về 1 khi đổi tab hoặc tìm kiếm
  useEffect(() => {
    setPage(1);
  }, [activeTab, search]);

  // Load lại data khi Tab, Page hoặc Search thay đổi
  useEffect(() => {
    loadItems();
  }, [loadItems]);

  const openAdd = () => {
    setEditItem(null);
    setForm({ value: '', type: 'domain', reason: '' });
    setShowModal(true);
  };

  const openEdit = (item) => {
    setEditItem(item);
    setForm({ value: item.value, type: item.type, reason: item.reason || '' });
    setShowModal(true);
  };

  const handleSave = async () => {
    if (!form.value.trim()) return;
    setSaving(true);
    try {
      if (editItem) {
        const fn = activeTab === 'blacklist' ? listAPI.updateBlacklist : listAPI.updateWhitelist;
        await fn(editItem.id, form);
        setMsg('✅ Đã cập nhật thành công');
      } else {
        const fn = activeTab === 'blacklist' ? listAPI.addBlacklist : listAPI.addWhitelist;
        await fn(form);
        setMsg('✅ Đã thêm vào danh sách');
      }
      setShowModal(false);
      loadItems(); // Refresh lại bảng
    } catch (err) {
      setMsg('❌ ' + (err.response?.data?.detail || 'Không thể lưu dữ liệu'));
    } finally {
      setSaving(false);
      setTimeout(() => setMsg(''), 3000);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Bạn có chắc chắn muốn xóa mục này không?')) return;
    try {
      const fn = activeTab === 'blacklist' ? listAPI.deleteBlacklist : listAPI.deleteWhitelist;
      await fn(id);
      setMsg('✅ Đã xóa mục tiêu');
      loadItems();
    } catch (err) {
      setMsg('❌ Lỗi: Không thể xóa');
    } finally {
      setTimeout(() => setMsg(''), 3000);
    }
  };

  const isBlacklist = activeTab === 'blacklist';
  const accentColor = isBlacklist ? '#dc3545' : '#28a745'; // Đỏ cho Black, Xanh cho White

  return (
    <div style={styles.page}>
      <div style={styles.header}>
        <h2 style={styles.title}>
          {isBlacklist ? '🚫 Quản lý Danh sách Đen' : '✅ Quản lý Danh sách Trắng'}
        </h2>
        <button style={{...styles.addBtn, background: accentColor}} onClick={openAdd}>
          + Thêm {isBlacklist ? 'Blacklist' : 'Whitelist'}
        </button>
      </div>

      {/* Chuyển đổi giữa Blacklist và Whitelist */}
      <div style={styles.tabs}>
        {TABS.map(tab => (
          <button key={tab} style={{
            ...styles.tab,
            ...(activeTab === tab ? { ...styles.tabActive, borderColor: accentColor, color: accentColor } : {})
          }} onClick={() => { setActiveTab(tab); setSearch(''); }}>
            {tab === 'blacklist' ? '🚫 Blacklist' : '✅ Whitelist'}
          </button>
        ))}
      </div>

      {/* Thông báo nhanh (Toast) */}
      {msg && (
        <div style={{...styles.toast, borderColor: msg.includes('✅') ? '#28a745' : '#dc3545'}}>
            {msg}
        </div>
      )}

      {/* Thanh tìm kiếm */}
      <input
        style={styles.search}
        placeholder={`🔍 Tìm kiếm ${activeTab} theo giá trị hoặc lý do...`}
        value={search}
        onChange={e => setSearch(e.target.value)}
      />

      {/* Bảng dữ liệu */}
      <div style={styles.tableWrap}>
        <table style={styles.table}>
          <thead>
            <tr>
              {['#', 'Giá trị (Domain/IP/Email)', 'Phân loại', 'Lý do ghi chú', 'Ngày tạo', 'Thao tác'].map(h => (
                <th key={h} style={styles.th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} style={styles.emptyCell}>⏳ Đang đồng bộ dữ liệu...</td></tr>
            ) : items.length === 0 ? (
              <tr><td colSpan={6} style={styles.emptyCell}>Danh sách trống.</td></tr>
            ) : items.map((item, i) => (
              <tr key={item.id} style={styles.row}>
                <td style={styles.td}>{(page-1)*20+i+1}</td>
                <td style={{...styles.td, fontWeight:600, color: accentColor}}>{item.value}</td>
                <td style={styles.td}>
                  <span style={{...styles.typeBadge, background: accentColor + '22', color: accentColor, border: `1px solid ${accentColor}44`}}>
                    {item.type.toUpperCase()}
                  </span>
                </td>
                <td style={{...styles.td, color:'#aaa', fontStyle: item.reason ? 'normal' : 'italic'}}>
                    {item.reason || '(Không có lý do)'}
                </td>
                <td style={{...styles.td, color:'#888', fontSize:'12px'}}>
                  {item.added_at ? new Date(item.added_at).toLocaleDateString('vi-VN') : '—'}
                </td>
                <td style={styles.td}>
                  <button style={styles.editBtn} title="Sửa" onClick={() => openEdit(item)}>✏️</button>
                  <button style={styles.deleteBtn} title="Xóa" onClick={() => handleDelete(item.id)}>🗑️</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Phân trang */}
      <div style={styles.pagination}>
        <span style={{color:'#888', fontSize:'13px'}}>Tổng cộng: <strong>{total}</strong> bản ghi</span>
        <div style={{display:'flex', gap:'5px'}}>
            <button style={styles.pageBtn} disabled={page<=1} onClick={() => setPage(p=>p-1)}>← Trước</button>
            <div style={styles.pageInfo}>Trang {page}</div>
            <button style={styles.pageBtn} disabled={items.length < 20} onClick={() => setPage(p=>p+1)}>Sau →</button>
        </div>
      </div>

      {/* Popup Thêm/Sửa */}
      {showModal && (
        <div style={styles.overlay}>
          <div style={styles.modal}>
            <h3 style={{margin:'0 0 20px', color:'#fff', textAlign:'center'}}>
              {editItem ? '✏️ Cập nhật' : '➕ Thêm mới'} {isBlacklist ? 'Blacklist' : 'Whitelist'}
            </h3>

            <div style={styles.formGroup}>
              <label style={styles.label}>Giá trị nguồn *</label>
              <input
                style={styles.input}
                placeholder="VD: evil-domain.com hoặc 112.x.x.x"
                value={form.value}
                onChange={e => setForm(f => ({...f, value: e.target.value}))}
                autoFocus
              />
            </div>

            <div style={styles.formGroup}>
              <label style={styles.label}>Loại dữ liệu</label>
              <select style={styles.input} value={form.type}
                      onChange={e => setForm(f => ({...f, type: e.target.value}))}>
                {TYPE_OPTIONS.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
              </select>
            </div>

            <div style={styles.formGroup}>
              <label style={styles.label}>Lý do / Ghi chú</label>
              <textarea
                style={{...styles.input, height:'80px', resize:'none'}}
                placeholder="Tại sao bạn muốn đưa mục này vào danh sách?"
                value={form.reason}
                onChange={e => setForm(f => ({...f, reason: e.target.value}))}
              />
            </div>

            <div style={styles.modalActions}>
              <button style={styles.cancelBtn} onClick={() => setShowModal(false)}>Đóng</button>
              <button style={{...styles.addBtn, background: accentColor, flex:1}} onClick={handleSave} disabled={saving}>
                {saving ? '⏳ Đang lưu...' : '💾 Xác nhận Lưu'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// STYLES - Đã tối ưu cho Dark Theme của CyberMail
const styles = {
  page:       { padding:'30px', fontFamily:"'Segoe UI',sans-serif", background:'#0d0d1a', minHeight:'100vh', color:'#fff' },
  header:     { display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'25px' },
  title:      { fontSize:'24px', fontWeight:700, margin:0 },
  addBtn:     { color:'#fff', border:'none', borderRadius:'8px', padding:'10px 22px', fontSize:'14px', fontWeight:600, cursor:'pointer', transition:'0.3s' },
  tabs:       { display:'flex', gap:'10px', marginBottom:'20px' },
  tab:        { background:'rgba(255,255,255,0.05)', border:'1px solid rgba(255,255,255,0.1)', borderRadius:'8px', padding:'10px 25px', color:'#888', cursor:'pointer', fontSize:'14px', transition:'0.3s' },
  tabActive:  { background:'rgba(255,255,255,0.08)', borderWidth:'2px' },
  toast:      { background:'rgba(0,0,0,0.3)', borderLeft:'5px solid', borderRadius:'4px', padding:'12px 20px', marginBottom:'20px', fontSize:'14px', color:'#eee' },
  search:     { width:'100%', boxSizing:'border-box', background:'#161b22', border:'1px solid #30363d', borderRadius:'10px', padding:'12px 16px', color:'#fff', fontSize:'14px', outline:'none', marginBottom:'20px' },
  tableWrap:  { background:'#161b22', borderRadius:'12px', overflow:'hidden', border:'1px solid #30363d' },
  table:      { width:'100%', borderCollapse:'collapse' },
  th:         { padding:'15px', textAlign:'left', fontSize:'12px', color:'#8b949e', fontWeight:600, background:'#21262d', textTransform:'uppercase' },
  td:         { padding:'14px 15px', fontSize:'14px', borderBottom:'1px solid #30363d' },
  emptyCell:  { padding:'50px', textAlign:'center', color:'#8b949e' },
  row:        { transition:'background 0.2s', '&:hover': { background: 'rgba(255,255,255,0.02)' } },
  typeBadge:  { padding:'3px 12px', borderRadius:'12px', fontSize:'11px', fontWeight:700 },
  editBtn:    { background:'rgba(255,193,7,0.1)', border:'1px solid rgba(255,193,7,0.3)', borderRadius:'6px', padding:'6px 10px', cursor:'pointer', marginRight:'8px' },
  deleteBtn:  { background:'rgba(220,53,69,0.1)', border:'1px solid rgba(220,53,69,0.3)', borderRadius:'6px', padding:'6px 10px', cursor:'pointer' },
  pagination: { display:'flex', alignItems:'center', justifyContent:'space-between', marginTop:'20px' },
  pageBtn:    { background:'#21262d', border:'1px solid #30363d', color:'#c9d1d9', borderRadius:'6px', padding:'8px 18px', cursor:'pointer', fontSize:'13px' },
  pageInfo:   { background:'rgba(255,255,255,0.05)', padding:'8px 15px', borderRadius:'6px', fontSize:'13px', color:'#fff' },
  // Modal
  overlay:    { position:'fixed', inset:0, background:'rgba(0,0,0,0.85)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000, backdropFilter:'blur(4px)' },
  modal:      { background:'#0d1117', borderRadius:'16px', padding:'35px', width:'450px', border:'1px solid #30363d', boxShadow:'0 20px 40px rgba(0,0,0,0.4)' },
  formGroup:  { marginBottom:'20px' },
  label:      { display:'block', color:'#8b949e', fontSize:'13px', marginBottom:'8px', fontWeight:500 },
  input:      { width:'100%', boxSizing:'border-box', background:'#010409', border:'1px solid #30363d', borderRadius:'8px', padding:'12px 15px', color:'#fff', fontSize:'14px', outline:'none' },
  modalActions:{ display:'flex', gap:'12px', marginTop:'25px' },
  cancelBtn:  { background:'transparent', border:'1px solid #30363d', color:'#8b949e', borderRadius:'8px', padding:'10px 25px', cursor:'pointer' },
};
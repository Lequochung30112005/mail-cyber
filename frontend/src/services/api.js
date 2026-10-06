// ========================
// frontend/src/services/api.js
// Cấu hình Axios và định nghĩa API endpoints - BẢN FIX XUẤT FILE 2026
// ========================

import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
    baseURL: BASE_URL,
    timeout: 30000,
    headers: { 'Content-Type': 'application/json' }
});

// --- INTERCEPTORS ---
api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('access_token');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => Promise.reject(error)
);

api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            localStorage.clear();
            if (!window.location.pathname.includes('/login')) {
                window.location.href = '/login?msg=expired';
            }
        }
        return Promise.reject(error);
    }
);

/**
 * API Xác thực (Giữ nguyên)
 */
export const authAPI = {
    login: (credentials) => api.post('/auth/login', credentials),
    register: (userData) => api.post('/auth/register', userData),
    verifyOTP: (otpData) => api.post('/auth/verify-otp', otpData),
    getProfile: () => api.get('/auth/me'),
};

/**
 * API Quản lý Email & AI Analysis (Giữ nguyên)
 */
export const emailAPI = {
    configImap: (appPassword) =>
        api.post('/email/config-imap', { app_password: appPassword }),

    fetchAndAnalyze: (limit = 20) =>
        api.post('/email/fetch-and-analyze', { limit, unseen_only: true }),

    getHistory: (page = 1, search = '', risk = '') =>
        api.get('/email/history', {
            params: { page, limit: 12, search, risk_level: risk }
        }),

    getStats: () => api.get('/email/stats'),

    getDetail: (id) => api.get(`/email/${id}`),

    predictSpam: (data) => api.post('/email/predict-spam', data),
};

/**
 * API Xuất báo cáo - FIX CHUẨN ĐỊNH DẠNG BLOB
 */
export const reportAPI = {
    getPreview: () => api.get('/reports/preview'),

    // Đảm bảo responseType nằm trong tham số thứ 2 của api.get
    downloadPDF: () =>
        api.get('/reports/download-pdf', { responseType: 'blob' }),

    downloadExcel: () =>
        api.get('/reports/export-excel', { responseType: 'blob' }),
};

/**
 * API Danh sách Đen/Trắng (Giữ nguyên)
 */
/**
 * API Danh sách Đen / Trắng (Cập nhật chuẩn Backend 2026)
 */
export const listAPI = {
    // Blacklist
    getBlacklist: (page = 1, search = '') => api.get('/lists/blacklist', { params: { page, limit: 20, search } }),
    addBlacklist: (data) => api.post('/lists/blacklist', data),
    updateBlacklist: (id, data) => api.put(`/lists/blacklist/${id}`, data),
    deleteBlacklist: (id) => api.delete(`/lists/blacklist/${id}`),

    // Whitelist
    getWhitelist: (page = 1, search = '') => api.get('/lists/whitelist', { params: { page, limit: 20, search } }),
    addWhitelist: (data) => api.post('/lists/whitelist', data),
    updateWhitelist: (id, data) => api.put(`/lists/whitelist/${id}`, data),
    deleteWhitelist: (id) => api.delete(`/lists/whitelist/${id}`),
};

/**
 * Helper: Tải file từ dữ liệu Blob
 * Đã sửa lỗi nhận diện file và xử lý trường hợp server trả về lỗi JSON thay vì file
 */
export const downloadFile = async (response, filename) => {
    try {
        if (!response || !response.data) {
            throw new Error("Dữ liệu phản hồi trống");
        }

        // Kiểm tra nếu server trả về JSON lỗi thay vì Blob (dù responseType là blob)
        if (response.data.type === 'application/json') {
            const text = await response.data.text();
            const errorData = JSON.parse(text);
            alert(`Lỗi từ hệ thống: ${errorData.detail || 'Không thể xuất file'}`);
            return;
        }

        // Lấy Content-Type từ headers hoặc ép kiểu theo đuôi file
        const contentType = response.headers['content-type'] ||
            (filename.endsWith('.xlsx') ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' : 'application/pdf');

        const blob = new Blob([response.data], { type: contentType });

        // Tạo đường dẫn ảo và tải file
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', filename);
        document.body.appendChild(link);
        link.click();

        // Giải phóng bộ nhớ
        setTimeout(() => {
            document.body.removeChild(link);
            window.URL.revokeObjectURL(url);
        }, 100);

    } catch (error) {
        console.error("Lỗi khi xử lý file tải về:", error);
        alert("Có lỗi xảy ra khi tạo file. Vui lòng kiểm tra log hệ thống.");
    }
};

export default api;
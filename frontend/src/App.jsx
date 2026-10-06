// ========================
// frontend/src/App.jsx - ĐÃ CẬP NHẬT
// ========================

import React, { useState, useEffect } from 'react';
import LoginPage from './pages/LoginPage';
import Dashboard from './pages/Dashboard';
import BlacklistPage from './pages/BlacklistPage';
import RegisterPage from './pages/Register';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';

function PrivateRoute({ children }) {
  const token = localStorage.getItem('access_token');
  return token ? children : <Navigate to="/login" replace />;
}

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(!!localStorage.getItem('access_token'));

  useEffect(() => {
    const checkAuth = () => setIsLoggedIn(!!localStorage.getItem('access_token'));
    window.addEventListener('storage', checkAuth);
    return () => window.removeEventListener('storage', checkAuth);
  }, []);

  return (
    <BrowserRouter>
      <Routes>
        {/* Route Đăng nhập */}
        <Route path="/login" element={
          isLoggedIn
            ? <Navigate to="/" replace />
            : <LoginPage onLoginSuccess={() => setIsLoggedIn(true)} />
        }/>

        {/* THÊM ROUTE ĐĂNG KÝ Ở ĐÂY */}
        <Route path="/register" element={
          isLoggedIn ? <Navigate to="/" replace /> : <RegisterPage />
        }/>

        {/* Các route bảo mật */}
        <Route path="/" element={
          <PrivateRoute><Dashboard /></PrivateRoute>
        }/>
        <Route path="/lists" element={
          <PrivateRoute><BlacklistPage /></PrivateRoute>
        }/>

        <Route path="*" element={<Navigate to="/" replace />}/>
      </Routes>
    </BrowserRouter>
  );
}
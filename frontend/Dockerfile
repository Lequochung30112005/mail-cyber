# Stage 1: Build
FROM node:20-alpine AS builder
WORKDIR /app

# Copy toàn bộ mã nguồn và cấu hình
COPY . .

# Xóa các tệp lock/cache cũ nếu có sót lại và cài đặt mới chuẩn 100%
RUN rm -rf node_modules package-lock.json && npm install

# Build ứng dụng
RUN npm run build

# Stage 2: Serve bằng Nginx
FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
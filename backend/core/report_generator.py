from fpdf import FPDF
import pandas as pd
from datetime import datetime


class SecurityReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.set_text_color(26, 26, 46)  # Màu Navy
        self.cell(0, 10, 'CYBERMAIL SHIELD - SECURITY ANALYSIS REPORT', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 10, f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'R')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')


def generate_email_report(email_data: list, filename: str, days: int):
    df = pd.DataFrame(email_data)
    pdf = SecurityReport()
    pdf.add_page()

    if df.empty:
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, f"No data found for the last {days} days.", 0, 1)
        pdf.output(filename)
        return filename

    # --- 1. THỐNG KÊ TỔNG QUAN ---
    total = len(df)
    stats = df['risk_level'].value_counts().to_dict()
    for level in ['SAFE', 'SUSPICIOUS', 'DANGEROUS']:
        if level not in stats: stats[level] = 0

    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, f"1. Statistics (Last {days} days)", 0, 1)

    pdf.set_font('Arial', '', 12)
    pdf.cell(60, 10, f"Total Emails Scanned:", 0, 0)
    pdf.cell(0, 10, str(total), 0, 1)

    # Vẽ bảng tỷ lệ %
    for level, count in stats.items():
        percentage = (count / total) * 100
        # Đổi màu chữ theo mức độ rủi ro
        if level == 'DANGEROUS':
            pdf.set_text_color(200, 0, 0)
        elif level == 'SUSPICIOUS':
            pdf.set_text_color(255, 140, 0)
        else:
            pdf.set_text_color(0, 128, 0)

        pdf.cell(60, 9, f"- {level}:", 0, 0)
        pdf.cell(0, 9, f"{count} ({percentage:.1f}%)", 0, 1)

    pdf.set_text_color(0, 0, 0)  # Reset màu đen
    pdf.ln(10)

    # --- 2. DANH SÁCH CHI TIẾT ---
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, "2. Detailed History Log", 0, 1)

    # Table Header
    pdf.set_fill_color(233, 69, 96)  # Màu đỏ theme CyberMail
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Arial', 'B', 10)

    pdf.cell(60, 10, "Sender", 1, 0, 'C', True)
    pdf.cell(85, 10, "Subject", 1, 0, 'C', True)
    pdf.cell(45, 10, "Risk Level", 1, 1, 'C', True)

    # Table Rows
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('Arial', '', 9)
    for _, row in df.iterrows():
        # Cắt ngắn text nếu quá dài để không vỡ khung
        sender = row['sender'][:30] + ".." if len(row['sender']) > 30 else row['sender']
        subject = row['subject'][:45] + ".." if len(row['subject']) > 45 else row['subject']

        pdf.cell(60, 8, sender, 1)
        pdf.cell(85, 8, subject, 1)
        pdf.cell(45, 8, row['risk_level'], 1, 1, 'C')

    pdf.output(filename)
    return filename

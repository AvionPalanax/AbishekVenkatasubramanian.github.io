from fpdf import FPDF
from PyPDF2 import PdfReader, PdfWriter
import tempfile

# --- Step 1: Generate PDF Content ---
def generate_pdf(anomalies_df, violations_df, full_df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.set_text_color(0)
    pdf.set_fill_color(230, 230, 250)
    pdf.cell(200, 10, txt="IoT Security Report", ln=True, align='C')
    pdf.ln(10)

    # --- Anomalies Summary ---
    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(200, 10, txt="Anomalies Detected:", ln=True)
    pdf.set_font("Arial", size=10)
    for index, row in anomalies_df.head(10).iterrows():
        pdf.cell(200, 8, txt=f"Device: {row['device_id']}, Anomaly Score: {row['anomaly_score']:.3f}", ln=True)

    pdf.ln(5)
    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(200, 10, txt="Policy Violations:", ln=True)
    pdf.set_font("Arial", size=10)
    for index, row in violations_df.head(10).iterrows():
        pdf.cell(200, 8, txt=f"Device: {row['device_id']}, VPN: {row['vpn']}, MFA: {row['mfa']}, FW: {row['firewall']}", ln=True)

    pdf.ln(5)
    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(200, 10, txt="Threat Actions Summary:", ln=True)
    pdf.set_font("Arial", size=10)
    for index, row in full_df.tail(10).iterrows():
        pdf.cell(200, 8, txt=f"Device: {row['device_id']}, Threat: {row['threat_level']}, Action: {row['auto_action']}", ln=True)

    # Save as a temp file
    temp_pdf_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name
    pdf.output(temp_pdf_path)
    return secure_pdf(temp_pdf_path, password="iot@123")

# --- Step 2: Secure the PDF ---
def secure_pdf(input_path, password="iot@123"):
    reader = PdfReader(input_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    writer.encrypt(user_password=password)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_output:
        writer.write(temp_output)
        temp_output.seek(0)
        return temp_output.read()

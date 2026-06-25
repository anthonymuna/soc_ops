import os
from pypdf import PdfReader
import google.generativeai as genai
from typing import Tuple

class DocumentIngestionPipeline:
    """
    Extracts text from PDF/image files.
    If the document is a scanned PDF (little to no text extracted),
    falls back to Gemini Multimodal API for high-fidelity document OCR.
    """
    
    def __init__(self):
        # Configure Gemini API
        api_key = os.getenv("GEMINI_API_KEY", "")
        if api_key:
            genai.configure(api_key=api_key)
            self.gemini_model = genai.GenerativeModel('gemini-1.5-flash')
        else:
            self.gemini_model = None

    def extract_text_from_pdf(self, file_path: str) -> str:
        """
        Primary extractor using pypdf (pure-Python, zero native dependencies).
        """
        try:
            reader = PdfReader(file_path)
            extracted_text = []
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    extracted_text.append(text)
            return "\n".join(extracted_text).strip()
        except Exception as e:
            print(f"Error reading PDF with pypdf: {e}")
            return ""

    def run_gemini_ocr(self, file_path: str) -> str:
        """
        Secondary OCR using Gemini. Accepts scanned PDFs or images.
        """
        if not self.gemini_model:
            raise ValueError("GEMINI_API_KEY is not configured. Cannot perform OCR fallback.")
            
        try:
            from google.generativeai import upload_file
            
            print(f"Uploading {file_path} to Gemini for OCR analysis...")
            uploaded_file = genai.upload_file(path=file_path)
            
            prompt = """
            You are a high-fidelity document OCR system.
            Extract the complete text of the uploaded document exactly as it is written.
            Format the output in clean markdown. Preserving headings, lists, tables, and section structures.
            Do not summarize. Just output the transcribed text.
            """
            
            response = self.gemini_model.generate_content([uploaded_file, prompt])
            
            try:
                genai.delete_file(uploaded_file.name)
            except Exception as cleanup_err:
                print(f"Failed to delete Gemini temporary file: {cleanup_err}")
                
            return response.text.strip()
        except Exception as e:
            print(f"Error during Gemini OCR: {e}")
            return ""

    def process_file(self, file_path: str) -> Tuple[str, str]:
        """
        Processes a file path. Returns (extracted_text, method_used).
        """
        _, ext = os.path.splitext(file_path.lower())
        
        if ext == ".txt":
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return f.read().strip(), "text_file"
            except Exception as e:
                print(f"Error reading text file: {e}")
                return "", "text_file"
                
        text = self.extract_text_from_pdf(file_path)
        
        # If the extracted text is suspiciously short, it is likely scanned.
        is_likely_scanned = len(text) < 100
        
        if is_likely_scanned and self.gemini_model:
            print("PDF appears to be scanned or empty. Running Gemini OCR fallback...")
            ocr_text = self.run_gemini_ocr(file_path)
            if ocr_text:
                return ocr_text, "gemini_ocr"
                
        return text, "pypdf_text"

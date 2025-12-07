# attachment_scanner.py
import hashlib
from typing import List, Dict, Any, Optional, Tuple
import re
import requests
import zipfile
from io import BytesIO
from PIL import Image
from PIL.ExifTags import TAGS
import logging


# Configuration du logging (journalisation)
logging.basicConfig(
    filename="attachment_scanner.log",   # fichier log créé à côté du script
    level=logging.INFO,                 # niveau: DEBUG, INFO, WARNING, ERROR, CRITICAL
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)

def scan_attachments(
    attachments: List[Dict[str, Any]],
    vt_api_key: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Point d'entrée principal.
    attachments = liste de fichiers joints sous forme de dict:
      {
        "filename": str,
        "content_type": str | None,
        "size": int,
        "data": bytes
      }
    """
    results = []
    for att in attachments:
        result = scan_single_attachment(att, vt_api_key=vt_api_key)
        results.append(result)
    return results


def scan_single_attachment(
    attachment: Dict[str, Any],
    vt_api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyse un seul fichier joint et retourne un rapport d'analyse:
     - hash SHA256
     - type détecté
     - vulnérabilités locales
     - résultat VirusTotal (si clé fournie)
     - score + verdict final
    """

    filename = attachment.get("filename", "unknown")
    content_type = attachment.get("content_type")
    data: bytes = attachment.get("data", b"")
    size = attachment.get("size", len(data))

    # Hash
    sha256 = compute_sha256(data)
    detected_type = detect_file_type(filename, content_type, data)
    vuln_result = analyze_vulnerabilities(detected_type, data, filename)
    # 4) VirusTotal (si clé fournie)
    if vt_api_key:
        vt_result = vt_lookup_hash(sha256, vt_api_key)
    else:
        vt_result = {"found": False}

    score, verdict, reasons = compute_score_and_verdict(
        detected_type=detected_type,
        vuln_result=vuln_result,
        vt_result=vt_result,
        size=size,
    )
    risk_summary = generate_risk_summary(verdict, reasons, vuln_result)
    confidence = compute_confidence_score(vt_result, reasons)
    severity = compute_severity(verdict)

    # Pour l'instant on renvoie juste ces infos
    report = {
        "filename": filename,
        "size": size,
        "sha256": sha256,
        "detected_type": detected_type,
        "verdict": verdict,
        "severity": severity,
        "score": score,
        "vulnerabilities": vuln_result.get("vulnerabilities", []),
        "details": vuln_result.get("details", {}),       
        "virus_total": vt_result,
        "reasons": reasons,
        "risk_summary": risk_summary,
        "confidence": confidence,
    
    }

    # Log de synthèse pour audit
    logger.info(
        "Scanned attachment '%s' | type=%s | size=%d | verdict=%s | score=%d | reasons=%s",
        filename,
        detected_type,
        size,
        verdict,
        score,
        ",".join(reasons) if reasons else "none"
    )
    return report


def compute_sha256(data: bytes) -> str:
    """Calcule le hash SHA256 du contenu du fichier."""
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def detect_file_type(filename: str, content_type: Optional[str], data: bytes) -> str:
    """
    Détecte le type du fichier (approximation):
      - d'abord via l'extension
      - puis via le content_type (MIME)
      - ensuite via quelques magic numbers simples
    """
    name = filename.lower()

    # 1) Extension
    if name.endswith(".pdf"):
        return "pdf"
    if name.endswith(".docx"):
        return "docx"
    if name.endswith(".xlsx"):
        return "xlsx"
    if name.endswith(".zip"):
        return "zip"
    if name.endswith(".txt"):
        return "txt"
    if name.endswith(".png"):
        return "png"
    if name.endswith(".jpg") or name.endswith(".jpeg"):
        return "jpg"
    if name.endswith(".exe"):
        return "exe"

    # 2) MIME type (content_type)
    if content_type:
        ct = content_type.lower()
        if "pdf" in ct:
            return "pdf"
        if "zip" in ct:
            return "zip"
        if "text" in ct:
            return "txt"
        if "png" in ct:
            return "png"
        if "jpeg" in ct or "jpg" in ct:
            return "jpg"

    # 3) Magic numbers (détection basique)
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"PK"):
        # PK = zip (donc aussi docx/xlsx/pptx)
        return "zip"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xFF\xD8"):
        return "jpg"
    if data.startswith(b"MZ"):
        # Fichiers PE/EXE sur Windows
        return "exe"

    return "unknown"

def analyze_vulnerabilities(
    detected_type: str,
    data: bytes,
    filename: str
) -> Dict[str, Any]:
    vulnerabilities = []
    details: Dict[str, Any] = {}

    # Texte lisible
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        text = ""

    # 1) Executable
    if detected_type == "exe":
        vulnerabilities.append("executable_file")

    # 2) ZIP (générique) + analyse interne
    if detected_type == "zip":
        vulnerabilities.append("compressed_file")
        zip_result = analyze_zip_content(data)
        vulnerabilities.extend(zip_result["vulnerabilities"])
        details["zip"] = zip_result["details"]

    # 3) TXT : recherche d'URL + commandes
    if detected_type == "txt":
        urls = re.findall(r"https?://[^\s]+", text)
        if urls:
            vulnerabilities.append("contains_urls")
            details["urls"] = urls

        # commandes shell / powershell simples
        suspicious_keywords = ["rm -rf", "powershell", "Invoke-WebRequest", "wget", "curl http"]
        found_keywords = [kw for kw in suspicious_keywords if kw.lower() in text.lower()]
        if found_keywords:
            vulnerabilities.append("suspicious_commands")
            details["suspicious_keywords"] = found_keywords

    # 4) PDF : JS ou actions
    if detected_type == "pdf":
        pdf_result = analyze_pdf_content(text)
        vulnerabilities.extend(pdf_result["vulnerabilities"])
        details["pdf"] = pdf_result["details"]

    # 5) DOCX / XLSX : macros + liens externes (fichiers Office ZIP)
    if detected_type in ("docx", "xlsx"):
        office_result = analyze_office_zip_for_macros(data)
        vulnerabilities.extend(office_result["vulnerabilities"])
        details["office"] = office_result["details"]

    # 6) Images
    if detected_type in ("png", "jpg"):
        vulnerabilities.append("image_file")

        try:
            img = Image.open(BytesIO(data))
            exif_data = img._getexif()
            if exif_data:
                details["exif"] = {
                    TAGS.get(tag, tag): str(value)
                    for tag, value in exif_data.items()
                }

                # Heuristique : recherche URLs dans les métadonnées
                meta_text = str(details["exif"])
                url_found = re.findall(r"https?://[^\s]+", meta_text)
                if url_found:
                    vulnerabilities.append("exif_hidden_urls")
                    details["exif_hidden_urls"] = url_found

        except Exception:
            details["exif_error"] = "Could not parse EXIF metadata"

    return {
        "vulnerabilities": vulnerabilities,
        "details": details,
    }

def vt_lookup_hash(sha256: str, api_key: str) -> Dict[str, Any]:
    """
    Interroge l'API VirusTotal pour un hash de fichier (SHA256).
    On ne soumet pas le fichier (juste une lookup).
    """
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=10)
    except Exception as e:
        logger.error("VirusTotal lookup failed for %s: %s", sha256, str(e))
        return {"found": False, "error": str(e)}

    if resp.status_code == 200:
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
        }
    else:
        logger.warning(
            "VirusTotal returned status %s for hash %s",
            resp.status_code,
            sha256
        )
        return {
            "found": False,
            "status_code": resp.status_code,
        }

def compute_score_and_verdict(
    detected_type: str,
    vuln_result: Dict[str, Any],
    vt_result: Dict[str, Any],
    size: int
) -> Tuple[int, str, List[str]]:
    score = 0
    reasons: List[str] = []
    vulns = vuln_result.get("vulnerabilities", [])

    # 1) vulnérabilités locales
    if "executable_file" in vulns:
        score += 80
        reasons.append("executable_file")

    if "compressed_file" in vulns:
        score += 20
        reasons.append("compressed_file")

    # pour les ZIP chiffrés
    if "encrypted_zip" in vulns:
        score += 30
        reasons.append("encrypted_zip")

    if "suspicious_commands" in vulns:
        score += 40
        reasons.append("suspicious_commands")

    if "embedded_executable_or_script" in vulns:
        score += 60
        reasons.append("embedded_executable_or_script")

    if "pdf_js_or_action" in vulns:
        score += 50
        reasons.append("pdf_js_or_action")

    if "macro_present" in vulns:
        score += 70
        reasons.append("macro_present")

    if "office_external_links" in vulns:
        score += 30
        reasons.append("office_external_links")

    if "embedded_ole_objects" in vulns:
        score += 40
        reasons.append("embedded_ole_objects")

    # 2) VirusTotal
    if vt_result.get("found"):
        mal = vt_result.get("malicious", 0)
        susp = vt_result.get("suspicious", 0)
        if mal > 0:
            score += 100
            reasons.append("vt_malicious")
        elif susp > 0:
            score += 40
            reasons.append("vt_suspicious")
        else:
            score -= 10
            reasons.append("vt_clean_or_undetected")

    # 3) Taille très petite (parfois signe de packer)
    if size < 10 * 1024:  # 10 KB
        score += 10
        reasons.append("very_small_file")

    if score < 0:
        score = 0

    # 4) Verdict selon score
    if score >= 90:
        verdict = "malicious"
    elif score >= 40:
        verdict = "suspicious"
    elif score == 0:
        verdict = "safe"
    else:
        verdict = "unknown"

    return score, verdict, reasons


def analyze_zip_content(data: bytes) -> Dict[str, Any]:
    """
    Analyse le contenu d'un ZIP:
      - liste les fichiers internes
      - marque une vulnérabilité si un .exe / .js / .vbs / .bat est trouvé
      - marque si le ZIP est chiffré (encrypted)
    """
    vulnerabilities = []
    details: Dict[str, Any] = {}

    try:
        with zipfile.ZipFile(BytesIO(data)) as z:
            names = z.namelist()
            details["files"] = names

            # détection ZIP chiffré
            encrypted = False
            for n in names:
                info = z.getinfo(n)
                # bit 0 du flag ZIP = chiffrement
                if info.flag_bits & 0x1:
                    encrypted = True
                    break

            if encrypted:
                vulnerabilities.append("encrypted_zip")
                details["encrypted"] = True

            # 🔹 Détection de fichiers dangereux dans le ZIP
            dangerous_ext = (".exe", ".dll", ".js", ".vbs", ".bat", ".cmd", ".scr")
            embedded_dangerous = [
                n for n in names if n.lower().endswith(dangerous_ext)
            ]
            if embedded_dangerous:
                vulnerabilities.append("embedded_executable_or_script")
                details["embedded_dangerous"] = embedded_dangerous

    except Exception as e:
        # Si ce n'est pas un zip valide (ou corrompu), on le note
        vulnerabilities.append("zip_parsing_error")
        details["error"] = str(e)

    return {
        "vulnerabilities": vulnerabilities,
        "details": details,
    }


def analyze_pdf_content(text: str) -> Dict[str, Any]:
    """
    Analyse heuristique d'un PDF à partir de son texte décodé:
      - recherche de /JS, /JavaScript, /OpenAction, /AA
    """
    vulnerabilities = []
    details: Dict[str, Any] = {}

    markers = ["/JS", "/JavaScript", "/OpenAction", "/AA"]
    found = [m for m in markers if m.lower() in text.lower()]
    if found:
        vulnerabilities.append("pdf_js_or_action")
        details["pdf_markers"] = found

    return {
        "vulnerabilities": vulnerabilities,
        "details": details,
    }


def analyze_office_zip_for_macros(data: bytes) -> Dict[str, Any]:
    """
    Analyse les fichiers Office basés sur ZIP (docx, xlsx, pptx):
      - recherche de vbaProject.bin (présence de macros)
      - recherche de liens externes (http/https) dans les .xml
      - recherche d'objets OLE embarqués
    """
    vulnerabilities = []
    details: Dict[str, Any] = {}

    try:
        with zipfile.ZipFile(BytesIO(data)) as z:
            names = z.namelist()
            details["files"] = names

            # 1) Macros (fichier vbaProject.bin)
            macro_files = [n for n in names if "vbaProject.bin".lower() in n.lower()]
            if macro_files:
                vulnerabilities.append("macro_present")
                details["macro_files"] = macro_files

            # 2) Objets OLE embarqués (souvent utilisés pour cacher du contenu malveillant)
            ole_objects = [n for n in names if "oleobject" in n.lower()]
            if ole_objects:
                vulnerabilities.append("embedded_ole_objects")
                details["ole_objects"] = ole_objects

            # 3) Liens externes dans les XML (très simple)
            external_links = []
            for n in names:
                if n.endswith(".xml"):
                    try:
                        xml_content = z.read(n).decode("utf-8", errors="ignore")
                        urls = re.findall(r"https?://[^\s\"<>]+", xml_content)
                        if urls:
                            external_links.extend(urls)
                    except Exception:
                        continue

            if external_links:
                vulnerabilities.append("office_external_links")
                details["external_links"] = external_links

    except Exception as e:
        vulnerabilities.append("office_zip_parsing_error")
        details["error"] = str(e)

    return {
        "vulnerabilities": vulnerabilities,
        "details": details,
    }

def generate_risk_summary(verdict: str, reasons: List[str], vuln_result: Dict[str, Any]) -> str:
    """
    Génère un résumé lisible comme dans les rapports professionnels.
    """
    if verdict == "malicious":
        risk = "HIGH RISK – Potential malware or active threat detected."
    elif verdict == "suspicious":
        risk = "MODERATE RISK – Suspicious patterns found."
    else:
        risk = "LOW RISK – No strong indicators of malicious behavior."

    details = ", ".join(reasons) if reasons else "No major indicators detected."
    return f"{risk} Indicators: {details}"


def compute_confidence_score(vt_result: Dict[str, Any], reasons: List[str]) -> float:
    """
    Calcule un score de confiance basé sur VirusTotal et les analyses locales.
    """
    confidence = 0.5  # base

    if vt_result.get("found"):
        mal = vt_result.get("malicious", 0)
        susp = vt_result.get("suspicious", 0)

        if mal > 0:
            confidence += 0.4
        elif susp > 0:
            confidence += 0.2
        else:
            confidence -= 0.1

    if "macro_present" in reasons:
        confidence += 0.1
    if "embedded_executable_or_script" in reasons:
        confidence += 0.2

    return round(min(max(confidence, 0), 1), 2)

def compute_severity(verdict: str) -> str:
    if verdict == "malicious":
        return "high"
    if verdict == "suspicious":
        return "medium"
    if verdict == "unknown":
        return "low"
    return "info"

if __name__ == "__main__":
    fake = {
        "filename": "test.txt",
        "content_type": "text/plain",
        "size": 4,
        "data": b"test"
    }
    print(scan_attachments([fake]))

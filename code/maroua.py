
# parse_email(raw_text) -> returns a dict with keys:
#   body: visible/plain text hda ykon fih text bla hdok ta3 html 
#   num_urls: integer ch7al kyn mn link 
#   urls: list of urls  list ta3 strings fih 9a3 les lien bch apres nverifyihom  
#   ip_like_url: bool ida link fih ip 
#   suspicious_words_count: int
#   suspicious_words_found: list


#Regex helps us to  search for patterns in text han ns79o bch n7ws 3la link like https
import re
import base64
import quopri


#hna la fonction principale li ra7 t3yt l9a3 fonction testi email
def teste_email(raw_text):
 print("g")

def find_url_from_text(email):
    """
    Find http/https links in the given email text and return a list of cleaned, unique URLs.
    """

    found_urls = []


    # find links that start with protocol complet 
    found_protocole =re.findall(r'((?:https?|ftp|ftps)://[^\s<>"{}|\\^\[\]`]+)', email,re.IGNORECASE)
    found_urls.extend(found_protocole)
    # find links that start with www
    found_www =re.findall(r'(?<![@/])(www\.[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,63}(?:\.[a-zA-Z]{2,})?(?:/[^\s<>"]*)?)', email,re.IGNORECASE)
    found_urls.extend(found_www)
    # find links without protocole like ushtb.dz google.com
    found_sansprotocole=re.findall(r'(?<![@/\w])([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|net|org|edu|gov|co\.uk|fr|de|io|app|xyz|tk|ml|ga|cf|gq|click|online|top|site|live|info|biz|dz)(?:/[^\s<>"]*)?)', email,re.IGNORECASE)
    found_urls.extend(found_sansprotocole)
    # find links li fihom @ ldakhel http://username@dz.com
    found_url_http = re.findall( r'((?:https?://)?[^\s<>"]+@[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}[^\s<>"]*)', email, re.IGNORECASE)
    found_urls.extend(found_url_http)
    # find links with ip adress rahom yst3mloha bzf  https://192.168.0.1 t9dr tkon bla https kima hadi 192.168.0.1
    found_ip_adress=re.findall( r'((?:https?://)?(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d+)?(?:/[^\s<>"]*)?)',email)
    found_urls.extend(found_ip_adress)




    #  clean each link from  the  symboles at the end and the start
    cleaned = []
    for link in found_urls:
        
        #remove the symbols like , ; : )  in the end of the link 
        #from the right
        link = link.rstrip(").,;:")
        #from the left 
        link = link.lstrip("([{\"'<")
        cleaned.append(link)

# we gonna delete the duplicate links to be faster with using set  while preserving order
    seen = set()
    clean_links = []
    for u in cleaned:
        if u not in seen:
            seen.add(u)
            clean_links.append(u)

    return clean_links





# netoyer email et decoder kyn ly yjo bytes python my9drch y9rahom lzm nrj3hom str
def convertir_str(email):
   # tchof ida email raho de type bytes 
   if isinstance(email,bytes):
      # kyn mindak yjo caractere m3ndhomch fyda bch python my7bsch ykml
      return email.decode('utf-8', errors='replace')
   # sinon rah deja str bla mydir wlo
   return email


# email dymen ykon fih headears body
#headrs hya info ta3 email chkon b3to lmen b3eto (from to subject) na ns79 contenue machi hado 
#body howa sa7 fih contenue de email
def separer_headers_body(email):
    email = convertir_str(email)
     #C’est un marqueur universel pour parseur les emails car tous les serveurs et clients mails utilisent ce format CRLF pour les fins de ligne, même si certains systèmes (ex: Linux) utilisent seulement \n en interne.
     #\r\n\r\n m3naha une ligne vide hadi rahi fles email chrol ki yl9aha y3redf bli dar header wkhla plasa bch ykteb body 
    if '\r\n\r\n' in email:
         # partition fonction t9smo texte 3la 3 3la hsab '\r\n\r\n'  header t7t fih partie 9bel separateur w _ t7t fih separateur body t7at lba9i
        header, _, body = email.partition('\r\n\r\n')
    elif '\n\n' in email:
        header, _, body = email.partition('\n\n')
    else:
        # m3naha ml9a hta separateur kyn rir body
        return '', email  # tout est body si pas de séparateur

    if ":" in header:
        #y9dr text ykon fih seperator bs7 machi m3naha kyn header
       # from: to: hka yji header dymn fih :
        return header, body
    else:
        return '', email




"""Pourquoi décoder base64 / quoted-printable ?
Les emails peuvent contenir du contenu encodé pour être transmis correctement sur Internet, notamment pour des caractères spéciaux ou des contenus non-ASCII.

Les encodages fréquents sont :

Base64 : encode binaire en texte ASCII (ex : images, fichiers, ou corps HTML encodé)

Quoted-printable : encode certains caractères spéciaux (ex : accents, caractères non ASCII) en séquences lisibles

Si le contenu est encodé et qu’on ne le décode pas, on analysera à tort des séquences codées (illisibles, bruit), ce qui rompt la détection des éléments importants (mots, URLs, structures).

En phishing, il est fréquent que les attaquants encodent leurs contenus pour cacher les vrais liens ou masquer le texte malveillant.

Le décodage permet donc de révéler la vraie structure et le contenu, indispensable pour une détection fiable."""

# tsema lzm ndecodiw
#1-Appliquer le décodage correspondant base64-quoted-printable  pour avoir le contenu réel.
#2-normaliser le text na7i les saute w espace bzf psq les ataquant ykhliw les espace bch mn9drch ndetecter l3wj
#3-nrj3hom 9a3 miniscule
# -----------------------
# Décodage selon headers
# -----------------------
#hadi fiha option avance m3rftch ndirha w7di
def decode_by_header(headers, body):
    """
    Si headers indiquent Content-Transfer-Encoding: base64 ou quoted-printable,
    on tente de décoder la portion body correspondante (prudemment).
    Si décodage échoue on renvoie la body d'origine.
    """

    # ida mkch headers yb3t direct body
    if not headers:
        return body
     #nrj3hom 9a3 miniscule
    lower_headers = headers.lower()

    # si header indique base64
    if 'content-transfer-encoding' in lower_headers and 'base64' in lower_headers:
        try:
            decoded_bytes = base64.b64decode(body, validate=False)
            return decoded_bytes.decode('utf-8', errors='replace')
        except Exception:
            return body

    # si header indique quoted-printable
    if 'content-transfer-encoding' in lower_headers and 'quoted-printable' in lower_headers:
        try:
            decoded_bytes = quopri.decodestring(body)
            return decoded_bytes.decode('utf-8', errors='replace')
        except Exception:
            return body

    return body

# -----------------------
# Heuristique si pas de header
# -----------------------
def try_decode_probable_base64(body):
    """
    Si on voit des lignes très longues composées de caractères base64-like,
    on tente un décodage prudent sur ces lignes et on retourne le body potentiellement décodé.
    (Ne change rien si échec.)
    """
    if not body:
        return body

     # separer le texte en ligne
    lines = body.splitlines()
    for ln in lines:
        # ligne longue (>120) et composée uniquement de base64 chars (+ possible padding =)
        # ykon fiha rir character w num
        if len(ln) > 120 and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', ln):
            try:
                decoded = base64.b64decode(ln, validate=False)
                s = decoded.decode('utf-8', errors='replace')
                # si le résultat ressemble à du HTML ou contient des headers -> plausible
                if '<html' in s.lower() or 'content-type' in s.lower() or '<body' in s.lower():
                    return s
            except Exception:
                pass
    return body




def eliminé_lower_space(email):
        # na7i les espace zaydine
    text = email.replace('\r\n', '\n').replace('\r', '\n')
        # remplacer séquences d'espaces/newlines/tabs par un seul espace
    text = re.sub(r'\s+', ' ', text)
        # yna7i espace ta3 debut w fin zayd
    text = text.strip()
    # yrj3 text netoyer sans espace w yzid yrj3o miniscule wyb3to
    return text, text.lower()



def decodé_eliminé_normalizé(email):
    
      # transfere en str si il est en bytes
      #separe entre headers et body
      #decoder si raho indique base64 / quoted-printable
      #elimine les espaces inutiles et separer les lignes 
      #normalise is produit en miniscule
      
    header,body=separer_headers_body(email)

    #garder version brut
    body_raw = body
    body_decoded = decode_by_header(header, body)


    #ida msra hta decodage nrj3ha if body_decoded == body:
    if body_decoded == body:
        body_decoded = try_decode_probable_base64(body_decoded)

    # na7i space newline wnrj3ha miniscule
    clean_text, lower_text = eliminé_lower_space(body_decoded)
   




    return {
        'headers_raw': header,
        'body_raw': body_raw,
        'body_decoded': body_decoded,
        'clean_text': clean_text,
        'lower_text': lower_text
    }































# verifier ida email raho mktob b html ra7 returni bool
def is_html(text):
    if not text:
        return False
    text_lower = text.lower()
    # détecte les balises HTML communes
    html_tags = ['<html', '<body', '<div', '<table', '<p', '<a', '<span']
    for tag in html_tags:
        if tag in text_lower:
            return True
    return False

    

 
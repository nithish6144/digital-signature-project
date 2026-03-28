from flask import Flask, render_template, request, redirect
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
SIGNATURE_FOLDER = "signatures"
KEY_FOLDER = "keys"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNATURE_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)

PRIVATE_KEY_FILE = os.path.join(KEY_FOLDER, "private.pem")
PUBLIC_KEY_FILE = os.path.join(KEY_FOLDER, "public.pem")

# Generate keys if not exist
if not os.path.exists(PRIVATE_KEY_FILE):

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/sign", methods=["GET", "POST"])
def sign():
    if request.method == "POST":
        file = request.files["file"]

        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)

        private_key = load_private_key()

        with open(filepath, "rb") as f:
            data = f.read()

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        sig_path = os.path.join(SIGNATURE_FOLDER, file.filename + ".sig")

        with open(sig_path, "wb") as f:
            f.write(signature)

        return render_template("sign_result.html", filename=file.filename + ".sig")

    return render_template("sign.html")

@app.route("/verify", methods=["GET", "POST"])
def verify():

    if request.method == "POST":

        file = request.files["file"]
        signature = request.files["signature"]

        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        sigpath = os.path.join(SIGNATURE_FOLDER, signature.filename)

        file.save(filepath)
        signature.save(sigpath)

        public_key = load_public_key()

        with open(filepath, "rb") as f:
            data = f.read()

        with open(sigpath, "rb") as f:
            sig = f.read()

        try:
            public_key.verify(
                sig,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return render_template("verify_result.html", result="valid")
        except:
            return render_template("verify_result.html", result="invalid")

    return render_template("verify.html")

if __name__ == "__main__":
    app.run(debug=True)
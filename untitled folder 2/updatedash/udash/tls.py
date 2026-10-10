"""Self-signed TLS certificate for serving HTTPS directly (no reverse proxy needed)."""
import datetime
import ipaddress
import os
import socket
from pathlib import Path

from .util import atomic_write

VALID_DAYS = 825
RENEW_BEFORE_DAYS = 30


def _names():
    names = {"localhost", socket.gethostname()}
    ips = {"127.0.0.1", "::1"}
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            ips.add(ip)
    except OSError:
        pass
    return names, ips


def _sans(extra):
    names, ips = _names()
    for item in extra or []:
        try:
            ips.add(str(ipaddress.ip_address(str(item))))
        except ValueError:
            names.add(str(item))
    return sorted(n for n in names if n), sorted(ips)


def fingerprint(cert_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    return "SHA256:" + cert.fingerprint(hashes.SHA256()).hex(":").upper()


def ensure_self_signed(directory, extra_names=()):
    """Create (or reuse) an ECDSA P-256 certificate. Returns (cert_path, key_path, fingerprint)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    cert_path, key_path = d / "tls.crt", d / "tls.key"
    names, ips = _sans(extra_names)
    want = {("dns", n) for n in names} | {("ip", i) for i in ips}
    if cert_path.is_file() and key_path.is_file():
        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            have = {("dns", n) for n in san.get_values_for_type(x509.DNSName)} | \
                   {("ip", str(i)) for i in san.get_values_for_type(x509.IPAddress)}
            left = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else \
                cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            if want <= have and (left - datetime.datetime.now(datetime.timezone.utc)).days > RENEW_BEFORE_DAYS:
                return str(cert_path), str(key_path), fingerprint(cert_path)
        except (ValueError, x509.ExtensionNotFound):
            pass
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "updatedash")])
    now = datetime.datetime.now(datetime.timezone.utc)
    alt = [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    atomic_write(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                             serialization.NoEncryption()), 0o600)
    atomic_write(cert_path, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    return str(cert_path), str(key_path), fingerprint(cert_path)

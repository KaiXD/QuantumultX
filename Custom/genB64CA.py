from OpenSSL import crypto
import base64

key = crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 2048)

cert = crypto.X509()
cert.get_subject().O = "Certificate Authority"
cert.get_subject().CN = "Kai Custom Root Certificate"
cert.set_issuer(cert.get_subject())
cert.set_serial_number(0)
cert.set_notBefore(b"20161001000000Z")
cert.set_notAfter(b"20991001000000Z")
cert.set_pubkey(key)
cert.set_version(1)
cert.sign(key, 'sha256')

pfx = crypto.PKCS12()
pfx.set_certificate(cert)
pfx.set_privatekey(key)
pfxData = pfx.export(b'BreakGFW')
print(base64.b64encode(pfxData))

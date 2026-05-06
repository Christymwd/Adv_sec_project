import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from src.ccm_mode import ccm_decrypt, ccm_encrypt


HTML_PAGE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>S-AES CCM UI</title>
  <style>
    :root {
      color-scheme: light;
      font-family: Arial, Helvetica, sans-serif;
      background: #f4f6f8;
      color: #17202a;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
    }

    main {
      width: min(980px, 100%);
      background: #ffffff;
      border: 1px solid #d7dee8;
      border-radius: 8px;
      box-shadow: 0 14px 35px rgba(23, 32, 42, 0.08);
      overflow: hidden;
    }

    header {
      padding: 24px 28px 18px;
      border-bottom: 1px solid #e4e9f0;
      background: #fbfcfe;
    }

    h1 {
      margin: 0;
      font-size: 24px;
      font-weight: 700;
      letter-spacing: 0;
    }

    .content {
      padding: 24px 28px 28px;
    }

    label {
      display: grid;
      gap: 8px;
      font-size: 14px;
      font-weight: 700;
      color: #2d3a4a;
    }

    input,
    textarea {
      width: 100%;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 12px;
      font: 14px/1.5 Consolas, Monaco, monospace;
      color: #111827;
      background: #ffffff;
      outline: none;
    }

    input:focus,
    textarea:focus {
      border-color: #2563eb;
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.14);
    }

    textarea {
      min-height: 230px;
      resize: vertical;
    }

    .key-row {
      max-width: 280px;
      margin-bottom: 18px;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 18px;
    }

    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      margin-top: 18px;
    }

    button {
      border: 0;
      border-radius: 6px;
      padding: 11px 15px;
      font: 700 14px/1 Arial, Helvetica, sans-serif;
      cursor: pointer;
      color: #ffffff;
      background: #2563eb;
    }

    button.secondary {
      background: #475569;
    }

    button.clear {
      background: #b42318;
    }

    #status {
      min-height: 20px;
      margin-left: auto;
      color: #475569;
      font-size: 14px;
    }

    #status.error {
      color: #b42318;
      font-weight: 700;
    }

    #status.ok {
      color: #16703c;
      font-weight: 700;
    }

    @media (max-width: 760px) {
      body {
        padding: 14px;
        place-items: start center;
      }

      header,
      .content {
        padding-left: 18px;
        padding-right: 18px;
      }

      .grid {
        grid-template-columns: 1fr;
      }

      #status {
        width: 100%;
        margin-left: 0;
      }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>S-AES CCM Text Interface</h1>
    </header>
    <section class="content">
      <label class="key-row">
        16-bit key
        <input id="key" value="0xABCD" autocomplete="off" spellcheck="false">
      </label>

      <div class="grid">
        <label>
          Plaintext
          <textarea id="plaintext" spellcheck="false">Hello Crypto World!</textarea>
        </label>
        <label>
          Ciphertext hex
          <textarea id="ciphertext" spellcheck="false"></textarea>
        </label>
      </div>

      <div class="actions">
        <button id="encrypt" type="button">Encrypt to ciphertext</button>
        <button id="decrypt" class="secondary" type="button">Decrypt to plaintext</button>
        <button id="clear" class="clear" type="button">Clear</button>
        <span id="status" aria-live="polite"></span>
      </div>
    </section>
  </main>

  <script>
    const keyInput = document.getElementById('key');
    const plaintextInput = document.getElementById('plaintext');
    const ciphertextInput = document.getElementById('ciphertext');
    const statusOutput = document.getElementById('status');

    function setStatus(message, kind) {
      statusOutput.textContent = message;
      statusOutput.className = kind || '';
    }

    async function postJson(path, payload) {
      const response = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Request failed.');
      }
      return data;
    }

    document.getElementById('encrypt').addEventListener('click', async () => {
      setStatus('Encrypting...', '');
      try {
        const data = await postJson('/api/encrypt', {
          key: keyInput.value,
          plaintext: plaintextInput.value
        });
        ciphertextInput.value = data.ciphertext;
        setStatus(`Encrypted ${data.plaintext_bytes} plaintext bytes.`, 'ok');
      } catch (error) {
        setStatus(error.message, 'error');
      }
    });

    document.getElementById('decrypt').addEventListener('click', async () => {
      setStatus('Decrypting...', '');
      try {
        const data = await postJson('/api/decrypt', {
          key: keyInput.value,
          ciphertext: ciphertextInput.value
        });
        plaintextInput.value = data.plaintext;
        setStatus(`Decrypted ${data.plaintext_bytes} plaintext bytes.`, 'ok');
      } catch (error) {
        setStatus(error.message, 'error');
      }
    });

    document.getElementById('clear').addEventListener('click', () => {
      plaintextInput.value = '';
      ciphertextInput.value = '';
      setStatus('', '');
    });
  </script>
</body>
</html>
"""


class CipherUIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        page = HTML_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self):
        try:
            payload = self.read_json_body()
            key = parse_key(payload.get("key", ""))

            if self.path == "/api/encrypt":
                plaintext = str(payload.get("plaintext", ""))
                plaintext_bytes = plaintext.encode("utf-8")
                ciphertext = ccm_encrypt(plaintext_bytes, key)
                self.send_json(
                    {
                        "ciphertext": ciphertext.hex().upper(),
                        "plaintext_bytes": len(plaintext_bytes),
                    }
                )
                return

            if self.path == "/api/decrypt":
                ciphertext_text = str(payload.get("ciphertext", "")).strip()
                if not ciphertext_text:
                    raise ValueError("Enter ciphertext hex first.")

                try:
                    ciphertext = bytes.fromhex(ciphertext_text)
                except ValueError as exc:
                    raise ValueError("Ciphertext must be valid hex.") from exc

                plaintext_bytes = ccm_decrypt(ciphertext, key)
                self.send_json(
                    {
                        "plaintext": plaintext_bytes.decode("utf-8", errors="replace"),
                        "plaintext_hex": plaintext_bytes.hex().upper(),
                        "plaintext_bytes": len(plaintext_bytes),
                    }
                )
                return

            self.send_error(404, "Unknown endpoint")
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:  # Keeps UI errors readable while preserving the original crypto code.
            self.send_json({"error": f"Operation failed: {exc}"}, status=500)

    def read_json_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length)
        try:
            return json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("Request body must be valid JSON.") from exc

    def send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def parse_key(raw_key):
    key_text = str(raw_key).strip()
    if key_text.lower().startswith("0x"):
        key_text = key_text[2:]

    if not key_text:
        raise ValueError("Enter a 16-bit hex key.")

    try:
        key = int(key_text, 16)
    except ValueError as exc:
        raise ValueError("Key must be a 16-bit hex value, for example 0xABCD.") from exc

    if not 0 <= key <= 0xFFFF:
        raise ValueError("Key must fit in 16 bits: 0x0000 through 0xFFFF.")

    return key


def main():
    parser = argparse.ArgumentParser(description="Run a simple browser UI for S-AES CCM text encryption.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind, default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind, default: 8080")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), CipherUIHandler)
    print(f"S-AES CCM UI running at http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

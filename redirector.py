from flask import Flask, request, redirect
import base64

app = Flask(__name__)

@app.route('/')
def decode_and_redirect():
    encoded_url = request.args.get('r')
    if not encoded_url:
        return "Missing 'r' parameter", 400

    try:
        decoded_bytes = base64.urlsafe_b64decode(encoded_url + '===')
        decoded_url = decoded_bytes.decode('utf-8')
        return redirect(decoded_url)
    except Exception as e:
        return f"Decode error: {e}", 500

if __name__ == '__main__':
    app.run()

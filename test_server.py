from http.server import BaseHTTPRequestHandler, HTTPServer
import time

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/app.js':
            self.send_response(200)
            self.send_header('Content-type', 'application/javascript')
            self.end_headers()
            self.wfile.write(b'var x = "?secret_param=" + val;\nfetch("/api?some_other=1");\nconst config = {"hidden_dev_mode": true};\n')
            return
            
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        response = f"<html><body><h1>Hello World</h1><script src='/app.js'></script><p>Time: {time.time()}</p>"
        
        if 'hidden_dev_mode=test_fuzz_1337' in self.path:
            response += "<div><h3>DEV MODE ENABLED!</h3><p>Here is some sensitive dev data that significantly changes the response length and content.</p></div>" * 10
            
        response += "</body></html>"
        self.wfile.write(response.encode())

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 13337), MyHandler)
    server.serve_forever()

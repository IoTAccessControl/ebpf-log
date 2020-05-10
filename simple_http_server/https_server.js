//

/*
https://nodejs.org/en/knowledge/HTTP/servers/how-to-create-a-HTTPS-server/

curl -k https://localhost:8000

sudo tcpflow -i lo -c port 8000

*/

const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

console.log("Starting up https-server.\n Available on:\n https://127.0.0.1:8000/")

https.createServer(options, function (req, res) {
    if (req.method === "GET") {
        console.log('https [%s] "%s %s"', new Date().toISOString(), req.method, req.url)
        res.writeHead(200, { "Content-Type": "text/html" });
        // 需要主动调用 end
        // fs.createReadStream("index.html", "UTF-8").pipe(res);
        fs.readFile("index.html", "UTF-8", function(err, data){ 
            res.end(data);
        }); 
        // res.end("get data long data");
    } else if (req.method === "POST") {
        var body = "POST: ";
        req.on("data", function (chunk) {
            body += chunk;
        });

        req.on("end", function(){
            console.log('https [%s] "%s %s" %s', new Date().toISOString(), req.method, req.url, body)
            res.writeHead(200, { "Content-Type": "text/html" });
            res.end(body);
        });
    }
}).listen(8000);
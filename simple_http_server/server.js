// Node.js: HTTP SERVER Handling GET and POST Request 
// Show HTML Form at GET request.
// At POST Request: Grab form data and display them.
// Get Complete Source Code from Pabbly.com
// 
// https://www.pabbly.com/tutorials/node-js-http-server-handling-get-and-post-request/
// https://flaviocopes.com/node-http-post/

/*
test:
GET: curl http://127.0.0.1:3000/
POST: curl -d "postdata"  http://127.0.0.1:3000/

trace:
sudo trace -p 3184 'u:/usr/local/bin/node:http__server__request "%s %d %s %s %d", arg3, arg4, arg5, arg6, arg7'

*/


var http = require('http');
var fs = require('fs');

console.log("Starting up simple-http-server.\n Available on:\n http://127.0.0.1:3000/")

var server = http.createServer(function (req, res) {
    console.log('[%s] "%s %s"', new Date().toISOString(), req.method, req.url)

    if (req.method === "GET") {
        res.writeHead(200, { "Content-Type": "text/html" });
        fs.createReadStream("index.html", "UTF-8").pipe(res);
    } else if (req.method === "POST") {
        var body = "";
        req.on("data", function (chunk) {
            body += chunk;
        });

        req.on("end", function(){
            res.writeHead(200, { "Content-Type": "text/html" });
            res.end(body);
        });
    }

}).listen(3000);
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
    
    if (req.method === "GET") {
        console.log('[%s] "%s %s"', new Date().toISOString(), req.method, req.url)
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
            console.log('[%s] "%s %s" %s', new Date().toISOString(), req.method, req.url, body)
            res.writeHead(200, { "Content-Type": "text/html" });
            res.end(body);
        });
    }

}).listen(3000);
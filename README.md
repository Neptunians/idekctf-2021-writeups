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

Of course, it filters it:



## Steghide as a Service

## Fancy Notes

## TODO: REPO

## References
* CTF Time Event: https://ctftime.org/event/1512
* idekCTF: https://ctf.idek.team/
* CTF Discord: https://discord.gg/Rrhdvzn
* Repo with the artifacts discussed here: https://github.com/Neptunians/idekctf-2021-writeups
* SSRF: https://portswigger.net/web-security/ssrf
* ssrf-req-filter: https://github.com/y-mehta/ssrf-req-filter
* Team: [FireShell](https://fireshellsecurity.team/)
* Team Twitter: [@fireshellst](https://twitter.com/fireshellst)
* Follow me too :) [@NeptunianHacks](https://twitter.com/NeptunianHacks) 
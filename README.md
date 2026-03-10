# Bonus #0

## VibeBot is the Best Bot! (25 Points)

### Topic: Format String Attacks

We were asked to perform a security audit on a brand new vibecoded project codenamed `clawdbot`. We know very little about the app, but we were just given access to the project's docker image available at `ethan42/clawdbot:latest`. The best-of-breed AI systems enabled devs to deliver this incredible app blazingly fast! However, is clawdbot secure?

## Requirements

Your mission, should you choose to accept it, is to:

1. Write up and commit an `exploit.py` script runnable in python3 that produces an exploit payload for clawdbot. We need the payload to spawn a root shell when provided to clawdbot. The `exploit.py` script should be committed to the top-level directory of the repo.
1. Add a `writeup.md` file and provide a detailed write up of how you managed to exploit this program. Include a successful invocation in your write up (extra points for using [asciinema](https://asciinema.org/)!).

An example successful invocation follows:

```
$ docker run --rm --privileged -v `pwd`/exploit.py:/exploit.py -it ethan42/clawdbot:latest bash
bot@a214b2962a8b:~$ python3 /exploit.py > /tmp/payload
bot@a214b2962a8b:~$ whoami
bot
bot@a214b2962a8b:~$ clawdbot `cat /tmp/payload`
... [snip] ...
# whoami
root
```

Extra points if you manage to exploit clawdbot without using the process function!

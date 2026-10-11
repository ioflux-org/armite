# Demo clips

Scripted terminal recordings, one [VHS](https://github.com/charmbracelet/vhs)
tape each, rendered against a running server:

| tape | shows |
| --- | --- |
| `hero.tape` | Owner is refused a secret (403 with the action and scope), one role assignment, the same command succeeds — the README's GIF |
| `storage.tape` | Owner creates the container and cannot upload the blob; the data role; a user delegation SAS that stops working the moment the role is revoked |
| `ops.tape` | the request id on a response is the id of one log line; `kill -9`, restart, everything is back |
| `docker.tape` | the published image: `docker run`, the boot log's next steps, the CA copied out, `az` through it, `armite hosts` inside |

## Where the clips are

`hero.gif` lives here because the README embeds it. Every clip, as MP4
and GIF, is attached to each release on the
[releases page](https://github.com/ioflux-org/armite/releases); the
tapes are the source, and a render takes seconds.

## Rendering

Needs `vhs`, `ttyd`, `ffmpeg` and `az`, the server on port 8443, and
`az` logged in as the built-in principal (the README's quickstart). Each
tape expects a state:

| tape | state before the take |
| --- | --- |
| `hero` | fresh; `kv-rg` and `kv-demo` created, nothing granted on the vault |
| `storage` | fresh, with `azurite-blob` on the server's PATH |
| `ops` | after `storage`, with the data roles granted and `db-pass` set in `kv-demo`; the server started as `armite > armite.log 2>&1 &` in this directory |
| `docker` | no server on the host; the image pulled |

`DEMO_AZ` is the az configuration directory and `DEMO_CA` the server's
`ca.pem`; the tape exports them off camera. VHS renders the MP4; the GIF
is two ffmpeg passes (VHS's own GIF renderer needs more memory than a
small VM has):

```bash
DEMO_AZ=$HOME/.azure-demo DEMO_CA=$HOME/.armite/ca.pem vhs demo/hero.tape
ffmpeg -y -i hero.mp4 -vf 'fps=12,scale=1200:-1:flags=lanczos,palettegen=stats_mode=diff' palette.png
ffmpeg -y -i hero.mp4 -i palette.png -lavfi 'fps=12,scale=1200:-1:flags=lanczos [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=5' hero.gif
```

A failed render has still run the commands, so reset the state before
every take.

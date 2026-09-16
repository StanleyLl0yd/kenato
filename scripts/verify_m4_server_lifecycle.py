#!/usr/bin/env python3
"""Pin the M4 server shutdown ordering required for upgraded WebSocket workers."""

from pathlib import Path

path = Path("server/cmd/kenato-server/main.go")
text = path.read_text(encoding="utf-8")
errors: list[str] = []

wss_shutdown = text.find("messagingWS.Shutdown(messagingShutdownCtx)")
http_shutdown = text.find("server.Shutdown(httpShutdownCtx)")
if wss_shutdown < 0 or http_shutdown < 0 or wss_shutdown > http_shutdown:
    errors.append("M4 WSS shutdown must precede HTTP shutdown")

failure_case = text.find("case err := <-errCh:")
ordered_shutdown = text.find("// Stop upgraded WSS work first")
if failure_case < 0 or ordered_shutdown < 0 or failure_case >= ordered_shutdown:
    errors.append("unable to locate server-failure common shutdown path")
else:
    failure_path = text[failure_case:ordered_shutdown]
    if "break running" not in failure_path:
        errors.append("server failure must enter the common ordered shutdown path")
    if "\n\t\t\treturn" in failure_path:
        errors.append("server failure must not return before M4 WSS shutdown")

for fragment in (
    "messagingWS.Shutdown(messagingShutdownCtx)",
    "server.Shutdown(httpShutdownCtx)",
    "mailboxStore.Close()",
    "store.Close()",
):
    if fragment not in text:
        errors.append(f"missing lifecycle fragment: {fragment}")

if errors:
    raise SystemExit("\n".join(errors))

print("M4 server lifecycle policy OK")
